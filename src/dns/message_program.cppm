export module dns.message_program;
import std;
export import functional;
import dns.message;
import dns.reverse;
import dns.message_fakeip;
import dns.input_budget;
export import dns.message_exchange;
import dns.policy;
import dns.response_program;
import rules;
import dns.response_race_walk;
import dns.message_race_program;
export import dns.message_synthetic;
import dns.message_cache;
import dns.response_query;
import dns.local_config;
import dns.predefined;
import dns.corosio_resolver;
import dns.corosio_query;
import capy;
import corosio;

export namespace dns {
    struct MessageUpstreamSnapshot {
        std::span<MessageUpstream const> upstreams;
        std::size_t fallback;
        MessageCache* cache;
        bool disable_cache;
        ReverseCache* reverse_cache = nullptr;
        bool independent_cache = false;
    };

    struct MessageRuleSnapshot {
        std::shared_ptr<std::vector<policy::DnsRule> const> rules;
        std::optional<std::uint64_t> view;
        // Aliases the state that owns the upstream table and cache.
        std::shared_ptr<MessageUpstreamSnapshot const> resolver;
        std::shared_ptr<detail::TransportSnapshot const> transports;

        MessageRuleSnapshot()=default;
        MessageRuleSnapshot(std::shared_ptr<std::vector<policy::DnsRule> const> values,
            std::optional<std::uint64_t> policy_view={}) noexcept : rules(std::move(values)),view(policy_view) {}
    };
    using MessageRuleSource=functional::copyable_function<MessageRuleSnapshot() const>;
    // One owner per client query; cancellation and run share an executor.
    // Upstream, rules, optional concurrent modes and context remain borrowed
    // until the task returns, including cancellation and task drain.
    class MessageProgram {
        using Clock=std::chrono::steady_clock;
        corosio::io_context& context_;
        std::span<policy::DnsRule const> rules_;
        std::span<MessageUpstream const> upstreams_;
        std::size_t fallback_;
        MessageCache* cache_;
        InputBudget* override_budget_;
        std::optional<std::uint64_t> view_;
        bool disable_cache_;
        bool independent_cache_=false;
        ReverseCache* reverse_cache_=nullptr;
        MessageExchange* active_=nullptr;
        MessageRaceProgram* racing_=nullptr;
        std::span<ResponseRaceMode const> modes_;
        bool started_=false,canceled_=false;
#ifdef NEXUS_DNS_FAKEIP
        FakeIpPublication publication_;
#endif
        static auto read_u16_be(std::span<std::uint8_t const> s, std::size_t off) noexcept -> std::uint16_t {
            return static_cast<std::uint16_t>((std::uint16_t{s[off]} << 8) | s[off + 1]);
        }
        static auto valid_ech_public_name(std::string_view name) noexcept -> bool {
            if (name.empty() || name.size() > 253 || name.back() == '.') return false;
            std::size_t start = 0;
            for (std::size_t i = 0; i <= name.size(); ++i) {
                if (i == name.size() || name[i] == '.') {
                    if (i == start || i - start > 63 || name[start] == '-' || name[i - 1] == '-') return false;
                    start = i + 1;
                } else {
                    char c = name[i];
                    if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-'))
                        return false;
                }
            }
            return true;
        }
        static auto skip_uncompressed_name(std::span<std::uint8_t const> data, std::size_t& off) noexcept -> bool {
            std::size_t total = 0;
            while (off < data.size()) {
                auto len = data[off++];
                if (len == 0) return true;
                if (len > 63 || len > data.size() - off || total + len + 1 > 255) return false;
                off += len;
                total += len + 1;
            }
            return false;
        }
        static auto record_reverse_answer(ReverseCache& reverse,std::uint64_t view,QueryMessage const& query,
            std::span<std::uint8_t const> wire) noexcept -> void {
            if (query.question.klass!=1) return;
            auto now_ms=static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                Clock::now().time_since_epoch()).count());
            if (query.question.type==65 || query.question.type==64) {
                (void)record_https_ech_reverse(reverse,view,query,wire,now_ms);
                return;
            }
            if (query.question.type!=1 && query.question.type!=28) return;
            auto parsed=parse_addresses(wire,query.id,query.question,query.edns.has_value());
            if (!parsed || parsed->addresses.empty() || !parsed->ttl || !*parsed->ttl) return;
            (void)reverse.record(view,query.question.name,parsed->addresses,*parsed->ttl,now_ms,reverse.token());
        }
    public:
        [[nodiscard]] static auto extract_https_ech_public_name(std::span<std::uint8_t const> ech_config_list) noexcept
            -> std::optional<std::string_view> {
            if (ech_config_list.size() < 2) return std::nullopt;
            auto list_len = std::size_t{read_u16_be(ech_config_list, 0)};
            if (list_len == 0 || list_len != ech_config_list.size() - 2) return std::nullopt;
            std::size_t pos = 2;
            while (pos < ech_config_list.size()) {
                if (ech_config_list.size() - pos < 4) return std::nullopt;
                auto version = read_u16_be(ech_config_list, pos);
                auto contents_len = std::size_t{read_u16_be(ech_config_list, pos + 2)};
                pos += 4;
                if (contents_len > ech_config_list.size() - pos) return std::nullopt;
                auto c = ech_config_list.subspan(pos, contents_len);
                pos += contents_len;
                if (version != 0xfe0d) continue;
                // ECHConfigContents: id(1), kem_id(2), pk_len(2), pk, cs_len(2), cs, max_name(1), pub_len(1), pub, ext_len(2), ext
                if (c.size() < 9) return std::nullopt;
                std::size_t off = 3; // skip id + kem_id
                auto pk_len = std::size_t{read_u16_be(c, off)}; off += 2;
                if (pk_len == 0 || pk_len > c.size() - off || c.size() - (off + pk_len) < 2) return std::nullopt;
                off += pk_len;
                auto cs_len = std::size_t{read_u16_be(c, off)}; off += 2;
                if (cs_len == 0 || (cs_len % 4) != 0 || cs_len > c.size() - off || c.size() - (off + cs_len) < 4)
                    return std::nullopt;
                off += cs_len;
                off += 1; // maximum_name_length
                auto name_len = std::size_t{c[off++]};
                if (name_len == 0 || name_len > c.size() - off || c.size() - (off + name_len) < 2) return std::nullopt;
                std::string_view pub_name(reinterpret_cast<char const*>(c.data() + off), name_len);
                off += name_len;
                auto ext_len = std::size_t{read_u16_be(c, off)}; off += 2;
                if (ext_len != c.size() - off) return std::nullopt;
                if (!valid_ech_public_name(pub_name)) return std::nullopt;
                return pub_name;
            }
            return std::nullopt;
        }
        static auto record_https_ech_reverse(ReverseCache& reverse,std::uint64_t view,QueryMessage const& query,
            std::span<std::uint8_t const> wire,std::uint64_t now_ms) noexcept -> std::size_t {
            if (query.question.klass != 1 || (query.question.type != 65 && query.question.type != 64)) return 0;
            auto parsed = parse_response(wire, query.id, query.question);
            if (!parsed || parsed->rcode != 0) return 0;
            auto tok = reverse.token();
            std::size_t recorded = 0;
            for (auto const& rec : parsed->records) {
                if (rec.section != Section::answer || rec.klass != 1 || !rec.ttl ||
                    (rec.type != 65 && rec.type != 64)) continue;
                if (rec.data_offset > parsed->wire.size() || rec.data_length > parsed->wire.size() - rec.data_offset)
                    continue;
                auto rdata = std::span<std::uint8_t const>(parsed->wire).subspan(rec.data_offset, rec.data_length);
                if (rdata.size() < 3) continue;
                auto priority = read_u16_be(rdata, 0);
                if (priority == 0) continue; // AliasMode carries no SvcParams.
                std::size_t off = 2;
                if (!skip_uncompressed_name(rdata, off)) continue;
                std::optional<std::string_view> pub_name;
                std::array<Address, 32> hints{};
                std::size_t hint_count = 0;
                std::optional<std::uint16_t> prev_key;
                bool malformed = false;
                while (off < rdata.size()) {
                    if (rdata.size() - off < 4) { malformed = true; break; }
                    auto key = read_u16_be(rdata, off);
                    auto len = std::size_t{read_u16_be(rdata, off + 2)};
                    off += 4;
                    if ((prev_key && key <= *prev_key) || len > rdata.size() - off) { malformed = true; break; }
                    prev_key = key;
                    auto val = rdata.subspan(off, len);
                    off += len;
                    if (key == 5) {
                        pub_name = extract_https_ech_public_name(val);
                    } else if (key == 4 && len > 0 && (len % 4) == 0) {
                        for (std::size_t p = 0; p < len && hint_count < hints.size(); p += 4) {
                            Address a{}; a.size = 4;
                            std::copy_n(val.data() + p, 4, a.bytes.begin());
                            hints[hint_count++] = a;
                        }
                    } else if (key == 6 && len > 0 && (len % 16) == 0) {
                        for (std::size_t p = 0; p < len && hint_count < hints.size(); p += 16) {
                            Address a{}; a.size = 16;
                            std::copy_n(val.data() + p, 16, a.bytes.begin());
                            hints[hint_count++] = a;
                        }
                    }
                }
                if (malformed || !pub_name) continue;
                if (reverse.record_ech_public_name(view, rec.name, *pub_name, rec.ttl, now_ms, tok) == ReverseRecord::stored)
                    ++recorded;
                if (query.question.name != rec.name &&
                    reverse.record_ech_public_name(view, query.question.name, *pub_name, rec.ttl, now_ms, tok) == ReverseRecord::stored)
                    ++recorded;
                for (std::size_t i = 0; i < hint_count; ++i) {
                    if (reverse.record_ech_public_name(view, hints[i], *pub_name, rec.ttl, now_ms, tok) == ReverseRecord::stored)
                        ++recorded;
                }
            }
            return recorded;
        }
        MessageProgram(corosio::io_context& context,std::span<policy::DnsRule const> rules,
            std::span<MessageUpstream const> upstreams,std::size_t fallback,MessageCache* cache=nullptr,bool disable_cache=false,
            std::span<ResponseRaceMode const> modes={},InputBudget* override_budget=nullptr,
            std::optional<std::uint64_t> policy_view={},ReverseCache* reverse_cache=nullptr,bool independent_cache=false) noexcept
            :context_(context),rules_(rules),upstreams_(upstreams),fallback_(fallback),cache_(cache),override_budget_(override_budget),
             view_(policy_view),disable_cache_(disable_cache),independent_cache_(independent_cache),reverse_cache_(reverse_cache),modes_(modes) {}
        MessageProgram(corosio::io_context& context,std::span<policy::DnsRule const> rules,
            MessageUpstreamSnapshot const& resolver,std::optional<std::uint64_t> policy_view) noexcept
            :MessageProgram(context,rules,resolver.upstreams,resolver.fallback,resolver.cache,
                resolver.disable_cache,{},nullptr,policy_view,resolver.reverse_cache,resolver.independent_cache) {}
        MessageProgram(MessageProgram const&)=delete;
        auto operator=(MessageProgram const&) -> MessageProgram& = delete;
        auto cancel() noexcept -> void {canceled_=true;if(active_)active_->cancel();if(racing_)racing_->cancel();}
        auto begin_send() noexcept -> void {
#ifdef NEXUS_DNS_FAKEIP
            publication_.begin_send();
#endif
        }
        auto finish_send() noexcept -> void {
#ifdef NEXUS_DNS_FAKEIP
            publication_.finish();
#endif
        }
        auto run(QueryMessage query,Clock::time_point deadline,policy::DnsContext context)
            -> capy::task<std::expected<Bytes,detail::ResolveError>> {
            auto result=co_await run_inner(query,deadline,context);
            if (!result) co_return std::unexpected(result.error());
            if (result->record_reverse && reverse_cache_)
                record_reverse_answer(*reverse_cache_,view_.value_or(0),query,result->wire);
            co_return std::move(result->wire);
        }
    private:
        struct RunOutcome { Bytes wire; bool record_reverse=false; };
        struct NamedEval {
            std::string_view tag;
            std::optional<ResponseEcsView> ecs;
            bool record_reverse=false;
        };
        auto run_inner(QueryMessage query,Clock::time_point deadline,policy::DnsContext context)
            -> capy::task<std::expected<RunOutcome,detail::ResolveError>> {
            using Error=detail::ResolveError;
            if(std::exchange(started_,true) || fallback_>=upstreams_.size()) co_return std::unexpected(Error::state);
            if(!modes_.empty()
#ifdef NEXUS_DNS_RESPONSE
                || policy::dns_has_concurrent_rules(rules_)
#endif
            ) {
                MessageRaceProgram operation(context_,rules_,modes_,upstreams_,fallback_,cache_,disable_cache_,override_budget_,view_,independent_cache_);
                struct Registration {MessageRaceProgram*& active;~Registration(){active=nullptr;}} registration{racing_};
#ifdef NEXUS_DNS_FAKEIP
                operation.set_fakeip_publication(publication_);
#endif
                racing_=&operation;if(canceled_)operation.cancel();
                auto raced=co_await operation.run(std::move(query),deadline,context);
                if (!raced) co_return std::unexpected(raced.error());
                co_return RunOutcome{std::move(*raced),operation.record_reverse()};
            }
            if(!encode_query(query))co_return std::unexpected(Error::protocol);
            if(query.edns && query.edns->version!=0) {
                policy::PredefinedResponse failure;
                auto wire=synthetic_message(query,failure,1);if(!wire)co_return std::unexpected(Error::protocol);
                co_return RunOutcome{std::move(*wire),false};
            }
            if (!apply_message_question(context,query)) co_return std::unexpected(Error::invalid_request);
            ResponseWalk walk(rules_,fallback_,disable_cache_);
            std::optional<ResponseEcsView> evaluated_query;
            bool evaluated_record_reverse=false;
            std::vector<NamedEval> named_queries;
            for(;;) {
                if(canceled_) co_return std::unexpected(Error::canceled);
                if(Clock::now()>=deadline) co_return std::unexpected(Error::timeout);
                auto step=walk.next(query.question.name,query.question.type,context);
                if(!step) co_return std::unexpected(step.error()==ResponseProgramError::resource_limit ? Error::limit : Error::state);
                if(step->action==policy::DnsAction::reject) {
                    if(step->reject_rcode) {
                        policy::PredefinedResponse reply{.rcode=*step->reject_rcode};
                        auto wire=synthetic_message(query,reply);
                        if(!wire)co_return std::unexpected(Error::protocol);
                        co_return RunOutcome{std::move(*wire),false};
                    }
                    co_return std::unexpected(step->rule<rules_.size() && rules_[step->rule].reject_drop ? Error::policy_dropped : Error::policy_rejected);
                }
                if(step->action==policy::DnsAction::predefined) {
                    if(step->rule>=rules_.size() || !rules_[step->rule].predefined) co_return std::unexpected(Error::state);
                    auto wire=synthetic_message(query,*rules_[step->rule].predefined);
                    if(!wire)co_return std::unexpected(Error::protocol);
                    if(step->rewrite_ttl) {
                        auto response=parse_response(*wire,query.id,query.question);
                        if(!response)co_return std::unexpected(Error::protocol);
                        wire=encode_response(*response,query.id,step->rewrite_ttl);
                        if(!wire)co_return std::unexpected(Error::protocol);
                    }
                    co_return RunOutcome{std::move(*wire),false};
                }
                if(step->action==policy::DnsAction::respond) {
                    auto response=walk.take_response();if(!response)co_return std::unexpected(Error::state);
                    auto* selected=&evaluated_query;
                    bool record_reverse=evaluated_record_reverse;
                    if(step->response_tag) {
                        auto found=std::ranges::find(named_queries,*step->response_tag,&NamedEval::tag);
                        if(found==named_queries.end())co_return std::unexpected(Error::state);
                        selected=&found->ecs;
                        record_reverse=found->record_reverse;
                    }
                    if(*selected) {
                        auto restored=restore_response_ecs(query,**selected,*response);
                        if(!restored)co_return std::unexpected(Error::protocol);
                        auto parsed=parse_owned_response(std::move(*restored),query.id,query.question);
                        if(!parsed)co_return std::unexpected(Error::protocol);
                        response=std::move(*parsed);
                    }
                    auto wire=encode_response(*response,query.id,step->rewrite_ttl);
                    if(!wire)co_return std::unexpected(Error::protocol);
                    co_return RunOutcome{std::move(*wire),record_reverse};
                }
                if(step->action!=policy::DnsAction::route && step->action!=policy::DnsAction::evaluate) co_return std::unexpected(Error::state);
                if(step->server>=upstreams_.size()) co_return std::unexpected(Error::state);
                if(step->action==policy::DnsAction::route && query.question.klass==1 &&
                   ((step->strategy==rules::DnsRuleStrategy::ipv4_only && query.question.type==28) ||
                    (step->strategy==rules::DnsRuleStrategy::ipv6_only && query.question.type==1))) {
                    policy::PredefinedResponse empty{.rcode=0};
                    auto wire=synthetic_message(query,empty);
                    if(!wire)co_return std::unexpected(Error::protocol);
                    co_return RunOutcome{std::move(*wire),false};
                }
#ifdef NEXUS_DNS_FAKEIP
                if (auto* publisher=upstreams_[step->server].fakeip; publisher && step->action==policy::DnsAction::route) {
                    if (auto wire=publisher->query_wire(query)) {
                        auto fake=publication_.respond(*publisher,query,*wire,step->rewrite_ttl,view_);
                        if (!fake) co_return std::unexpected(fake.error());
                        co_return RunOutcome{std::move(*fake),false};
                    }
                }
#endif
                auto until=step->timeout_ms ? std::min(deadline,Clock::now()+std::chrono::milliseconds(*step->timeout_ms)) : deadline;
                MessageExchange operation(context_,upstreams_,cache_,query,*step,until,override_budget_,view_.value_or(0),independent_cache_);
                struct Registration {MessageExchange*& active;~Registration(){active=nullptr;}} registration{active_};
                active_=&operation;
                auto wire=co_await operation.run();
                auto const& upstream_query=operation.upstream_query();
                auto local_synthetic=operation.local_synthetic();
                bool eligible_reverse=!local_synthetic && !operation.stale_cache();
                if(canceled_ || (!wire && wire.error()==Error::canceled))co_return std::unexpected(Error::canceled);
                if(!wire) {
                    if(wire.error()==Error::budget_exhausted)co_return std::unexpected(Error::limit);
                    if(step->action!=policy::DnsAction::evaluate)co_return std::unexpected(wire.error());
                    if(!walk.failed())co_return std::unexpected(Error::state);
                    continue;
                }
                if(step->action==policy::DnsAction::route) {
                    if(step->subnet && !local_synthetic) {
                        auto response=parse_response(*wire,query.id,query.question);if(!response)co_return std::unexpected(Error::protocol);
                        auto restored=restore_response_ecs(query,upstream_query,*response);if(!restored)co_return std::unexpected(Error::protocol);
                        wire=std::move(*restored);
                    }
                    if(step->rewrite_ttl) {
                        auto response=parse_response(*wire,query.id,query.question);
                        if(!response)co_return std::unexpected(Error::protocol);
                        auto output=encode_response(*response,query.id,step->rewrite_ttl);
                        if(!output)co_return std::unexpected(Error::protocol);
                        co_return RunOutcome{std::move(*output),eligible_reverse};
                    }
                    co_return RunOutcome{std::move(*wire),eligible_reverse};
                }
                auto response=parse_owned_response(std::move(*wire),query.id,query.question);
                std::optional<ResponseEcsView> query_metadata;
                if(step->subnet && !local_synthetic) {
                    auto view=response_ecs_view(upstream_query);if(!view)co_return std::unexpected(Error::protocol);
                    query_metadata=*view;
                }
                if(response && step->rewrite_ttl) {
                    if(!rewrite_response(*response,query.id,step->rewrite_ttl))co_return std::unexpected(Error::protocol);
                }
                if(!response)co_return std::unexpected(Error::protocol);
                auto saved=walk.evaluated(std::move(*response));
                if(!saved)co_return std::unexpected(saved.error()==ResponseProgramError::resource_limit ? Error::limit : Error::state);
                if(step->response_tag)named_queries.push_back({*step->response_tag,std::move(query_metadata),eligible_reverse});
                else {evaluated_query=std::move(query_metadata);evaluated_record_reverse=eligible_reverse;}
            }
        }
    };
}
