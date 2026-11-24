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
        static auto record_reverse_answer(ReverseCache& reverse,std::uint64_t view,QueryMessage const& query,
            std::span<std::uint8_t const> wire) noexcept -> void {
            if (query.question.klass!=1 || (query.question.type!=1 && query.question.type!=28)) return;
            auto parsed=parse_addresses(wire,query.id,query.question,query.edns.has_value());
            if (!parsed || parsed->addresses.empty() || !parsed->ttl || !*parsed->ttl) return;
            auto now_ms=static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                Clock::now().time_since_epoch()).count());
            (void)reverse.record(view,query.question.name,parsed->addresses,*parsed->ttl,now_ms,reverse.token());
        }
    public:
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
            if (result && reverse_cache_)
                record_reverse_answer(*reverse_cache_,view_.value_or(0),query,*result);
            co_return result;
        }
    private:
        auto run_inner(QueryMessage query,Clock::time_point deadline,policy::DnsContext context)
            -> capy::task<std::expected<Bytes,detail::ResolveError>> {
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
                co_return co_await operation.run(std::move(query),deadline,context);
            }
            if(!encode_query(query))co_return std::unexpected(Error::protocol);
            if(query.edns && query.edns->version!=0) {
                policy::PredefinedResponse failure;
                auto wire=synthetic_message(query,failure,1);if(!wire)co_return std::unexpected(Error::protocol);
                co_return std::move(*wire);
            }
            if (!apply_message_question(context,query)) co_return std::unexpected(Error::invalid_request);
            ResponseWalk walk(rules_,fallback_,disable_cache_);
            std::optional<ResponseEcsView> evaluated_query;
            std::vector<std::pair<std::string_view,std::optional<ResponseEcsView>>> named_queries;
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
                        co_return std::move(*wire);
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
                    co_return std::move(*wire);
                }
                if(step->action==policy::DnsAction::respond) {
                    auto response=walk.take_response();if(!response)co_return std::unexpected(Error::state);
                    auto* selected=&evaluated_query;
                    if(step->response_tag) {
                        auto found=std::ranges::find(named_queries,*step->response_tag,&std::pair<std::string_view,std::optional<ResponseEcsView>>::first);
                        if(found==named_queries.end())co_return std::unexpected(Error::state);
                        selected=&found->second;
                    }
                    if(*selected) {
                        auto restored=restore_response_ecs(query,**selected,*response);
                        if(!restored)co_return std::unexpected(Error::protocol);
                        auto parsed=parse_owned_response(std::move(*restored),query.id,query.question);
                        if(!parsed)co_return std::unexpected(Error::protocol);
                        response=std::move(*parsed);
                    }
                    auto wire=encode_response(*response,query.id,step->rewrite_ttl);
                    if(!wire)co_return std::unexpected(Error::protocol);co_return std::move(*wire);
                }
                if(step->action!=policy::DnsAction::route && step->action!=policy::DnsAction::evaluate) co_return std::unexpected(Error::state);
                if(step->server>=upstreams_.size()) co_return std::unexpected(Error::state);
                if(step->action==policy::DnsAction::route && query.question.klass==1 &&
                   ((step->strategy==rules::DnsRuleStrategy::ipv4_only && query.question.type==28) ||
                    (step->strategy==rules::DnsRuleStrategy::ipv6_only && query.question.type==1))) {
                    policy::PredefinedResponse empty{.rcode=0};
                    auto wire=synthetic_message(query,empty);
                    if(!wire)co_return std::unexpected(Error::protocol);
                    co_return std::move(*wire);
                }
#ifdef NEXUS_DNS_FAKEIP
                if (auto* publisher=upstreams_[step->server].fakeip; publisher && step->action==policy::DnsAction::route) {
                    if (auto wire=publisher->query_wire(query))
                        co_return publication_.respond(*publisher,query,*wire,step->rewrite_ttl,view_);
                }
#endif
                auto until=step->timeout_ms ? std::min(deadline,Clock::now()+std::chrono::milliseconds(*step->timeout_ms)) : deadline;
                MessageExchange operation(context_,upstreams_,cache_,query,*step,until,override_budget_,view_.value_or(0),independent_cache_);
                struct Registration {MessageExchange*& active;~Registration(){active=nullptr;}} registration{active_};
                active_=&operation;
                auto wire=co_await operation.run();
                auto const& upstream_query=operation.upstream_query();
                auto local_synthetic=operation.local_synthetic();
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
                        co_return std::move(*output);
                    }
                    co_return std::move(*wire);
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
                if(step->response_tag)named_queries.emplace_back(*step->response_tag,std::move(query_metadata));
                else evaluated_query=std::move(query_metadata);
            }
        }
    };
}
