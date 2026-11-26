export module dns.response_program;
import std;
import dns.message;
import dns.input_budget;
import dns.response_match;
import dns.response_addresses;
import dns.policy;
import rules;

export namespace dns {
    using ResponseAction=policy::DnsAction;
    using ResponseRule=policy::DnsRule;
    enum class ResponseProgramError { invalid_rule, invalid_cursor, invalid_state, missing_response, invalid_response, resource_limit };
    struct ResponseStep {
        ResponseAction action;
        std::size_t server;
        bool disable_cache;
        std::size_t rule;
        std::optional<std::uint32_t> timeout_ms;
        std::optional<std::uint32_t> rewrite_ttl;
        // Outer optional means an override; the inner empty value removes ECS.
        std::optional<std::optional<ClientSubnet>> subnet;
        // Set for tagged evaluate and for respond of that tagged response.
        std::optional<std::string_view> response_tag;
        std::optional<rules::DnsRuleStrategy> strategy{};
        std::optional<std::uint8_t> reject_rcode{};
    };
    [[nodiscard]] inline auto normalize_response_rule(ResponseRule& rule,std::size_t servers) -> bool {
        return policy::normalize_dns_rule(rule,servers);
    }
    [[nodiscard]] inline auto apply_message_question(policy::DnsContext& context,QueryMessage const& query) -> bool {
        context.query_class=query.question.klass;
        context.query_dnssec=query.edns && query.edns->dnssec_ok;
        context.query_checking_disabled=bool(query.flags&checking_disabled_flag);
        context.query_authenticated_data=bool(query.flags&authenticated_data_flag);
        context.subnet_known=true;
        context.query_subnet.reset();
        if (!query.edns) return true;
        auto subnet=query_client_subnet(*query.edns);
        if (!subnet) return false;
        if (*subnet) {
            auto const& value=**subnet;
            context.query_subnet=policy::ResponsePrefix{value.address,static_cast<std::uint8_t>(value.family==1 ? 4 : 16),value.prefix};
        }
        return true;
    }
    // Evaluate one complete rule against the response generation selected by
    // the caller. A missing response remains unknown, including under invert.
    // Address cache belongs to that generation and must not be shared across
    // unrelated responses. A disengaged optional denotes malformed input.
    [[nodiscard]] inline auto response_rule_truth(ResponseRule const& rule,std::string_view name,std::uint16_t type,
        policy::DnsContext const& context,Response const* response,
        std::optional<std::vector<rules::ProgramAddress>>& addresses,InputBudget* address_budget=nullptr,
        std::optional<InputBudget::Lease>* address_lease=nullptr,std::optional<std::size_t> address_limit={}) noexcept
        -> std::expected<std::optional<rules::Matcher::Truth>,ResponseProgramError> {
        using Truth=rules::Matcher::Truth;
        auto input=context;input.response_addresses.reset();
        auto question=policy::dns_question_truth(rule,name,type,input);
        if(!question)return std::optional<Truth>{};
        if(*question==Truth::unknown && rule.match_response && (rule.rule_set_needs_response || rule.inline_needs_response) && response) {
            if(!addresses) {
                try {
                    std::optional<InputBudget::Lease> reservation;
                    std::size_t count=0;
                    bool counted=(address_budget && address_lease) || address_limit.has_value();
                    if(counted) {
                        auto measured=dns::response_address_count(*response);
                        if(!measured)return std::unexpected(measured.error()==MessageError::limit ? ResponseProgramError::resource_limit : ResponseProgramError::invalid_response);
                        count=*measured;
                        if(count>std::numeric_limits<std::size_t>::max()/sizeof(rules::ProgramAddress))return std::unexpected(ResponseProgramError::resource_limit);
                        auto bytes=count*sizeof(rules::ProgramAddress);
                        if(address_limit && bytes>*address_limit)return std::unexpected(ResponseProgramError::resource_limit);
                        if(address_budget && address_lease) {
                            auto lease=address_budget->acquire(bytes);
                            if(!lease)return std::unexpected(ResponseProgramError::resource_limit);
                            reservation.emplace(std::move(*lease));
                        }
                    }
                    auto parsed=dns::response_addresses(*response,count);
                    if(!parsed)return std::unexpected(parsed.error()==MessageError::limit ? ResponseProgramError::resource_limit : ResponseProgramError::invalid_response);
                    if(counted && (parsed->size()!=count || parsed->capacity()!=count))return std::unexpected(ResponseProgramError::resource_limit);
                    addresses=std::move(*parsed);
                    if(reservation)address_lease->emplace(std::move(*reservation));
                } catch(std::bad_alloc const&) {return std::unexpected(ResponseProgramError::resource_limit);}
            }
            input.response_addresses=std::span<rules::ProgramAddress const>(*addresses);
            question=policy::dns_question_truth(rule,name,type,input);
            if(!question)return std::optional<Truth>{};
        }
        auto combined=*question;
        if(rule.match_response) {
            auto matched=rule.response ? match_response(*rule.response,response) : (response ? ResponseTruth::yes : ResponseTruth::unknown);
            if(matched==ResponseTruth::no)combined=Truth::no;
            else if(matched==ResponseTruth::unknown && combined==Truth::yes)combined=Truth::unknown;
        }
        if(rule.invert && combined!=Truth::unknown)combined=combined==Truth::yes ? Truth::no : Truth::yes;
        return std::optional<Truth>{combined};
    }
    // Owner stores rule and response lifetimes. This synchronous walker never
    // performs I/O; the caller executes evaluate with its existing deadline,
    // cancellation and cache, then commits the full result before resuming.
    class ResponseWalk {
        std::span<ResponseRule const> rules_;
        std::size_t cursor_=0, fallback_;
        bool disable_cache_,waiting_=false,terminal_=false,responded_=false;
        std::optional<std::uint32_t> timeout_ms_;
        std::optional<std::uint32_t> rewrite_ttl_;
        std::optional<std::optional<ClientSubnet>> subnet_;
        std::optional<rules::DnsRuleStrategy> strategy_;
        struct SavedResponse {
            std::optional<std::string_view> tag;
            InputBudget::Lease lease;
            Response response;
            std::optional<InputBudget::Lease> addresses_lease;
            std::optional<std::vector<rules::ProgramAddress>> addresses;
            bool ttl_changed=false;
        };
        InputBudget& response_budget_;
        std::optional<SavedResponse> anonymous_;
        std::vector<SavedResponse> named_;
        std::optional<std::string_view> pending_tag_,selected_tag_;
        auto find(std::optional<std::string_view> tag) noexcept -> SavedResponse* {
            if(!tag)return anonymous_ ? &*anonymous_ : nullptr;
            auto item=std::ranges::find_if(named_,[&](auto const& value){return value.tag==tag;});
            return item==named_.end() ? nullptr : &*item;
        }
        static auto view(std::optional<std::string> const& value) noexcept -> std::optional<std::string_view> {
            return value ? std::optional<std::string_view>(*value) : std::nullopt;
        }
        static auto cost(Response const& response) noexcept -> std::optional<std::size_t> {
            auto total=sizeof(SavedResponse);
            auto add=[&](std::size_t value) {
                if(value>std::numeric_limits<std::size_t>::max()-total)return false;
                total+=value;return true;
            };
            if(response.records.capacity()>std::numeric_limits<std::size_t>::max()/sizeof(Record) ||
               !add(response.wire.capacity()) || !add(response.records.capacity()*sizeof(Record)))return {};
            for(auto const& record:response.records)
                if(!add(record.name.capacity()) || (record.cname && !add(record.cname->capacity())))return {};
            return total;
        }
    public:
        ResponseWalk(std::span<ResponseRule const> rules,std::size_t fallback,bool disabled=false,InputBudget* response_budget=nullptr) noexcept
            : rules_(rules),fallback_(fallback),disable_cache_(disabled),response_budget_(response_budget ? *response_budget : default_serial_response_budget()) {}
        auto next(std::string_view name,std::uint16_t type,policy::DnsContext const& context={}) noexcept
            -> std::expected<ResponseStep,ResponseProgramError> {
            if (waiting_ || terminal_) return std::unexpected(ResponseProgramError::invalid_state);
            while (cursor_<rules_.size()) {
                auto index=cursor_++;auto const& rule=rules_[index];
                using Truth=rules::Matcher::Truth;
                auto* tested=rule.match_response ? find(view(rule.match_response_tag)) : nullptr;
                std::optional<std::vector<rules::ProgramAddress>> unused;
                auto truth=response_rule_truth(rule,name,type,context,tested ? &tested->response : nullptr,tested ? tested->addresses : unused,
                    tested ? &response_budget_ : nullptr,tested ? &tested->addresses_lease : nullptr);
                if(!truth)return std::unexpected(truth.error());
                if(!*truth || **truth!=Truth::yes)continue;
                switch (rule.action) {
                case ResponseAction::route_options:
                    if (rule.disable_cache) disable_cache_=*rule.disable_cache;
                    if (rule.timeout_ms) timeout_ms_=rule.timeout_ms;
                    if (rule.rewrite_ttl) {
                        rewrite_ttl_=rule.rewrite_ttl;
                        if(anonymous_)anonymous_->ttl_changed=true;
                        for(auto& saved:named_)saved.ttl_changed=true;
                    }
                    if (rule.client_subnet) subnet_.emplace(ClientSubnet{static_cast<std::uint16_t>(rule.client_subnet->size==4 ? 1 : 2),rule.client_subnet->bits,rule.client_subnet->address});
                    if (rule.remove_client_subnet) subnet_.emplace(std::nullopt);
                    if (rule.strategy) strategy_=rule.strategy;
                    continue;
                case ResponseAction::evaluate:
                    waiting_=true;pending_tag_=view(rule.evaluate_tag);
                    if(!pending_tag_)anonymous_.reset();
                    break;
                case ResponseAction::respond:
                    selected_tag_=view(rule.match_response_tag);
                    if (!find(selected_tag_)) { terminal_=true;return std::unexpected(ResponseProgramError::missing_response); }
                    terminal_=true;responded_=true;break;
                case ResponseAction::route: case ResponseAction::reject: case ResponseAction::predefined: terminal_=true;break;
                default: return std::unexpected(ResponseProgramError::invalid_rule);
                }
                auto ttl=rule.action==ResponseAction::respond && !find(selected_tag_)->ttl_changed ? std::optional<std::uint32_t>{} : rule.rewrite_ttl ? rule.rewrite_ttl : rewrite_ttl_;
                auto subnet=subnet_;
                if(rule.client_subnet) subnet.emplace(ClientSubnet{static_cast<std::uint16_t>(rule.client_subnet->size==4 ? 1 : 2),rule.client_subnet->bits,rule.client_subnet->address});
                if(rule.remove_client_subnet) subnet.emplace(std::nullopt);
                auto tag=rule.action==ResponseAction::evaluate ? pending_tag_ : rule.action==ResponseAction::respond ? selected_tag_ : std::nullopt;
                auto eff_strategy=rule.strategy ? rule.strategy : strategy_;
                return ResponseStep{rule.action,rule.server,rule.disable_cache.value_or(disable_cache_),index,rule.timeout_ms ? rule.timeout_ms : timeout_ms_,ttl,subnet,tag,eff_strategy,rule.reject_rcode};
            }
            terminal_=true;
            return ResponseStep{ResponseAction::route,fallback_,disable_cache_,rules_.size(),timeout_ms_,rewrite_ttl_,subnet_,{},strategy_,{}};
        }
        auto evaluated(Response response) noexcept -> std::expected<void,ResponseProgramError> {
            if (!waiting_) return std::unexpected(ResponseProgramError::invalid_state);
            if(response.wire.size()>65535 || response.records.size()>128)return std::unexpected(ResponseProgramError::invalid_response);
            auto bytes=cost(response);if(!bytes)return std::unexpected(ResponseProgramError::resource_limit);
            auto lease=response_budget_.acquire(*bytes);if(!lease)return std::unexpected(ResponseProgramError::resource_limit);
            if(pending_tag_) {
                if(named_.size()>=policy::max_named_dns_responses || find(pending_tag_))return std::unexpected(ResponseProgramError::invalid_state);
                try {named_.push_back({pending_tag_,std::move(*lease),std::move(response),{},{},false});}
                catch(std::bad_alloc const&) {return std::unexpected(ResponseProgramError::resource_limit);}
            } else anonymous_.emplace(SavedResponse{{},std::move(*lease),std::move(response),{},{},false});
            pending_tag_.reset();waiting_=false;return {};
        }
        // A failed evaluate must not expose a previous response. The caller
        // retains the original transport error and decides whether to stop.
        auto failed() noexcept -> bool { if (!waiting_) return false;pending_tag_.reset();waiting_=false;return true; }
        [[nodiscard]] auto response() const noexcept -> Response const* { return anonymous_ ? &anonymous_->response : nullptr; }
        // The walk retains the reservation after transfer and must outlive
        // the returned response, including any asynchronous continuation.
        [[nodiscard]] auto take_response() noexcept -> std::optional<Response> {
            if (!responded_) return {};
            auto* selected=find(selected_tag_);if(!selected)return {};
            auto value=std::optional<Response>{std::move(selected->response)};
            selected->addresses.reset();selected->addresses_lease.reset();responded_=false;return value;
        }
    };
}
