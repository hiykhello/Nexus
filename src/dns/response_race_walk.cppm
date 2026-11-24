export module dns.response_race_walk;
import std;
import dns.message;
import dns.response_program;
import dns.evaluate_race;
import dns.policy;
import rules;

export namespace dns {
    // Modes are supplied separately until every production execution path can
    // run concurrent queries and drain them. Rules and context outlive the walk.
    struct ResponseRaceMode {bool race=false,speculative=false;};
    class ResponseRaceWalk {
        using Race=EvaluateRace<32,64>;
    public:
        using Ticket=Race::Ticket;
        enum class Kind {start,wait,commit};
        struct Event {Kind kind;ResponseStep step;std::optional<Ticket> ticket;};
    private:
        struct Slot {
            std::optional<Ticket> ticket;
            std::optional<std::string_view> tag;
            std::optional<Response> response;
            std::optional<std::vector<rules::ProgramAddress>> addresses;
            bool ready=false,ttl_changed=false;
        };
        struct Armed {std::size_t index;ResponseStep step;};
        std::span<ResponseRule const> rules_;
        std::span<ResponseRaceMode const> modes_;
        std::size_t fallback_,cursor_=0,bytes_=0;
        bool disabled_,terminal_=false;
        std::optional<std::uint32_t> timeout_,ttl_;
        std::optional<std::optional<ClientSubnet>> subnet_;
        std::optional<rules::DnsRuleStrategy> strategy_;
        std::array<Slot,32> slots_{};
        std::array<std::optional<Armed>,64> armed_{};
        std::optional<Ticket> anonymous_;
        std::optional<Ticket> selected_;
        std::optional<ResponseStep> held_;
        Race race_;
        static constexpr std::size_t max_response_bytes=2*1024*1024;
        static auto view(std::optional<std::string> const& tag) noexcept -> std::optional<std::string_view> {
            return tag ? std::optional<std::string_view>(*tag) : std::nullopt;
        }
        auto slot(Ticket ticket) noexcept -> Slot* {
            if(ticket.index>=slots_.size())return nullptr;
            auto& item=slots_[ticket.index];return item.ticket==ticket ? &item : nullptr;
        }
        auto find(std::optional<std::string_view> tag) noexcept -> std::optional<Ticket> {
            if(!tag)return anonymous_;
            for(auto const& item:slots_)if(item.ticket && item.tag==tag)return item.ticket;
            return {};
        }
        auto response_step(std::size_t index,ResponseRule const& rule,Slot const* selected=nullptr) const noexcept -> ResponseStep {
            auto subnet=subnet_;
            if(rule.client_subnet)subnet.emplace(ClientSubnet{static_cast<std::uint16_t>(rule.client_subnet->size==4 ? 1 : 2),rule.client_subnet->bits,rule.client_subnet->address});
            if(rule.remove_client_subnet)subnet.emplace(std::nullopt);
            auto ttl=rule.action==ResponseAction::respond && (!selected || !selected->ttl_changed) ? std::optional<std::uint32_t>{} : rule.rewrite_ttl ? rule.rewrite_ttl : ttl_;
            auto tag=rule.action==ResponseAction::evaluate ? view(rule.evaluate_tag) : rule.action==ResponseAction::respond ? view(rule.match_response_tag) : std::nullopt;
            return {rule.action,rule.server,rule.disable_cache.value_or(disabled_),index,rule.timeout_ms ? rule.timeout_ms : timeout_,ttl,subnet,tag,rule.strategy ? rule.strategy : strategy_,rule.reject_rcode};
        }
        auto options(ResponseRule const& rule) noexcept -> void {
            if(rule.disable_cache)disabled_=*rule.disable_cache;
            if(rule.timeout_ms)timeout_=rule.timeout_ms;
            if(rule.rewrite_ttl) {ttl_=rule.rewrite_ttl;for(auto& item:slots_)if(item.ticket)item.ttl_changed=true;}
            if(rule.client_subnet)subnet_.emplace(ClientSubnet{static_cast<std::uint16_t>(rule.client_subnet->size==4 ? 1 : 2),rule.client_subnet->bits,rule.client_subnet->address});
            if(rule.remove_client_subnet)subnet_.emplace(std::nullopt);
            if(rule.strategy)strategy_=rule.strategy;
        }
        auto start(ResponseStep step,bool bind) noexcept -> std::expected<Event,ResponseProgramError> {
            auto ticket=race_.start();if(!ticket)return std::unexpected(ResponseProgramError::resource_limit);
            auto& item=slots_[ticket->index];item.ticket=*ticket;
            if(bind) {
                item.tag=step.response_tag;
                if(item.tag) {
                    for(auto const& other:slots_)if(other.ticket && other.ticket!=*ticket && other.tag==item.tag)return std::unexpected(ResponseProgramError::invalid_rule);
                } else anonymous_=*ticket;
            }
            return Event{Kind::start,step,*ticket};
        }
        auto remember(std::size_t index,ResponseStep step) noexcept -> bool {
            for(auto& item:armed_)if(!item){item=Armed{index,step};return true;}
            return false;
        }
        auto saved(std::size_t index) noexcept -> std::optional<Armed>* {
            for(auto& item:armed_)if(item && item->index==index)return &item;
            return nullptr;
        }
        static auto response_cost(Response const& response) noexcept -> std::optional<std::size_t> {
            std::size_t total=sizeof(Response);
            auto add=[&](std::size_t amount) {
                if(amount>max_response_bytes-total)return false;
                total+=amount;return true;
            };
            if(!add(response.wire.capacity()) || response.records.capacity()>(max_response_bytes-total)/sizeof(Record) ||
               !add(response.records.capacity()*sizeof(Record)))return {};
            for(auto const& record:response.records)
                if(!add(record.name.capacity()) || (record.cname && !add(record.cname->capacity())))return {};
            return total;
        }
        auto truth(ResponseRule const& rule,std::string_view name,std::uint16_t type,
            policy::DnsContext const& context,Slot* item) noexcept
            -> std::expected<std::optional<rules::Matcher::Truth>,ResponseProgramError> {
            std::optional<std::vector<rules::ProgramAddress>> unused;
            auto before=item && item->addresses ? item->addresses->capacity() : 0;
            auto result=response_rule_truth(rule,name,type,context,item && item->response ? &*item->response : nullptr,item ? item->addresses : unused,
                nullptr,nullptr,max_response_bytes-bytes_);
            auto after=item && item->addresses ? item->addresses->capacity() : 0;
            if(after>before) {
                auto count=after-before;
                if(count>(max_response_bytes-bytes_)/sizeof(rules::ProgramAddress))return std::unexpected(ResponseProgramError::resource_limit);
                bytes_+=count*sizeof(rules::ProgramAddress);
            }
            return result;
        }
        static auto dummy() noexcept -> ResponseStep {return {ResponseAction::route,0,false,0,{},{},{},{},{},{}};}
    public:
        ResponseRaceWalk(std::span<ResponseRule const> rules,std::span<ResponseRaceMode const> modes,
            std::size_t fallback,bool disabled=false) noexcept :rules_(rules),modes_(modes),fallback_(fallback),disabled_(disabled) {}
        // A completion batch must be fully published before calling next().
        // The caller retains query metadata and cancels/drains all tasks after
        // commit, without publishing their late completions into this walk.
        auto complete(Ticket ticket,std::optional<Response> response) noexcept -> std::expected<void,ResponseProgramError> {
            auto* item=slot(ticket);if(!item || item->ready || terminal_)return std::unexpected(ResponseProgramError::invalid_state);
            if(response) {
                auto cost=response_cost(*response);
                if(response->wire.size()>65535 || response->records.size()>128 || !cost || *cost>max_response_bytes-bytes_)
                    return std::unexpected(ResponseProgramError::resource_limit);
                bytes_+=*cost;item->response=std::move(response);
            }
            if(!race_.complete(ticket,!item->response))return std::unexpected(ResponseProgramError::invalid_state);
            item->ready=true;return {};
        }
        [[nodiscard]] auto response(Ticket ticket) noexcept -> Response const* {
            auto* item=slot(ticket);return item && item->response ? &*item->response : nullptr;
        }
        [[nodiscard]] auto take_response(Ticket ticket) noexcept -> std::optional<Response> {
            auto* item=slot(ticket);
            if(!terminal_ || selected_!=ticket || !item || !item->response)return {};
            auto result=std::move(item->response);item->response.reset();return result;
        }
        auto next(std::string_view name,std::uint16_t type,policy::DnsContext const& context={}) noexcept
            -> std::expected<Event,ResponseProgramError> {
            if(terminal_ || (!modes_.empty() && modes_.size()!=rules_.size()))return std::unexpected(ResponseProgramError::invalid_state);
            using Truth=rules::Matcher::Truth;
            for(;;) {
                auto event=race_.poll();if(!event)return std::unexpected(ResponseProgramError::invalid_state);
                if(event->kind==Race::Kind::judge) {
                    auto* record=saved(event->rule);if(!record)return std::unexpected(ResponseProgramError::invalid_state);
                    auto* item=event->response ? slot(*event->response) : nullptr;
                    auto matched_truth=truth(rules_[event->rule],name,type,context,item);
                    if(!matched_truth)return std::unexpected(matched_truth.error());
                    bool matched=*matched_truth && **matched_truth==Truth::yes;
                    if(!race_.judged(matched))return std::unexpected(ResponseProgramError::invalid_state);
                    if(!matched)record->reset();
                    continue;
                }
                if(event->kind==Race::Kind::wait)return Event{Kind::wait,dummy(),{}};
                if(event->kind==Race::Kind::proceed) {
                    if(!held_ || held_->rule!=event->rule)return std::unexpected(ResponseProgramError::invalid_state);
                    auto step=*held_;held_.reset();return start(step,true);
                }
                if(event->kind==Race::Kind::commit) {
                    ResponseStep step=dummy();
                    if(auto* record=saved(event->rule))step=(*record)->step;
                    else if(held_ && held_->rule==event->rule)step=*held_;
                    else return std::unexpected(ResponseProgramError::invalid_state);
                    auto selected=event->response;
                    if(step.action==ResponseAction::respond) {
                        if(!selected)selected=find(step.response_tag);
                        auto* item=selected ? slot(*selected) : nullptr;
                        if(!item || !item->response)return std::unexpected(ResponseProgramError::missing_response);
                        selected_=selected;
                    }
                    terminal_=true;return Event{Kind::commit,step,selected};
                }
                if(cursor_==rules_.size()) {
                    held_=ResponseStep{ResponseAction::route,fallback_,disabled_,cursor_,timeout_,ttl_,subnet_,{},strategy_,{}};
                    if(!race_.hold(cursor_))return std::unexpected(ResponseProgramError::invalid_state);
                    continue;
                }
                auto index=cursor_;auto const& rule=rules_[index];
                auto mode=modes_.empty() ? ResponseRaceMode{rule.race,rule.speculative} : modes_[index];
                if((mode.race && (!rule.match_response || mode.speculative || (rule.action!=ResponseAction::route && rule.action!=ResponseAction::respond && rule.action!=ResponseAction::reject && rule.action!=ResponseAction::predefined))) ||
                   (mode.speculative && rule.action!=ResponseAction::route && rule.action!=ResponseAction::evaluate))return std::unexpected(ResponseProgramError::invalid_rule);
                auto ticket=rule.match_response ? find(view(rule.match_response_tag)) : std::nullopt;
                auto* item=ticket ? slot(*ticket) : nullptr;
                if(mode.race) {
                    auto step=response_step(index,rule,item);
                    if(!remember(index,step) || !race_.arm(index,ticket))return std::unexpected(ResponseProgramError::resource_limit);
                    ++cursor_;continue;
                }
                if(item && !item->ready)return Event{Kind::wait,dummy(),{}};
                auto matched_truth=truth(rule,name,type,context,item);
                if(!matched_truth)return std::unexpected(matched_truth.error());
                if(!*matched_truth || **matched_truth!=Truth::yes){++cursor_;continue;}
                if(rule.action==ResponseAction::respond && !rule.match_response) {
                    ticket=anonymous_;item=ticket ? slot(*ticket) : nullptr;
                    if(item && !item->ready)return Event{Kind::wait,dummy(),{}};
                }
                ++cursor_;
                if(rule.action==ResponseAction::route_options){options(rule);continue;}
                auto step=response_step(index,rule,item);
                if(rule.action==ResponseAction::evaluate && mode.speculative)return start(step,true);
                if(rule.action==ResponseAction::route && mode.speculative) {
                    auto started=start(step,false);if(!started)return started;
                    held_=step;if(!race_.hold(index,started->ticket))return std::unexpected(ResponseProgramError::invalid_state);
                    return started;
                }
                held_=step;
                if(!race_.hold(index,rule.action==ResponseAction::respond ? ticket : std::nullopt,rule.action!=ResponseAction::evaluate))return std::unexpected(ResponseProgramError::invalid_state);
            }
        }
    };
}
