export module dns.message_race_program;
import std;
import dns.message;
import dns.message_fakeip;
import dns.input_budget;
import dns.message_exchange;
import dns.message_synthetic;
import dns.response_program;
import dns.response_race_walk;
import dns.evaluate_owner;
import dns.race_admission;
import dns.policy;
import dns.message_cache;
import dns.corosio_resolver;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;

export namespace dns {
    // A single executor owns the walk and all concurrent exchanges. Inputs
    // and rule modes remain alive through cancellation and drain.
    class MessageRaceProgram {
        using Clock=std::chrono::steady_clock;
        using Error=detail::ResolveError;
        using Result=std::expected<EvaluatedMessage,Error>;
        using Owner=EvaluateOwner<EvaluatedMessageExchange,Result,32>;
        using Walk=ResponseRaceWalk;
        struct Slot {
            std::optional<Walk::Ticket> ticket;
            std::optional<Owner::Handle> handle;
            ResponseStep step{};
            std::optional<ResponseEcsView> ecs;
            std::optional<Result> terminal;
        };
        nex::corosio::io_context& context_;
        std::span<policy::DnsRule const> rules_;
        std::span<ResponseRaceMode const> modes_;
        std::span<MessageUpstream const> upstreams_;
        std::size_t fallback_;
        MessageCache* cache_;
        InputBudget* override_budget_;
        std::optional<std::uint64_t> view_;
        bool disabled_,started_=false,canceled_=false;
        Owner* owner_=nullptr;
        MessageExchange* active_=nullptr;
        std::array<Slot,32> slots_{};
#ifdef NEXUS_DNS_FAKEIP
        FakeIpPublication* publication_ = nullptr;
#endif
        auto start(Owner& owner,Walk::Ticket ticket,ResponseStep step,QueryMessage const& query,Clock::time_point deadline)
            -> std::expected<void,Error> {
            if(ticket.index>=slots_.size() || step.server>=upstreams_.size())return std::unexpected(Error::state);
            auto until=step.timeout_ms ? std::min(deadline,Clock::now()+std::chrono::milliseconds(*step.timeout_ms)) : deadline;
            auto operation=std::make_unique<EvaluatedMessageExchange>(context_,upstreams_,cache_,query,step,until,
                override_budget_,view_.value_or(0));
            auto handle=owner.start(std::move(operation));if(!handle)return std::unexpected(
                handle.error()==Owner::StartError::full || handle.error()==Owner::StartError::allocation ? Error::limit : Error::state);
            auto& slot=slots_[ticket.index];slot.ticket=ticket;slot.handle=*handle;slot.step=step;
            return {};
        }
        auto publish(Owner& owner,Walk& walk,QueryMessage const& query) -> std::expected<void,Error> {
            for(auto& slot:slots_) {
                if(!slot.handle)continue;
                auto view=owner.inspect(*slot.handle);if(!view)return std::unexpected(Error::state);
                if(!view->ready)continue;
                if(view->exception)return std::unexpected(detail::resolve_task_exception(view->exception));
                auto value=owner.take_result(*slot.handle);if(!value)return std::unexpected(Error::state);
                if(!owner.release(*slot.handle))return std::unexpected(Error::state);
                slot.handle.reset();
                if(slot.step.action==policy::DnsAction::route) {
                    slot.terminal=std::move(*value);
                    if(!walk.complete(*slot.ticket,{}))return std::unexpected(Error::state);
                    continue;
                }
                if(!*value) {
                    if(value->error()==Error::budget_exhausted)return std::unexpected(Error::limit);
                    if(!walk.complete(*slot.ticket,{}))return std::unexpected(Error::state);
                    continue;
                }
                auto response=parse_owned_response(std::move((**value).wire),query.id,query.question);
                if(!response)return std::unexpected(Error::protocol);
                if(slot.step.rewrite_ttl) {
                    if(!rewrite_response(*response,query.id,slot.step.rewrite_ttl))return std::unexpected(Error::protocol);
                }
                if(slot.step.subnet && !(**value).local_synthetic)slot.ecs=(**value).upstream_ecs;
                auto completed=walk.complete(*slot.ticket,std::move(*response));
                if(!completed)return std::unexpected(completed.error()==ResponseProgramError::resource_limit ? Error::limit : Error::state);
            }
            return {};
        }
        auto output(QueryMessage const& query,ResponseStep const& step,EvaluatedMessage message) -> std::expected<Bytes,Error> {
            if(step.subnet && !message.local_synthetic) {
                auto response=parse_response(message.wire,query.id,query.question);if(!response)return std::unexpected(Error::protocol);
                auto restored=restore_response_ecs(query,message.upstream_ecs,*response);if(!restored)return std::unexpected(Error::protocol);
                message.wire=std::move(*restored);
            }
            if(step.rewrite_ttl) {
                auto response=parse_response(message.wire,query.id,query.question);if(!response)return std::unexpected(Error::protocol);
                auto encoded=encode_response(*response,query.id,step.rewrite_ttl);if(!encoded)return std::unexpected(Error::protocol);
                message.wire=std::move(*encoded);
            }
            return std::move(message.wire);
        }
        auto execute(Owner& owner,QueryMessage const& query,Clock::time_point deadline,policy::DnsContext context)
            -> nex::capy::task<std::expected<Bytes,Error>> {
            Walk walk(rules_,modes_,fallback_,disabled_);
            for(;;) {
                if(canceled_)co_return std::unexpected(Error::canceled);
                if(Clock::now()>=deadline)co_return std::unexpected(Error::timeout);
                auto epoch=owner.epoch();
                auto published=publish(owner,walk,query);if(!published)co_return std::unexpected(published.error());
                auto event=walk.next(query.question.name,query.question.type,context);
                if(!event)co_return std::unexpected(event.error()==ResponseProgramError::resource_limit ? Error::limit : Error::state);
                if(event->kind==Walk::Kind::start) {
                    if(!event->ticket)co_return std::unexpected(Error::state);
#ifdef NEXUS_DNS_FAKEIP
                    if (publication_ && event->step.action==policy::DnsAction::route && event->step.server<upstreams_.size()) {
                        if (auto* publisher=upstreams_[event->step.server].fakeip; publisher && publisher->query_wire(query)) {
                            if (!walk.complete(*event->ticket, {})) co_return std::unexpected(Error::state);
                            continue;
                        }
                    }
#endif
                    auto launched=start(owner,*event->ticket,event->step,query,deadline);
                    if(!launched)co_return std::unexpected(launched.error());
                    continue;
                }
                if(event->kind==Walk::Kind::wait) {
                    auto [error]=co_await nex::corosio::timeout(owner.wait(epoch),deadline);
                    if(error)co_return std::unexpected(canceled_ ? Error::canceled : Clock::now()>=deadline ? Error::timeout : Error::state);
                    continue;
                }
                auto step=event->step;
#ifdef NEXUS_DNS_FAKEIP
                if (publication_ && step.action==policy::DnsAction::route && step.server<upstreams_.size()) {
                    if (auto* publisher=upstreams_[step.server].fakeip) {
                        if (auto wire=publisher->query_wire(query)) {
                            owner.stop();
                            co_return publication_->respond(*publisher,query,*wire,step.rewrite_ttl,view_);
                        }
                    }
                }
#endif
                if(step.action==policy::DnsAction::route && event->ticket &&
                   event->ticket->index<slots_.size() && slots_[event->ticket->index].step.action==policy::DnsAction::route) {
                    auto& slot=slots_[event->ticket->index];
                    if(slot.ticket!=event->ticket)co_return std::unexpected(Error::state);
                    if(slot.handle) {
                        if(!owner.stop_except(*slot.handle))co_return std::unexpected(Error::state);
                        while(slot.handle) {
                            if(canceled_)co_return std::unexpected(Error::canceled);
                            auto observed=owner.epoch();auto view=owner.inspect(*slot.handle);
                            if(!view)co_return std::unexpected(Error::state);
                            if(view->ready) {
                                if(view->exception)co_return std::unexpected(detail::resolve_task_exception(view->exception));
                                slot.terminal=owner.take_result(*slot.handle);
                                if(!slot.terminal || !owner.release(*slot.handle))co_return std::unexpected(Error::state);
                                slot.handle.reset();break;
                            }
                            auto [error]=co_await nex::corosio::timeout(owner.wait(observed),deadline);
                            if(error)co_return std::unexpected(canceled_ ? Error::canceled : Clock::now()>=deadline ? Error::timeout : Error::state);
                        }
                    } else owner.stop();
                    if(!slot.terminal)co_return std::unexpected(Error::state);
                    if(!*slot.terminal)co_return std::unexpected(slot.terminal->error()==Error::budget_exhausted ? Error::limit : slot.terminal->error());
                    co_return output(query,step,std::move(**slot.terminal));
                }
                owner.stop();
                if(step.action==policy::DnsAction::reject)co_return std::unexpected(step.rule<rules_.size() && rules_[step.rule].reject_drop ? Error::policy_dropped : Error::policy_rejected);
                if(step.action==policy::DnsAction::predefined) {
                    if(step.rule>=rules_.size() || !rules_[step.rule].predefined)co_return std::unexpected(Error::state);
                    auto wire=synthetic_message(query,*rules_[step.rule].predefined);if(!wire)co_return std::unexpected(Error::protocol);
                    if(step.rewrite_ttl) {
                        auto response=parse_response(*wire,query.id,query.question);if(!response)co_return std::unexpected(Error::protocol);
                        wire=encode_response(*response,query.id,step.rewrite_ttl);if(!wire)co_return std::unexpected(Error::protocol);
                    }
                    co_return std::move(*wire);
                }
                if(step.action==policy::DnsAction::respond) {
                    if(!event->ticket || event->ticket->index>=slots_.size())co_return std::unexpected(Error::state);
                    auto response=walk.take_response(*event->ticket);if(!response)co_return std::unexpected(Error::state);
                    auto& metadata=slots_[event->ticket->index];
                    if(metadata.ecs) {
                        auto restored=restore_response_ecs(query,*metadata.ecs,*response);if(!restored)co_return std::unexpected(Error::protocol);
                        auto parsed=parse_owned_response(std::move(*restored),query.id,query.question);if(!parsed)co_return std::unexpected(Error::protocol);
                        response=std::move(*parsed);
                    }
                    auto wire=encode_response(*response,query.id,step.rewrite_ttl);if(!wire)co_return std::unexpected(Error::protocol);
                    co_return std::move(*wire);
                }
                if(step.action!=policy::DnsAction::route || step.server>=upstreams_.size())co_return std::unexpected(Error::state);
                auto until=step.timeout_ms ? std::min(deadline,Clock::now()+std::chrono::milliseconds(*step.timeout_ms)) : deadline;
                MessageExchange operation(context_,upstreams_,cache_,query,step,until,override_budget_,view_.value_or(0));
                struct Guard {MessageExchange*& active;~Guard(){active=nullptr;}} guard{active_};active_=&operation;
                auto wire=co_await operation.run();
                if(canceled_)co_return std::unexpected(Error::canceled);
                if(!wire)co_return std::unexpected(wire.error()==Error::budget_exhausted ? Error::limit : wire.error());
                auto view=response_ecs_view(operation.upstream_query());if(!view)co_return std::unexpected(Error::protocol);
                co_return output(query,step,EvaluatedMessage{std::move(*wire),*view,operation.local_synthetic()});
            }
        }
    public:
        MessageRaceProgram(nex::corosio::io_context& context,std::span<policy::DnsRule const> rules,
            std::span<ResponseRaceMode const> modes,std::span<MessageUpstream const> upstreams,std::size_t fallback,
            MessageCache* cache=nullptr,bool disabled=false,InputBudget* override_budget=nullptr,
            std::optional<std::uint64_t> policy_view={}) noexcept
            :context_(context),rules_(rules),modes_(modes),upstreams_(upstreams),fallback_(fallback),cache_(cache),
             override_budget_(override_budget),view_(policy_view),disabled_(disabled) {}
        MessageRaceProgram(MessageRaceProgram const&)=delete;
        auto operator=(MessageRaceProgram const&) -> MessageRaceProgram& = delete;
#ifdef NEXUS_DNS_FAKEIP
        auto set_fakeip_publication(FakeIpPublication& publication) noexcept -> void { publication_=&publication; }
#endif
        auto cancel() noexcept -> void {canceled_=true;if(owner_)owner_->stop();if(active_)active_->cancel();}
        auto run(QueryMessage query,Clock::time_point deadline,policy::DnsContext context)
            -> nex::capy::task<std::expected<Bytes,Error>> {
            if(std::exchange(started_,true) || fallback_>=upstreams_.size() || (!modes_.empty() && rules_.size()!=modes_.size()))co_return std::unexpected(Error::state);
            if(canceled_)co_return std::unexpected(Error::canceled);
            if(!encode_query(query))co_return std::unexpected(Error::protocol);
            if(query.edns && query.edns->version!=0) {
                policy::PredefinedResponse failure;auto wire=synthetic_message(query,failure,1);
                if(!wire)co_return std::unexpected(Error::protocol);co_return std::move(*wire);
            }
            if (!apply_message_question(context,query)) co_return std::unexpected(Error::invalid_request);
            RaceAdmission admission;if(!admission.acquired())co_return std::unexpected(Error::limit);
            Owner owner(context_);owner_=&owner;
            std::expected<Bytes,Error> result=std::unexpected(Error::state);
            try {result=co_await execute(owner,query,deadline,context);}
            catch(std::bad_alloc const&) {result=std::unexpected(Error::limit);}
            catch(...) {result=std::unexpected(Error::state);}
            owner.stop();
            while(!owner.drained()) {
                auto epoch=owner.epoch();if(owner.drained())break;
                auto [error]=co_await owner.wait_drain(epoch);if(error)std::terminate();
            }
            owner_=nullptr;
            if(canceled_)co_return std::unexpected(Error::canceled);
            co_return result;
        }
    };
}
