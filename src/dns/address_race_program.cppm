export module dns.address_race_program;
import std;
import dns.message;
import dns.input_budget;
import dns.local_response;
import dns.response_program;
import dns.response_race_walk;
import dns.evaluate_owner;
import dns.race_admission;
import dns.policy;
import dns.corosio_resolver;
import capy;
import corosio;

export namespace dns {
    // One query operation returns a raw response for evaluate, or a complete
    // address answer for a speculative route. Its owner must retain all
    // borrowed cache, executor, snapshot and connection state until drain.
    using AddressRaceValue=std::variant<detail::LocalResponseSelection,AddressAnswer>;
    using AddressRaceResult=std::expected<AddressRaceValue,detail::ResolveError>;
    struct ReservedAddressRaceResult {
        std::optional<InputBudget::Lease> lease;
        AddressRaceResult value;
        ReservedAddressRaceResult(AddressRaceResult result,std::optional<InputBudget::Lease> reservation={}) noexcept
            :lease(std::move(reservation)),value(std::move(result)) {}
        ReservedAddressRaceResult(ReservedAddressRaceResult const&)=delete;
        auto operator=(ReservedAddressRaceResult const&) -> ReservedAddressRaceResult& = delete;
        ReservedAddressRaceResult(ReservedAddressRaceResult&&) noexcept = default;
        auto operator=(ReservedAddressRaceResult&& other) noexcept -> ReservedAddressRaceResult& {
            if(this!=&other) {
                value=std::unexpected(detail::ResolveError::state);
                lease=std::move(other.lease);value=std::move(other.value);
            }
            return *this;
        }
    };
    struct AddressRaceReservation {
        [[nodiscard]] static auto cost(AddressRaceValue const& value) noexcept -> std::optional<std::size_t> {
            auto total=sizeof(ReservedAddressRaceResult);
            auto add=[&](std::size_t size) {if(size>std::numeric_limits<std::size_t>::max()-total)return false;total+=size;return true;};
            auto array=[&](std::size_t count,std::size_t size) {return count<=std::numeric_limits<std::size_t>::max()/size && add(count*size);};
            if(auto* response=std::get_if<detail::LocalResponseSelection>(&value)) {
                auto const& parsed=response->response;
                if(!add(response->question.capacity()) || !add(parsed.wire.capacity()) || !array(parsed.records.capacity(),sizeof(Record)))return {};
                for(auto const& record:parsed.records)
                    if(!add(record.name.capacity()) || (record.cname && !add(record.cname->capacity())))return {};
            } else if(auto* answer=std::get_if<AddressAnswer>(&value)) {
                if(!add(answer->canonical_name.capacity()) || !array(answer->chain.capacity(),sizeof(std::string)) || !array(answer->addresses.capacity(),sizeof(Address)))return {};
                for(auto const& name:answer->chain)if(!add(name.capacity()))return {};
            } else return {};
            return total;
        }
        static auto apply(AddressRaceResult result) noexcept -> ReservedAddressRaceResult {
            if(!result)return ReservedAddressRaceResult(std::move(result));
            auto bytes=cost(*result);if(!bytes)return ReservedAddressRaceResult(std::unexpected(detail::ResolveError::budget_exhausted));
            auto lease=default_address_race_result_budget().acquire(*bytes);
            if(!lease)return ReservedAddressRaceResult(std::unexpected(detail::ResolveError::budget_exhausted));
            return ReservedAddressRaceResult(std::move(result),std::move(lease));
        }
    };
    struct AddressRaceDecision {
        ResponseStep step;
        std::optional<Response> response;
        std::optional<detail::EvaluatedResponseMeta> metadata;
        std::optional<AddressRaceResult> route;
    };
    // Preserve the first resolved local search candidate for later evaluates
    // and the other address family. Parallel completions are observed on the
    // owning executor in the same batch order as their publication.
    struct AddressRaceLocalCandidate {
        std::optional<std::pair<std::size_t,std::string>>& value;
        auto completed(ResponseStep const& step,detail::EvaluatedResponseMeta const& meta) -> void {
            if(meta.local && !value)value.emplace(step.server,meta.question);
        }
    };

    template<class Operation>
    class AddressRaceProgram {
        using Clock=std::chrono::steady_clock;
        using Error=detail::ResolveError;
        using Owner=EvaluateOwner<Operation,ReservedAddressRaceResult,32,AddressRaceReservation>;
        using Walk=ResponseRaceWalk;
        struct Slot {
            std::optional<InputBudget::Lease> result_lease;
            std::optional<Walk::Ticket> ticket;
            std::optional<typename Owner::Handle> handle;
            ResponseStep step{};
            Clock::time_point deadline{};
            std::optional<detail::EvaluatedResponseMeta> metadata;
            std::optional<AddressRaceResult> route;
        };
        corosio::io_context& context_;
        std::span<policy::DnsRule const> rules_;
        std::span<ResponseRaceMode const> modes_;
        std::size_t fallback_;
        bool disabled_,started_=false,canceled_=false;
        Owner* owner_=nullptr;
        std::array<Slot,32> slots_{};
        template<class Factory>
        auto publish(Owner& owner,Walk& walk,Factory& factory,std::uint16_t type) -> std::expected<void,Error> {
            for(auto& slot:slots_) {
                if(!slot.handle)continue;
                auto view=owner.inspect(*slot.handle);if(!view)return std::unexpected(Error::state);
                if(!view->ready)continue;
                if(view->exception)return std::unexpected(detail::resolve_task_exception(view->exception));
                auto value=owner.take_result(*slot.handle);if(!value || !owner.release(*slot.handle))return std::unexpected(Error::state);
                slot.handle.reset();
                slot.result_lease=std::move(value->lease);
                if(slot.step.action==policy::DnsAction::route) {
                    if(!value->value && value->value.error()==Error::budget_exhausted)return std::unexpected(Error::limit);
                    slot.route=std::move(value->value);
                    if(!walk.complete(*slot.ticket,{}))return std::unexpected(Error::state);
                    continue;
                }
                if(!value->value) {
                    if(value->value.error()==Error::budget_exhausted)return std::unexpected(Error::limit);
                    if(!walk.complete(*slot.ticket,{}))return std::unexpected(Error::state);
                    continue;
                }
                auto* selected=std::get_if<detail::LocalResponseSelection>(&*value->value);
                if(!selected)return std::unexpected(Error::state);
                if(slot.step.rewrite_ttl) {
                    auto const& wire=selected->response.wire;
                    if(wire.size()<2)return std::unexpected(Error::protocol);
                    auto id=static_cast<std::uint16_t>((std::uint16_t(wire[0])<<8)|wire[1]);
                    if(!rewrite_response(selected->response,id,slot.step.rewrite_ttl))return std::unexpected(Error::protocol);
                }
                slot.metadata.emplace(detail::EvaluatedResponseMeta{selected->upstream,selected->tcp,std::move(selected->question),
                    selected->local,selected->response.records.empty(),slot.deadline,slot.step.subnet.value_or(std::nullopt),selected->protection});
                if constexpr (requires { factory.completed(slot.step,*slot.metadata); })factory.completed(slot.step,*slot.metadata);
                auto completed=walk.complete(*slot.ticket,std::move(selected->response));
                if(!completed)return std::unexpected(completed.error()==ResponseProgramError::resource_limit ? Error::limit : Error::state);
            }
            return {};
        }
        template<class Factory>
        auto execute(Owner& owner,Factory& factory,std::string_view name,std::uint16_t type,policy::DnsContext context,Clock::time_point deadline)
            -> capy::task<std::expected<AddressRaceDecision,Error>> {
            Walk walk(rules_,modes_,fallback_,disabled_);
            for(;;) {
                if(canceled_)co_return std::unexpected(Error::canceled);
                if(Clock::now()>=deadline)co_return std::unexpected(Error::timeout);
                auto epoch=owner.epoch();auto published=publish(owner,walk,factory,type);
                if(!published)co_return std::unexpected(published.error());
                auto event=walk.next(name,type,context);
                if(!event)co_return std::unexpected(event.error()==ResponseProgramError::resource_limit ? Error::limit : Error::state);
                if(event->kind==Walk::Kind::start) {
                    if(!event->ticket || event->ticket->index>=slots_.size())co_return std::unexpected(Error::state);
                    auto until=event->step.timeout_ms ? std::min(deadline,Clock::now()+std::chrono::milliseconds(*event->step.timeout_ms)) : deadline;
                    auto operation=factory(event->step,until);if(!operation)co_return std::unexpected(Error::state);
                    auto handle=owner.start(std::move(operation));
                    if(!handle)co_return std::unexpected(handle.error()==Owner::StartError::full ||
                        handle.error()==Owner::StartError::allocation ? Error::limit : Error::state);
                    auto& slot=slots_[event->ticket->index];slot.ticket=event->ticket;slot.handle=*handle;slot.step=event->step;slot.deadline=until;
                    continue;
                }
                if(event->kind==Walk::Kind::wait) {
                    auto [error]=co_await corosio::timeout(owner.wait(epoch),deadline);
                    if(error)co_return std::unexpected(canceled_ ? Error::canceled : Clock::now()>=deadline ? Error::timeout : Error::state);
                    continue;
                }
                AddressRaceDecision decision{event->step};
                if(event->step.action==policy::DnsAction::respond) {
                    if(!event->ticket || event->ticket->index>=slots_.size())co_return std::unexpected(Error::state);
                    auto& slot=slots_[event->ticket->index];if(slot.ticket!=event->ticket || !slot.metadata)co_return std::unexpected(Error::state);
                    decision.response=walk.take_response(*event->ticket);decision.metadata=std::move(slot.metadata);
                    if(!decision.response)co_return std::unexpected(Error::state);
                } else if(event->step.action==policy::DnsAction::route && event->ticket && event->ticket->index<slots_.size()) {
                    auto& slot=slots_[event->ticket->index];
                    // A race route carries the response ticket that matched it;
                    // only a speculative route ticket represents a route task.
                    if(slot.ticket==event->ticket && slot.step.action==policy::DnsAction::route) {
                        if(slot.handle) {
                            if(!owner.stop_except(*slot.handle))co_return std::unexpected(Error::state);
                            while(slot.handle) {
                                if(canceled_)co_return std::unexpected(Error::canceled);
                                auto observed=owner.epoch();auto view=owner.inspect(*slot.handle);
                                if(!view)co_return std::unexpected(Error::state);
                                if(view->ready) {
                                    if(view->exception)co_return std::unexpected(detail::resolve_task_exception(view->exception));
                                    auto value=owner.take_result(*slot.handle);
                                    if(!value || !owner.release(*slot.handle))co_return std::unexpected(Error::state);
                                    if(!value->value && value->value.error()==Error::budget_exhausted)co_return std::unexpected(Error::limit);
                                    slot.result_lease=std::move(value->lease);slot.route.emplace(std::move(value->value));
                                    slot.handle.reset();break;
                                }
                                auto [error]=co_await corosio::timeout(owner.wait(observed),deadline);
                                if(error)co_return std::unexpected(canceled_ ? Error::canceled : Clock::now()>=deadline ? Error::timeout : Error::state);
                            }
                        }
                        decision.route=std::move(slot.route);
                        if(!decision.route)co_return std::unexpected(Error::state);
                    }
                }
                co_return decision;
            }
        }
    public:
        AddressRaceProgram(corosio::io_context& context,std::span<policy::DnsRule const> rules,
            std::span<ResponseRaceMode const> modes,std::size_t fallback,bool disabled=false) noexcept
            :context_(context),rules_(rules),modes_(modes),fallback_(fallback),disabled_(disabled) {}
        AddressRaceProgram(AddressRaceProgram const&)=delete;
        auto operator=(AddressRaceProgram const&) -> AddressRaceProgram& = delete;
        auto cancel() noexcept -> void {canceled_=true;if(owner_)owner_->stop();}
        // Factory returns an independent single-use Operation for each start.
        // Its lifetime, like all borrowed policy inputs, extends through drain.
        // The program retains result reservations and must also outlive its
        // returned decision, including asynchronous CNAME continuation.
        template<class Factory>
        auto run(Factory& factory,std::string_view name,std::uint16_t type,policy::DnsContext context,Clock::time_point deadline)
            -> capy::task<std::expected<AddressRaceDecision,Error>> {
            if(std::exchange(started_,true) || (!modes_.empty() && modes_.size()!=rules_.size()))co_return std::unexpected(Error::state);
            if(canceled_)co_return std::unexpected(Error::canceled);
            RaceAdmission admission;if(!admission.acquired())co_return std::unexpected(Error::limit);
            Owner owner(context_);owner_=&owner;
            std::expected<AddressRaceDecision,Error> result=std::unexpected(Error::state);
            try {result=co_await execute(owner,factory,name,type,context,deadline);}
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
