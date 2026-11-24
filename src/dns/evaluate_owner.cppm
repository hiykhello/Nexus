export module dns.evaluate_owner;
import std;
import capy;
import corosio;

export namespace dns {
    template<class Result>
    struct EvaluateIdentity {
        static auto apply(Result value) noexcept(std::is_nothrow_move_constructible_v<Result>) -> Result {return value;}
    };
    // One owner and its operations belong to a single-threaded, non-reentrant
    // io_context. Operation::run()
    // returns task<Result>; cancel() must be noexcept, idempotent and
    // eventually settle it. Stop and drain before destroying the context;
    // abandoning an active chain is not supported. This owner outlives callbacks.
    // Callers retain each completed generation until no rule references it.
    template<class Operation,class Result,std::size_t Capacity=32,class Transform=EvaluateIdentity<Result>>
    class EvaluateOwner {
        static_assert(Capacity>0);
    public:
        struct Handle {std::size_t index;std::uint64_t generation;auto operator==(Handle const&) const -> bool = default;};
        enum class StartError {stopped,full,generation_exhausted,allocation,startup};
        struct View {bool ready;Result const* result;std::exception_ptr exception;std::uint64_t completion;};
    private:
        struct Slot {
            std::unique_ptr<Operation> operation;
            std::optional<Result> result;
            std::exception_ptr exception;
            std::uint64_t generation=0,completion=0;
            bool active=false,ready=false;
        };
        corosio::io_context& context_;
        std::array<Slot,Capacity> slots_{};
        capy::async_event changed_;
        std::uint64_t generation_=0,epoch_=0,completion_=0;
        std::size_t active_=0,waiters_=0;
        bool stopped_=false;
        // Drain must survive cancellation of the enclosing request. Keep the
        // copied environment alive until the event awaiter has been destroyed.
        class DrainWait {
            std::optional<capy::await_context> environment_;
            capy::async_event::wait_awaiter operation_;
        public:
            explicit DrainWait(capy::async_event& event) noexcept :operation_(event.wait()) {}
            DrainWait(DrainWait const&)=delete;
            DrainWait(DrainWait&& other) noexcept :operation_(std::move(other.operation_)) {
                if(other.environment_)std::terminate();
            }
            auto await_ready() const noexcept -> bool {return operation_.await_ready();}
            auto await_suspend(std::coroutine_handle<> continuation,capy::await_context const* parent) {
                environment_.emplace(*parent);
                environment_->stop_token={};
                return operation_.await_suspend(continuation,&*environment_);
            }
            auto await_resume() {return operation_.await_resume();}
        };
        // Both supported io_context schedulers enqueue post() on the owner
        // thread; no callback may recursively run that context.
        auto notify() noexcept -> void {++epoch_;changed_.set();}
        auto current(Handle handle) noexcept -> Slot* {
            if(handle.index>=Capacity)return nullptr;
            auto& slot=slots_[handle.index];
            return slot.operation && slot.generation==handle.generation ? &slot : nullptr;
        }
        auto run(Slot& slot) -> capy::task<> {
            auto result=co_await slot.operation->run();
            slot.result.emplace(Transform::apply(std::move(result)));
        }
        auto finish(Handle handle,std::exception_ptr error={}) noexcept -> void {
            auto* slot=current(handle);
            if(!slot || !slot->active)std::terminate();
            slot->exception=std::move(error);slot->active=false;slot->ready=true;
            slot->completion=++completion_;--active_;notify();
        }
    public:
        explicit EvaluateOwner(corosio::io_context& context) noexcept :context_(context) {}
        EvaluateOwner(EvaluateOwner const&)=delete;
        auto operator=(EvaluateOwner const&) -> EvaluateOwner& = delete;
        ~EvaluateOwner(){if(active_ || waiters_)std::terminate();}
        [[nodiscard]] auto start(std::unique_ptr<Operation> operation) -> std::expected<Handle,StartError> {
            if(stopped_)return std::unexpected(StartError::stopped);
            if(!operation)return std::unexpected(StartError::allocation);
            if(generation_==std::numeric_limits<std::uint64_t>::max())return std::unexpected(StartError::generation_exhausted);
            auto found=std::ranges::find_if(slots_,[](auto const& slot){return !slot.operation;});
            if(found==slots_.end())return std::unexpected(StartError::full);
            auto index=static_cast<std::size_t>(found-slots_.begin());
            auto handle=Handle{index,++generation_};
            found->operation=std::move(operation);found->generation=handle.generation;found->active=true;++active_;
            try {
                capy::run_async(context_.get_executor(),[this,handle]() noexcept {finish(handle);},
                    [this,handle](std::exception_ptr error) noexcept {finish(handle,std::move(error));})(run(*found));
            } catch(std::bad_alloc const&) {
                --active_;*found=Slot{};return std::unexpected(StartError::allocation);
            } catch(...) {
                --active_;*found=Slot{};return std::unexpected(StartError::startup);
            }
            return handle;
        }
        [[nodiscard]] auto inspect(Handle handle) noexcept -> std::optional<View> {
            auto* slot=current(handle);if(!slot)return {};
            return View{slot->ready,slot->result ? &*slot->result : nullptr,slot->exception,slot->completion};
        }
        // A resumed owner may transfer a completed result into its bounded
        // response store before releasing the operation and its query copies.
        // Taking invalidates any result pointer previously returned by inspect.
        [[nodiscard]] auto take_result(Handle handle) noexcept -> std::optional<Result>
            requires std::is_nothrow_move_constructible_v<Result> {
            auto* slot=current(handle);
            if(!slot || !slot->ready || !slot->result)return {};
            std::optional<Result> result(std::move(*slot->result));slot->result.reset();return result;
        }
        [[nodiscard]] auto release(Handle handle) noexcept -> bool {
            auto* slot=current(handle);if(!slot || slot->active || !slot->ready)return false;
            *slot=Slot{};return true;
        }
        auto cancel(Handle handle) noexcept -> bool {
            auto* slot=current(handle);if(!slot || !slot->active)return false;
            slot->operation->cancel();return true;
        }
        // Close admission and cancel every other operation while preserving a
        // speculative terminal query. A later stop() also cancels that query.
        [[nodiscard]] auto stop_except(Handle handle) noexcept -> bool {
            if(stopped_)return false;
            auto* retained=current(handle);if(!retained)return false;
            stopped_=true;
            for(auto& slot:slots_)if(&slot!=retained && slot.active)slot.operation->cancel();
            notify();return true;
        }
        auto stop() noexcept -> void {
            auto changed=!std::exchange(stopped_,true);
            for(auto& slot:slots_)if(slot.active)slot.operation->cancel();
            if(changed || active_)notify();
        }
        [[nodiscard]] auto active() const noexcept -> std::size_t {return active_;}
        [[nodiscard]] auto drained() const noexcept -> bool {return active_==0 && waiters_==0;}
        [[nodiscard]] auto epoch() const noexcept -> std::uint64_t {return epoch_;}
        // Clear and recheck on the owner executor before suspending: signals
        // are hints, while epoch and slot states are authoritative.
        auto wait(std::uint64_t observed) -> capy::task<capy::results<>> {
            if(epoch_!=observed)co_return capy::results<>{};
            changed_.clear();
            if(epoch_!=observed)co_return capy::results<>{};
            ++waiters_;
            struct Waiter {EvaluateOwner& owner;~Waiter(){--owner.waiters_;}} waiter{*this};
            co_return co_await changed_.wait();
        }
        auto wait_drain(std::uint64_t observed) -> capy::task<capy::results<>> {
            if(epoch_!=observed)co_return capy::results<>{};
            changed_.clear();
            if(epoch_!=observed)co_return capy::results<>{};
            ++waiters_;
            struct Waiter {EvaluateOwner& owner;~Waiter(){--owner.waiters_;}} waiter{*this};
            co_return co_await DrainWait(changed_);
        }
    };
}
