export module net.operation_token;
import std;
import capy;

export namespace net {
    // Bind one operation to an already-owned stop source while preserving its
    // parent's cancellation and the same executor/frame/abandonment owner.
    // The context lives in the awaiter through complete drain; no new task,
    // stop-source allocation, or heap owner is introduced by this adapter.
    template<class Operation>
    class OperationToken {
        struct Cancel {
            std::stop_source* source;
            auto operator()() const noexcept -> void{source->request_stop();}
        };
        std::stop_source& source_;
        std::optional<capy::await_context> environment_;
        std::optional<std::stop_callback<Cancel>> parent_;
        Operation operation_;
    public:
        OperationToken(Operation&& operation,std::stop_source& source)
            :source_(source),operation_(std::move(operation)){}
        OperationToken(OperationToken const&)=delete;
        OperationToken(OperationToken&& other) noexcept(std::is_nothrow_move_constructible_v<Operation>)
            :source_(other.source_),operation_(std::move(other.operation_)){
            if(other.environment_)std::terminate();
        }
        auto await_ready() noexcept(noexcept(operation_.await_ready())) -> bool{return operation_.await_ready();}
        auto await_suspend(std::coroutine_handle<> continuation,capy::await_context const* parent){
            environment_.emplace(*parent);
            environment_->stop_token=source_.get_token();
            parent_.emplace(parent->stop_token,Cancel{&source_});
            return operation_.await_suspend(continuation,&*environment_);
        }
        auto await_resume(){
            parent_.reset();
            return operation_.await_resume();
        }
    };
    template<class Operation>OperationToken(Operation&&,std::stop_source&)->OperationToken<std::remove_cvref_t<Operation>>;
}
