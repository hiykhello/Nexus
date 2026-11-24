export module net.buffered_input;
import std;
import net.socket_stream;
import capy;

export namespace net {
    enum class InputStatus { ready,consumer,eof,state,transport,timeout,capacity };
    enum class InputAction { more,complete,fail };
    struct InputStep {std::size_t consumed=0,minimum=1;InputAction action=InputAction::more;};
    namespace buffered_detail {
        inline auto erase(std::span<std::uint8_t> bytes) noexcept -> void {
            volatile std::uint8_t* pointer=bytes.data();for (std::size_t i=0;i<bytes.size();++i) pointer[i]=0;
        }
        inline auto expired(StreamDeadline deadline) noexcept -> bool {return deadline && std::chrono::steady_clock::now()>=*deadline;}
    }
    // One stable window is shared by successive synchronous consumers. A
    // consumer may request contiguous input without copying it elsewhere.
    // Its factory constructs nonmovable state directly in this one task.
    template<std::size_t Capacity>
    class BufferedInput {
        std::array<std::uint8_t,Capacity> bytes_{};
        std::size_t begin_=0,end_=0;
        bool active_=false,failed_=false,eof_=false;
    public:
        BufferedInput()=default;
        ~BufferedInput() {buffered_detail::erase(bytes_);}
        BufferedInput(BufferedInput const&)=delete;
        auto operator=(BufferedInput const&) -> BufferedInput& = delete;
        auto pending() const noexcept -> std::span<std::uint8_t const> {return std::span(bytes_).subspan(begin_,end_-begin_);}
        auto active() const noexcept -> bool {return active_;}
        auto failed() const noexcept -> bool {return failed_;}
        auto invalidate() noexcept -> void {failed_=true;buffered_detail::erase(bytes_);begin_=end_=0;}
        template<class Lower,class Factory>
        static auto drive(Lower& lower,Factory factory,StreamDeadline deadline={})
            -> capy::task<typename decltype(factory())::Result> {
            auto state=factory();auto& input=state.input();
            if (input.active_ || input.failed_) {
                state.abort();lower.cancel();co_return state.finish(InputStatus::state);
            }
            input.active_=true;
            struct Guard {
                BufferedInput& input;Lower& lower;decltype(state)& consumer;bool released=false;
                ~Guard() {input.active_=false;if (!released) {input.invalidate();consumer.abort();lower.cancel();}}
            } guard{input,lower,state};
            auto finish=[&](InputStatus status) -> typename decltype(factory())::Result {
                auto result=state.finish(status);
                if (result && buffered_detail::expired(deadline)) result=state.finish(InputStatus::timeout);
                if (!result) {input.invalidate();state.abort();lower.cancel();}
                guard.released=true;return result;
            };
            for (;;) {
                if (buffered_detail::expired(deadline)) co_return finish(InputStatus::timeout);
                auto pending=std::span(input.bytes_).subspan(input.begin_,input.end_-input.begin_);
                auto step=state.feed(pending);
                if (step.consumed>pending.size()) co_return finish(InputStatus::state);
                input.begin_+=step.consumed;
                if (step.action==InputAction::fail) co_return finish(InputStatus::consumer);
                if (step.action==InputAction::complete) co_return finish(InputStatus::ready);
                if (step.consumed) continue;
                if (step.minimum>Capacity) co_return finish(InputStatus::capacity);
                if (step.minimum<=pending.size()) co_return finish(InputStatus::state);
                if (input.eof_) co_return finish(InputStatus::eof);
                if (input.begin_) {
                    auto size=input.end_-input.begin_;
                    std::memmove(input.bytes_.data(),input.bytes_.data()+input.begin_,size);input.begin_=0;input.end_=size;
                }
                auto output=std::span(input.bytes_).subspan(input.end_);
                if (output.empty()) co_return finish(InputStatus::capacity);
                auto received=co_await lower.read(output,deadline);
                if (buffered_detail::expired(deadline)) co_return finish(InputStatus::timeout);
                if (input.failed_ || !received || *received>output.size()) co_return finish(InputStatus::transport);
                if (!*received) input.eof_=true;else input.end_+=*received;
            }
        }
    };
}
