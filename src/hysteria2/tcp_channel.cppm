export module hysteria2.tcp_channel;
import std;
import hysteria2.stream_state;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;

export namespace hysteria2 {
    using StreamClock=std::chrono::steady_clock;
    using StreamDeadline=std::optional<StreamClock::time_point>;
    enum class StreamError { canceled,timeout,reset,rejected,state,transport };
    struct StreamFailure { StreamError error=StreamError::state; std::uint64_t code=0; };
    // One business stream borrows the sole application/driver, with no actor
    // forwarding bytes between independently owned queues. Shared byte relay
    // uses this ordinary read/send/close_output contract directly.
    template<class Application,class Driver>
    class TcpChannel {
        Application& application_;
        Driver& driver_;
        StreamHandle stream_;
        StreamDeadline deadline_;
        StreamDeadline response_deadline_;
        nex::capy::async_mutex writer_;
        bool reading_=false,canceled_=false;
        std::optional<StreamFailure> failure_;
        struct Guard {
            TcpChannel& owner; bool released=false;
            ~Guard() { if (!released) owner.cancel(); }
        };
        struct Reader { bool& flag; ~Reader() { flag=false; } };
        auto limit(StreamDeadline value) const noexcept -> StreamDeadline {
            if (!deadline_) return value; if (!value) return deadline_; return std::min(*value,*deadline_);
        }
        static auto expired(StreamDeadline value) noexcept -> bool { return value && StreamClock::now()>=*value; }
        auto fail(StreamFailure failure) noexcept -> void {
            if (!failure_) failure_=failure;
            cancel();
        }
        auto valid(StreamDeadline deadline,bool allow_closed=false) noexcept -> bool {
            if (canceled_) return false;
            if (expired(deadline)) { fail({StreamError::timeout}); return false; }
            auto phase=application_.phase(stream_);
            if (!phase) { fail({StreamError::state}); return false; }
            if (*phase==StreamPhase::reset) { fail({StreamError::reset,application_.reset_code(stream_).value_or(0)}); return false; }
            if (*phase==StreamPhase::rejected) { fail({StreamError::rejected}); return false; }
            if (allow_closed && *phase==StreamPhase::closed) return true;
            if (application_.stopping() || !driver_.running()) { fail({StreamError::transport}); return false; }
            return true;
        }
        auto wait(StreamDeadline deadline,bool allow_closed=false) -> nex::capy::task<bool> {
            driver_.changed().clear();
            auto operation=driver_.changed().wait();
            auto [error]=deadline ? co_await nex::corosio::timeout(std::move(operation),*deadline) : co_await std::move(operation);
            if (error) { fail({expired(deadline)?StreamError::timeout:StreamError::canceled}); co_return false; }
            co_return valid(deadline,allow_closed);
        }
    public:
        TcpChannel(Application& application,Driver& driver,StreamHandle stream,StreamDeadline deadline={},
                   StreamDeadline response_deadline={}) noexcept
            :application_(application),driver_(driver),stream_(stream),deadline_(deadline),response_deadline_(response_deadline) {}
        TcpChannel(TcpChannel const&)=delete;
        auto operator=(TcpChannel const&) -> TcpChannel& = delete;
        ~TcpChannel() { application_.abandon(stream_);driver_.notify(); }
        auto failure() const noexcept -> std::optional<StreamFailure> { return failure_; }
        auto cancel() noexcept -> void {
            if (std::exchange(canceled_,true)) return;
            if(!failure_)failure_=StreamFailure{StreamError::canceled};
            try { (void)application_.reset(stream_); } catch (...) {}
            driver_.notify();
        }
        auto ready(StreamDeadline requested={}) -> nex::capy::task<bool> {
            Guard guard{*this};auto deadline=limit(requested);
            while (valid(deadline)) {
                if (application_.phase(stream_)==StreamPhase::ready) { guard.released=true;co_return true; }
                if (!co_await wait(deadline)) break;
            } co_return false;
        }
        auto read(std::span<std::uint8_t> output,StreamDeadline requested={}) -> nex::capy::task<std::expected<std::size_t,StreamFailure>> {
            if (reading_) co_return std::unexpected(StreamFailure{StreamError::state});
            Guard guard{*this}; reading_=true;Reader reader{reading_};auto deadline=limit(requested);
            while (valid(deadline,true)) {
                if (response_deadline_ && application_.phase(stream_)==StreamPhase::opening) {
                    auto response_limit=deadline ? std::min(*deadline,*response_deadline_) : *response_deadline_;
                    if (!valid(response_limit,true)) break;
                    if (!co_await wait(response_limit,true)) break;
                    continue;
                }
                auto result=application_.read(stream_,output);
                if (!result) { fail({StreamError::state});break; }
                if (result->size || result->eof || output.empty()) { if (result->size) driver_.notify();guard.released=true;co_return result->size; }
                if (!co_await wait(deadline,true)) break;
            } co_return std::unexpected(failure_.value_or(StreamFailure{StreamError::canceled}));
        }
        auto send(std::span<std::uint8_t const> input,StreamDeadline requested={}) -> nex::capy::task<bool> {
            Guard guard{*this};auto deadline=limit(requested);auto operation=writer_.scoped_lock();
            auto [error,lock]=deadline ? co_await nex::corosio::timeout(std::move(operation),*deadline) : co_await std::move(operation);
            if (error || !valid(deadline)) { if (error) fail({expired(deadline)?StreamError::timeout:StreamError::canceled});co_return false; }
            while (!input.empty()) {
                if (!valid(deadline)) co_return false;
                auto sent=application_.send(stream_,input,response_deadline_.has_value());if (!sent) { fail({StreamError::state});co_return false; }
                input=input.subspan(*sent);if (*sent) driver_.notify();
                if (!input.empty() && !co_await wait(deadline)) co_return false;
            } guard.released=true;co_return true;
        }
        auto close_output(StreamDeadline requested={}) -> nex::capy::task<bool> {
            Guard guard{*this};auto deadline=limit(requested);auto operation=writer_.scoped_lock();
            auto [error,lock]=deadline ? co_await nex::corosio::timeout(std::move(operation),*deadline) : co_await std::move(operation);
            if (error || !valid(deadline)) { if (error) fail({expired(deadline)?StreamError::timeout:StreamError::canceled});co_return false; }
            if (!application_.close_output(stream_,response_deadline_.has_value())) { fail({StreamError::state});co_return false; } driver_.notify();
            while (valid(deadline)) {
                if (application_.fin_accepted(stream_)) { guard.released=true;co_return true; }
                if (application_.output_stopped(stream_)) { fail({StreamError::reset});co_return false; }
                if (!co_await wait(deadline)) break;
            } co_return false;
        }
    };
}
