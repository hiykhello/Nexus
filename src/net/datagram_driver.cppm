export module net.datagram_driver;
import std;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;

export namespace net {
    using DatagramClock=std::chrono::steady_clock;
    using DatagramDeadline=std::optional<DatagramClock::time_point>;
    enum class DatagramError { canceled,deadline,receive,send,short_send,invalid_output,expiry_stalled,allocation,callback,already_started };
    struct DatagramFailure { DatagramError code; std::error_code system{}; };
    struct DatagramOutput { nex::corosio::endpoint peer; std::size_t size=0; std::uint64_t token=0; bool mtu_probe=false,mtu_recoverable=false; };
    // One executor, one borrowed concrete UDP socket and one typed protocol.
    // Protocol request_stop gates business only; stop/drain may delete native
    // transport and H3 only after all three persistent tasks have joined.
    template<class Protocol,class Socket=nex::corosio::udp_socket,
        std::size_t ReceiveCapacity=65536,std::size_t SendCapacity=1500>
    class DatagramDriver {
        static_assert(ReceiveCapacity && ReceiveCapacity<=65536 && SendCapacity && SendCapacity<=65535);
    public:
        using Failure=std::variant<DatagramFailure,typename Protocol::Failure>;
    private:
        Socket& socket_;
        Protocol& protocol_;
        DatagramDeadline armed_deadline_;
        nex::capy::async_event write_work_,expiry_work_,changed_;
        DatagramDeadline deadline_;
        std::optional<Failure> failure_;
        bool started_=false,running_=false,stopped_=false,finalized_=false;
        struct RunGuard {
            // One explicit activation bit shares the aligned owner pointer.
            // A never-started duplicate task must not clean up another run.
            std::uintptr_t state;
            explicit RunGuard(DatagramDriver& value) noexcept:state(reinterpret_cast<std::uintptr_t>(&value)) { static_assert(alignof(DatagramDriver)>=2); }
            RunGuard(RunGuard const&)=delete;
            RunGuard(RunGuard&& other) noexcept:state(std::exchange(other.state,0)) {}
            auto owner() const noexcept -> DatagramDriver* { return reinterpret_cast<DatagramDriver*>(state&~std::uintptr_t{1}); }
            auto activate() noexcept -> void { state|=1; }
            ~RunGuard() {
                // The when_all awaiter releases its children before this
                // parameter guard on normal exit and context abandonment.
                // No I/O array may still be borrowed by native stop/drain.
                if (state&1) {
                    auto* value=owner();
                    value->request_stop(); value->finalize(); value->running_=false; value->changed_.set();
                }
            }
        };
        auto wake_expiry() noexcept -> void {
            if (stopped_) { expiry_work_.set(); return; }
            auto next=protocol_.next_expiry();
            if (deadline_ && (!next || *deadline_<*next)) next=deadline_;
            if (!armed_deadline_ || (next && *next<*armed_deadline_)) expiry_work_.set();
        }
        auto request_stop() noexcept -> void {
            if (std::exchange(stopped_,true)) return;
            static_assert(noexcept(protocol_.request_stop()) && noexcept(socket_.close()));
            protocol_.request_stop(); socket_.close();
            write_work_.set(); expiry_work_.set(); changed_.set();
        }
        auto finalize() noexcept -> void {
            if (std::exchange(finalized_,true)) return;
            static_assert(noexcept(protocol_.stop()) && noexcept(protocol_.drain()));
            protocol_.stop(); protocol_.drain(); changed_.set();
        }
        auto fail(DatagramFailure failure) noexcept -> void {
            if (!failure_) failure_.emplace(std::in_place_index<0>,failure);
            request_stop();
        }
        auto fail_protocol(typename Protocol::Failure failure) noexcept -> void {
            static_assert(std::is_nothrow_move_constructible_v<typename Protocol::Failure>);
            if (!failure_) failure_.emplace(std::in_place_index<1>,std::move(failure));
            request_stop();
        }
        auto expired(DatagramClock::time_point time) noexcept -> bool {
            if (deadline_ && time>=*deadline_) { fail({DatagramError::deadline}); return true; }
            return false;
        }
        template<class Function> auto invoke(Function&& function) noexcept -> bool {
            try {
                auto result=std::forward<Function>(function)();
                if (!result) { fail_protocol(std::move(result.error())); return false; }
                return !stopped_;
            } catch (std::bad_alloc const&) { fail({DatagramError::allocation}); }
            catch (...) { fail({DatagramError::callback}); }
            return false;
        }
        auto reader() -> nex::capy::task<nex::capy::results<>> {
            std::array<std::uint8_t,ReceiveCapacity> bytes{};
            while (!stopped_) {
                nex::corosio::endpoint source;
                auto [error,size]=co_await socket_.recv_from(nex::capy::mutable_buffer(bytes.data(),bytes.size()),source);
                if (stopped_ || expired(DatagramClock::now())) break;
                if (error || size>bytes.size()) { fail({DatagramError::receive,error}); break; }
                if (!invoke([&] { return protocol_.receive(source,std::span(bytes).first(size),DatagramClock::now()); })) break;
                notify();
            }
            co_return nex::capy::results<>{};
        }
        auto writer() -> nex::capy::task<nex::capy::results<>> {
            std::array<std::uint8_t,SendCapacity> bytes{};
            while (!stopped_) {
                write_work_.clear();
                if (expired(DatagramClock::now())) break;
                std::optional<DatagramOutput> packet;
                if (!invoke([&] -> std::expected<void,typename Protocol::Failure> {
                    auto result=protocol_.output(bytes,DatagramClock::now());
                    if (!result) return std::unexpected(std::move(result.error()));
                    packet=std::move(*result); return {};
                })) break;
                wake_expiry();
                if (!packet) {
                    auto [error]=co_await write_work_.wait();
                    if (error && !stopped_) fail({DatagramError::canceled,error});
                    continue;
                }
                if (packet->size>bytes.size()) { fail({DatagramError::invalid_output}); break; }
                // The sole pending array is immutable through this await.
                // The independent expiry task continues during socket EAGAIN.
                auto [error,size]=co_await socket_.send_to(nex::capy::const_buffer(bytes.data(),packet->size),packet->peer);
                if (stopped_ || expired(DatagramClock::now())) break;
                if constexpr(requires {protocol_.mtu_rejected(packet->token,DatagramClock::now());}) {
                    if(error==std::errc::message_size && !packet->mtu_probe && packet->mtu_recoverable) {
                        if (!invoke([&] {return protocol_.mtu_rejected(packet->token,DatagramClock::now());})) break;
                        wake_expiry();changed_.set();continue;
                    }
                }
                // QUIC has already registered a PMTU probe for loss detection.
                // A local MTU rejection is equivalent to losing that probe;
                // commit its token so the transport can wait for its timer.
                if (error && !(packet->mtu_probe && error==std::errc::message_size)) { fail({DatagramError::send,error}); break; }
                if (error) {
                    if (!invoke([&] { return protocol_.transmitted(packet->token,DatagramClock::now()); })) break;
                    wake_expiry();changed_.set();continue;
                }
                if (size!=packet->size) { fail({DatagramError::short_send}); break; }
                if (!invoke([&] { return protocol_.transmitted(packet->token,DatagramClock::now()); })) break;
                wake_expiry(); changed_.set();
            }
            co_return nex::capy::results<>{};
        }
        auto timer() -> nex::capy::task<nex::capy::results<>> {
            while (!stopped_) {
                expiry_work_.clear(); auto time=DatagramClock::now();
                if (expired(time)) break;
                DatagramDeadline next;
                if (!invoke([&] -> std::expected<void,typename Protocol::Failure> { next=protocol_.next_expiry(); return {}; })) break;
                if (next && *next<=time) {
                    if (!invoke([&] { return protocol_.expire(time); })) break;
                    write_work_.set(); changed_.set();
                    if (!invoke([&] -> std::expected<void,typename Protocol::Failure> { next=protocol_.next_expiry(); return {}; })) break;
                    if (next && *next<=time) { fail({DatagramError::expiry_stalled}); break; }
                }
                if (deadline_ && (!next || *deadline_<*next)) next=deadline_;
                if (next) {
                    armed_deadline_=next;
                    struct Clear { DatagramDeadline& armed; ~Clear() { armed.reset(); } } clear{armed_deadline_};
                    auto [error]=co_await nex::corosio::timeout(expiry_work_.wait(),*next);
                    if (error && !stopped_ && !nex::capy::is_timeout(error) &&
                        error!=nex::capy::make_error_condition(nex::capy::cond::canceled))
                        fail({DatagramError::canceled,error});
                } else {
                    armed_deadline_.reset();
                    auto [error]=co_await expiry_work_.wait();
                    if (error && !stopped_) fail({DatagramError::canceled,error});
                }
            }
            co_return nex::capy::results<>{};
        }
    public:
        DatagramDriver(Socket& socket,Protocol& protocol,DatagramDeadline deadline={}) noexcept
            :socket_(socket),protocol_(protocol),deadline_(deadline) {}
        ~DatagramDriver() { cancel(); if (running_) std::terminate(); finalize(); }
        DatagramDriver(DatagramDriver const&)=delete;
        auto operator=(DatagramDriver const&) -> DatagramDriver& = delete;
        DatagramDriver(DatagramDriver&&)=delete;
        auto operator=(DatagramDriver&&) -> DatagramDriver& = delete;
        auto notify() noexcept -> void { write_work_.set(); wake_expiry(); changed_.set(); }
        auto finish() noexcept -> void { request_stop(); }
        auto cancel() noexcept -> void { if (!stopped_) fail({DatagramError::canceled}); }
        auto running() const noexcept -> bool { return running_ && !stopped_; }
        auto drained() const noexcept -> bool { return started_ && !running_ && finalized_; }
        auto failure() const noexcept -> std::optional<Failure> const& { return failure_; }
        auto changed() noexcept -> nex::capy::async_event& { return changed_; }
        // The caller joins this task with its application tasks. Natural
        // context abandonment releases child I/O before the guard finalizes;
        // destroying the borrowed driver/protocol first is a lifetime error.
    private:
        // The frame's single owner pointer is the guard parameter, replacing
        // the member coroutine's implicit this parameter without a new actor.
        static auto drive(RunGuard guard) -> nex::capy::task<nex::capy::results<>> {
            if (guard.owner()->started_ || guard.owner()->stopped_) {
                co_return nex::capy::results<>{std::make_error_code(std::errc::operation_not_permitted)};
            }
            guard.activate(); guard.owner()->started_=guard.owner()->running_=true;
            try {
                auto [error,input,output,expiry]=co_await nex::capy::when_all(guard.owner()->reader(),guard.owner()->writer(),guard.owner()->timer());
                (void)input; (void)output; (void)expiry;
                if (error && !guard.owner()->stopped_) guard.owner()->fail({DatagramError::canceled,error});
            } catch (std::bad_alloc const&) { guard.owner()->fail({DatagramError::allocation}); }
            catch (...) { guard.owner()->fail({DatagramError::callback}); }
            co_return nex::capy::results<>{guard.owner()->failure_ ? std::make_error_code(std::errc::operation_canceled) : std::error_code{}};
        }
    public:
        auto run() -> nex::capy::task<nex::capy::results<>> { return drive(RunGuard{*this}); }
    };
}
