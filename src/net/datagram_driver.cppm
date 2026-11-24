module;
#if !defined(_WIN32)
#include <cerrno>
#include <cstring>
#include <netinet/in.h>
#include <sys/socket.h>
#else
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <cstring>
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

export module net.datagram_driver;
import std;
import capy;
import corosio;
import platform.ip_address;
import platform.udp_batch;

export namespace net {
    using DatagramClock=std::chrono::steady_clock;
    using DatagramDeadline=std::optional<DatagramClock::time_point>;
    enum class DatagramError { canceled,deadline,receive,send,short_send,invalid_output,expiry_stalled,allocation,callback,already_started };
    struct DatagramFailure { DatagramError code; std::error_code system{}; };
    struct DatagramOutput { corosio::endpoint peer; std::size_t size=0; std::uint64_t token=0; bool mtu_probe=false,mtu_recoverable=false; };
    // One executor, one borrowed concrete UDP socket and one typed protocol.
    // Protocol request_stop gates business only; stop/drain may delete native
    // transport and H3 only after all three persistent tasks have joined.
    template<class Protocol,class Socket=corosio::udp_socket,
        std::size_t ReceiveCapacity=65536,std::size_t SendCapacity=1500>
    class DatagramDriver {
        static_assert(ReceiveCapacity && ReceiveCapacity<=65536 && SendCapacity && SendCapacity<=65535);
    public:
        using Failure=std::variant<DatagramFailure,typename Protocol::Failure>;
    private:
        static constexpr std::size_t kRecvBatch = 16;
        static constexpr std::size_t kMaxSyncSendBurst = 32;
        static auto sockaddr_to_endpoint(sockaddr_storage const& storage, socklen_t len) noexcept
            -> std::optional<corosio::endpoint> {
            if (storage.ss_family == AF_INET && len >= static_cast<socklen_t>(sizeof(sockaddr_in))) {
                sockaddr_in addr{};
                std::memcpy(&addr, &storage, sizeof(addr));
                corosio::ipv4_address::bytes_type b{};
                std::memcpy(b.data(), &addr.sin_addr, 4);
                return corosio::endpoint(corosio::ipv4_address(b), platform::net_to_host16(addr.sin_port));
            }
            if (storage.ss_family == AF_INET6 && len >= static_cast<socklen_t>(sizeof(sockaddr_in6))) {
                sockaddr_in6 addr{};
                std::memcpy(&addr, &storage, sizeof(addr));
                corosio::ipv6_address::bytes_type b{};
                std::memcpy(b.data(), &addr.sin6_addr, 16);
                return corosio::endpoint(corosio::ipv6_address(b), platform::net_to_host16(addr.sin6_port));
            }
            return std::nullopt;
        }
        static auto endpoint_to_sockaddr(corosio::endpoint const& ep, sockaddr_storage& storage) noexcept -> socklen_t {
            storage = {};
            if (ep.address().is_v6()) {
                sockaddr_in6 addr{};
                addr.sin6_family = AF_INET6;
                addr.sin6_port = platform::host_to_net16(ep.port());
                auto v6 = ep.address().to_v6();
                auto b = v6.to_bytes();
                std::memcpy(&addr.sin6_addr, b.data(), 16);
                addr.sin6_scope_id = static_cast<std::uint32_t>(v6.scope_id());
                std::memcpy(&storage, &addr, sizeof(addr));
                return static_cast<socklen_t>(sizeof(addr));
            }
            sockaddr_in addr{};
            addr.sin_family = AF_INET;
            addr.sin_port = platform::host_to_net16(ep.port());
            auto b = ep.address().to_v4().to_bytes();
            std::memcpy(&addr.sin_addr, b.data(), 4);
            std::memcpy(&storage, &addr, sizeof(addr));
            return static_cast<socklen_t>(sizeof(addr));
        }
        static auto recv_batch_slab() -> std::pair<std::uint8_t*, bool*> {
            thread_local std::unique_ptr<std::uint8_t[]> slab;
            thread_local bool in_use = false;
            if (in_use) return {nullptr, nullptr};
            if (!slab) slab = std::make_unique_for_overwrite<std::uint8_t[]>(kRecvBatch * 65536);
            return {slab.get(), &in_use};
        }
        static auto is_transient_peer_send_error(std::error_code const& error) noexcept -> bool {
            return error == std::errc::network_unreachable ||
                   error == std::errc::host_unreachable ||
                   error == std::errc::operation_not_permitted ||
                   error == std::errc::permission_denied ||
                   error == std::errc::message_size ||
                   error == std::errc::connection_refused ||
                   error == std::errc::no_buffer_space;
        }
        auto unconnected_socket() noexcept -> bool {
#if !defined(_WIN32)
            if constexpr (requires(Socket& s) { { s.native_handle() } -> std::same_as<int>; }) {
                int const fd = socket_.native_handle();
                if (fd < 0) return false;
                sockaddr_storage peer{};
                socklen_t len = sizeof(peer);
                return ::getpeername(fd, reinterpret_cast<sockaddr*>(&peer), &len) != 0 && errno == ENOTCONN;
            }
#endif
            return false;
        }
        Socket& socket_;
        Protocol& protocol_;
        DatagramDeadline armed_deadline_;
        capy::async_event write_work_,expiry_work_,changed_;
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
        auto reader() -> capy::task<capy::results<>> {
            std::array<std::uint8_t,ReceiveCapacity> bytes;
            while (!stopped_) {
                corosio::endpoint source;
                auto [error,size]=co_await socket_.recv_from(capy::mutable_buffer(bytes.data(),bytes.size()),source);
                auto now=DatagramClock::now();
                if (stopped_ || expired(now)) break;
                if (error || size>bytes.size()) { fail({DatagramError::receive,error}); break; }
                if (!invoke([&] { return protocol_.receive(source,std::span(bytes).first(size),now); })) break;
#if !defined(_WIN32)
                if constexpr (requires(Socket& s) { { s.native_handle() } -> std::same_as<int>; }) {
                    int const fd = socket_.native_handle();
                    if (!stopped_ && fd >= 0) {
                        auto [slab, busy_flag] = recv_batch_slab();
                        if (slab && busy_flag) {
                            *busy_flag = true;
                            struct BusyGuard { bool* f; ~BusyGuard() { *f = false; } } bg{busy_flag};
                            std::array<platform::UdpRecvSlot, kRecvBatch> slots{};
                            for (std::size_t i = 0; i < kRecvBatch; ++i) {
                                slots[i].data = slab + i * ReceiveCapacity;
                                slots[i].capacity = ReceiveCapacity;
                            }
                            for (int round = 0; round < 2 && !stopped_; ++round) {
                                auto got = platform::recv_udp_batch(fd, slots);
                                if (!got) { fail({DatagramError::receive, got.error()}); break; }
                                if (*got == 0) break;
                                for (std::size_t i = 0; i < *got && !stopped_; ++i) {
                                    if (slots[i].truncated || slots[i].received > ReceiveCapacity) {
                                        fail({DatagramError::receive, std::make_error_code(std::errc::message_size)});
                                        break;
                                    }
                                    auto peer = sockaddr_to_endpoint(slots[i].peer, slots[i].peer_len);
                                    if (!peer) continue;
                                    if (!invoke([&] { return protocol_.receive(*peer, std::span(slots[i].data, slots[i].received), now); }))
                                        break;
                                }
                                if (*got < kRecvBatch) break;
                            }
                        }
                    }
                }
#endif
                if (stopped_) break;
                notify();
            }
            co_return capy::results<>{};
        }
        auto writer() -> capy::task<capy::results<>> {
            std::array<std::uint8_t,SendCapacity> bytes;
            auto now = DatagramClock::now();
            bool dirty = false;
            std::size_t sync_burst = 0;
            auto flush_signals = [&]() noexcept {
                wake_expiry();
                if (dirty) { changed_.set(); dirty = false; }
            };
            while (!stopped_) {
                if (sync_burst == 0) write_work_.clear();
                if (expired(now)) break;
                std::optional<DatagramOutput> packet;
                if (!invoke([&] -> std::expected<void,typename Protocol::Failure> {
                    auto result=protocol_.output(bytes,now);
                    if (!result) return std::unexpected(std::move(result.error()));
                    packet=std::move(*result); return {};
                })) break;
                if (!packet) {
                    write_work_.clear();
                    flush_signals();
                    sync_burst = 0;
                    auto [error]=co_await write_work_.wait();
                    if (error && !stopped_) fail({DatagramError::canceled,error});
                    now = DatagramClock::now();
                    continue;
                }
                if (packet->size>bytes.size()) { fail({DatagramError::invalid_output}); break; }
                std::error_code error;
                std::size_t size = 0;
                bool sent_sync = false;
#if !defined(_WIN32)
                if constexpr (requires(Socket& s) { { s.native_handle() } -> std::same_as<int>; }) {
                    if (sync_burst < kMaxSyncSendBurst) {
                        int const fd = socket_.native_handle();
                        if (fd >= 0) {
                            sockaddr_storage ss{};
                            auto slen = endpoint_to_sockaddr(packet->peer, ss);
                            platform::UdpSendSlot slot{reinterpret_cast<sockaddr const*>(&ss), slen, bytes.data(), packet->size};
                            auto res = platform::send_udp_batch(fd, std::span(&slot, 1));
                            if (res && *res == 1) {
                                size = packet->size;
                                sent_sync = true;
                                ++sync_burst;
                                if ((sync_burst & 15u) == 0u) now = DatagramClock::now();
                            } else if (!res) {
                                error = res.error();
                                sent_sync = true;
                                sync_burst = 0;
                                now = DatagramClock::now();
                            }
                        }
                    }
                }
#endif
                if (!sent_sync) {
                    // The sole pending array is immutable through this await.
                    // The independent expiry task continues during socket EAGAIN.
                    flush_signals();
                    sync_burst = 0;
                    std::tie(error,size)=co_await socket_.send_to(capy::const_buffer(bytes.data(),packet->size),packet->peer);
                    now = DatagramClock::now();
                }
                if (stopped_ || expired(now)) break;
                if constexpr(requires {protocol_.mtu_rejected(packet->token,now);}) {
                    if(error==std::errc::message_size && !packet->mtu_probe && packet->mtu_recoverable) {
                        if (!invoke([&] {return protocol_.mtu_rejected(packet->token,now);})) break;
                        dirty = true;
                        if (!sent_sync) flush_signals();
                        continue;
                    }
                }
                // QUIC has already registered a PMTU probe for loss detection.
                // A local MTU rejection is equivalent to losing that probe;
                // commit its token so the transport can wait for its timer.
                // On unconnected multi-peer server sockets, per-peer transient
                // send errors drop only that packet instead of killing the server.
                bool const drop_peer_error = error && (
                    (packet->mtu_probe && error == std::errc::message_size) ||
                    (unconnected_socket() && is_transient_peer_send_error(error)));
                if (error && !drop_peer_error) { fail({DatagramError::send,error}); break; }
                if (error) {
                    if (!invoke([&] { return protocol_.transmitted(packet->token,now); })) break;
                    dirty = true;
                    flush_signals();
                    continue;
                }
                if (size!=packet->size) { fail({DatagramError::short_send}); break; }
                if (!invoke([&] { return protocol_.transmitted(packet->token,now); })) break;
                dirty = true;
                if (!sent_sync) flush_signals();
            }
            co_return capy::results<>{};
        }
        auto timer() -> capy::task<capy::results<>> {
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
                    auto [error]=co_await corosio::timeout(expiry_work_.wait(),*next);
                    if (error && !stopped_ && !capy::is_timeout(error) &&
                        error!=capy::make_error_condition(capy::cond::canceled))
                        fail({DatagramError::canceled,error});
                } else {
                    armed_deadline_.reset();
                    auto [error]=co_await expiry_work_.wait();
                    if (error && !stopped_) fail({DatagramError::canceled,error});
                }
            }
            co_return capy::results<>{};
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
        auto changed() noexcept -> capy::async_event& { return changed_; }
        // The caller joins this task with its application tasks. Natural
        // context abandonment releases child I/O before the guard finalizes;
        // destroying the borrowed driver/protocol first is a lifetime error.
    private:
        // The frame's single owner pointer is the guard parameter, replacing
        // the member coroutine's implicit this parameter without a new actor.
        static auto drive(RunGuard guard) -> capy::task<capy::results<>> {
            if (guard.owner()->started_ || guard.owner()->stopped_) {
                co_return capy::results<>{std::make_error_code(std::errc::operation_not_permitted)};
            }
            guard.activate(); guard.owner()->started_=guard.owner()->running_=true;
            try {
                auto [error,input,output,expiry]=co_await capy::when_all(guard.owner()->reader(),guard.owner()->writer(),guard.owner()->timer());
                (void)input; (void)output; (void)expiry;
                if (error && !guard.owner()->stopped_) guard.owner()->fail({DatagramError::canceled,error});
            } catch (std::bad_alloc const&) { guard.owner()->fail({DatagramError::allocation}); }
            catch (...) { guard.owner()->fail({DatagramError::callback}); }
            co_return capy::results<>{guard.owner()->failure_ ? std::make_error_code(std::errc::operation_canceled) : std::error_code{}};
        }
    public:
        auto run() -> capy::task<capy::results<>> { return drive(RunGuard{*this}); }
    };
}
