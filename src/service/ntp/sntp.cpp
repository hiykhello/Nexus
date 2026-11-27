module;
#include <cerrno>
#include <cstring>
#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <netioapi.h>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#else
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#if defined(__linux__)
#include <sys/random.h>
#elif defined(__APPLE__)
#include <cstdlib>
#endif
#endif

module ntp;
import std;
import capy;
import corosio;
import encoding.endian;
import platform.ip_address;
import platform.socket_options;
import utility;

namespace ntp {
    namespace {
        constexpr std::int64_t kMaxSaneOffsetMs = 3600LL * 1000;
        constexpr std::int64_t kMinSaneDelayMs = -5000LL;
        constexpr std::int64_t kMaxSaneDelayMs = 30000LL;
        constexpr int kMaxInflightResolves = 8;

        struct HostResolveHookState {
            std::mutex mutex;
            HostResolveCallback cb = nullptr;
            void* ctx = nullptr;
        };

        auto host_resolve_hook() noexcept -> HostResolveHookState& {
            static auto* state = new HostResolveHookState();
            return *state;
        }

        auto inflight_resolve_counter() noexcept -> std::atomic<int>& {
            static auto* counter = new std::atomic<int>(0);
            return *counter;
        }

        auto write_be32(std::uint8_t* dst, std::uint32_t v) noexcept -> void {
            encoding::write_be32(std::span<std::uint8_t, 4>(dst, 4), v);
        }

        auto read_be32(std::uint8_t const* src) noexcept -> std::uint32_t {
            return encoding::read_be32(std::span<std::uint8_t const, 4>(src, 4));
        }

        auto random_origin_timestamp(std::int64_t t1_ms) noexcept -> Timestamp {
            std::array<std::uint8_t, 8> rnd{};
            bool ok = false;
#if defined(__linux__)
            ssize_t n = -1;
            do { n = ::getrandom(rnd.data(), rnd.size(), 0); } while (n < 0 && errno == EINTR);
            ok = (n == static_cast<ssize_t>(rnd.size()));
#elif defined(__APPLE__)
            ::arc4random_buf(rnd.data(), rnd.size());
            ok = true;
#endif
            if (!ok) {
                try {
                    std::random_device rd;
                    std::uint32_t a = rd(), b = rd();
                    std::memcpy(rnd.data(), &a, 4);
                    std::memcpy(rnd.data() + 4, &b, 4);
                    ok = true;
                } catch (...) {}
            }
            if (!ok) {
                auto base = unix_ms_to_ntp(t1_ms);
                auto steady = static_cast<std::uint64_t>(std::chrono::steady_clock::now().time_since_epoch().count());
                base.fraction ^= static_cast<std::uint32_t>(steady ^ (steady >> 32));
                return base;
            }
            std::uint32_t sec = 0, frac = 0;
            std::memcpy(&sec, rnd.data(), 4);
            std::memcpy(&frac, rnd.data() + 4, 4);
            if (sec == 0) sec = 1;
            return Timestamp{sec, frac};
        }

        auto resolve_zone_id(std::string_view zone) noexcept -> std::uint32_t {
            if (zone.empty() || zone.find('\0') != std::string_view::npos) return 0;
            std::uint32_t numeric = 0;
            auto [end, ec] = std::from_chars(zone.data(), zone.data() + zone.size(), numeric);
            if (ec == std::errc{} && end == zone.data() + zone.size()) return numeric;
            if (zone.size() >= 64) return 0;
            std::array<char, 64> name{};
            std::ranges::copy(zone, name.begin());
            return static_cast<std::uint32_t>(::if_nametoindex(name.data()));
        }

        auto parse_literal_endpoint(std::string_view host, std::uint16_t port) noexcept -> std::optional<corosio::endpoint> {
            if (host.size() >= 2 && host.front() == '[' && host.back() == ']') {
                host.remove_prefix(1);
                host.remove_suffix(1);
            }
            std::string_view zone;
            if (auto pct = host.find('%'); pct != std::string_view::npos) {
                zone = host.substr(pct + 1);
                host = host.substr(0, pct);
            }
            auto ip = platform::parse_ip_address(host);
            if (!ip) return std::nullopt;
            if (ip->size == 4) {
                if (!zone.empty()) return std::nullopt;
                corosio::ipv4_address::bytes_type b{};
                std::copy_n(ip->bytes.begin(), 4, b.begin());
                return corosio::endpoint{corosio::ipv4_address(b), port};
            }
            std::uint32_t scope_id = 0;
            if (!zone.empty()) {
                scope_id = resolve_zone_id(zone);
                if (scope_id == 0) return std::nullopt;
            }
            return corosio::endpoint{corosio::ipv6_address(ip->bytes, scope_id), port};
        }

        auto os_resolve_host(std::string const& host, std::uint16_t port) -> std::vector<corosio::endpoint> {
            std::vector<corosio::endpoint> out;
            std::string port_str = std::to_string(port);
            addrinfo hints{};
            hints.ai_family = AF_UNSPEC;
            hints.ai_socktype = SOCK_DGRAM;
            addrinfo* res = nullptr;
            if (::getaddrinfo(host.c_str(), port_str.c_str(), &hints, &res) != 0 || !res) return out;
            utility::scope_exit free_res([res]() noexcept { ::freeaddrinfo(res); });
            for (addrinfo* rp = res; rp && out.size() < 8; rp = rp->ai_next) {
                corosio::endpoint ep{};
                if (rp->ai_family == AF_INET && rp->ai_addrlen >= static_cast<decltype(rp->ai_addrlen)>(sizeof(sockaddr_in))) {
                    sockaddr_in sa{};
                    std::memcpy(&sa, rp->ai_addr, sizeof(sa));
                    corosio::ipv4_address::bytes_type b{};
                    std::memcpy(b.data(), &sa.sin_addr, 4);
                    ep = {corosio::ipv4_address(b), port};
                } else if (rp->ai_family == AF_INET6 && rp->ai_addrlen >= static_cast<decltype(rp->ai_addrlen)>(sizeof(sockaddr_in6))) {
                    sockaddr_in6 sa{};
                    std::memcpy(&sa, rp->ai_addr, sizeof(sa));
                    corosio::ipv6_address::bytes_type b{};
                    std::memcpy(b.data(), &sa.sin6_addr, 16);
                    ep = {corosio::ipv6_address(b, sa.sin6_scope_id), port};
                } else {
                    continue;
                }
                if (std::ranges::find(out, ep) == out.end()) out.push_back(ep);
            }
            return out;
        }

        auto resolve_endpoints_async(std::string_view host, std::uint16_t port,
            std::chrono::steady_clock::time_point deadline, std::stop_token stop)
            -> capy::task<std::expected<std::vector<corosio::endpoint>, SntpError>> {
            if (auto literal = parse_literal_endpoint(host, port)) {
                co_return std::vector<corosio::endpoint>{*literal};
            }
            if (stop.stop_requested()) co_return std::unexpected(SntpError::timeout);
            if (std::chrono::steady_clock::now() >= deadline) co_return std::unexpected(SntpError::timeout);

            HostResolveCallback custom_cb = nullptr;
            void* custom_ctx = nullptr;
            {
                std::lock_guard lk(host_resolve_hook().mutex);
                custom_cb = host_resolve_hook().cb;
                custom_ctx = host_resolve_hook().ctx;
            }

            auto& inflight = inflight_resolve_counter();
            int prev = inflight.fetch_add(1, std::memory_order_acq_rel);
            if (prev >= kMaxInflightResolves) {
                inflight.fetch_sub(1, std::memory_order_acq_rel);
                co_return std::unexpected(SntpError::io_error);
            }

            struct ResolveState {
                std::mutex mutex;
                std::vector<corosio::endpoint> endpoints;
                bool done = false;
                std::stop_source wake;
            };
            auto state = std::make_shared<ResolveState>();
            std::stop_callback forward_stop(stop, [state]() noexcept { state->wake.request_stop(); });

            try {
                std::thread([state, host_str = std::string(host), port, custom_cb, custom_ctx]() noexcept {
                    utility::scope_exit dec([]() noexcept {
                        inflight_resolve_counter().fetch_sub(1, std::memory_order_acq_rel);
                    });
                    std::vector<corosio::endpoint> resolved;
                    try {
                        resolved = custom_cb ? custom_cb(host_str, port, custom_ctx) : os_resolve_host(host_str, port);
                    } catch (...) {}
                    {
                        std::lock_guard lk(state->mutex);
                        state->endpoints = std::move(resolved);
                        state->done = true;
                    }
                    state->wake.request_stop();
                }).detach();
            } catch (...) {
                inflight.fetch_sub(1, std::memory_order_acq_rel);
                co_return std::unexpected(SntpError::io_error);
            }

            auto wait_until = [](std::chrono::steady_clock::time_point dl) -> capy::task<void> {
                (void)co_await corosio::delay(dl);
            };
            co_await capy::run(state->wake.get_token())(wait_until(deadline));

            if (stop.stop_requested()) co_return std::unexpected(SntpError::timeout);
            std::lock_guard lk(state->mutex);
            if (!state->done) co_return std::unexpected(SntpError::timeout);
            if (state->endpoints.empty()) co_return std::unexpected(SntpError::io_error);
            if (state->endpoints.size() > 8) state->endpoints.resize(8);
            co_return std::move(state->endpoints);
        }
    }

    auto set_host_resolve_callback(HostResolveCallback cb, void* ctx) noexcept -> void {
        std::lock_guard lk(host_resolve_hook().mutex);
        host_resolve_hook().cb = cb;
        host_resolve_hook().ctx = ctx;
    }

    auto unix_ms_to_ntp(std::int64_t unix_ms) noexcept -> Timestamp {
        std::int64_t secs = unix_ms / 1000;
        std::int64_t ms = unix_ms % 1000;
        if (ms < 0) { ms += 1000; --secs; }
        auto ntp_sec = static_cast<std::uint32_t>(static_cast<std::uint64_t>(secs) + ntp_unix_epoch_delta);
        auto ntp_frac = static_cast<std::uint32_t>((static_cast<std::uint64_t>(ms) << 32) / 1000ULL);
        return {ntp_sec, ntp_frac};
    }

    auto ntp_to_unix_ms(Timestamp ts) noexcept -> std::int64_t {
        std::int64_t secs = static_cast<std::int64_t>(static_cast<std::uint64_t>(ts.seconds) - ntp_unix_epoch_delta);
        std::int64_t ms = static_cast<std::int64_t>((static_cast<std::uint64_t>(ts.fraction) * 1000ULL) >> 32);
        return secs * 1000 + ms;
    }

    auto encode_request(Timestamp transmit_ts) noexcept -> std::array<std::uint8_t, packet_size> {
        std::array<std::uint8_t, packet_size> out{};
        // LI = 0, VN = 4, Mode = 3 (client) => 0x23
        out[0] = 0x23;
        write_be32(out.data() + 40, transmit_ts.seconds);
        write_be32(out.data() + 44, transmit_ts.fraction);
        return out;
    }

    auto decode_response(
        std::span<std::uint8_t const> packet,
        Timestamp expected_origin,
        std::int64_t t1_unix_ms,
        std::int64_t t4_unix_ms) noexcept -> std::expected<SyncSample, SntpError> {
        if (packet.size() < packet_size) return std::unexpected(SntpError::invalid_length);
        auto li = (packet[0] >> 6) & 0x03u;
        auto vn = (packet[0] >> 3) & 0x07u;
        auto mode = packet[0] & 0x07u;
        auto stratum = packet[1];
        if (vn < 3 || vn > 4) return std::unexpected(SntpError::invalid_version);
        if (mode != 4 && mode != 5) return std::unexpected(SntpError::invalid_mode);
        if (li == 3) return std::unexpected(SntpError::unsynchronized);
        if (stratum == 0) return std::unexpected(SntpError::kiss_of_death);
        if (stratum > 15) return std::unexpected(SntpError::unsynchronized);

        Timestamp origin{read_be32(packet.data() + 24), read_be32(packet.data() + 28)};
        if (origin != expected_origin) return std::unexpected(SntpError::origin_mismatch);

        Timestamp rx{read_be32(packet.data() + 32), read_be32(packet.data() + 36)};
        Timestamp tx{read_be32(packet.data() + 40), read_be32(packet.data() + 44)};
        if (rx.seconds == 0 || tx.seconds == 0) return std::unexpected(SntpError::unsynchronized);

        constexpr std::int64_t kMaxSaneUnixMs = 1'000'000'000'000'000LL;
        if (t1_unix_ms < -kMaxSaneUnixMs || t1_unix_ms > kMaxSaneUnixMs ||
            t4_unix_ms < -kMaxSaneUnixMs || t4_unix_ms > kMaxSaneUnixMs)
            return std::unexpected(SntpError::unsynchronized);
        auto t2 = ntp_to_unix_ms(rx);
        auto t3 = ntp_to_unix_ms(tx);
        std::int64_t offset = ((t2 - t1_unix_ms) + (t3 - t4_unix_ms)) / 2;
        std::int64_t delay = (t4_unix_ms - t1_unix_ms) - (t3 - t2);
        if (offset < -kMaxSaneOffsetMs || offset > kMaxSaneOffsetMs ||
            delay < kMinSaneDelayMs || delay > kMaxSaneDelayMs)
            return std::unexpected(SntpError::unsynchronized);
        return SyncSample{offset, delay, stratum};
    }

    auto sync_once_async(corosio::io_context& io, std::string_view host, std::uint16_t port,
        std::uint32_t timeout_ms, std::stop_token stop)
        -> capy::task<std::expected<SyncSample, SntpError>> {
        using Clock = std::chrono::steady_clock;
        if (stop.stop_requested()) co_return std::unexpected(SntpError::timeout);
        if (host.empty() || !port || !timeout_ms) co_return std::unexpected(SntpError::io_error);

        // Unified deadline covers both hostname resolution and UDP exchange.
        auto const total_deadline = Clock::now() +
            std::chrono::milliseconds(std::min<std::uint32_t>(timeout_ms, 30000));

        auto resolved = co_await resolve_endpoints_async(host, port, total_deadline, stop);
        if (!resolved) co_return std::unexpected(resolved.error());

        auto const& endpoints = *resolved;
        SntpError last_error = SntpError::io_error;
        for (std::size_t idx = 0; idx < endpoints.size(); ++idx) {
            if (stop.stop_requested()) co_return std::unexpected(SntpError::timeout);
            auto const now = Clock::now();
            if (now >= total_deadline) co_return std::unexpected(SntpError::timeout);
            auto const rem_total = std::chrono::duration_cast<std::chrono::milliseconds>(total_deadline - now).count();
            auto const left = static_cast<std::int64_t>(endpoints.size() - idx);
            auto const slice_ms = std::min<std::int64_t>(rem_total, std::max<std::int64_t>(rem_total / std::max<std::int64_t>(left, 1), 500));
            auto const attempt_deadline = std::min(total_deadline, now + std::chrono::milliseconds(slice_ms));

            auto const& ep = endpoints[idx];
            corosio::udp_socket sock(io);
            if (sock.open(ep.address().family())) { last_error = SntpError::io_error; continue; }
            utility::scope_exit close_sock([&]() noexcept { sock.close(); });
#if !defined(_WIN32)
            if (auto perr = platform::invoke_protect_fd(sock.native_handle()); perr)
                co_return std::unexpected(SntpError::io_error);
#endif
            auto const local = ep.is_v6()
                ? corosio::endpoint(corosio::ipv6_address::any(), 0)
                : corosio::endpoint(corosio::ipv4_address::any(), 0);
            if (sock.bind(local)) { last_error = SntpError::io_error; continue; }

            std::stop_callback cancel_sock(stop, [&]() noexcept { sock.cancel(); });
            if (stop.stop_requested()) co_return std::unexpected(SntpError::timeout);

            auto const t1_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();
            auto const origin = random_origin_timestamp(t1_ms);
            auto const req = encode_request(origin);

            auto [tx_ec, tx_n] = co_await corosio::timeout(
                sock.send_to(capy::const_buffer(req.data(), req.size()), ep), attempt_deadline);
            if (stop.stop_requested()) co_return std::unexpected(SntpError::timeout);
            if (tx_ec || tx_n != req.size()) {
                last_error = (capy::is_timeout(tx_ec) || Clock::now() >= attempt_deadline)
                    ? SntpError::timeout : SntpError::io_error;
                continue;
            }

            bool got_reply = false;
            std::array<std::uint8_t, 64> reply{};
            for (unsigned attempts = 0; attempts < 32; ++attempts) {
                if (stop.stop_requested()) co_return std::unexpected(SntpError::timeout);
                if (Clock::now() >= attempt_deadline) { last_error = SntpError::timeout; break; }
                corosio::endpoint from{};
                auto [rx_ec, rx_n] = co_await corosio::timeout(
                    sock.recv_from(capy::mutable_buffer(reply.data(), reply.size()), from), attempt_deadline);
                if (stop.stop_requested()) co_return std::unexpected(SntpError::timeout);
                if (rx_ec) {
                    last_error = (capy::is_timeout(rx_ec) || Clock::now() >= attempt_deadline)
                        ? SntpError::timeout : SntpError::io_error;
                    break;
                }
                if (from != ep) continue;
                auto const t4_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count();
                if (rx_n < packet_size) {
                    last_error = SntpError::invalid_length;
                    continue;
                }
                auto decoded = decode_response(std::span(reply).first(rx_n), origin, t1_ms, t4_ms);
                if (decoded) co_return *decoded;
                last_error = decoded.error();
                if (decoded.error() == SntpError::origin_mismatch) continue;
                got_reply = true;
                break;
            }
            if (got_reply && last_error == SntpError::kiss_of_death) continue;
        }
        co_return std::unexpected(last_error);
    }

    auto sync_once(std::string_view host, std::uint16_t port, std::uint32_t timeout_ms, std::stop_token stop)
        -> std::expected<SyncSample, SntpError> {
        if (stop.stop_requested()) return std::unexpected(SntpError::timeout);
        if (host.empty() || !port || !timeout_ms) return std::unexpected(SntpError::io_error);
        corosio::io_context io;
        std::expected<SyncSample, SntpError> result = std::unexpected(SntpError::io_error);
        auto run = [&]() -> capy::task<void> {
            result = co_await sync_once_async(io, host, port, timeout_ms, stop);
        };
        capy::run_async(io.get_executor(), stop, []() noexcept {},
            [&](std::exception_ptr) noexcept { result = std::unexpected(SntpError::io_error); })(run());
        io.run();
        return result;
    }

    auto global_calibrator() noexcept -> ClockCalibrator& {
        static ClockCalibrator instance;
        return instance;
    }
}
