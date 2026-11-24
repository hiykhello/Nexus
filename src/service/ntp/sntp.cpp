module;
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#if defined(__linux__)
#include <sys/random.h>
#elif defined(__APPLE__)
#include <cstdlib>
#endif
#include <sys/socket.h>
#include <unistd.h>

module ntp;
import std;
import encoding.endian;
import platform.socket_options;

namespace ntp {
    namespace {
        constexpr std::int64_t kMaxSaneOffsetMs = 3600LL * 1000;
        constexpr std::int64_t kMinSaneDelayMs = -5000LL;
        constexpr std::int64_t kMaxSaneDelayMs = 30000LL;

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

        auto same_peer_endpoint(sockaddr const* expected, socklen_t exp_len,
            sockaddr_storage const& actual, socklen_t act_len) noexcept -> bool {
            if (!expected || actual.ss_family != expected->sa_family) return false;
            if (expected->sa_family == AF_INET) {
                if (exp_len < static_cast<socklen_t>(sizeof(sockaddr_in)) ||
                    act_len < static_cast<socklen_t>(sizeof(sockaddr_in))) return false;
                sockaddr_in a{}, b{};
                std::memcpy(&a, expected, sizeof(a));
                std::memcpy(&b, &actual, sizeof(b));
                return a.sin_port == b.sin_port && a.sin_addr.s_addr == b.sin_addr.s_addr;
            }
            if (expected->sa_family == AF_INET6) {
                if (exp_len < static_cast<socklen_t>(sizeof(sockaddr_in6)) ||
                    act_len < static_cast<socklen_t>(sizeof(sockaddr_in6))) return false;
                sockaddr_in6 a{}, b{};
                std::memcpy(&a, expected, sizeof(a));
                std::memcpy(&b, &actual, sizeof(b));
                return a.sin6_port == b.sin6_port && std::memcmp(&a.sin6_addr, &b.sin6_addr, sizeof(in6_addr)) == 0;
            }
            return false;
        }
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
        // RFC 4330 Section 5 (t1..t4 bounded well below INT64_MAX/4 so arithmetic cannot overflow):
        // offset = ((T2 - T1) + (T3 - T4)) / 2
        // delay  = (T4 - T1) - (T3 - T2)
        std::int64_t offset = ((t2 - t1_unix_ms) + (t3 - t4_unix_ms)) / 2;
        std::int64_t delay = (t4_unix_ms - t1_unix_ms) - (t3 - t2);
        if (offset < -kMaxSaneOffsetMs || offset > kMaxSaneOffsetMs ||
            delay < kMinSaneDelayMs || delay > kMaxSaneDelayMs)
            return std::unexpected(SntpError::unsynchronized);
        return SyncSample{offset, delay, stratum};
    }

    auto sync_once(std::string_view host, std::uint16_t port, std::uint32_t timeout_ms, std::stop_token stop)
        -> std::expected<SyncSample, SntpError> {
        if (stop.stop_requested()) return std::unexpected(SntpError::timeout);
        if (host.empty() || !port || !timeout_ms) return std::unexpected(SntpError::io_error);
        std::string host_str(host);
        std::string port_str = std::to_string(port);
        addrinfo hints{};
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_DGRAM;
        addrinfo* res = nullptr;
        if (::getaddrinfo(host_str.c_str(), port_str.c_str(), &hints, &res) != 0 || !res)
            return std::unexpected(SntpError::io_error);
        struct AddrGuard { addrinfo* p; ~AddrGuard() { ::freeaddrinfo(p); } } ag{res};
        if (stop.stop_requested()) return std::unexpected(SntpError::timeout);

        std::size_t total_addrs = 0;
        for (addrinfo* rp = res; rp && total_addrs < 8; rp = rp->ai_next) ++total_addrs;
        auto total_deadline = std::chrono::steady_clock::now() +
            std::chrono::milliseconds(std::min<std::uint32_t>(timeout_ms, 30000));
        SntpError last_error = SntpError::io_error;
        std::size_t idx = 0;

        for (addrinfo* rp = res; rp && idx < 8; rp = rp->ai_next, ++idx) {
            if (stop.stop_requested()) return std::unexpected(SntpError::timeout);
            auto now = std::chrono::steady_clock::now();
            if (now >= total_deadline) return std::unexpected(SntpError::timeout);
            auto rem_total = std::chrono::duration_cast<std::chrono::milliseconds>(total_deadline - now).count();
            auto left = static_cast<std::int64_t>(total_addrs - idx);
            auto slice_ms = std::min<std::int64_t>(rem_total, std::max<std::int64_t>(rem_total / std::max<std::int64_t>(left, 1), 500));
            auto attempt_deadline = std::min(total_deadline, now + std::chrono::milliseconds(slice_ms));

#if defined(SOCK_CLOEXEC) && defined(SOCK_NONBLOCK)
            int fd = ::socket(rp->ai_family, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, rp->ai_protocol);
#else
            int fd = ::socket(rp->ai_family, SOCK_DGRAM, rp->ai_protocol);
            if (fd >= 0) {
                int fl = ::fcntl(fd, F_GETFL, 0);
                if (fl >= 0) (void)::fcntl(fd, F_SETFL, fl | O_NONBLOCK);
                (void)::fcntl(fd, F_SETFD, FD_CLOEXEC);
            }
#endif
            if (fd < 0) { last_error = SntpError::io_error; continue; }
            struct FdGuard { int f; ~FdGuard() { ::close(f); } } fg{fd};
            if (auto perr = platform::invoke_protect_fd(fd); perr)
                return std::unexpected(SntpError::io_error);

            auto t1_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();
            auto origin = random_origin_timestamp(t1_ms);
            auto req = encode_request(origin);
            ssize_t sent = -1;
            do {
                sent = ::sendto(fd, req.data(), req.size(), 0, rp->ai_addr, rp->ai_addrlen);
            } while (sent < 0 && errno == EINTR && !stop.stop_requested());
            if (sent != static_cast<ssize_t>(req.size())) {
                last_error = SntpError::io_error;
                continue;
            }

            bool got_reply = false;
            for (;;) {
                if (stop.stop_requested()) return std::unexpected(SntpError::timeout);
                auto rem = std::chrono::duration_cast<std::chrono::milliseconds>(
                    attempt_deadline - std::chrono::steady_clock::now()).count();
                if (rem <= 0) { last_error = SntpError::timeout; break; }
                pollfd pfd{fd, POLLIN, 0};
                auto ready = ::poll(&pfd, 1, static_cast<int>(std::min<std::int64_t>(rem, 50)));
                if (ready == 0) continue;
                if (ready < 0) {
                    if (errno == EINTR) continue;
                    last_error = SntpError::io_error;
                    break;
                }
                std::array<std::uint8_t, 64> reply{};
                sockaddr_storage from{};
                socklen_t from_len = sizeof(from);
                auto n = ::recvfrom(fd, reply.data(), reply.size(), 0, reinterpret_cast<sockaddr*>(&from), &from_len);
                if (n < 0) {
                    if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
                    last_error = SntpError::io_error;
                    break;
                }
                if (!same_peer_endpoint(rp->ai_addr, rp->ai_addrlen, from, from_len)) continue;
                auto t4_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count();
                if (n < static_cast<ssize_t>(packet_size)) {
                    last_error = SntpError::invalid_length;
                    continue;
                }
                auto decoded = decode_response(std::span(reply).first(static_cast<std::size_t>(n)), origin, t1_ms, t4_ms);
                if (decoded) return decoded;
                last_error = decoded.error();
                if (decoded.error() == SntpError::origin_mismatch) continue;
                got_reply = true;
                break;
            }
            if (got_reply && last_error == SntpError::kiss_of_death) continue;
        }
        return std::unexpected(last_error);
    }

    auto global_calibrator() noexcept -> ClockCalibrator& {
        static ClockCalibrator instance;
        return instance;
    }
}
