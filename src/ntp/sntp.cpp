module;
#include <cerrno>
#include <cstring>
#include <netdb.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

module ntp;
import std;

namespace ntp {
    namespace {
        auto write_be32(std::uint8_t* dst, std::uint32_t v) noexcept -> void {
            dst[0] = static_cast<std::uint8_t>(v >> 24);
            dst[1] = static_cast<std::uint8_t>(v >> 16);
            dst[2] = static_cast<std::uint8_t>(v >> 8);
            dst[3] = static_cast<std::uint8_t>(v);
        }

        auto read_be32(std::uint8_t const* src) noexcept -> std::uint32_t {
            return (std::uint32_t{src[0]} << 24) | (std::uint32_t{src[1]} << 16) |
                (std::uint32_t{src[2]} << 8) | std::uint32_t{src[3]};
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

        auto t2 = ntp_to_unix_ms(rx);
        auto t3 = ntp_to_unix_ms(tx);
        // RFC 4330 Section 5:
        // offset = ((T2 - T1) + (T3 - T4)) / 2
        // delay  = (T4 - T1) - (T3 - T2)
        std::int64_t offset = ((t2 - t1_unix_ms) + (t3 - t4_unix_ms)) / 2;
        std::int64_t delay = (t4_unix_ms - t1_unix_ms) - (t3 - t2);
        return SyncSample{offset, delay, stratum};
    }

    auto sync_once(std::string_view host, std::uint16_t port, std::uint32_t timeout_ms)
        -> std::expected<SyncSample, SntpError> {
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

        int fd = ::socket(res->ai_family, SOCK_DGRAM | SOCK_CLOEXEC, 0);
        if (fd < 0) return std::unexpected(SntpError::io_error);
        struct FdGuard { int f; ~FdGuard() { ::close(f); } } fg{fd};

        auto t1_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        auto origin = unix_ms_to_ntp(t1_ms);
        auto req = encode_request(origin);
        if (::sendto(fd, req.data(), req.size(), 0, res->ai_addr, res->ai_addrlen) != static_cast<ssize_t>(req.size()))
            return std::unexpected(SntpError::io_error);

        pollfd pfd{fd, POLLIN, 0};
        auto ready = ::poll(&pfd, 1, static_cast<int>(std::min<std::uint32_t>(timeout_ms, 30000)));
        if (ready == 0) return std::unexpected(SntpError::timeout);
        if (ready < 0) return std::unexpected(SntpError::io_error);

        std::array<std::uint8_t, 64> reply{};
        auto n = ::recv(fd, reply.data(), reply.size(), 0);
        if (n < static_cast<ssize_t>(packet_size)) return std::unexpected(SntpError::invalid_length);
        auto t4_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        return decode_response(std::span(reply).first(static_cast<std::size_t>(n)), origin, t1_ms, t4_ms);
    }

    auto global_calibrator() noexcept -> ClockCalibrator& {
        static ClockCalibrator instance;
        return instance;
    }
}
