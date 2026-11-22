module;
#include <cerrno>
#include <sys/socket.h>
module platform.udp_batch;
import std;

namespace platform {
    namespace {
        auto last_error() noexcept -> std::error_code {
            return {errno, std::generic_category()};
        }

        auto gso_unsupported_error(int err) noexcept -> bool {
            return err == EIO || err == EINVAL || err == EOPNOTSUPP || err == ENOPROTOOPT || err == EMSGSIZE;
        }

        auto default_send_gso(int, sockaddr const*, socklen_t, std::span<std::uint8_t const>,
            std::uint16_t) noexcept -> int {
            return EOPNOTSUPP;
        }
    }

    auto recv_udp_batch(int fd, std::span<UdpRecvSlot> slots) noexcept
        -> std::expected<std::size_t, std::error_code> {
        if (fd < 0) return std::unexpected(std::make_error_code(std::errc::bad_file_descriptor));
        auto const count = std::min(slots.size(), kUdpBatchMax);
        if (count == 0) return std::size_t{0};

        std::size_t got = 0;
        for (; got < count; ++got) {
            slots[got].peer = {};
            slots[got].peer_len = sizeof(sockaddr_storage);
            auto r = ::recvfrom(fd, slots[got].data, slots[got].capacity, MSG_DONTWAIT | MSG_TRUNC,
                reinterpret_cast<sockaddr*>(&slots[got].peer), &slots[got].peer_len);
            if (r < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) break;
                if (got > 0) break;
                return std::unexpected(last_error());
            }
            slots[got].received = static_cast<std::size_t>(r);
            slots[got].truncated = slots[got].received > slots[got].capacity;
        }
        return got;
    }

    auto send_udp_batch(int fd, std::span<UdpSendSlot const> slots) noexcept
        -> std::expected<std::size_t, std::error_code> {
        if (fd < 0) return std::unexpected(std::make_error_code(std::errc::bad_file_descriptor));
        auto const count = std::min(slots.size(), kUdpBatchMax);
        if (count == 0) return std::size_t{0};

        std::size_t sent = 0;
        for (; sent < count; ++sent) {
            auto r = ::sendto(fd, slots[sent].data, slots[sent].size, MSG_DONTWAIT,
                slots[sent].peer, slots[sent].peer_len);
            if (r < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) break;
                if (sent > 0) break;
                return std::unexpected(last_error());
            }
        }
        return sent;
    }

    auto UdpGsoSender::send_segments(this UdpGsoSender& self, int fd, sockaddr const* peer, socklen_t peer_len,
        std::span<std::uint8_t const> payload, std::uint16_t segment_size,
        SendGsoFn custom_gso) noexcept -> std::expected<std::size_t, std::error_code> {
        if (fd < 0) return std::unexpected(std::make_error_code(std::errc::bad_file_descriptor));
        if (payload.empty()) return std::size_t{0};
        if (segment_size == 0) return std::unexpected(std::make_error_code(std::errc::invalid_argument));

        auto const seg_count = (payload.size() + segment_size - 1) / segment_size;
        if (self.gso_enabled_ && seg_count > 1 && seg_count <= 64) {
            auto fn = custom_gso ? custom_gso : default_send_gso;
            int err = fn(fd, peer, peer_len, payload, segment_size);
            if (err == 0) {
                ++self.gso_bursts_;
                return payload.size();
            }
            if (gso_unsupported_error(err)) {
                self.gso_enabled_ = false;
                ++self.fallback_bursts_;
            } else if (err == EAGAIN || err == EWOULDBLOCK) {
                return std::size_t{0};
            } else {
                return std::unexpected(std::error_code(err, std::generic_category()));
            }
        }

        std::size_t offset = 0;
        while (offset < payload.size()) {
            std::array<UdpSendSlot, kUdpBatchMax> batch{};
            std::size_t n = 0;
            std::size_t probe = offset;
            while (n < kUdpBatchMax && probe < payload.size()) {
                auto chunk = std::min<std::size_t>(segment_size, payload.size() - probe);
                batch[n++] = {peer, peer_len, payload.data() + probe, chunk};
                probe += chunk;
            }
            auto sent = send_udp_batch(fd, std::span(batch).first(n));
            if (!sent) return offset > 0 ? std::expected<std::size_t, std::error_code>(offset) : std::unexpected(sent.error());
            if (*sent == 0) break;
            for (std::size_t i = 0; i < *sent; ++i) offset += batch[i].size;
            if (*sent < n) break;
        }
        return offset;
    }
}
