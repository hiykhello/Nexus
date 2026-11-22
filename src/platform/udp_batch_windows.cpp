module;
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <cerrno>
module platform.udp_batch;
import std;

namespace platform {
    namespace {
        auto last_error(int err) noexcept -> std::error_code {
            return {err, std::system_category()};
        }

        auto gso_unsupported_error(int err) noexcept -> bool {
            return err == EIO || err == EINVAL || err == EOPNOTSUPP || err == ENOPROTOOPT || err == EMSGSIZE ||
                err == WSAEOPNOTSUPP || err == WSAEINVAL || err == WSAEMSGSIZE;
        }

        auto default_send_gso(int, sockaddr const*, socklen_t, std::span<std::uint8_t const>,
            std::uint16_t) noexcept -> int {
            return WSAEOPNOTSUPP;
        }
    }

    auto recv_udp_batch(int fd, std::span<UdpRecvSlot> slots) noexcept
        -> std::expected<std::size_t, std::error_code> {
        if (fd < 0) return std::unexpected(std::make_error_code(std::errc::bad_file_descriptor));
        auto const count = std::min(slots.size(), kUdpBatchMax);
        if (count == 0) return std::size_t{0};

        SOCKET s = static_cast<SOCKET>(fd);
        std::size_t got = 0;
        for (; got < count; ++got) {
            slots[got].peer = {};
            slots[got].peer_len = static_cast<socklen_t>(sizeof(sockaddr_storage));
            slots[got].received = 0;
            slots[got].truncated = false;
            int r = ::recvfrom(s, reinterpret_cast<char*>(slots[got].data), static_cast<int>(slots[got].capacity), 0,
                reinterpret_cast<sockaddr*>(&slots[got].peer), &slots[got].peer_len);
            if (r < 0) {
                int err = ::WSAGetLastError();
                if (err == WSAEWOULDBLOCK || err == WSAEINTR) break;
                if (err == WSAEMSGSIZE) {
                    slots[got].received = slots[got].capacity;
                    slots[got].truncated = true;
                    continue;
                }
                if (got > 0) break;
                return std::unexpected(last_error(err));
            }
            slots[got].received = static_cast<std::size_t>(r);
        }
        return got;
    }

    auto send_udp_batch(int fd, std::span<UdpSendSlot const> slots) noexcept
        -> std::expected<std::size_t, std::error_code> {
        if (fd < 0) return std::unexpected(std::make_error_code(std::errc::bad_file_descriptor));
        auto const count = std::min(slots.size(), kUdpBatchMax);
        if (count == 0) return std::size_t{0};

        SOCKET s = static_cast<SOCKET>(fd);
        std::size_t sent = 0;
        for (; sent < count; ++sent) {
            int r = ::sendto(s, reinterpret_cast<char const*>(slots[sent].data), static_cast<int>(slots[sent].size), 0,
                slots[sent].peer, slots[sent].peer_len);
            if (r < 0) {
                int err = ::WSAGetLastError();
                if (err == WSAEWOULDBLOCK || err == WSAEINTR) break;
                if (sent > 0) break;
                return std::unexpected(last_error(err));
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
            } else if (err == EAGAIN || err == EWOULDBLOCK || err == WSAEWOULDBLOCK) {
                return std::size_t{0};
            } else {
                return std::unexpected(last_error(err));
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
