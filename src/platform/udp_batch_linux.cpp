module;
#include <cerrno>
#include <cstring>
#include <netinet/in.h>
#include <netinet/udp.h>
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

        auto default_send_gso(int fd, sockaddr const* peer, socklen_t peer_len,
            std::span<std::uint8_t const> payload, std::uint16_t segment_size) noexcept -> int {
#if defined(UDP_SEGMENT) && defined(SOL_UDP)
            iovec iov{const_cast<std::uint8_t*>(payload.data()), payload.size()};
            alignas(cmsghdr) std::array<char, CMSG_SPACE(sizeof(std::uint16_t))> ctrl{};
            msghdr msg{};
            msg.msg_name = const_cast<sockaddr*>(peer);
            msg.msg_namelen = peer_len;
            msg.msg_iov = &iov;
            msg.msg_iovlen = 1;
            msg.msg_control = ctrl.data();
            msg.msg_controllen = ctrl.size();
            auto* cmsg = CMSG_FIRSTHDR(&msg);
            cmsg->cmsg_level = SOL_UDP;
            cmsg->cmsg_type = UDP_SEGMENT;
            cmsg->cmsg_len = CMSG_LEN(sizeof(std::uint16_t));
            std::memcpy(CMSG_DATA(cmsg), &segment_size, sizeof(segment_size));
            ssize_t sent = 0;
            do {
                sent = ::sendmsg(fd, &msg, MSG_DONTWAIT | MSG_NOSIGNAL);
            } while (sent < 0 && errno == EINTR);
            return sent >= 0 ? 0 : errno;
#else
            (void)fd; (void)peer; (void)peer_len; (void)payload; (void)segment_size;
            return EOPNOTSUPP;
#endif
        }
    }

    auto recv_udp_batch(int fd, std::span<UdpRecvSlot> slots) noexcept
        -> std::expected<std::size_t, std::error_code> {
        if (fd < 0) return std::unexpected(std::make_error_code(std::errc::bad_file_descriptor));
        auto const count = std::min(slots.size(), kUdpBatchMax);
        if (count == 0) return std::size_t{0};

        std::array<mmsghdr, kUdpBatchMax> msgs{};
        std::array<iovec, kUdpBatchMax> iovs{};
        for (std::size_t i = 0; i < count; ++i) {
            slots[i].peer = {};
            slots[i].peer_len = sizeof(sockaddr_storage);
            slots[i].received = 0;
            slots[i].truncated = false;
            iovs[i] = {slots[i].data, slots[i].capacity};
            msgs[i].msg_hdr.msg_name = &slots[i].peer;
            msgs[i].msg_hdr.msg_namelen = sizeof(sockaddr_storage);
            msgs[i].msg_hdr.msg_iov = &iovs[i];
            msgs[i].msg_hdr.msg_iovlen = 1;
        }
        int n = 0;
        do {
            n = ::recvmmsg(fd, msgs.data(), static_cast<unsigned int>(count), MSG_DONTWAIT | MSG_TRUNC, nullptr);
        } while (n < 0 && errno == EINTR);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) return std::size_t{0};
            return std::unexpected(last_error());
        }
        auto const got = static_cast<std::size_t>(n);
        for (std::size_t i = 0; i < got; ++i) {
            slots[i].peer_len = msgs[i].msg_hdr.msg_namelen;
            slots[i].received = msgs[i].msg_len;
            slots[i].truncated = (msgs[i].msg_hdr.msg_flags & MSG_TRUNC) != 0 || slots[i].received > slots[i].capacity;
        }
        return got;
    }

    auto send_udp_batch(int fd, std::span<UdpSendSlot const> slots) noexcept
        -> std::expected<std::size_t, std::error_code> {
        if (fd < 0) return std::unexpected(std::make_error_code(std::errc::bad_file_descriptor));
        auto const count = std::min(slots.size(), kUdpBatchMax);
        if (count == 0) return std::size_t{0};

        std::array<mmsghdr, kUdpBatchMax> msgs{};
        std::array<iovec, kUdpBatchMax> iovs{};
        for (std::size_t i = 0; i < count; ++i) {
            iovs[i] = {const_cast<std::uint8_t*>(slots[i].data), slots[i].size};
            msgs[i].msg_hdr.msg_name = const_cast<sockaddr*>(slots[i].peer);
            msgs[i].msg_hdr.msg_namelen = slots[i].peer_len;
            msgs[i].msg_hdr.msg_iov = &iovs[i];
            msgs[i].msg_hdr.msg_iovlen = 1;
        }
        int n = 0;
        do {
            n = ::sendmmsg(fd, msgs.data(), static_cast<unsigned int>(count), MSG_DONTWAIT | MSG_NOSIGNAL);
        } while (n < 0 && errno == EINTR);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) return std::size_t{0};
            return std::unexpected(last_error());
        }
        return static_cast<std::size_t>(n);
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
