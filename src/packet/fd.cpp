module;
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <sys/uio.h>
#include <unistd.h>
module packet.fd;
import std;

namespace packet {
    static_assert(requires { static_cast<decltype(&fd_detail::abi::read)>(&::read); });
    static_assert(requires { static_cast<decltype(&fd_detail::abi::write)>(&::write); });
    static_assert(requires { static_cast<decltype(&fd_detail::abi::fcntl)>(&::fcntl); });
    static_assert(requires { static_cast<int* (*)()>(&::__errno_location); });
    static_assert(F_GETFL==fd_detail::abi::get_flags && O_NONBLOCK==fd_detail::abi::nonblocking);
    static_assert(EAGAIN==std::to_underlying(std::errc::resource_unavailable_try_again) && EWOULDBLOCK==std::to_underlying(std::errc::operation_would_block) && EINTR==std::to_underlying(std::errc::interrupted));
    namespace {
        struct VirtioNetHdr {
            std::uint8_t flags = 0;
            std::uint8_t gso_type = 0;
            std::uint16_t hdr_len = 0;
            std::uint16_t gso_size = 0;
            std::uint16_t csum_start = 0;
            std::uint16_t csum_offset = 0;
        };
        static_assert(sizeof(VirtioNetHdr) == 10);
        constexpr std::uint8_t kVnetNeedsCsum = 1;
        constexpr std::uint8_t kVnetGsoNone = 0;
        constexpr std::uint8_t kVnetGsoTcpV4 = 1;
        constexpr std::uint8_t kVnetGsoTcpV6 = 4;
        constexpr std::uint8_t kVnetGsoUdpL4 = 5;
        constexpr std::uint8_t kVnetGsoEcn = 0x80;
        struct MemoryDevice {
            using Packet=QueuedPacket;
            using Failure=DeviceError;
            MemoryLink& link;
            FdPump::OutputValidator validator;
            void* context;
            auto receive_packet() -> std::expected<std::optional<Packet>,Failure> { return link.receive_packet(Side::first); }
            auto send(std::span<std::uint8_t const> packet) -> std::expected<void,Failure> { return link.send(Side::first,packet); }
            static auto packet_bytes(Packet const& packet) noexcept -> std::span<std::uint8_t const> { return packet.bytes; }
            static auto retryable(Failure failure) noexcept -> bool { return failure==DeviceError::queue_full; }
            auto valid_output(Packet const& packet) const noexcept -> bool {
                return (!packet.generation || packet.generation->valid) && (!validator || validator(context,packet));
            }
        };

        auto csum_add(std::uint32_t sum, std::span<std::uint8_t const> data) noexcept -> std::uint32_t {
            for (std::size_t i = 0; i + 1 < data.size(); i += 2)
                sum += (std::uint32_t(data[i]) << 8) | data[i + 1];
            if (data.size() & 1u) sum += std::uint32_t(data.back()) << 8;
            return sum;
        }
        auto csum_fold(std::uint32_t sum) noexcept -> std::uint16_t {
            while (sum >> 16) sum = (sum & 0xffffu) + (sum >> 16);
            return static_cast<std::uint16_t>(~sum);
        }
        auto be16(std::span<std::uint8_t const> p, std::size_t off) noexcept -> std::uint16_t {
            return static_cast<std::uint16_t>((std::uint16_t(p[off]) << 8) | p[off + 1]);
        }
        auto put_be16(std::span<std::uint8_t> p, std::size_t off, std::uint16_t v) noexcept -> void {
            p[off] = static_cast<std::uint8_t>(v >> 8);
            p[off + 1] = static_cast<std::uint8_t>(v & 0xffu);
        }
        auto be32(std::span<std::uint8_t const> p, std::size_t off) noexcept -> std::uint32_t {
            return (std::uint32_t(p[off]) << 24) | (std::uint32_t(p[off + 1]) << 16) |
                   (std::uint32_t(p[off + 2]) << 8) | p[off + 3];
        }
        auto put_be32(std::span<std::uint8_t> p, std::size_t off, std::uint32_t v) noexcept -> void {
            p[off] = static_cast<std::uint8_t>(v >> 24);
            p[off + 1] = static_cast<std::uint8_t>(v >> 16);
            p[off + 2] = static_cast<std::uint8_t>(v >> 8);
            p[off + 3] = static_cast<std::uint8_t>(v & 0xffu);
        }

        auto complete_partial_csum(std::span<std::uint8_t> pkt, std::uint16_t start, std::uint16_t offset) noexcept -> void {
            if (start >= pkt.size() || std::size_t(start) + offset + 2 > pkt.size()) return;
            // In Linux virtio_net_hdr NEEDS_CSUM, the field at start+offset already holds the
            // un-complemented pseudo-header sum; clear it before summing or fold directly.
            std::uint16_t seed = be16(pkt, start + offset);
            put_be16(pkt, start + offset, 0);
            std::uint32_t sum = seed;
            sum = csum_add(sum, pkt.subspan(start));
            std::uint16_t fin = csum_fold(sum);
            bool is_udp = (!pkt.empty() && (((pkt[0] >> 4) == 4 && pkt.size() >= 20 && pkt[9] == 17) ||
                ((pkt[0] >> 4) == 6 && pkt.size() >= 40 && pkt[6] == 17)));
            if (is_udp && fin == 0) fin = 0xffffu;
            put_be16(pkt, start + offset, fin);
        }

        auto l4_pseudo_sum(std::span<std::uint8_t const> pkt, bool v6, std::uint8_t proto, std::size_t l4_len) noexcept -> std::uint32_t {
            std::uint32_t sum = proto + static_cast<std::uint32_t>(l4_len);
            if (!v6) sum = csum_add(sum, pkt.subspan(12, 8));
            else sum = csum_add(sum, pkt.subspan(8, 32));
            return sum;
        }

        auto segment_vnet_rx(std::span<std::uint8_t> raw, std::size_t mtu, std::vector<Bytes>& out) -> bool {
            if (raw.size() <= sizeof(VirtioNetHdr)) return false;
            VirtioNetHdr hdr{};
            std::memcpy(&hdr, raw.data(), sizeof hdr);
            auto pkt = raw.subspan(sizeof hdr);
            if (pkt.size() < 20) return false;
            bool v4 = (pkt[0] >> 4) == 4, v6 = (pkt[0] >> 4) == 6;
            std::uint8_t gso = hdr.gso_type & static_cast<std::uint8_t>(~kVnetGsoEcn);
            if (v4) {
                std::size_t ip_hl = static_cast<std::size_t>((pkt[0] & 0x0fu) * 4u);
                std::size_t tot_len = be16(pkt, 2);
                if (ip_hl < 20 || tot_len < ip_hl || pkt.size() < tot_len) return false;
                pkt = pkt.first(tot_len);
            } else if (v6) {
                if (pkt.size() < 40) return false;
                std::size_t plen = be16(pkt, 4);
                if (plen > 0) {
                    if (pkt.size() < 40u + plen) return false;
                    pkt = pkt.first(40u + plen);
                } else if (gso == kVnetGsoNone || hdr.gso_size == 0) {
                    pkt = pkt.first(40u);
                }
            } else {
                return false;
            }
            if (gso == kVnetGsoNone || hdr.gso_size == 0) {
                if (pkt.size() > mtu) return false;
                if (hdr.flags & kVnetNeedsCsum)
                    complete_partial_csum(pkt, hdr.csum_start, hdr.csum_offset);
                out.emplace_back(pkt.begin(), pkt.end());
                return true;
            }
            std::size_t ip_hl = v4 ? static_cast<std::size_t>((pkt[0] & 0x0fu) * 4u) : std::size_t{40};
            std::uint8_t proto = v4 ? pkt[9] : pkt[6];
            bool is_tcp = (gso == kVnetGsoTcpV4 && v4 && proto == 6) ||
                          (gso == kVnetGsoTcpV6 && v6 && proto == 6);
            bool is_udp = (gso == kVnetGsoUdpL4 && proto == 17);
            if (!is_tcp && !is_udp) return false;
            std::size_t l4_hl = is_udp ? std::size_t{8} :
                (pkt.size() >= ip_hl + 20 ? static_cast<std::size_t>((pkt[ip_hl + 12] >> 4) * 4u) : std::size_t{0});
            if ((is_tcp && l4_hl < 20) || pkt.size() < ip_hl + l4_hl) return false;
            std::size_t hdr_total = ip_hl + l4_hl;
            if (hdr_total >= mtu) return false;
            std::size_t max_seg = std::min<std::size_t>(hdr.gso_size, mtu - hdr_total);
            if (!max_seg) return false;
            std::size_t data_len = pkt.size() - hdr_total;
            std::uint16_t base_id = v4 ? be16(pkt, 4) : std::uint16_t{0};
            std::uint32_t base_seq = is_tcp ? be32(pkt, ip_hl + 4) : 0u;
            std::size_t seg_idx = 0;
            for (std::size_t off = 0; off < data_len || (data_len == 0 && seg_idx == 0); off += max_seg, ++seg_idx) {
                std::size_t chunk = std::min(max_seg, data_len - off);
                bool last = (off + chunk >= data_len);
                Bytes seg(hdr_total + chunk);
                std::memcpy(seg.data(), pkt.data(), hdr_total);
                if (chunk) std::memcpy(seg.data() + hdr_total, pkt.data() + hdr_total + off, chunk);
                if (v4) {
                    put_be16(seg, 2, static_cast<std::uint16_t>(seg.size()));
                    put_be16(seg, 4, static_cast<std::uint16_t>(base_id + seg_idx));
                    put_be16(seg, 10, 0);
                    put_be16(seg, 10, csum_fold(csum_add(0, std::span(seg).first(ip_hl))));
                } else {
                    put_be16(seg, 4, static_cast<std::uint16_t>(l4_hl + chunk));
                }
                if (is_tcp) {
                    put_be32(seg, ip_hl + 4, static_cast<std::uint32_t>(base_seq + off));
                    if (!last) seg[ip_hl + 13] &= static_cast<std::uint8_t>(~0x09u); // clear FIN(0x01) & PSH(0x08)
                    if (seg_idx > 0) seg[ip_hl + 13] &= static_cast<std::uint8_t>(~0x80u); // clear CWR
                    put_be16(seg, ip_hl + 16, 0);
                    std::uint32_t ps = l4_pseudo_sum(seg, v6, 6, l4_hl + chunk);
                    put_be16(seg, ip_hl + 16, csum_fold(csum_add(ps, std::span(seg).subspan(ip_hl))));
                } else {
                    put_be16(seg, ip_hl + 4, static_cast<std::uint16_t>(l4_hl + chunk));
                    put_be16(seg, ip_hl + 6, 0);
                    std::uint32_t ps = l4_pseudo_sum(seg, v6, 17, l4_hl + chunk);
                    std::uint16_t ucsum = csum_fold(csum_add(ps, std::span(seg).subspan(ip_hl)));
                    put_be16(seg, ip_hl + 6, ucsum ? ucsum : std::uint16_t{0xffffu});
                }
                out.push_back(std::move(seg));
                if (last) break;
            }
            return true;
        }

        auto step_vnet_output(int fd, MemoryDevice& device, std::size_t mtu,
            std::optional<QueuedPacket>& output, FdStep& result) -> void {
            if (!output) {
                auto packet = device.receive_packet();
                if (!packet) result.output_error = FdFailure{packet.error()};
                else if (*packet) output = std::move(**packet);
            }
            if (output && !device.valid_output(*output)) { output.reset(); result.output_discarded = true; }
            if (!output) return;
            auto bytes = device.packet_bytes(*output);
            if (bytes.size() > mtu) { result.output_error = FdFailure{FdError::packet_too_large}; output.reset(); return; }
            static constexpr VirtioNetHdr kZeroHdr{};
            iovec iov[2]{
                {const_cast<VirtioNetHdr*>(&kZeroHdr), sizeof(kZeroHdr)},
                {const_cast<std::uint8_t*>(bytes.data()), bytes.size()}
            };
            auto count = ::writev(fd, iov, 2);
            if (count < 0) {
                auto error = fd_detail::system_error();
                if (fd_detail::temporary(error)) result.output_backpressured = true;
                else { result.output_error = FdFailure{error}; output.reset(); }
            } else if (static_cast<std::size_t>(count) != sizeof(kZeroHdr) + bytes.size()) {
                result.output_error = FdFailure{FdError::partial_write}; output.reset();
            } else {
                result.output_delivered = true;
                output.reset();
            }
        }
    }

    FdPump::FdPump(int fd, MemoryLink& link, std::size_t mtu, bool vnet_hdr)
        : fd_(fd), link_(&link), mtu_(mtu), vnet_hdr_(vnet_hdr),
          buffer_(vnet_hdr ? (65536 + 128 + sizeof(VirtioNetHdr)) : (mtu + 1)) {}
    FdPump::~FdPump()=default;
    FdPump::FdPump(FdPump&&) noexcept=default;
    auto FdPump::operator=(FdPump&&) noexcept -> FdPump& = default;
    auto FdPump::create(int fd, MemoryLink& link, std::size_t mtu, bool vnet_hdr) -> std::expected<FdPump,FdFailure> {
        auto checked=fd_detail::validate(fd,mtu,65535);
        if (!checked) return std::unexpected(fd_detail::convert<FdFailure>(checked.error()));
        return FdPump(fd,link,mtu,vnet_hdr);
    }
    auto FdPump::step(OutputValidator validator,void* context) -> FdStep {
        MemoryDevice device{*link_,validator,context};
        if (!vnet_hdr_) return fd_detail::step(fd_,device,mtu_,buffer_,input_size_,output_);
        FdStep result;
        step_vnet_output(fd_, device, mtu_, output_, result);
        if (pending_rx_head_ >= pending_rx_.size()) {
            pending_rx_.clear();
            pending_rx_head_ = 0;
            auto count = ::read(fd_, buffer_.data(), buffer_.size());
            if (count < 0) {
                auto error = fd_detail::system_error();
                if (!fd_detail::temporary(error)) result.input_error = FdFailure{error};
            } else if (!count) {
                result.input_error = FdFailure{FdError::end_of_file};
            } else if (!segment_vnet_rx(std::span(buffer_).first(static_cast<std::size_t>(count)), mtu_, pending_rx_)) {
                result.input_error = FdFailure{FdError::packet_too_large};
            } else {
                result.input = true;
            }
        }
        while (pending_rx_head_ < pending_rx_.size()) {
            try {
                auto sent = device.send(pending_rx_[pending_rx_head_]);
                if (sent) { result.input_delivered = true; ++pending_rx_head_; }
                else if (device.retryable(sent.error())) { result.input_backpressured = true; break; }
                else { result.input_error = FdFailure{sent.error()}; ++pending_rx_head_; break; }
            } catch (std::bad_alloc const&) { result.input_backpressured = true; break; }
        }
        if (pending_rx_head_ >= pending_rx_.size()) { pending_rx_.clear(); pending_rx_head_ = 0; }
        return result;
    }
    auto FdPump::step_output(OutputValidator validator,void* context) -> FdStep {
        MemoryDevice device{*link_,validator,context};
        FdStep result;
        if (!vnet_hdr_) fd_detail::step_output(fd_,device,mtu_,output_,result);
        else step_vnet_output(fd_,device,mtu_,output_,result);
        return result;
    }
}
