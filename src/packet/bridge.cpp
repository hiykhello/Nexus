module packet.bridge;
import std;
import packet;

namespace packet::bridge {
    namespace {
        [[nodiscard]] auto is_link_local_v4(std::span<std::uint8_t const> pkt) noexcept -> bool {
            auto s0 = pkt[12], s1 = pkt[13], d0 = pkt[16], d1 = pkt[17];
            return (s0 == 169 && s1 == 254) || (d0 == 169 && d1 == 254);
        }

        [[nodiscard]] auto is_link_local_v6(std::span<std::uint8_t const> pkt) noexcept -> bool {
            auto const src_ll = pkt[8] == 0xfe && (pkt[9] & 0xc0) == 0x80;
            auto const dst_ll = pkt[24] == 0xfe && (pkt[25] & 0xc0) == 0x80;
            return src_ll || dst_ll;
        }
    }

    auto Layer3Bridge::forward(Direction dir, std::string_view ingress_if,
                               std::span<std::uint8_t const> pkt,
                               std::optional<std::array<std::uint8_t, 6>> src_mac)
        -> std::expected<packet::Bytes, ForwardError> {
        if ((dir == Direction::tun_to_phys && ingress_if == config_.physical_interface) ||
            (dir == Direction::phys_to_tun && ingress_if == config_.tun_interface)) {
            ++stats_.dropped_loop;
            return std::unexpected(ForwardError::loop_detected);
        }
        if (!config_.allowed_source_macs.empty()) {
            if (!src_mac || std::ranges::find(config_.allowed_source_macs, *src_mac) == config_.allowed_source_macs.end()) {
                ++stats_.dropped_filtered;
                return std::unexpected(ForwardError::filtered);
            }
        }
        if (pkt.empty()) return std::unexpected(ForwardError::truncated);
        if (pkt.size() > config_.mtu) {
            ++stats_.dropped_mtu;
            return std::unexpected(ForwardError::mtu_exceeded);
        }

        auto const version = static_cast<std::uint8_t>((pkt[0] >> 4) & 0x0f);
        if (version == 4) {
            if (!config_.allow_ipv4) {
                ++stats_.dropped_filtered;
                return std::unexpected(ForwardError::protocol_disabled);
            }
            if (pkt.size() < 20) return std::unexpected(ForwardError::truncated);
            std::size_t const ihl = static_cast<std::size_t>(pkt[0] & 0x0f) * 4;
            std::size_t const total = (static_cast<std::size_t>(pkt[2]) << 8) | pkt[3];
            if (ihl < 20 || ihl > pkt.size() || total < ihl || total > pkt.size()) {
                return std::unexpected(ForwardError::truncated);
            }
            if (config_.drop_link_local && is_link_local_v4(pkt)) {
                ++stats_.dropped_filtered;
                return std::unexpected(ForwardError::link_local_blocked);
            }
            if (pkt[8] <= 1) {
                ++stats_.dropped_ttl;
                return std::unexpected(ForwardError::ttl_expired);
            }
            packet::Bytes out(pkt.begin(), pkt.begin() + static_cast<std::ptrdiff_t>(total));
            out[8] = static_cast<std::uint8_t>(out[8] - 1);
            out[10] = 0;
            out[11] = 0;
            auto const sum = packet::internet_checksum(std::span(out).first(ihl));
            out[10] = static_cast<std::uint8_t>((sum >> 8) & 0xff);
            out[11] = static_cast<std::uint8_t>(sum & 0xff);
            ++stats_.forwarded_v4;
            return out;
        }
        if (version == 6) {
            if (!config_.allow_ipv6) {
                ++stats_.dropped_filtered;
                return std::unexpected(ForwardError::protocol_disabled);
            }
            if (pkt.size() < 40) return std::unexpected(ForwardError::truncated);
            if (config_.drop_link_local && is_link_local_v6(pkt)) {
                ++stats_.dropped_filtered;
                return std::unexpected(ForwardError::link_local_blocked);
            }
            if (pkt[7] <= 1) {
                ++stats_.dropped_ttl;
                return std::unexpected(ForwardError::ttl_expired);
            }
            packet::Bytes out(pkt.begin(), pkt.end());
            out[7] = static_cast<std::uint8_t>(out[7] - 1);
            ++stats_.forwarded_v6;
            return out;
        }
        return std::unexpected(ForwardError::invalid_version);
    }
}
