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
            std::size_t const payload_len = (static_cast<std::size_t>(pkt[4]) << 8) | pkt[5];
            if (payload_len > pkt.size() - 40) return std::unexpected(ForwardError::truncated);
            if (config_.drop_link_local && is_link_local_v6(pkt)) {
                ++stats_.dropped_filtered;
                return std::unexpected(ForwardError::link_local_blocked);
            }
            if (pkt[7] <= 1) {
                ++stats_.dropped_ttl;
                return std::unexpected(ForwardError::ttl_expired);
            }
            packet::Bytes out(pkt.begin(), pkt.begin() + static_cast<std::ptrdiff_t>(40 + payload_len));
            out[7] = static_cast<std::uint8_t>(out[7] - 1);
            ++stats_.forwarded_v6;
            return out;
        }
        return std::unexpected(ForwardError::invalid_version);
    }

    namespace {
        [[nodiscard]] auto non_zero_mac(MacAddress const& mac) noexcept -> bool {
            return std::ranges::any_of(mac, [](std::uint8_t b) { return b != 0; });
        }

        [[nodiscard]] auto prefix_matches(std::span<std::uint8_t const> dst, std::span<std::uint8_t const> net,
                                          std::uint8_t prefix) noexcept -> bool {
            std::size_t const bits = dst.size() * 8;
            if (prefix > bits) return false;
            std::size_t const full = prefix / 8;
            std::size_t const rem = prefix % 8;
            for (std::size_t i = 0; i < full; ++i)
                if (dst[i] != net[i]) return false;
            if (rem != 0) {
                auto const mask = static_cast<std::uint8_t>(0xffu << (8u - rem));
                if ((dst[full] & mask) != (net[full] & mask)) return false;
            }
            return true;
        }

        [[nodiscard]] auto lookup_neighbor(std::uint8_t family, std::span<std::uint8_t const> ip,
                                           std::span<NeighborEntry const> neighbors) noexcept
            -> std::optional<MacAddress> {
            for (auto const& n : neighbors) {
                if (n.family != family || !non_zero_mac(n.mac)) continue;
                if (std::ranges::equal(ip, std::span(n.address).first(ip.size()))) return n.mac;
            }
            return std::nullopt;
        }

        [[nodiscard]] auto resolve_unicast_mac(std::uint8_t family, std::span<std::uint8_t const> dst,
                                               std::span<RouteHint const> routes,
                                               std::span<NeighborEntry const> neighbors) noexcept
            -> std::optional<MacAddress> {
            RouteHint const* best = nullptr;
            for (auto const& r : routes) {
                if (r.family != family) continue;
                if (!prefix_matches(dst, std::span(r.destination).first(dst.size()), r.prefix)) continue;
                if (!best || r.prefix > best->prefix || (r.prefix == best->prefix && r.priority < best->priority))
                    best = &r;
            }
            if (best && best->gateway)
                return lookup_neighbor(family, std::span(*best->gateway).first(dst.size()), neighbors);
            return lookup_neighbor(family, dst, neighbors);
        }
    }

    auto resolve_destination_mac(std::span<std::uint8_t const> pkt,
                                 std::span<RouteHint const> routes,
                                 std::span<NeighborEntry const> neighbors) noexcept
        -> std::optional<MacAddress> {
        if (pkt.empty()) return std::nullopt;
        auto const ver = static_cast<std::uint8_t>((pkt[0] >> 4) & 0x0f);
        if (ver == 4) {
            if (pkt.size() < 20) return std::nullopt;
            auto dst = pkt.subspan(16, 4);
            if (dst[0] == 255 && dst[1] == 255 && dst[2] == 255 && dst[3] == 255)
                return MacAddress{0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
            if ((dst[0] & 0xf0u) == 0xe0u)
                return MacAddress{0x01, 0x00, 0x5e, static_cast<std::uint8_t>(dst[1] & 0x7fu), dst[2], dst[3]};
            return resolve_unicast_mac(4, dst, routes, neighbors);
        }
        if (ver == 6) {
            if (pkt.size() < 40) return std::nullopt;
            auto dst = pkt.subspan(24, 16);
            if (dst[0] == 0xffu)
                return MacAddress{0x33, 0x33, dst[12], dst[13], dst[14], dst[15]};
            return resolve_unicast_mac(6, dst, routes, neighbors);
        }
        return std::nullopt;
    }
}
