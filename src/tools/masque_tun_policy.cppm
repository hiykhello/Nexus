export module cli.masque_tun_policy;
import std;
import masque.connect_ip;
import masque.ip_control;
import masque.ip_packet;
import packet;
import packet.tun_network_types;
import platform.ip_address;

export namespace cli::masque_tun {
    auto parse_route(std::string_view text) noexcept -> std::optional<packet::TunAddress> {
        auto slash = text.find('/');
        if (slash == text.npos) return {};
        auto ip = platform::parse_ip_address(text.substr(0, slash));
        unsigned bits = 0;
        auto [end, ec] = std::from_chars(text.data() + slash + 1, text.data() + text.size(), bits);
        if (!ip || ec != std::errc{} || end != text.data() + text.size() || !bits || bits > ip->size * 8) return {};
        packet::TunAddress route{static_cast<std::uint8_t>(ip->size == 4 ? 4 : 6), ip->bytes, static_cast<std::uint8_t>(bits)};
        if (!packet::tun_network_detail::valid(route, true)) return {};
        return route;
    }

    auto scope_view(masque::ConnectIpScope const& scope) noexcept -> masque::IpRequestScope {
        if (scope.kind == masque::IpTargetKind::any) return {{}, true, scope.protocol};
        return {std::span(&scope.prefix, 1), false, scope.protocol};
    }

    auto route_contains(packet::TunAddress const& network, packet::TunAddress const& host) noexcept -> bool {
        return packet::tun_network_detail::contains(network, host);
    }

    using Ip = std::array<std::uint8_t,16>;
    auto last_address(packet::TunAddress prefix) noexcept -> Ip {
        auto bytes = packet::tun_network_detail::ip_bytes(prefix.family);
        for (unsigned bit = prefix.prefix; bit < bytes * 8; ++bit)
            prefix.bytes[bit / 8] |= static_cast<std::uint8_t>(128 >> (bit % 8));
        return prefix.bytes;
    }

    // Exact CIDR cover of one intersection. The local prefix prevents a
    // default route and bounds every candidate before it reaches netlink.
    auto append_range(packet::TunNetworkOptions& options, std::uint8_t family, Ip first, Ip const& last) noexcept -> bool {
        auto width = packet::tun_network_detail::ip_bytes(family);
        while (first <= last) {
            packet::TunAddress route{family, first, static_cast<std::uint8_t>(width * 8)};
            while (route.prefix > 1) {
                auto wider = route;
                --wider.prefix;
                if (first[wider.prefix / 8] & (128 >> (wider.prefix % 8))) break;
                if (last_address(wider) > last) break;
                route = wider;
            }
            auto installed = std::span(options.routes).first(options.route_count);
            if (std::ranges::find(installed, route) == installed.end()) {
                if (options.route_count == options.routes.size()) return false;
                options.routes[options.route_count++] = route;
            }
            first = last_address(route);
            if (first == last) break;
            for (auto i = width; i && ++first[i - 1] == 0; --i) {}
        }
        return true;
    }

    auto snapshot(std::uint16_t mtu, std::span<const masque::AddressEntry> addresses,
                  std::span<const masque::RouteEntry> advertised, std::span<const packet::TunAddress> allowed,
                  masque::ConnectIpScope const& scope) noexcept -> std::optional<packet::TunNetworkOptions> {
        packet::TunNetworkOptions options{.mtu=mtu};
        for (auto const& entry : addresses) {
            if (masque::address_rejection(entry)) continue;
            packet::TunAddress address{entry.version, entry.address, entry.prefix_length};
            if (options.address_count == options.addresses.size() ||
                !packet::tun_network_detail::valid(address, false)) return {};
            options.addresses[options.address_count++] = address;
        }
        for (auto const& local : allowed) {
            auto configured = std::span(options.addresses).first(options.address_count);
            if (std::ranges::none_of(configured, [&](auto const& address) { return address.family == local.family; })) continue;
            for (auto const& remote : advertised) {
                if (local.family != remote.version ||
                    (scope.protocol && remote.protocol && *scope.protocol != remote.protocol)) continue;
                auto first = std::max(local.bytes, remote.first);
                auto last = std::min(last_address(local), remote.last);
                if (scope.kind == masque::IpTargetKind::prefix) {
                    if (scope.prefix.version != local.family) continue;
                    first = std::max(first, scope.prefix.address);
                    last = std::min(last, last_address({scope.prefix.version, scope.prefix.address, scope.prefix.prefix_length}));
                }
                if (!append_range(options, local.family, first, last)) return {};
            }
        }
        if (!packet::tun_network_detail::validate(options, true)) return {};
        return options;
    }

    auto permitted(masque::IpPacketView view, packet::TunNetworkOptions const& network,
                   std::span<const masque::RouteEntry> routes, masque::ConnectIpScope const& scope, bool inbound) noexcept -> bool {
        if (view.fragmented || view.routed || view.source_override || !view.hop_limit) return false;
        if (!masque::ip_matches_scope(view, scope_view(scope),
                inbound ? masque::IpScopeSide::source : masque::IpScopeSide::destination)) return false;
        if (inbound) std::swap(view.source, view.destination);
        auto const& remote = view.destination;
        if (view.version == 4) {
            if (!remote[0] || remote[0] == 127 || remote[0] >= 224 || (remote[0] == 169 && remote[1] == 254)) return false;
        } else if (remote[0] == 0xff || (remote[0] == 0xfe && (remote[1] & 0xc0) == 0x80) ||
                   (std::ranges::all_of(std::span(remote).first<15>(), [](auto byte) { return !byte; }) && remote[15] <= 1))
            return false;
        auto width = masque::ip_address_bytes(view.version);
        auto local = std::span(network.addresses).first(network.address_count);
        if (std::ranges::none_of(local, [&](auto const& address) {
                return address.family == view.version && address.bytes == view.source;
            })) return false;
        auto installed = std::span(network.routes).first(network.route_count);
        return std::ranges::any_of(installed, [&](auto const& route) {
            return route_contains(route, {view.version, view.destination, static_cast<std::uint8_t>(width * 8)});
        }) && masque::ip_destination_advertised(view, routes);
    }

    auto packet_too_big(masque::IpPacketView const& original, std::uint16_t mtu,
                        std::span<std::uint8_t,1280> buffer) noexcept -> std::span<std::uint8_t const> {
        bool v6 = original.version == 6;
        if (original.protocol == (v6 ? 58 : 1)) return {};
        if (!v6 && !(original.packet[6] & 0x40)) return {};
        auto header = v6 ? 40u : 20u;
        auto size = std::min<std::size_t>((v6 ? 1280 : 576) - header - 8, original.packet.size()) + header + 8;
        auto bytes = buffer.first(size);
        std::ranges::fill(bytes.first(header + 8), 0);
        std::ranges::copy(original.packet.first(size - header - 8), bytes.begin() + header + 8);
        auto write16 = [](std::span<std::uint8_t> destination, std::size_t offset, std::uint16_t value) {
            destination[offset] = static_cast<std::uint8_t>(value >> 8);
            destination[offset + 1] = static_cast<std::uint8_t>(value);
        };
        if (v6) {
            bytes[0] = 0x60;
            write16(bytes, 4, static_cast<std::uint16_t>(size - header));
            bytes[6] = 58;
            bytes[7] = 64;
            std::ranges::copy(original.destination, bytes.begin() + 8);
            std::ranges::copy(original.source, bytes.begin() + 24);
        } else {
            bytes[0] = 0x45;
            write16(bytes, 2, static_cast<std::uint16_t>(size));
            bytes[8] = 64;
            bytes[9] = 1;
            std::copy_n(original.destination.begin(), 4, bytes.begin() + 12);
            std::copy_n(original.source.begin(), 4, bytes.begin() + 16);
            write16(bytes, 10, packet::internet_checksum(bytes.first(header)));
        }
        auto icmp = bytes.subspan(header);
        icmp[0] = v6 ? 2 : 3;
        icmp[1] = v6 ? 0 : 4;
        write16(icmp, 6, mtu);
        auto checksum = packet::internet_checksum(icmp);
        if (v6) {
            auto address_sum = static_cast<std::uint16_t>(~packet::internet_checksum(bytes.subspan(8, 32)));
            std::uint32_t sum = static_cast<std::uint16_t>(~checksum) + address_sum + icmp.size() + 58;
            while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
            checksum = static_cast<std::uint16_t>(~sum);
        }
        write16(icmp, 2, checksum);
        return bytes;
    }
}
