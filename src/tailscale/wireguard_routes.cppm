export module tailscale.wireguard_routes;
import std;
import tailscale.control_messages;
import tailscale.control;
import tailscale.map_session;
import tailscale.snapshot;
import net.udp_socket;
import packet.tun_network_types;
import wireguard.endpoint;

export namespace tailscale::wireguard_routes {
    using Wall = std::chrono::system_clock;
    namespace cm = control_messages;
    namespace pn = packet::tun_network_detail;

    enum class Error { unauthorized, conflict, limit, address };
    struct Peer {
        std::int64_t id = 0;
        wireguard::EndpointConfig settings;
        std::optional<std::chrono::sys_seconds> not_after;
        bool managed_path = false;
    };
    struct Plan {
        packet::TunNetworkOptions network;
        std::vector<Peer> peers;
        std::optional<std::chrono::sys_seconds> expires;
    };

    inline auto usable(snapshot::Peer const& peer, Wall::time_point now) noexcept -> bool {
        return peer.machine_authorized && !peer.expired &&
            (!peer.not_after || now < *peer.not_after);
    }

    namespace detail {
        inline auto prefix(cm::Prefix const& remote) noexcept -> packet::TunAddress {
            return {remote.family, remote.address, remote.bits};
        }

        inline auto host(packet::TunAddress const& address) noexcept -> bool {
            return address.prefix == pn::ip_bytes(address.family) * 8 && pn::valid(address, false);
        }

        inline auto covers(packet::TunAddress const& route, net::UdpEndpoint const& endpoint) noexcept -> bool {
            return pn::contains(route, {endpoint.family, endpoint.address,
                static_cast<std::uint8_t>(pn::ip_bytes(endpoint.family) * 8)});
        }

        inline auto expires_with(Plan& plan, std::optional<std::chrono::sys_seconds> expiry) noexcept -> void {
            if (expiry && (!plan.expires || *expiry < *plan.expires)) plan.expires = expiry;
        }

        inline auto add_route(Plan& plan, Peer& peer, packet::TunAddress const& route,
                               std::span<const net::UdpEndpoint> protected_endpoints) -> std::expected<void, Error> {
            auto addresses = std::span(plan.network.addresses).first(plan.network.address_count);
            if (std::ranges::none_of(addresses, [&](auto const& local) { return local.family == route.family; })) return {};
            if (std::ranges::any_of(addresses, [&](auto const& local) { return pn::contains(route, local); }) ||
                std::ranges::any_of(protected_endpoints, [&](auto const& remote) { return covers(route, remote); }))
                return std::unexpected(Error::conflict);
            auto routes = std::span(plan.network.routes).first(plan.network.route_count);
            if (std::ranges::find(routes, route) != routes.end()) return std::unexpected(Error::conflict);
            if (plan.network.route_count == plan.network.routes.size()) return std::unexpected(Error::limit);
            plan.network.routes[plan.network.route_count++] = route;
            peer.settings.allowed_ips.push_back({route.family, route.bytes, route.prefix});
            return {};
        }
    }

    [[nodiscard]] inline auto plan(map_session::State const& state, bool accept_routes, std::uint16_t mtu,
                                  std::span<const net::UdpEndpoint> protected_endpoints, Wall::time_point now,
                                  std::uint16_t relay_region = 0,
                                  std::function<std::optional<net::UdpEndpoint>(control::NodePublic const&)> discovery = {})
        -> std::expected<Plan, Error> {
        auto self = state.self();
        if (!self || !usable(*self, now)) return std::unexpected(Error::unauthorized);
        Plan result;
        result.network.mtu = mtu;
        detail::expires_with(result, self->not_after);
        for (auto const& address : self->addresses) {
            auto local = detail::prefix(address);
            if (!detail::host(local) || result.network.address_count == result.network.addresses.size() ||
                std::ranges::any_of(protected_endpoints, [&](auto const& remote) { return detail::covers(local, remote); }))
                return std::unexpected(Error::address);
            result.network.addresses[result.network.address_count++] = local;
        }
        if (!result.network.address_count) return std::unexpected(Error::address);

        // Outer destinations learned from the Map must stay reachable outside
        // the tunnel, including endpoints of peers selected in later entries.
        std::vector<net::UdpEndpoint> outer(protected_endpoints.begin(), protected_endpoints.end());
        for (auto const& remote : state.peers()) {
            if (!usable(remote, now)) continue;
            for (auto const& address : remote.endpoints) {
                auto candidate = net::UdpEndpoint{address.family, address.address, address.port};
                outer.push_back(candidate);
                auto local = std::span(result.network.addresses).first(result.network.address_count);
                if (std::ranges::any_of(local, [&](auto const& entry) { return detail::covers(entry, candidate); }))
                    return std::unexpected(Error::conflict);
            }
        }
        for (auto const& remote : state.peers()) {
            if (!usable(remote, now)) continue;
            std::optional<net::UdpEndpoint> direct;
            if (discovery) direct = discovery(remote.key);
            else if (!remote.endpoints.empty()) {
                auto const& endpoint = remote.endpoints.front();
                direct = net::UdpEndpoint{endpoint.family, endpoint.address, endpoint.port};
            }
            bool relay = !direct && relay_region && remote.home_derp == relay_region;
            if (!relay && !direct) continue;
            Peer peer;
            peer.id = remote.id;
            peer.settings.relay_only = relay;
            peer.settings.peer = direct;
            peer.settings.mtu = mtu;
            peer.not_after = remote.not_after;
            peer.managed_path = bool(discovery);
            std::ranges::copy(remote.key.view(), peer.settings.peer_public.begin());
            for (auto const& address : remote.allowed_ips) {
                auto route = detail::prefix(address);
                if (!pn::valid(route, true)) return std::unexpected(Error::address);
                bool peer_address = detail::host(route) && std::ranges::find(remote.addresses, address) != remote.addresses.end();
                if (!peer_address && !accept_routes) continue;
                auto added = detail::add_route(result, peer, route, outer);
                if (!added) return std::unexpected(added.error());
            }
            if (!peer.settings.allowed_ips.empty()) {
                detail::expires_with(result, peer.not_after);
                result.peers.push_back(std::move(peer));
            }
        }
        if (!pn::validate(result.network)) return std::unexpected(Error::address);
        return result;
    }
}
