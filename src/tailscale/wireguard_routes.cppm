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

    enum class Error { unauthorized, conflict, limit, address, exit_node_not_found };
    struct Peer {
        std::int64_t id = 0;
        wireguard::EndpointConfig settings;
        std::optional<std::chrono::sys_seconds> not_after;
        bool managed_path = false;
        bool is_exit_node = false;
    };
    struct Policy {
        bool accept_routes = false;
        std::optional<control::NodePublic> exit_node;
        std::string_view exit_node_name;
        std::optional<packet::TunAddress> exit_node_ip;
        bool exit_node_allow_lan_access = true;
        std::span<cm::Prefix const> advertise_routes{};
    };
    struct Plan {
        packet::TunNetworkOptions network;
        std::vector<Peer> peers;
        std::optional<std::chrono::sys_seconds> expires;
        std::optional<std::int64_t> exit_node_peer_id;
        std::vector<cm::Prefix> advertised_routes;
        std::vector<net::UdpEndpoint> bypass_endpoints;
        std::vector<cm::Prefix> lan_bypass_routes;
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

        inline auto is_default_route(cm::Prefix const& route) noexcept -> bool {
            return (route.family == 4 || route.family == 6) && route.bits == 0 &&
                std::ranges::all_of(route.address, [](auto b) { return b == 0; });
        }

        inline auto covers(packet::TunAddress const& route, net::UdpEndpoint const& endpoint) noexcept -> bool {
            return pn::contains(route, {endpoint.family, endpoint.address,
                static_cast<std::uint8_t>(pn::ip_bytes(endpoint.family) * 8)});
        }

        inline auto expires_with(Plan& plan, std::optional<std::chrono::sys_seconds> expiry) noexcept -> void {
            if (expiry && (!plan.expires || *expiry < *plan.expires)) plan.expires = expiry;
        }

        inline auto matches_exit_node(snapshot::Peer const& remote, Policy const& policy) noexcept -> bool {
            if (policy.exit_node) return remote.key == *policy.exit_node;
            if (policy.exit_node_ip) {
                for (auto const& addr : remote.addresses) {
                    if (addr.family == policy.exit_node_ip->family && addr.address == policy.exit_node_ip->bytes)
                        return true;
                }
            }
            if (!policy.exit_node_name.empty() && !remote.dns_name.empty()) {
                auto want = policy.exit_node_name;
                while (!want.empty() && want.back() == '.') want.remove_suffix(1);
                auto eq_icase = [](std::string_view a, std::string_view b) noexcept {
                    if (a.size() != b.size()) return false;
                    for (std::size_t i = 0; i < a.size(); ++i) {
                        auto ca = static_cast<unsigned char>(a[i]), cb = static_cast<unsigned char>(b[i]);
                        if (ca >= 'A' && ca <= 'Z') ca = static_cast<unsigned char>(ca - 'A' + 'a');
                        if (cb >= 'A' && cb <= 'Z') cb = static_cast<unsigned char>(cb - 'A' + 'a');
                        if (ca != cb) return false;
                    }
                    return true;
                };
                if (eq_icase(remote.dns_name, want)) return true;
                auto dot = remote.dns_name.find('.');
                if (dot != std::string::npos && eq_icase(std::string_view(remote.dns_name).substr(0, dot), want))
                    return true;
            }
            return false;
        }

        inline auto push_tun_route(Plan& plan, packet::TunAddress const& route) -> std::expected<void, Error> {
            auto routes = std::span(plan.network.routes).first(plan.network.route_count);
            if (std::ranges::find(routes, route) != routes.end()) return std::unexpected(Error::conflict);
            if (plan.network.route_count == plan.network.routes.size()) return std::unexpected(Error::limit);
            plan.network.routes[plan.network.route_count++] = route;
            return {};
        }

        inline auto add_route(Plan& plan, Peer& peer, packet::TunAddress const& route,
                              std::span<const net::UdpEndpoint> protected_endpoints) -> std::expected<void, Error> {
            auto addresses = std::span(plan.network.addresses).first(plan.network.address_count);
            if (std::ranges::none_of(addresses, [&](auto const& local) { return local.family == route.family; })) return {};
            if (std::ranges::any_of(addresses, [&](auto const& local) { return pn::contains(route, local); }) ||
                std::ranges::any_of(protected_endpoints, [&](auto const& remote) { return covers(route, remote); }))
                return std::unexpected(Error::conflict);
            if (auto pushed = push_tun_route(plan, route); !pushed) return pushed;
            peer.settings.allowed_ips.push_back({route.family, route.bytes, route.prefix});
            return {};
        }

        // Install an exit-node default route (0.0.0.0/0 or ::/0) using def1 /1
        // halves in TunNetworkOptions (keeping TunAddress::prefix >= 1 valid while
        // allowing host-specific bypass routes for control/DERP/outer endpoints)
        // and installing the canonical /0 prefix on the WireGuard peer AllowedIPs.
        inline auto add_exit_default_route(Plan& plan, Peer& peer, std::uint8_t family) -> std::expected<bool, Error> {
            auto addresses = std::span(plan.network.addresses).first(plan.network.address_count);
            if (std::ranges::none_of(addresses, [&](auto const& local) { return local.family == family; })) return false;
            packet::TunAddress lo{family, {}, 1};
            packet::TunAddress hi{family, {}, 1};
            hi.bytes[0] = 0x80;
            if (auto a = push_tun_route(plan, lo); !a) return std::unexpected(a.error());
            if (auto b = push_tun_route(plan, hi); !b) return std::unexpected(b.error());
            peer.settings.allowed_ips.push_back({family, {}, 0});
            return true;
        }

        inline auto append_lan_bypass_routes(Plan& plan) -> void {
            auto addresses = std::span(plan.network.addresses).first(plan.network.address_count);
            bool has_v4 = std::ranges::any_of(addresses, [](auto const& a) { return a.family == 4; });
            bool has_v6 = std::ranges::any_of(addresses, [](auto const& a) { return a.family == 6; });
            if (has_v4) {
                plan.lan_bypass_routes.push_back({{10, 0, 0, 0}, 4, 8});
                plan.lan_bypass_routes.push_back({{172, 16, 0, 0}, 4, 12});
                plan.lan_bypass_routes.push_back({{192, 168, 0, 0}, 4, 16});
                plan.lan_bypass_routes.push_back({{169, 254, 0, 0}, 4, 16});
            }
            if (has_v6) {
                plan.lan_bypass_routes.push_back({{0xfc, 0x00}, 6, 7});
                plan.lan_bypass_routes.push_back({{0xfe, 0x80}, 6, 10});
            }
        }
    }

    [[nodiscard]] inline auto plan(map_session::State const& state, Policy const& policy, std::uint16_t mtu,
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

        // Validate locally advertised subnet routes (advertise-routes).
        for (auto const& adv : policy.advertise_routes) {
            if (detail::is_default_route(adv)) {
                result.advertised_routes.push_back(adv);
                continue;
            }
            auto route = detail::prefix(adv);
            if (!pn::valid(route, true)) return std::unexpected(Error::address);
            result.advertised_routes.push_back(adv);
        }

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
        result.bypass_endpoints = outer;

        bool wants_exit = policy.exit_node.has_value() || !policy.exit_node_name.empty() || policy.exit_node_ip.has_value();
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
            bool selected_exit = wants_exit && detail::matches_exit_node(remote, policy) && remote.offers_exit_node();
            Peer peer;
            peer.id = remote.id;
            peer.settings.relay_only = relay;
            peer.settings.peer = direct;
            peer.settings.mtu = mtu;
            peer.not_after = remote.not_after;
            peer.managed_path = bool(discovery);
            peer.is_exit_node = false;
            std::ranges::copy(remote.key.view(), peer.settings.peer_public.begin());
            bool exit_routes_added = false;
            for (auto const& address : remote.allowed_ips) {
                if (detail::is_default_route(address)) {
                    if (!selected_exit) continue;
                    auto added = detail::add_exit_default_route(result, peer, address.family);
                    if (!added) return std::unexpected(added.error());
                    if (*added) exit_routes_added = true;
                    continue;
                }
                auto route = detail::prefix(address);
                if (!pn::valid(route, true)) return std::unexpected(Error::address);
                bool peer_address = detail::host(route) && std::ranges::find(remote.addresses, address) != remote.addresses.end();
                if (!peer_address && !policy.accept_routes) continue;
                auto added = detail::add_route(result, peer, route, outer);
                if (!added) return std::unexpected(added.error());
            }
            if (selected_exit && exit_routes_added) {
                peer.is_exit_node = true;
                result.exit_node_peer_id = remote.id;
                if (policy.exit_node_allow_lan_access) detail::append_lan_bypass_routes(result);
            }
            if (!peer.settings.allowed_ips.empty()) {
                detail::expires_with(result, peer.not_after);
                result.peers.push_back(std::move(peer));
            }
        }
        if (wants_exit && !result.exit_node_peer_id) return std::unexpected(Error::exit_node_not_found);
        if (!pn::validate(result.network)) return std::unexpected(Error::address);
        return result;
    }

    [[nodiscard]] inline auto plan(map_session::State const& state, bool accept_routes, std::uint16_t mtu,
                                   std::span<const net::UdpEndpoint> protected_endpoints, Wall::time_point now,
                                   std::uint16_t relay_region = 0,
                                   std::function<std::optional<net::UdpEndpoint>(control::NodePublic const&)> discovery = {})
        -> std::expected<Plan, Error> {
        return plan(state, Policy{.accept_routes = accept_routes}, mtu, protected_endpoints, now, relay_region, std::move(discovery));
    }
}
