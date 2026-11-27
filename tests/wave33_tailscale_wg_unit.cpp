import std;
import config;
import cli.tailscale_endpoint;
import crypto;
import net.udp_socket;
import packet.tun_network_types;
import tailscale.control;
import tailscale.control_messages;
import tailscale.magic_dns;
import tailscale.map_session;
import tailscale.multi_worker;
import tailscale.snapshot;
import tailscale.wireguard_routes;
import tailscale.wireguard_tun;
import wireguard;
import wireguard.crypto;
import wireguard.endpoint;
import wireguard.multi_peer_outbound;
import wireguard.port_types;
import wireguard.routing;

namespace {
    auto require(bool cond, char const* msg) -> void {
        if (!cond) { std::cerr << "FAIL: " << msg << '\n'; std::exit(1); }
    }

    auto hex_key(std::span<std::uint8_t const, 32> key) -> std::string {
        constexpr char kHex[] = "0123456789abcdef";
        std::string out; out.reserve(64);
        for (auto b : key) { out.push_back(kHex[b >> 4]); out.push_back(kHex[b & 0x0f]); }
        return out;
    }

    auto frame_map_json(std::string_view json) -> std::vector<std::uint8_t> {
        std::vector<std::uint8_t> out(4 + json.size());
        auto n = static_cast<std::uint32_t>(json.size());
        out[0] = static_cast<std::uint8_t>(n); out[1] = static_cast<std::uint8_t>(n >> 8);
        out[2] = static_cast<std::uint8_t>(n >> 16); out[3] = static_cast<std::uint8_t>(n >> 24);
        std::copy(json.begin(), json.end(), out.begin() + 4);
        return out;
    }

    auto make_ipv4_udp(std::array<std::uint8_t, 4> src, std::array<std::uint8_t, 4> dst,
                       std::uint16_t sport, std::uint16_t dport, std::string_view payload)
        -> std::vector<std::uint8_t> {
        auto ulen = static_cast<std::uint16_t>(8 + payload.size()), tot = static_cast<std::uint16_t>(20 + ulen);
        std::vector<std::uint8_t> pkt(tot, 0);
        pkt[0] = 0x45; pkt[2] = static_cast<std::uint8_t>(tot >> 8); pkt[3] = static_cast<std::uint8_t>(tot);
        pkt[8] = 64; pkt[9] = 17;
        std::ranges::copy(src, pkt.begin() + 12); std::ranges::copy(dst, pkt.begin() + 16);
        pkt[20] = static_cast<std::uint8_t>(sport >> 8); pkt[21] = static_cast<std::uint8_t>(sport);
        pkt[22] = static_cast<std::uint8_t>(dport >> 8); pkt[23] = static_cast<std::uint8_t>(dport);
        pkt[24] = static_cast<std::uint8_t>(ulen >> 8); pkt[25] = static_cast<std::uint8_t>(ulen);
        std::copy(payload.begin(), payload.end(), pkt.begin() + 28);
        return pkt;
    }

    auto make_ipv6_udp(std::array<std::uint8_t, 16> src, std::array<std::uint8_t, 16> dst,
                       std::uint16_t sport, std::uint16_t dport, std::string_view payload)
        -> std::vector<std::uint8_t> {
        auto ulen = static_cast<std::uint16_t>(8 + payload.size());
        std::vector<std::uint8_t> pkt(40 + ulen, 0);
        pkt[0] = 0x60; pkt[4] = static_cast<std::uint8_t>(ulen >> 8); pkt[5] = static_cast<std::uint8_t>(ulen);
        pkt[6] = 17; pkt[7] = 64;
        std::ranges::copy(src, pkt.begin() + 8); std::ranges::copy(dst, pkt.begin() + 24);
        pkt[40] = static_cast<std::uint8_t>(sport >> 8); pkt[41] = static_cast<std::uint8_t>(sport);
        pkt[42] = static_cast<std::uint8_t>(dport >> 8); pkt[43] = static_cast<std::uint8_t>(dport);
        pkt[44] = static_cast<std::uint8_t>(ulen >> 8); pkt[45] = static_cast<std::uint8_t>(ulen);
        std::copy(payload.begin(), payload.end(), pkt.begin() + 48);
        return pkt;
    }

    auto test_tailscale_advertise_exit_and_magic_dns() -> void {
        namespace cm = tailscale::control_messages;
        namespace ms = tailscale::map_session;
        namespace wr = tailscale::wireguard_routes;
        namespace md = tailscale::magic_dns;

        auto self_priv = crypto::X25519Private::generate();
        auto exit_priv = crypto::X25519Private::generate();
        auto peer_priv = crypto::X25519Private::generate();
        require(self_priv && exit_priv && peer_priv, "generate tailscale keys");
        auto self_pub_raw = self_priv->public_key();
        auto exit_pub_raw = exit_priv->public_key();
        auto peer_pub_raw = peer_priv->public_key();
        auto self_pub = tailscale::control::NodePublic::from_bytes(*self_pub_raw);
        auto exit_pub = tailscale::control::NodePublic::from_bytes(*exit_pub_raw);
        auto peer_pub = tailscale::control::NodePublic::from_bytes(*peer_pub_raw);
        require(self_pub && exit_pub && peer_pub, "NodePublic wrap");

        // 1. Verify advertise-routes encoding in RegisterRequest & MapRequest.
        std::array<cm::Prefix, 2> adv_routes{{
            {{10, 20, 0, 0}, 4, 24},
            {{0xfd, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 6, 64},
        }};
        std::array<std::uint8_t, 4096> reg_buf{};
        cm::RegisterRequest reg{*self_pub, "tskey-auth-test", "nexus-gw", "linux", "Nexus-1.0", true, adv_routes};
        auto reg_wire = cm::encode_register(reg_buf, reg);
        require(reg_wire.has_value(), "encode_register with advertise_routes");
        std::string_view reg_sv(reinterpret_cast<char const*>(reg_wire->bytes().data()), reg_wire->bytes().size());
        require(reg_sv.contains(R"("RoutableIPs":["10.20.0.0/24","fd00::/64"])"), "RegisterRequest RoutableIPs JSON");

        auto map_req = cm::encode_map_request(*self_pub, cm::MapRequestMode::stream, {}, std::nullopt, adv_routes);
        require(map_req && map_req->contains(R"("RoutableIPs":["10.20.0.0/24","fd00::/64"])"), "MapRequest RoutableIPs JSON");

        // 2. Build a MapResponse with DNSConfig + Exit Node + Regular Peer + PacketFilter.
        auto map_json = std::format(
            R"({{"Node":{{"ID":1,"Name":"nexus-gw.tailnet.ts.net.","Key":"nodekey:{}","Addresses":["100.64.0.1/32","fd7a:115c:a1e0::1/128"],"AllowedIPs":["100.64.0.1/32","fd7a:115c:a1e0::1/128"],"MachineAuthorized":true,"Expired":false}},"Peers":[{{"ID":2,"Name":"exit-us.tailnet.ts.net.","Key":"nodekey:{}","Addresses":["100.64.0.2/32","fd7a:115c:a1e0::2/128"],"AllowedIPs":["100.64.0.2/32","fd7a:115c:a1e0::2/128","0.0.0.0/0","::/0"],"Endpoints":["203.0.113.10:41641"],"MachineAuthorized":true,"Expired":false}},{{"ID":3,"Name":"db-srv.tailnet.ts.net.","Key":"nodekey:{}","Addresses":["100.64.0.3/32"],"AllowedIPs":["100.64.0.3/32","10.99.0.0/16","0.0.0.0/0"],"Endpoints":["203.0.113.20:41641"],"MachineAuthorized":true,"Expired":false}}],"Domain":"tailnet.ts.net","DNSConfig":{{"Proxied":true,"Domains":["tailnet.ts.net"],"Resolvers":[{{"Addr":"1.1.1.1:53","UseWithExitNode":true}}],"FallbackResolvers":[{{"Addr":"9.9.9.9"}}],"Routes":{{"corp.internal":[{{"Addr":"10.99.0.53:53"}}],"eng.corp.internal":[{{"Addr":"10.99.1.53:5353"}}]}}}},"PacketFilter":[{{"SrcIPs":["*"],"DstPorts":[{{"IP":"*","Ports":{{"First":0,"Last":65535}}}}]}}]}})",
            hex_key(*self_pub_raw), hex_key(*exit_pub_raw), hex_key(*peer_pub_raw));

        auto frame = frame_map_json(map_json);
        std::vector<std::uint8_t> storage(65536);
        auto candidate = std::make_unique<cm::MapCandidate>();
        auto state = std::make_unique<ms::State>();
        auto scratch = std::make_unique<tailscale::snapshot::Scratch>();
        ms::Session session({*self_pub, 1, 1}, storage, *candidate, *state, *scratch);
        auto fed = session.feed(frame);
        require(!fed.error && state->ready(), "map_session feed with DNSConfig + exit node");

        // 3. Verify exit-node planning (select exit-us by name, ignore unselected exit on db-srv!).
        net::UdpEndpoint ctrl_ep{4, {198, 51, 100, 1}, 443};
        std::array<net::UdpEndpoint, 1> protected_eps{ctrl_ep};
        wr::Policy pol{
            .accept_routes = true,
            .exit_node_name = "exit-us",
            .advertise_routes = adv_routes,
        };
        auto planned = wr::plan(*state, pol, 1280, protected_eps, wr::Wall::now());
        require(planned.has_value(), "exit-node route plan succeeded");
        require(planned->exit_node_peer_id == 2, "selected exit-node peer ID == 2");
        require(planned->advertised_routes.size() == 2, "advertised routes recorded");
        require(!planned->bypass_endpoints.empty(), "bypass endpoints populated");
        bool saw_exit_v4_zero = false, saw_exit_v6_zero = false, saw_other_zero = false;
        for (auto const& p : planned->peers) {
            for (auto const& a : p.settings.allowed_ips) {
                if (a.bits == 0) {
                    if (p.id == 2 && a.family == 4) saw_exit_v4_zero = true;
                    else if (p.id == 2 && a.family == 6) saw_exit_v6_zero = true;
                    else saw_other_zero = true;
                }
            }
        }
        require(saw_exit_v4_zero && saw_exit_v6_zero && !saw_other_zero, "default AllowedIPs only on chosen exit node");

        wr::Policy missing_exit{.exit_node_name = "nonexistent-exit"};
        auto bad_plan = wr::plan(*state, missing_exit, 1280, protected_eps, wr::Wall::now());
        require(!bad_plan && bad_plan.error() == wr::Error::exit_node_not_found, "missing exit node fails closed");
        // P2-2: verify exit-node LAN bypass routes populated when allowed, empty when disallowed.
        {
            wr::Policy allow_lan{.accept_routes = true, .exit_node_name = "exit-us", .exit_node_allow_lan_access = true};
            auto p_lan = wr::plan(*state, allow_lan, 1280, protected_eps, wr::Wall::now());
            require(p_lan && !p_lan->lan_bypass_routes.empty(), "P2-2 lan bypass routes present");
            wr::Policy block_lan{.accept_routes = true, .exit_node_name = "exit-us", .exit_node_allow_lan_access = false};
            auto p_nolan = wr::plan(*state, block_lan, 1280, protected_eps, wr::Wall::now());
            require(p_nolan && p_nolan->lan_bypass_routes.empty(), "P2-2 lan bypass routes omitted when false");
        }
        // P2-6: verify URL resolver ports (http->80, tls->853, explicit :8443).
        {
            constexpr std::string_view kUrlDns =
                R"({"Proxied":true,"Resolvers":[{"Addr":"https://dns.example:8443/dns-query","UseWithExitNode":true},{"Addr":"http://10.0.0.53/dns"},{"Addr":"tls://dot.example"}]})";
            auto parsed_u = md::parse_dns_config({cm::Presence::value, kUrlDns}, {cm::Presence::missing, {}});
            require(parsed_u && *parsed_u && (*parsed_u)->resolvers.size() == 3 &&
                    (*parsed_u)->resolvers[0].port == 8443 && (*parsed_u)->resolvers[1].port == 80 &&
                    (*parsed_u)->resolvers[2].port == 853, "P2-6 MagicDNS URL ports");
        }

        // 4. Verify MagicDNS resolution + split-DNS + concurrent thread safety.
        auto resolver = std::make_shared<md::Resolver>();
        state->sync_magic_dns(*resolver);
        require(resolver->ready() && resolver->proxied(), "MagicDNS ready & proxied");

        auto r_fqdn = resolver->resolve("exit-us.tailnet.ts.net.", md::QueryType::any);
        require(r_fqdn.authoritative_local && !r_fqdn.nxdomain && r_fqdn.ipv4.size() == 1 && r_fqdn.ipv6.size() == 1,
                "MagicDNS FQDN A+AAAA resolution");
        require(r_fqdn.ipv4[0] == std::array<std::uint8_t, 4>{100, 64, 0, 2}, "MagicDNS A IPv4 value");

        auto r_short = resolver->resolve("db-srv", md::QueryType::a);
        require(r_short.authoritative_local && r_short.ipv4.size() == 1 &&
                r_short.ipv4[0] == std::array<std::uint8_t, 4>{100, 64, 0, 3}, "MagicDNS short-name A resolution");

        auto r_nx = resolver->resolve("ghost.tailnet.ts.net", md::QueryType::a);
        require(r_nx.authoritative_local && r_nx.nxdomain, "MagicDNS authoritative NXDOMAIN inside tailnet suffix");

        auto split_eng = resolver->select_upstreams("api.eng.corp.internal");
        require(split_eng.size() == 1 && split_eng[0].addr == "10.99.1.53" && split_eng[0].port == 5353,
                "MagicDNS split-DNS longest-suffix match");
        auto split_corp = resolver->select_upstreams("mail.corp.internal");
        require(split_corp.size() == 1 && split_corp[0].addr == "10.99.0.53", "MagicDNS split-DNS parent domain");
        auto global_dns = resolver->select_upstreams("example.com", true);
        require(global_dns.size() == 1 && global_dns[0].addr == "1.1.1.1", "MagicDNS global resolver fallback");

        // Multi-threaded reader/writer stress on MagicDNS Resolver.
        std::atomic<bool> stop_dns{false};
        std::vector<std::thread> dns_readers;
        for (int t = 0; t < 4; ++t) {
            dns_readers.emplace_back([&] {
                while (!stop_dns.load(std::memory_order_relaxed)) {
                    auto res = resolver->resolve("exit-us.tailnet.ts.net", md::QueryType::a);
                    require(!resolver->ready() || (res.authoritative_local && !res.ipv4.empty()), "concurrent MagicDNS read");
                }
            });
        }
        for (int i = 0; i < 32; ++i) state->sync_magic_dns(*resolver);
        stop_dns.store(true, std::memory_order_relaxed);
        for (auto& th : dns_readers) th.join();

        // P2-2: Delta MapResponse with Domain and omitted DNSConfig must preserve split-DNS/resolvers/proxied!
        {
            auto d1 = frame_map_json(R"({"Domain":"renamed.ts.net"})");
            auto f1 = session.feed(d1);
            auto const* cfg1 = state->dns_config();
            require(!f1.error && cfg1 && cfg1->magic_dns_suffix == "renamed.ts.net" && cfg1->proxied &&
                    cfg1->resolvers.size() == 1 && cfg1->resolvers[0].addr == "1.1.1.1" &&
                    cfg1->fallback_resolvers.size() == 1 && cfg1->fallback_resolvers[0].addr == "9.9.9.9" &&
                    cfg1->search_domains.size() == 1 && cfg1->split_routes.size() == 2,
                    "P2-2 delta Domain preserves existing DNSConfig");
            state->sync_magic_dns(*resolver);
            auto sp = resolver->select_upstreams("api.eng.corp.internal");
            auto rn = resolver->resolve("ghost.renamed.ts.net", md::QueryType::a);
            auto rs = resolver->resolve("exit-us", md::QueryType::a);
            require(resolver->magic_dns_suffix() == "renamed.ts.net" && resolver->proxied() &&
                    sp.size() == 1 && sp[0].addr == "10.99.1.53" && sp[0].port == 5353 &&
                    rn.authoritative_local && rn.nxdomain && rs.authoritative_local && rs.ipv4.size() == 1,
                    "P2-2 synced MagicDNS split-DNS + new suffix");
            // Delta DNSConfig object without Domain preserves renamed.ts.net; explicit DNSConfig: null clears it!
            auto d2 = frame_map_json(R"({"DNSConfig":{"Proxied":true,"Domains":["corp.local"],"Resolvers":[{"Addr":"8.8.8.8:53"}]}})");
            auto f2 = session.feed(d2);
            auto const* cfg2 = state->dns_config();
            require(!f2.error && cfg2 && cfg2->magic_dns_suffix == "renamed.ts.net" &&
                    cfg2->resolvers.size() == 1 && cfg2->resolvers[0].addr == "8.8.8.8", "P2-2 delta DNSConfig keeps prior Domain");
            auto d3 = frame_map_json(R"({"DNSConfig":null})");
            auto f3 = session.feed(d3);
            require(!f3.error && state->dns_config() == nullptr, "P2-2 explicit DNSConfig null clears snapshot");
        }
    }

    auto test_tailscale_multi_worker_hub() -> void {
        tailscale::MultiWorkerMeshHub hub(4);
        hub.update_network(tailscale::MultiWorkerMeshHub::Network{
            std::array<std::uint8_t, 4>{100, 64, 0, 1}, std::nullopt, 7});
        auto net = hub.network();
        require(net && net->revision == 1, "MultiWorkerMeshHub initial revision");

        // Verify port ranges are disjoint across all 4 workers.
        std::array<tailscale::MultiWorkerMeshHub::PortRange, 4> ranges{};
        for (std::size_t w = 0; w < 4; ++w) {
            ranges[w] = tailscale::MultiWorkerMeshHub::port_range_for(w, 4);
            require(ranges[w].begin < ranges[w].end, "valid worker port range");
            if (w > 0) require(ranges[w].begin > ranges[w - 1].end, "disjoint worker port ranges");
            require(hub.register_worker(w), "register worker");
        }

        // Concurrently submit packets from 4 workers, then inject replies in reverse order
        // and verify ZERO cross-worker packet theft!
        std::array<std::uint8_t, 4> local_ip{100, 64, 0, 1};
        std::array<std::uint8_t, 4> remote_ip{100, 64, 0, 9};
        std::vector<std::thread> senders;
        for (std::size_t w = 0; w < 4; ++w) {
            senders.emplace_back([&, w] {
                for (std::uint16_t k = 0; k < 8; ++k) {
                    auto sport = static_cast<std::uint16_t>(ranges[w].begin + k);
                    auto pkt = make_ipv4_udp(local_ip, remote_ip, sport, 8080, std::format("w{}-{}", w, k));
                    require(hub.send_from_worker(w, net->revision, pkt), "worker send_from_worker");
                }
            });
        }
        for (auto& th : senders) th.join();

        std::size_t popped = 0;
        while (auto out = hub.pop_outbound()) ++popped;
        require(popped == 32, "all 32 outbound packets drained from hub");

        // Dispatch replies for all 4 workers (reversed order) and check each worker receives ONLY its own!
        for (int w = 3; w >= 0; --w) {
            for (std::uint16_t k = 0; k < 8; ++k) {
                auto dport = static_cast<std::uint16_t>(ranges[static_cast<std::size_t>(w)].begin + k);
                auto reply = make_ipv4_udp(remote_ip, local_ip, 8080, dport, std::format("r{}-{}", w, k));
                require(hub.dispatch_inbound(reply), "dispatch_inbound");
            }
        }
        for (std::size_t w = 0; w < 4; ++w) {
            std::size_t got = 0;
            while (auto pkt = hub.receive_for_worker(w, net->revision)) {
                auto dport = static_cast<std::uint16_t>((std::uint16_t((*pkt)[22]) << 8) | (*pkt)[23]);
                require(dport >= ranges[w].begin && dport <= ranges[w].end, "reply delivered to exact owning worker");
                ++got;
            }
            require(got == 8, "each worker received exactly its 8 replies");
        }
    }

    auto test_wireguard_multi_peer_and_on_demand() -> void {
        using namespace wireguard;
        auto now = Clock::time_point{std::chrono::seconds(1000)};
        auto wall = std::chrono::system_clock::now();

        SecretKey cli_priv, peer1_priv, peer2_priv;
        require(crypto::random_bytes(cli_priv.writable()).has_value(), "rng cli");
        require(crypto::random_bytes(peer1_priv.writable()).has_value(), "rng peer1");
        require(crypto::random_bytes(peer2_priv.writable()).has_value(), "rng peer2");

        auto cli_id = crypto::X25519Private::from_bytes(cli_priv.view());
        auto p1_id = crypto::X25519Private::from_bytes(peer1_priv.view());
        auto p2_id = crypto::X25519Private::from_bytes(peer2_priv.view());
        require(cli_id && p1_id && p2_id, "X25519 keys");
        auto cli_pub = *cli_id->public_key();
        auto p1_pub = *p1_id->public_key();
        auto p2_pub = *p2_id->public_key();

        auto outbound_exp = MultiPeerOutbound::create(cli_priv.view());
        require(outbound_exp.has_value(), "create MultiPeerOutbound");
        auto& outbound = **outbound_exp;

        EndpointAddress ep1{4, {198, 51, 100, 11}, 51820};
        EndpointAddress ep2{4, {198, 51, 100, 22}, 51821};
        EndpointAddress cli_ep{4, {198, 51, 100, 1}, 40000};

        // Peer 1: always-active for 10.10.0.0/16; Peer 2: on-demand (idle 30s) for 10.10.5.0/24 + fd11::/64 (more specific!).
        OutboundPeerSpec spec1{
            .peer_public = p1_pub,
            .endpoint = ep1,
            .allowed_ips = {{4, {10, 10, 0, 0}, 16}},
            .on_demand = false,
        };
        constexpr std::array<std::uint8_t, 3> warp_tag{0x11, 0x22, 0x33};
        auto warp_prof = ReservedProfile::create(Provider::warp, warp_tag);
        require(warp_prof.has_value(), "WARP reserved profile");
        OutboundPeerSpec spec2{
            .peer_public = p2_pub,
            .endpoint = ep2,
            .allowed_ips = {{4, {10, 10, 5, 0}, 24}, {6, {0xfd, 0x11}, 64}},
            .reserved = *warp_prof,
            .on_demand = true,
            .idle_timeout = std::chrono::seconds(30),
        };
        auto h1 = outbound.add_peer(std::move(spec1), now);
        auto h2 = outbound.add_peer(std::move(spec2), now);
        require(h1 && h2, "added both WireGuard peers");
        require(outbound.peer_state(*h1) == PeerActivationState::waking, "peer1 eager waking");
        require(outbound.peer_state(*h2) == PeerActivationState::asleep, "peer2 on-demand starts asleep");

        // Create real remote responder Endpoints for Peer 1 and Peer 2.
        EndpointConfig remote1_cfg{.peer_public = cli_pub, .allowed_ips = {{4, {10, 10, 0, 1}, 32}}, .peer = cli_ep};
        EndpointConfig remote2_cfg{.peer_public = cli_pub, .allowed_ips = {{4, {10, 10, 5, 1}, 32}, {6, {0xfd, 0x11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, 128}}, .peer = cli_ep};
        std::optional<Endpoint> remote1, remote2;
        require(Endpoint::emplace_into(remote1, std::move(*p1_id), std::move(remote1_cfg)).has_value(), "remote1");
        require(Endpoint::emplace_into(remote2, std::move(*p2_id), std::move(remote2_cfg)).has_value(), "remote2");

        // Verify Peer 2 emits ZERO handshakes while asleep!
        auto tx0 = outbound.poll_tx(now, wall);
        require(tx0 && tx0->size() == 1 && (*tx0)[0].peer == *h1 && (*tx0)[0].kind == OutboundKind::initiation,
                "only eager peer1 emits initial handshake; on-demand peer2 stays silent");

        auto pump_remote = [&](Endpoint& remote, EndpointAddress src, std::span<std::uint8_t const> wire,
                               Clock::time_point t) -> std::vector<std::vector<std::uint8_t>> {
            std::vector<std::uint8_t> clean(wire.begin(), wire.end());
            if (clean.size() >= 4) clean[1] = clean[2] = clean[3] = 0;
            auto rec = remote.receive(clean, src, true, t);
            require(rec.has_value(), "remote receive");
            std::vector<std::vector<std::uint8_t>> outs;
            for (int i = 0; i < 4; ++i) {
                auto p = remote.poll(t);
                require(p.has_value(), "remote poll");
                if (p->handshake) {
                    auto eph = crypto::X25519Private::generate();
                    auto dg = remote.respond(*p->handshake, 0x123400 + static_cast<std::uint32_t>(i), std::move(*eph), t);
                    require(dg.has_value(), "remote respond");
                    require(remote.complete_send(dg->serial, true, t).has_value(), "remote complete_send");
                    outs.push_back(std::move(dg->bytes));
                } else if (p->datagram) {
                    require(remote.complete_send(p->datagram->serial, true, t).has_value(), "remote complete_send data");
                    outs.push_back(std::move(p->datagram->bytes));
                } else break;
            }
            return outs;
        };

        // Complete Peer 1 handshake.
        for (auto const& resp : pump_remote(*remote1, cli_ep, (*tx0)[0].bytes, now)) {
            auto r = outbound.receive_udp(resp, ep1, now);
            require(r && *r, "outbound receive peer1 handshake response");
        }
        require(outbound.peer_state(*h1) == PeerActivationState::active, "peer1 active after handshake");
        require(outbound.peer_state(*h2) == PeerActivationState::asleep, "peer2 still asleep");

        // Enqueue IPv4 packet to 10.10.5.99 -> longest-prefix match routes to on-demand Peer 2 & wakes it!
        auto pkt_p2 = make_ipv4_udp({10, 10, 5, 1}, {10, 10, 5, 99}, 12345, 443, "hello-p2");
        auto routed = outbound.enqueue_ip(pkt_p2, now);
        require(routed && *routed == *h2, "LPM 10.10.5.0/24 beats 10.10.0.0/16 -> peer2");
        require(outbound.peer_state(*h2) == PeerActivationState::waking, "peer2 woke up on first packet");

        auto tx1 = outbound.poll_tx(now, wall);
        require(tx1 && !tx1->empty() && (*tx1)[0].peer == *h2 && (*tx1)[0].kind == OutboundKind::initiation,
                "peer2 emits handshake initiation upon wake");
        // Verify WARP reserved bytes applied to peer2 wire header!
        require((*tx1)[0].bytes[1] == 0x11 && (*tx1)[0].bytes[2] == 0x22 && (*tx1)[0].bytes[3] == 0x33,
                "peer2 WARP reserved bytes stamped");

        for (auto const& resp : pump_remote(*remote2, cli_ep, (*tx1)[0].bytes, now)) {
            auto r = outbound.receive_udp(resp, ep2, now);
            require(r && *r, "outbound receive peer2 handshake response");
        }
        require(outbound.peer_state(*h2) == PeerActivationState::active, "peer2 active after handshake");

        // Poll queued data packet out to peer2 and send an IPv6 reply back!
        auto tx2 = outbound.poll_tx(now, wall);
        require(tx2 && !tx2->empty() && (*tx2)[0].peer == *h2 && (*tx2)[0].kind == OutboundKind::data,
                "peer2 flushed queued data packet");
        {
            std::vector<std::uint8_t> clean((*tx2)[0].bytes.begin(), (*tx2)[0].bytes.end());
            clean[1] = clean[2] = clean[3] = 0;
            auto r2 = remote2->receive(clean, cli_ep, true, now);
            require(r2 && r2->packet == pkt_p2, "remote2 decrypted queued packet from client");
        }

        // Send IPv6 reply from remote2 back to client; verify client decrypts and enforces RPF.
        auto reply_v6 = make_ipv6_udp(
            {0xfd, 0x11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9},
            {0xfd, 0x11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
            443, 12345, "reply-v6");
        require(remote2->enqueue(reply_v6, now).has_value(), "remote2 enqueue IPv6 reply");
        auto r2_poll = remote2->poll(now);
        require(r2_poll && r2_poll->datagram, "remote2 seal IPv6 reply");
        require(remote2->complete_send(r2_poll->datagram->serial, true, now).has_value(), "remote2 complete");
        auto rx_ok = outbound.receive_udp(r2_poll->datagram->bytes, ep2, now);
        require(rx_ok && *rx_ok, "outbound accepted remote2 IPv6 packet");
        auto delivered = outbound.take_rx();
        require(delivered && delivered->peer == *h2 && delivered->ip_packet == reply_v6, "IPv6 reply delivered");

        // Advance clock past peer2's 30s idle_timeout -> peer2 transitions cleanly back to asleep!
        auto later = now + std::chrono::seconds(35);
        auto tx_idle = outbound.poll_tx(later, wall + std::chrono::seconds(35));
        require(tx_idle.has_value(), "poll_tx after idle timeout");
        require(outbound.peer_state(*h2) == PeerActivationState::asleep, "on-demand peer2 returned to asleep");
        require(outbound.peer_state(*h1) == PeerActivationState::active, "always-on peer1 stayed active");
        auto st = outbound.stats();
        require(st.wakes == 1 && st.sleeps == 1 && st.asleep_peers == 1 && st.active_peers == 1, "on-demand stats");

        // Second wake after idle-sleep!
        auto pkt_wake2 = make_ipv4_udp({10, 10, 5, 1}, {10, 10, 5, 88}, 22222, 443, "wake-again");
        require(outbound.enqueue_ip(pkt_wake2, later).has_value(), "re-wake peer2");
        require(outbound.peer_state(*h2) == PeerActivationState::waking && outbound.stats().wakes == 2, "second wake recorded");
        // P2-5: reject invalid endpoint without mutating existing endpoint!
        require(!outbound.update_peer_endpoint(*h1, EndpointAddress{4, {1, 2, 3, 4}, 0}).has_value(), "P2-5 reject port 0");
        outbound.close();
        // P2-8: verify MultiWorkerMeshHub rejects non-initial IPv4 fragments in dispatch_inbound.
        {
            tailscale::MultiWorkerMeshHub frag_hub(2);
            frag_hub.update_network(tailscale::MultiWorkerMeshHub::Network{std::array<std::uint8_t, 4>{100, 64, 0, 1}, std::nullopt, 1});
            auto frag = make_ipv4_udp({1, 1, 1, 1}, {100, 64, 0, 1}, 443, 10005, "frag");
            frag[7] = 1; // non-zero fragment offset
            require(!frag_hub.dispatch_inbound(frag), "P2-8 reject non-initial IPv4 fragment");
        }
    }

    auto test_kdl_tailscale_and_wireguard_config() -> void {
        std::string pin = "mkey:" + std::string(64, 'a');
        auto ts_ep = cli::tailscale_endpoint::parse(std::format(
            "schema-version 1\nrole \"client\"\nendpoint \"ts-gw\" type=\"tailscale\" {{\n"
            "  control-url \"https://control.example.com\"; control-address \"198.51.100.10\"; control-key \"{0}\"\n"
            "  ca-file \"/etc/ssl/ca.pem\"; auth-key-file \"/etc/nexus/ts.key\"; interface-name \"ts0\"\n"
            "  ephemeral #true; accept-routes #true; exit-node \"exit-us\"; exit-node-allow-lan-access #false\n"
            "  advertise-routes \"10.20.0.0/24\" \"fd00::/64\"; listen host=\"127.0.0.1\" port=41641\n}}\n", pin));
        require(ts_ep && *ts_ep && (*ts_ep)->exit_node_name == "exit-us" && !(*ts_ep)->exit_node_allow_lan_access &&
                (*ts_ep)->advertise_routes.size() == 2, "Tailscale endpoint KDL exit-node & advertise-routes");
        auto cfg = config::parse_kdl(
            "schema-version 1\nrole \"client\"\nworkers 4\n"
            "inbounds { inbound \"in\" type=\"socks5\" { listen host=\"127.0.0.1\" port=1080; authentication \"none\"; }; }\n"
            "outbounds { outbound \"direct\" type=\"direct\"; outbound \"ts\" type=\"tailscale\" { endpoint-file \"/etc/nexus/ts.kdl\"; }\n"
            "  outbound \"wg-mp\" type=\"wireguard\" { private-key-file \"/etc/nexus/wg.priv\"; local-address \"10.10.0.2/32\"; on-demand #true; idle-timeout 45\n"
            "    peer { server host=\"198.51.100.11\" port=51820; peer-public-key-file \"/etc/nexus/p1.pub\"; allowed-ips \"10.10.0.0/16\"; }\n"
            "    peer { server host=\"198.51.100.22\" port=51821; peer-public-key-file \"/etc/nexus/p2.pub\"; allowed-ips \"10.10.5.0/24\" \"fd11::/64\"; reserved 1 2 3; persistent-keepalive 25; }\n"
            "  }\n  outbound \"sel\" type=\"selector\" { members \"ts\" \"wg-mp\"; }\n}\nrouting { final \"sel\"; }\n");
        require(cfg && cfg->workers == 4 && cfg->tailscale_outbounds.size() == 1, "Tailscale multi-worker accepted");
        require(cfg->wireguard_outbounds.size() == 1 && cfg->wireguard_outbounds[0].config.on_demand &&
                cfg->wireguard_outbounds[0].config.idle_timeout_s == 45 && cfg->wireguard_outbounds[0].config.peers.size() == 2 &&
                cfg->wireguard_outbounds[0].config.peers[1].allowed_ips.size() == 2 && cfg->wireguard_outbounds[0].config.peers[1].warp,
                "WireGuard multi-peer & on-demand parsed");
        constexpr std::string_view kIn = "schema-version 1\nrole \"client\"\ninbounds { inbound \"in\" type=\"socks5\" { listen host=\"127.0.0.1\" port=1080; authentication \"none\"; }; }\n";
        require(!config::parse_kdl(std::format("{}workers 17\noutbounds {{ outbound \"direct\" type=\"direct\"; outbound \"ts\" type=\"tailscale\" {{ endpoint-file \"/etc/nexus/ts.kdl\"; }}; }}\nrouting {{ final \"ts\"; }}\n", kIn)).has_value(), "P1-A reject Tailscale workers > 16");
        require(!config::parse_kdl(std::format("{}outbounds {{ outbound \"direct\" type=\"direct\"; outbound \"wg\" type=\"wireguard\" {{ private-key-file \"/etc/nexus/wg.priv\"; on-demand #true; detour \"direct\"; server host=\"198.51.100.11\" port=51820; peer-public-key-file \"/etc/nexus/p1.pub\"; }}; }}\nrouting {{ final \"wg\"; }}\n", kIn)).has_value(), "P1-C reject WireGuard detour + on-demand");
        require(!config::parse_kdl(std::format("{}outbounds {{ outbound \"direct\" type=\"direct\"; outbound \"wg\" type=\"wireguard\" {{ private-key-file \"/etc/nexus/wg.priv\"; peer {{ server host=\"198.51.100.11\" port=51820; peer-public-key-file \"/etc/nexus/p1.pub\"; allowed-ips \"10.0.0.1/24\"; }}; }}; }}\nrouting {{ final \"wg\"; }}\n", kIn)).has_value(), "P1-D reject non-canonical WireGuard allowed-ips CIDR");
        require(!cli::tailscale_endpoint::parse(std::format("schema-version 1\nrole \"client\"\nendpoint \"ts-bad\" type=\"tailscale\" {{ control-url \"https://control.example.com\"; control-address \"198.51.100.10\"; control-key \"{0}\"; ca-file \"/etc/ssl/ca.pem\"; auth-key-file \"/etc/nexus/ts.key\"; interface-name \"ts0\"; ephemeral #true; advertise-routes \"10.20.0.1/24\"; listen host=\"127.0.0.1\" port=41641; }}\n", pin)).has_value(), "P1-D reject non-canonical Tailscale advertise-routes CIDR");
    }
}

int main() {
    test_tailscale_advertise_exit_and_magic_dns();
    test_tailscale_multi_worker_hub();
    test_wireguard_multi_peer_and_on_demand();
    test_kdl_tailscale_and_wireguard_config();
    std::cout << "wave33_tailscale_wg_unit: ALL PASSED\n";
    return 0;
}
