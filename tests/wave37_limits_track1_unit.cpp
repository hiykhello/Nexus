// Wave 37 Track 1 scale & correctness regression tests:
// 1. >= 512 outbounds & selector groups (O(1) transparent index, hot reselect, relay::Server registration > 256)
// 2. >= 128 multi-user inbound configs & O(1) zero-alloc constant-time auth tables (VLESS, Trojan, AnyTLS, SS2022, Hy2, Naive, TUIC)
// 3. Artificial config caps removed: http-clients (>16), headers (>16), use-providers (>64), probe-expected-status (>16),
//    probe-concurrency (>16), provider include/exclude regex (>256B) & tag-prefix (>32B), cors-allow-origin (>32),
//    mux max-connections (>64), tcp-splice-pipes (>256), WS batch items (>16), Tailscale advertise-routes (>64) & packet_filter (>512).
#include <csignal>

import std;
import config;
import provider;
import relay;
import rules;
import cli.proxy_selector_state;
import vless;
import trojan;
import trojan.auth;
import anytls;
import anytls.auth;
import shadowsocks.identity;
import shadowsocks.corosio_server;
import shadowsocks.replay;
import hysteria2.credential;
import naive.padding;
import tuic.stream_input;
import control_api.http_ws;
import tailscale.packet_filter;
import cli.tailscale_endpoint;

namespace {
    auto require(bool cond, std::string_view msg) -> void {
        if (!cond) {
            std::cerr << "FAIL: " << msg << '\n';
            std::exit(1);
        }
    }

    auto test_outbounds_and_selectors_scale() -> void {
        constexpr int kPhys = 520;
        constexpr int kGroups = 26;
        std::string kdl =
            "schema-version 1\nrole \"client\"\n"
            "inbounds { inbound \"in0\" type=\"socks5\" { listen host=\"127.0.0.1\" port=1080; authentication \"none\"; }; }\n"
            "outbounds {\n  outbound \"direct\" type=\"direct\"\n";
        for (int i = 0; i < kPhys; ++i) {
            kdl += std::format(
                "  outbound \"p{:03d}\" type=\"socks5\" {{ server host=\"127.0.0.1\" port={}; }}\n",
                i, 10000 + i);
        }
        for (int g = 0; g < kGroups; ++g) {
            kdl += std::format("  outbound \"sel-{:02d}\" type=\"selector\" {{\n", g);
            for (int m = 0; m < 20; ++m) {
                int const idx = g * 20 + m;
                kdl += std::format("    member \"p{:03d}\"\n", idx);
            }
            if (g > 0) kdl += std::format("    member \"sel-{:02d}\"\n", g - 1);
            kdl += "  }\n";
        }
        kdl += "}\nrouting {\n  final \"sel-25\"\n}\n";

        auto parsed = config::parse_kdl(kdl);
        require(parsed.has_value(), parsed ? "" : "520 outbounds + 26 selectors parse: " + parsed.error());
        require(parsed->tcp_proxy_outbounds.size() == kPhys, "520 physical tcp_proxy outbounds parsed");
        require(parsed->selectors.size() == kGroups, "26 selector groups parsed");
        require(parsed->physical_index.size() >= kPhys, "O(1) physical_index populated");
        require(parsed->selector_index.size() == kGroups, "O(1) selector_index populated");

        // O(1) lookup for first, middle, last physical outbound and selector group
        auto i0 = config::configured_outbound_index(*parsed, "p000");
        auto i_mid = config::configured_outbound_index(*parsed, "p260");
        auto i_last = config::configured_outbound_index(*parsed, "p519");
        auto i_sel = config::configured_outbound_index(*parsed, "sel-25");
        require(i0 && i_mid && i_last && i_sel, "O(1) configured_outbound_index lookups succeed");
        require(*i0 != *i_mid && *i_mid != *i_last && *i_last >= 520, "distinct outbound indices > 256");

        // Hot reselect on top selector group
        auto requested = *parsed;
        requested.selectors.back().selected = "p519";
        auto reselected = config::reselect_outbounds(*parsed, requested);
        require(reselected.has_value(), reselected ? "" : "reselect_outbounds: " + reselected.error());
        auto i_after = config::configured_outbound_index(*reselected, "sel-25");
        auto i_519 = config::configured_outbound_index(*reselected, "p519");
        require(i_after && i_519 && *i_after == *i_519, "reselect_outbounds updated O(1) target");

        // Register all 520 TCP proxy outbounds in relay::Server (exceeds old 256 cap)
        // and verify P1-1 (activate_context + compile_route_snapshot TunnelRefBits >256) + P1-2 (queue >16 probes).
        relay::Server server;
        for (int i = 0; i < kPhys; ++i) {
            auto added = server.add_tcp_proxy(parsed->tcp_proxy_outbounds[static_cast<std::size_t>(i)].config);
            require(added.has_value(), added ? "" : "relay::Server::add_tcp_proxy failed: " + added.error());
            require(*added == static_cast<std::size_t>(i) + 2u, "relay::Server outbound index monotonic");
        }
        auto activated = server.activate_context();
        require(activated.has_value(), "P1-1: Server::activate_context() succeeds with 520 outbounds (>256)");
        auto snap = server.compile_route_snapshot({}, 521, {}, {}, config::outbound_distribution(*parsed));
        require(snap.has_value() && snap->tunnel_references.has_value() &&
                snap->tunnel_references->size() == kPhys && snap->tunnel_references->test(kPhys - 1) &&
                !snap->tunnel_references->test(0),
                "P1-1: compile_route_snapshot TunnelRefBits tracks outbound #519 (>256)");
        for (int p = 0; p < 32; ++p) {
            auto probe = std::make_shared<relay::OutboundProbe>();
            require(server.queue_outbound_probe(std::move(probe)), "P1-2: queue_outbound_probe accepts >16 probes");
        }
        server.stop();

        // P2-2: policy::dependency_order supports >4096 nodes
        std::vector<policy::DependencyEdge> dep_edges;
        dep_edges.reserve(4999);
        for (std::size_t i = 1; i < 5000; ++i) dep_edges.push_back({i, i - 1});
        auto dep_ord = policy::dependency_order(5000, dep_edges);
        require(dep_ord.has_value() && dep_ord->size() == 5000, "P2-2: policy::dependency_order handles 5000 nodes (>4096)");

        // P2-3: build_group_tag_map saturates count so 257+ selectors sharing one outbound do not wrap uint8_t
        config::Config shared_cfg = *parsed;
        shared_cfg.selectors.clear();
        for (int s = 0; s < 258; ++s) {
            config::OutboundSelector sel{};
            sel.name = std::format("dup-{:03d}", s);
            sel.members = {"p000"};
            sel.selected = "p000";
            sel.selected_leaf = "p000";
            shared_cfg.selectors.push_back(std::move(sel));
        }
        auto gmap = cli::run_detail::build_group_tag_map(shared_cfg);
        require(gmap && *i0 < gmap->unique_outbound_group.size() && !gmap->unique_outbound_group[*i0].has_value(),
                "P2-3: build_group_tag_map saturates shared-outbound counts at 258 selectors");
        std::cout << "  [PASS] Outbounds & selectors scale (520 physical + activate_context + TunnelRefBits + 32 probes + 5000-node dep + 258-sel saturation)\n";
    }

    auto test_multi_user_inbound_configs() -> void {
        constexpr int kUsers = 140;
        // Shadowsocks (>32), VLESS (>64), Trojan (>64), AnyTLS (>64), Hysteria2 (>64), ShadowTLS (>64), TUIC (>64), Naive (>64)
        auto parse_server = [](std::string const& body, std::string_view label) {
            std::string kdl =
                "schema-version 1\nrole \"server\"\n"
                "inbounds {\n" + body + "}\n"
                "outbounds { outbound \"direct\" type=\"direct\"; }\n"
                "routing { final \"direct\"; }\n";
            auto r = config::parse_kdl(kdl);
            require(r.has_value(), r ? "" : std::string(label) + ": " + r.error());
            return std::move(*r);
        };

        std::string ss_users = "    authentication {\n";
        for (int i = 0; i < kUsers; ++i)
            ss_users += std::format("      user \"u{:03d}\" key-file=\"/etc/nexus/ss/u{:03d}.key\"\n", i, i);
        ss_users += "    }\n";
        auto ss = parse_server(
            "  inbound \"ss\" type=\"shadowsocks\" {\n"
            "    listen host=\"127.0.0.1\" port=8388\n"
            "    method \"2022-blake3-aes-256-gcm\"\n"
            "    key-file \"/etc/nexus/ss/server.key\"\n" + ss_users + "  }\n", "shadowsocks 140 users");
        require(ss.inbounds[0].shadowsocks->users.size() == kUsers, "SS2022 140 users");

        std::string vless_users = "    authentication {\n";
        for (int i = 0; i < kUsers; ++i)
            vless_users += std::format("      user \"u{:03d}\" uuid-file=\"/etc/nexus/v/u{:03d}.uuid\"\n", i, i);
        vless_users += "    }\n";
        auto vl = parse_server(
            "  inbound \"vl\" type=\"vless\" {\n"
            "    listen host=\"127.0.0.1\" port=8443\n"
            "    tls { certificate-file \"/etc/nexus/cert.pem\"; private-key-file \"/etc/nexus/key.pem\"; }\n"
            + vless_users + "  }\n", "vless 140 users");
        require(vl.inbounds[0].vless->users.size() == kUsers, "VLESS 140 users");

        std::string pw_users = "    authentication {\n";
        for (int i = 0; i < kUsers; ++i)
            pw_users += std::format("      user \"u{:03d}\" password-file=\"/etc/nexus/pw/u{:03d}.pw\"\n", i, i);
        pw_users += "    }\n";
        for (std::string_view proto : {"trojan", "anytls", "hysteria2"}) {
            auto r = parse_server(std::format(
                "  inbound \"in\" type=\"{}\" {{\n"
                "    listen host=\"127.0.0.1\" port=8444\n"
                "    tls {{ certificate-file \"/etc/nexus/cert.pem\"; private-key-file \"/etc/nexus/key.pem\"; }}\n"
                "{}  }}\n", proto, pw_users), proto);
            require(!r.inbounds.empty(), proto);
        }

        auto stls = parse_server(
            "  inbound \"stls\" type=\"shadowtls\" {\n"
            "    listen host=\"127.0.0.1\" port=8445\n"
            "    handshake host=\"example.com\" port=443\n"
            "    target host=\"127.0.0.1\" port=8388\n" + pw_users + "  }\n", "shadowtls 140 users");
        require(stls.inbounds[0].shadowtls->users.size() == kUsers, "ShadowTLS 140 users");

        std::string tuic_users = "    authentication {\n";
        for (int i = 0; i < kUsers; ++i)
            tuic_users += std::format(
                "      user \"u{:03d}\" uuid-file=\"/etc/nexus/t/u{:03d}.uuid\" password-file=\"/etc/nexus/t/u{:03d}.pw\"\n",
                i, i, i);
        tuic_users += "    }\n";
        auto tc = parse_server(
            "  inbound \"tuic\" type=\"tuic\" {\n"
            "    listen host=\"127.0.0.1\" port=8446\n"
            "    tls { certificate-file \"/etc/nexus/cert.pem\"; private-key-file \"/etc/nexus/key.pem\"; }\n"
            + tuic_users + "  }\n", "tuic 140 users");
        require(tc.inbounds[0].tuic->users.size() == kUsers, "TUIC 140 users");

        std::string naive_users = "    authentication {\n";
        for (int i = 0; i < kUsers; ++i)
            naive_users += std::format(
                "      user \"u{:03d}\" username=\"user{:03d}\" password-file=\"/etc/nexus/n/u{:03d}.pw\"\n",
                i, i, i);
        naive_users += "    }\n";
        auto nv = parse_server(
            "  inbound \"nv\" type=\"naive\" {\n"
            "    listen host=\"127.0.0.1\" port=8447\n"
            "    tls { certificate-file \"/etc/nexus/cert.pem\"; private-key-file \"/etc/nexus/key.pem\"; }\n"
            + naive_users + "  }\n", "naive 140 users");
        require(nv.inbounds[0].naive->users.size() == kUsers, "Naive 140 users");
        std::cout << "  [PASS] Multi-user inbound configs (140 users across SS2022/VLESS/Trojan/AnyTLS/Hy2/ShadowTLS/TUIC/Naive)\n";
    }

    auto test_o1_auth_tables() -> void {
        constexpr std::size_t kN = 160;
        // 1. VLESS UserTable + ServerHandshake
        std::vector<vless::UserId> v_ids(kN);
        for (std::size_t i = 0; i < kN; ++i) {
            v_ids[i].fill(0x11);
            v_ids[i][0] = static_cast<std::uint8_t>(i & 0xffu);
            v_ids[i][1] = static_cast<std::uint8_t>((i >> 8) & 0xffu);
        }
        auto v_table = vless::UserTable::create(v_ids);
        require(v_table.has_value() && (*v_table)->size() == kN, "vless::UserTable 160 users");
        for (std::size_t idx : {std::size_t{0}, std::size_t{79}, kN - 1}) {
            auto found = (*v_table)->find(v_ids[idx]);
            require(found && *found == idx, "vless::UserTable O(1) hit");
            auto hs = vless::ServerHandshake::create_shared(*v_table);
            require(hs.has_value(), "vless::ServerHandshake::create(shared UserTable)");
            vless::TcpRequest req{v_ids[idx], vless::AddressKind::ipv4, 443, {127, 0, 0, 1}};
            auto wire = vless::encode_tcp_request(req);
            require(wire.has_value(), "vless::encode_tcp_request");
            auto step = hs->feed(*wire);
            require(step.status == vless::ServerStatus::dialing && hs->request() && hs->request()->user == v_ids[idx],
                    "vless::ServerHandshake authenticates user via shared UserTable");
        }
        vless::UserId v_miss{}; v_miss.fill(0xee);
        require(!(*v_table)->find(v_miss).has_value(), "vless::UserTable rejects unknown UUID");
        std::vector<vless::UserId> v_dup{v_ids[0], v_ids[0]};
        require(!vless::UserTable::create(v_dup).has_value(), "vless::UserTable rejects duplicate UUID");

        // 2. Trojan UserTable
        std::vector<trojan::PasswordKey> tr_keys;
        tr_keys.reserve(kN);
        std::vector<std::array<std::uint8_t, 56>> tr_raw(kN);
        for (std::size_t i = 0; i < kN; ++i) {
            auto pw = std::format("trojan-secret-{}", i);
            auto k = trojan::PasswordKey::from_password({reinterpret_cast<std::uint8_t const*>(pw.data()), pw.size()});
            require(k.has_value(), "trojan PasswordKey");
            std::ranges::copy(k->view(), tr_raw[i].begin());
            tr_keys.push_back(std::move(*k));
        }
        auto tr_table = trojan::UserTable::create(std::move(tr_keys));
        require(tr_table.has_value() && tr_table->size() == kN, "trojan::UserTable 160 users");
        for (std::size_t idx : {std::size_t{0}, std::size_t{80}, kN - 1})
            require(tr_table->authenticate(tr_raw[idx]) == idx, "trojan::UserTable O(1) hit");
        std::array<std::uint8_t, 56> tr_bad{}; tr_bad.fill('0');
        require(!tr_table->authenticate(tr_bad).has_value(), "trojan::UserTable miss");

        // 3. AnyTLS UserTable
        std::vector<anytls::PasswordKey> an_keys;
        an_keys.reserve(kN);
        std::vector<std::array<std::uint8_t, 32>> an_raw(kN);
        for (std::size_t i = 0; i < kN; ++i) {
            auto pw = std::format("anytls-secret-{}", i);
            auto k = anytls::PasswordKey::from_password({reinterpret_cast<std::uint8_t const*>(pw.data()), pw.size()});
            require(k.has_value(), "anytls PasswordKey");
            std::ranges::copy(k->view(), an_raw[i].begin());
            an_keys.push_back(std::move(*k));
        }
        auto an_table = anytls::UserTable::create(std::move(an_keys));
        require(an_table.has_value() && an_table->size() == kN, "anytls::UserTable 160 users");
        for (std::size_t idx : {std::size_t{0}, std::size_t{80}, kN - 1})
            require(an_table->authenticate(an_raw[idx]) == idx, "anytls::UserTable O(1) hit");
        std::array<std::uint8_t, 32> an_bad{}; an_bad.fill(0xff);
        require(!an_table->authenticate(an_bad).has_value(), "anytls::UserTable miss");

        // 4. Shadowsocks 2022 IdentityTable
        std::vector<std::array<std::uint8_t, 16>> ss_keys(kN);
        std::vector<shadowsocks::detail::TcpIdentityUser> ss_users;
        ss_users.reserve(kN);
        shadowsocks::ReplayTable dummy_replay{64};
        for (std::size_t i = 0; i < kN; ++i) {
            ss_keys[i].fill(0x22);
            ss_keys[i][0] = static_cast<std::uint8_t>(i & 0xffu);
            ss_keys[i][1] = static_cast<std::uint8_t>((i >> 8) & 0xffu);
            ss_users.push_back({ss_keys[i], &dummy_replay, shadowsocks::identity_hash(ss_keys[i])});
        }
        shadowsocks::detail::IdentityTable ss_table(ss_users);
        for (std::size_t idx : {std::size_t{0}, std::size_t{80}, kN - 1})
            require(ss_table.find(ss_users, ss_users[idx].hash) == idx, "shadowsocks IdentityTable O(1) hit");
        shadowsocks::IdentityBlock ss_bad{}; ss_bad.fill(0xaa);
        require(!ss_table.find(ss_users, ss_bad).has_value(), "shadowsocks IdentityTable miss");

        // 5. Hysteria2 PasswordIndex
        std::vector<hysteria2::Password> hy_pws;
        hy_pws.reserve(kN);
        for (std::size_t i = 0; i < kN; ++i) {
            auto s = std::format("hy2-cred-{:04d}", i);
            auto p = hysteria2::Password::create({reinterpret_cast<std::uint8_t const*>(s.data()), s.size()});
            require(p.has_value(), "hysteria2 Password");
            hy_pws.push_back(std::move(*p));
        }
        hysteria2::PasswordIndex hy_idx(hy_pws);
        for (std::size_t idx : {std::size_t{0}, std::size_t{80}, kN - 1})
            require(hy_idx.authenticate(hy_pws, std::format("hy2-cred-{:04d}", idx)) == idx, "Hysteria2 PasswordIndex O(1) hit");
        require(!hy_idx.authenticate(hy_pws, "hy2-cred-9999").has_value(), "Hysteria2 PasswordIndex miss");

        // 6. NaiveProxy UserIndex + zero-alloc Basic auth
        std::vector<naive::UserCredential> nv_users;
        nv_users.reserve(kN);
        for (std::size_t i = 0; i < kN; ++i)
            nv_users.emplace_back(std::format("name-{:03d}", i), std::format("user-{:03d}", i), std::format("pass-{:03d}", i));
        naive::UserIndex nv_idx(nv_users);
        for (std::size_t idx : {std::size_t{0}, std::size_t{80}, kN - 1}) {
            auto hdr = naive::make_basic_auth(std::format("user-{:03d}", idx), std::format("pass-{:03d}", idx));
            auto m = naive::verify_basic_auth(hdr, nv_users, nv_idx);
            require(m && *m == std::format("name-{:03d}", idx), "Naive UserIndex O(1) Basic auth hit");
        }
        require(!naive::verify_basic_auth(naive::make_basic_auth("user-000", "wrong-pass"), nv_users, nv_idx).has_value(),
                "Naive UserIndex rejects wrong password");
        require(!naive::verify_basic_auth(naive::make_basic_auth("ghost", "pass-000"), nv_users, nv_idx).has_value(),
                "Naive UserIndex rejects unknown user");

        // 7. TUIC UserIndex
        struct TuicCred { std::array<std::uint8_t, 16> uuid{}; };
        std::vector<TuicCred> tuic_users(kN);
        for (std::size_t i = 0; i < kN; ++i) {
            tuic_users[i].uuid.fill(0x33);
            tuic_users[i].uuid[0] = static_cast<std::uint8_t>(i & 0xffu);
            tuic_users[i].uuid[1] = static_cast<std::uint8_t>((i >> 8) & 0xffu);
        }
        tuic::detail::UserIndex tuic_idx{std::span<TuicCred const>(tuic_users)};
        for (std::size_t idx : {std::size_t{0}, std::size_t{80}, kN - 1})
            require(tuic_idx.find(std::span<TuicCred const>(tuic_users), tuic_users[idx].uuid) == idx, "TUIC UserIndex O(1) hit");
        std::array<std::uint8_t, 16> tuic_bad{}; tuic_bad.fill(0x77);
        require(!tuic_idx.find(std::span<TuicCred const>(tuic_users), tuic_bad).has_value(), "TUIC UserIndex miss");

        std::cout << "  [PASS] O(1) zero-alloc constant-time auth tables (VLESS/Trojan/AnyTLS/SS2022/Hy2/Naive/TUIC x 160 users)\n";
    }

    auto test_config_caps_ws_and_tailscale() -> void {
        // 1. http-clients (>16), headers (>16), use-providers (>64), probe-expected-status (>16),
        //    probe-concurrency (>16), include/exclude regex (>256B), tag-prefix (>32B),
        //    cors-allow-origin (>32), mux max-connections (>64), tcp-splice-pipes (>256)
        std::string kdl =
            "schema-version 1\nrole \"client\"\n"
            "tcp-splice-pipes 512\n"
            "control http-listen=\"127.0.0.1:19090\" {\n";
        for (int i = 0; i < 48; ++i)
            kdl += std::format("  cors-allow-origin \"https://app{:02d}.example.com\"\n", i);
        kdl += "}\n"
               "dns { servers { local \"sys\"; }; final \"sys\"; }\n"
               "http-clients {\n";
        for (int i = 0; i < 24; ++i) {
            kdl += std::format("  hc{:02d} {{\n    outbound \"direct\"\n    domain-resolver \"sys\"\n    ca-file \"/etc/ssl/ca.pem\"\n", i);
            if (i == 0) {
                for (int h = 0; h < 24; ++h)
                    kdl += std::format("    header \"X-Custom-{:02d}\" \"val-{:02d}\"\n", h, h);
            }
            kdl += "  }\n";
        }
        kdl += "}\nproxy-providers {\n";
        std::string long_regex = "^(";
        for (int i = 0; i < 45; ++i) {
            if (i) long_regex.push_back('|');
            long_regex += std::format("region{:02d}", i);
        }
        long_regex += ")$";
        require(long_regex.size() > 256, "test regex exceeds old 256B cap");
        std::string long_prefix = "provider_region_cluster_asia_pacific_node_prefix_01_";
        require(long_prefix.size() > 32, "test tag-prefix exceeds old 32B cap");
        for (int i = 0; i < 72; ++i) {
            kdl += std::format(
                "  provider \"pr{:02d}\" type=\"file\" {{\n    path \"/etc/nexus/p{:02d}.kdl\"\n", i, i);
            if (i == 0) {
                kdl += std::format("    include \"{}\"\n    include \"^extra-[0-9]+$\"\n    exclude \"^blocked-[0-9]+$\"\n    tag-prefix \"{}\"\n",
                                   long_regex, long_prefix);
            }
            kdl += "  }\n";
        }
        kdl += "}\ninbounds { inbound \"in0\" type=\"socks5\" { listen host=\"127.0.0.1\" port=1080; authentication \"none\"; }; }\n"
               "outbounds {\n"
               "  outbound \"direct\" type=\"direct\"\n"
               "  outbound \"ss-mux\" type=\"shadowsocks\" {\n"
               "    server host=\"127.0.0.1\" port=8388; method \"2022-blake3-aes-256-gcm\"; key-file \"/etc/nexus/k\";\n"
               "    multiplex { protocol \"smux\"; max-connections 256; min-streams 4; max-streams 2048; }\n"
               "  }\n"
               "  outbound \"grp\" type=\"url-test\" {\n"
               "    member \"direct\"\n    member \"ss-mux\"\n"
               "    probe-url \"http://127.0.0.1/generate_204\"\n"
               "    probe-concurrency 64\n"
               "    probe-expected-status";
        for (int s = 200; s < 224; ++s) kdl += std::format(" {}", s);
        kdl += "\n";
        for (int i = 0; i < 72; ++i) kdl += std::format("    use \"pr{:02d}\"\n", i);
        kdl += "  }\n}\nrouting { final \"grp\"; }\n";

        auto cfg = config::parse_kdl(kdl);
        require(cfg.has_value(), cfg ? "" : "track1 config caps parse: " + cfg.error());
        require(cfg->tcp_splice_pipes == 512, "tcp-splice-pipes 512");
        require(cfg->control_http && cfg->control_http->cors_allow_origins.size() == 48, "48 cors-allow-origin entries");
        require(cfg->http_clients.size() == 24, "24 http-clients");
        require(cfg->http_clients[0].headers.size() == 24, "24 custom headers on http-client");
        require(cfg->proxy_providers.size() == 72, "72 proxy-providers");
        require(cfg->proxy_providers[0].filter.include_regex == long_regex, "include regex > 256B");
        require(cfg->proxy_providers[0].filter.include_regexes.size() == 2, "dynamic multi-include regex list");
        require(cfg->proxy_providers[0].filter.tag_prefix == long_prefix, "tag-prefix > 32B");
        {
            std::vector<provider::ParsedProxy> sample;
            sample.push_back({.tag = "region00"});
            sample.push_back({.tag = "region44"});
            sample.push_back({.tag = "extra-7"});
            sample.push_back({.tag = "blocked-1"});
            sample.push_back({.tag = "region99"});
            auto applied = provider::apply_filter(sample, cfg->proxy_providers[0].filter);
            require(applied.has_value() && sample.size() == 3, "provider::apply_filter handles >256B regex & multi-include");
        }
        require(cfg->shadowsocks_outbounds[0].config.multiplex->max_connections == 256, "mux max-connections 256");
        require(cfg->selectors[0].use_providers.size() == 72, "72 use-providers");
        require(cfg->selectors[0].probe.probe_concurrency == 64, "probe-concurrency 64");
        require(cfg->selectors[0].probe.expected_status.size() == 24, "24 probe-expected-status ranges");

        // relay::Server::set_tcp_splice_pipes(512)
        std::signal(SIGPIPE, SIG_IGN);
        relay::Server srv;
        require(srv.set_tcp_splice_pipes(512), "relay::Server::set_tcp_splice_pipes(512)");

        // 2. WebSocket batch array (>16 items)
        std::string ws_json = "{\"items\":[";
        for (int i = 0; i < 64; ++i) {
            if (i) ws_json.push_back(',');
            ws_json += std::format("\"ch-{:02d}\"", i);
        }
        ws_json += "]}";
        auto items = control_api::http_detail::extract_json_string_array(ws_json, "items");
        require(items.has_value() && items->size() == 64 && items->front() == "ch-00" && items->back() == "ch-63",
                "WS extract_json_string_array supports 64 items (>16)");

        // 3. Tailscale advertise-routes (>64 CIDRs)
        std::string ts_ep =
            "schema-version 1\nrole \"client\"\n"
            "endpoint \"ts0\" type=\"tailscale\" {\n"
            "  control-url \"https://control.example.com\"\n"
            "  control-address \"198.51.100.10\"\n"
            "  control-key \"mkey:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"\n"
            "  ca-file \"/etc/ssl/ca.pem\"\n"
            "  auth-key-file \"/etc/nexus/ts.key\"\n"
            "  interface-name \"ts0\"\n"
            "  ephemeral #true\n"
            "  listen host=\"127.0.0.1\" port=41641\n"
            "  advertise-routes";
        for (int i = 0; i < 100; ++i) ts_ep += std::format(" \"10.{}.0.0/16\"", i + 1);
        ts_ep += "\n}\n";
        auto parsed_ts = cli::tailscale_endpoint::parse(ts_ep);
        require(parsed_ts.has_value() && parsed_ts->has_value() && (*parsed_ts)->advertise_routes.size() == 100,
                "Tailscale advertise-routes supports 100 CIDRs (>64)");

        // 4. Tailscale packet_filter (>512 rules -> 1024 rules + merged-range binary search)
        std::string acl = "[";
        for (int i = 0; i < 1024; ++i) {
            if (i) acl.push_back(',');
            int const a = (i / 256) + 1;
            int const b = i % 256;
            acl += std::format(
                "{{\"SrcIPs\":[\"10.{}.{}.0/24\"],\"DstPorts\":[{{\"IP\":\"100.64.0.1\",\"Ports\":{{\"First\":{},\"Last\":{}}}}}],\"IPProto\":[6]}}",
                a, b, 1000 + i, 1000 + i);
        }
        acl += "]";
        tailscale::packet_filter::Filter pf;
        auto up = pf.update(acl, std::nullopt);
        require(up.has_value(), "Tailscale packet_filter accepts 1024 ACL rules (>512)");
        auto mk_ip4 = [](std::uint8_t x, std::uint8_t y, std::uint8_t z, std::uint8_t w) {
            tailscale::packet_filter::Address addr{};
            addr.family = 4;
            addr.bytes[0] = x; addr.bytes[1] = y; addr.bytes[2] = z; addr.bytes[3] = w;
            return addr;
        };
        auto dst = mk_ip4(100, 64, 0, 1);
        require(pf.matches(mk_ip4(10, 1, 0, 42), dst, 6, 1000), "packet_filter matches rule #0");
        require(pf.matches(mk_ip4(10, 3, 0, 9), dst, 6, 1512), "packet_filter matches rule #512");
        require(pf.matches(mk_ip4(10, 4, 255, 7), dst, 6, 2023), "packet_filter matches rule #1023");
        require(!pf.matches(mk_ip4(10, 4, 255, 7), dst, 6, 1000), "packet_filter rejects mismatched port");
        require(!pf.matches(mk_ip4(10, 99, 1, 1), dst, 6, 1512), "packet_filter rejects unmatched source");
        require(tailscale::packet_filter::max_chunks == 64, "packet_filter anti-DoS max_chunks preserved");

        std::cout << "  [PASS] Config caps (http-clients/headers/providers/probes/regex/cors/mux/splice), WS (>16), Tailscale (>64 routes, 1024 ACL rules)\n";
    }
}

auto main() -> int {
    std::cout << "Running Wave 37 Track 1 hard-limits removal scale & correctness tests...\n";
    test_outbounds_and_selectors_scale();
    test_multi_user_inbound_configs();
    test_o1_auth_tables();
    test_config_caps_ws_and_tailscale();
    std::cout << "ALL WAVE 37 TRACK 1 TESTS PASSED\n";
    return 0;
}
