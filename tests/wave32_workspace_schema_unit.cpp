// Wave 32 Core Workspace Schema Sync unit tests:
// - h2mux preservation in workspace_emit.cpp and kdl_emit.cpp
// - policy_group.interrupt_exist_connections
// - routing_profile.auto_detect_interface & find_process
// - tls.fragment, tls.record_fragment, tls.ech_query_server_name (and QUIC non-TCP suppression)
// - transport WS max_early_data / early_data_header_name & gRPC keepalive fields
// - backwards compatibility with minimal legacy workspace JSON + share bundle round-trip
import std;
import config;
import provider;
import provider.workspace_compose;

namespace {
    void require(bool cond, std::string_view msg) {
        if (!cond) {
            std::cerr << "FAIL: " << msg << '\n';
            std::exit(1);
        }
    }

    constexpr std::string_view kHostJson = R"({
        "schema_version": 1,
        "platform": "desktop-linux",
        "log_level": "info",
        "desktop": { "enable_mixed": true, "mixed_listen": "127.0.0.1:7890" }
    })";

    auto compose_ok(std::string_view ws_json, std::string_view active_id = {})
        -> std::pair<provider::WorkspaceComposeResult, config::Config> {
        provider::WorkspaceComposeOptions opts{};
        opts.active_profile_id = std::string(active_id);
        auto res = provider::compose_workspace(ws_json, kHostJson, opts);
        if (!res.ok) {
            std::cerr << "compose_workspace failed:";
            for (auto const& e : res.errors) std::cerr << " " << e;
            std::cerr << "\nKDL:\n" << res.kdl << '\n';
            std::exit(1);
        }
        auto parsed = config::parse_kdl(res.kdl);
        if (!parsed) {
            std::cerr << "config::parse_kdl failed: " << parsed.error() << "\nKDL:\n" << res.kdl << '\n';
            std::exit(1);
        }
        return {std::move(res), std::move(*parsed)};
    }

    auto has_warning(provider::WorkspaceComposeResult const& res, std::string_view needle) -> bool {
        return std::ranges::any_of(res.warnings, [&](auto const& w) { return w.contains(needle); });
    }

    void test_h2mux_preservation() {
        constexpr std::string_view ws = R"({
            "schema_version": 1,
            "profiles": [
                {
                    "id": "n-h2", "remarks": "H2MuxNode", "kind": "node",
                    "node": {
                        "protocol": "vless", "server": "h2.example.test", "port": 443,
                        "password": "11111111-2222-3333-4444-555555555555",
                        "tls": { "enabled": true, "sni": "h2.example.test" },
                        "multiplex": { "enabled": true, "protocol": "h2mux", "max_connections": 4, "padding": true }
                    }
                },
                {
                    "id": "n-s1", "remarks": "Smux1Node", "kind": "node",
                    "node": {
                        "protocol": "vless", "server": "s1.example.test", "port": 443,
                        "password": "11111111-2222-3333-4444-555555555555",
                        "tls": { "enabled": true, "sni": "s1.example.test" },
                        "multiplex": { "enabled": true, "protocol": "smux-v1" }
                    }
                },
                {
                    "id": "n-upper", "remarks": "UpperH2", "kind": "node",
                    "node": {
                        "protocol": "trojan", "server": "up.example.test", "port": 443,
                        "password": "secret-password",
                        "tls": { "enabled": true, "sni": "up.example.test" },
                        "multiplex": { "enabled": true, "protocol": "H2MUX" }
                    }
                }
            ]
        })";
        auto [res, cfg] = compose_ok(ws, "n-h2");
        require(res.kdl.contains("protocol \"h2mux\""), "workspace emit must preserve h2mux");
        require(res.kdl.contains("protocol \"smux-v1\""), "workspace emit must preserve smux-v1");
        require(cfg.vless_outbounds.size() == 2, "expected 2 vless outbounds");
        require(cfg.vless_outbounds[0].config.multiplex.has_value(), "n-h2 multiplex parsed");
        require(cfg.vless_outbounds[0].config.multiplex->protocol == config::MultiplexProtocol::h2mux,
                "n-h2 parsed protocol must be h2mux");
        require(cfg.vless_outbounds[1].config.multiplex->protocol == config::MultiplexProtocol::smux_v1,
                "n-s1 parsed protocol must be smux_v1");
        require(cfg.trojan_outbounds.size() == 1 && cfg.trojan_outbounds[0].config.multiplex.has_value(),
                "trojan multiplex parsed");
        require(cfg.trojan_outbounds[0].config.multiplex->protocol == config::MultiplexProtocol::h2mux,
                "uppercase H2MUX must normalize to h2mux");

        // Also verify provider::emit_outbound_kdl (kdl_emit.cpp) preserves h2mux (default & explicit).
        provider::SecretWriter writer = [](std::string_view hint, std::string_view)
            -> std::expected<std::string, std::string> { return "/tmp/sec-" + std::string(hint); };
        provider::ParsedProxy p{};
        p.tag = "kdl-h2";
        p.protocol = provider::ProxyProtocol::vless;
        p.host = "kdl.example.test";
        p.port = 443;
        p.secret = "11111111-2222-3333-4444-555555555555";
        p.tls_enabled = true;
        p.sni = "kdl.example.test";
        p.mux_enabled = true;
        p.mux_protocol = "h2mux";
        auto kdl = provider::emit_outbound_kdl(p, writer, {});
        require(kdl.has_value() && kdl->contains("protocol \"h2mux\""), "kdl_emit must preserve h2mux");
        p.mux_protocol = "smux-v1";
        auto kdl1 = provider::emit_outbound_kdl(p, writer, {});
        require(kdl1.has_value() && kdl1->contains("protocol \"smux-v1\""), "kdl_emit must preserve smux-v1");
    }

    void test_policy_group_and_routing_profile_fields() {
        constexpr std::string_view ws = R"({
            "schema_version": 1,
            "profiles": [
                {
                    "id": "n1", "remarks": "Node1", "kind": "node",
                    "node": {
                        "protocol": "vless", "server": "n1.example.test", "port": 443,
                        "password": "11111111-2222-3333-4444-555555555555",
                        "tls": { "enabled": true, "sni": "n1.example.test" }
                    }
                },
                {
                    "id": "pg-int", "remarks": "InterruptGroup", "kind": "policy_group",
                    "policy_group": {
                        "strategy": "url-test",
                        "member_ids": ["n1"],
                        "interrupt_exist_connections": true
                    }
                }
            ],
            "routing_profiles": [
                {
                    "id": "rp1", "name": "Default", "is_active": true,
                    "auto_detect_interface": true,
                    "find_process": true,
                    "rules": []
                }
            ]
        })";
        auto [res, cfg] = compose_ok(ws, "pg-int");
        require(res.kdl.contains("interrupt-exist-connections #true"), "missing interrupt-exist-connections");
        require(res.kdl.contains("auto-detect-interface #true"), "missing auto-detect-interface");
        require(res.kdl.contains("find-process #true"), "missing find-process");
        require(cfg.defaults.auto_detect_interface, "parsed defaults.auto_detect_interface must be true");
        require(cfg.defaults.find_process, "parsed defaults.find_process must be true");
        bool found_int = std::ranges::any_of(cfg.selectors, [](auto const& s) { return s.interrupt_exist_connections; });
        require(found_int, "parsed policy group interrupt_exist_connections must be true");
    }

    void test_tls_fragment_and_ech_query_sni() {
        constexpr std::string_view ws = R"({
            "schema_version": 1,
            "profiles": [
                {
                    "id": "n-frag", "remarks": "FragOnly", "kind": "node",
                    "node": {
                        "protocol": "vless", "server": "f1.example.test", "port": 443,
                        "password": "11111111-2222-3333-4444-555555555555",
                        "tls": { "enabled": true, "sni": "f1.example.test", "fragment": true }
                    }
                },
                {
                    "id": "n-both", "remarks": "FragAndRec", "kind": "node",
                    "node": {
                        "protocol": "trojan", "server": "f2.example.test", "port": 443,
                        "password": "secret-password",
                        "tls": { "enabled": true, "sni": "f2.example.test", "fragment": true, "record_fragment": true }
                    }
                },
                {
                    "id": "n-rec", "remarks": "RecOnly", "kind": "node",
                    "node": {
                        "protocol": "anytls", "server": "f3.example.test", "port": 443,
                        "password": "secret-password",
                        "tls": { "enabled": true, "sni": "f3.example.test", "fragment": false, "record_fragment": true }
                    }
                },
                {
                    "id": "n-quic", "remarks": "Hy2NoFrag", "kind": "node",
                    "node": {
                        "protocol": "hysteria2", "server": "hy2.example.test", "port": 443,
                        "password": "secret-password",
                        "tls": { "enabled": true, "sni": "hy2.example.test", "fragment": true, "record_fragment": true }
                    }
                }
            ]
        })";
        auto [res, cfg] = compose_ok(ws, "n-frag");
        require(res.kdl.contains("tls-fragment #true"), "vless fragment-only must emit tls-fragment #true");
        require(has_warning(res, "tls.fragment ignored on non-TCP outbound"), "QUIC outbound must warn & skip tls-fragment");
        require(cfg.vless_outbounds.size() == 1 && cfg.vless_outbounds[0].config.tls_fragment.enabled &&
                !cfg.vless_outbounds[0].config.tls_fragment.record_fragment, "vless tls_fragment parsed");
        require(cfg.trojan_outbounds.size() == 1 && cfg.trojan_outbounds[0].config.tls_fragment.enabled &&
                cfg.trojan_outbounds[0].config.tls_fragment.record_fragment, "trojan tls_fragment + record_fragment parsed");
        require(cfg.anytls_outbounds.size() == 1 && !cfg.anytls_outbounds[0].config.connection.tls_fragment.enabled &&
                cfg.anytls_outbounds[0].config.connection.tls_fragment.record_fragment, "anytls record-fragment-only parsed");

#ifdef NEXUS_DNS_RESPONSE
        constexpr std::string_view ws_ech = R"({
            "schema_version": 1,
            "profiles": [
                {
                    "id": "n-ech", "remarks": "EchQsn", "kind": "node",
                    "node": {
                        "protocol": "vless", "server": "ech.example.test", "port": 443,
                        "password": "11111111-2222-3333-4444-555555555555",
                        "tls": {
                            "enabled": true, "sni": "ech.example.test",
                            "ech_mode": "dns", "ech_query_server_name": "public.example.net"
                        }
                    }
                },
                {
                    "id": "n-ech-bad", "remarks": "EchBadIp", "kind": "node",
                    "node": {
                        "protocol": "trojan", "server": "ech2.example.test", "port": 443,
                        "password": "secret-password",
                        "tls": {
                            "enabled": true, "sni": "ech2.example.test",
                            "ech_mode": "dns", "ech_query_server_name": "1.2.3.4"
                        }
                    }
                }
            ]
        })";
        auto [ech_res, ech_cfg] = compose_ok(ws_ech, "n-ech");
        require(ech_res.kdl.contains("ech-query-server-name \"public.example.net\""), "missing ech-query-server-name");
        require(has_warning(ech_res, "ignored invalid ech_query_server_name"), "IP ech_query_server_name must warn");
        require(ech_cfg.vless_outbounds.size() == 1 && ech_cfg.vless_outbounds[0].config.ech.dns &&
                ech_cfg.vless_outbounds[0].config.ech.query_server_name == "public.example.net",
                "parsed ech.query_server_name mismatch");
        require(ech_cfg.trojan_outbounds.size() == 1 && ech_cfg.trojan_outbounds[0].config.ech.query_server_name.empty(),
                "invalid IP ech_query_server_name must not be emitted");
#endif
    }

    void test_transport_ws_early_data_and_grpc_keepalive() {
        constexpr std::string_view ws = R"({
            "schema_version": 1,
            "profiles": [
                {
                    "id": "n-ws", "remarks": "WsEarly", "kind": "node",
                    "node": {
                        "protocol": "vless", "server": "ws.example.test", "port": 443,
                        "password": "11111111-2222-3333-4444-555555555555",
                        "tls": { "enabled": true, "sni": "ws.example.test" },
                        "transport": {
                            "type": "ws", "host": "ws.example.test", "path": "/ray",
                            "max_early_data": 2048,
                            "early_data_header_name": "Sec-WebSocket-Protocol"
                        }
                    }
                },
                {
                    "id": "n-ws-clamp", "remarks": "WsClamp", "kind": "node",
                    "node": {
                        "protocol": "vless", "server": "ws2.example.test", "port": 443,
                        "password": "11111111-2222-3333-4444-555555555555",
                        "tls": { "enabled": true, "sni": "ws2.example.test" },
                        "transport": {
                            "type": "websocket", "path": "/ed",
                            "max_early_data": 99999,
                            "early_data_header_name": "Host"
                        }
                    }
                },
                {
                    "id": "n-hu", "remarks": "HttpUpgradeNoEd", "kind": "node",
                    "node": {
                        "protocol": "vless", "server": "hu.example.test", "port": 443,
                        "password": "11111111-2222-3333-4444-555555555555",
                        "tls": { "enabled": true, "sni": "hu.example.test" },
                        "transport": {
                            "type": "httpupgrade", "path": "/hu",
                            "max_early_data": 2048,
                            "early_data_header_name": "Sec-WebSocket-Protocol"
                        }
                    }
                },
                {
                    "id": "n-grpc", "remarks": "GrpcKeepalive", "kind": "node",
                    "node": {
                        "protocol": "vless", "server": "gr.example.test", "port": 443,
                        "password": "11111111-2222-3333-4444-555555555555",
                        "tls": { "enabled": true, "sni": "gr.example.test" },
                        "transport": {
                            "type": "grpc", "service_name": "tun", "authority": "gr.example.test",
                            "grpc_idle_timeout_ms": 30000,
                            "grpc_ping_timeout_ms": 10000,
                            "grpc_permit_without_stream": true
                        }
                    }
                }
            ]
        })";
        auto [res, cfg] = compose_ok(ws, "n-ws");
        require(has_warning(res, "ignored invalid early_data_header_name"), "forbidden Host header must warn");
        require(cfg.vless_outbounds.size() == 4, "expected 4 vless outbounds");
        auto const& ws_t = cfg.vless_outbounds[0].config.transport;
        require(ws_t && ws_t->websocket && ws_t->max_early_data == 2048 &&
                ws_t->early_data_header_name == "Sec-WebSocket-Protocol", "WS early data parsed");
        auto const& ws2_t = cfg.vless_outbounds[1].config.transport;
        require(ws2_t && ws2_t->max_early_data == 8192 && ws2_t->early_data_header_name.empty(),
                "WS early data clamped to 8192 & invalid header omitted");
        auto const& hu_t = cfg.vless_outbounds[2].config.transport;
        require(hu_t && !hu_t->websocket && hu_t->max_early_data == 0 && hu_t->early_data_header_name.empty(),
                "httpupgrade must not emit WS early data");
        auto const& gr_t = cfg.vless_outbounds[3].config.grpc;
        require(gr_t && gr_t->idle_timeout_ms == 30000 && gr_t->ping_timeout_ms == 10000 &&
                gr_t->permit_without_stream, "gRPC keepalive fields parsed");
    }

    void test_legacy_backwards_compat_and_share_roundtrip() {
        constexpr std::string_view legacy_ws = R"({
            "schema_version": 1,
            "profiles": [
                {
                    "id": "old1", "remarks": "Legacy", "kind": "node",
                    "node": {
                        "protocol": "vless", "server": "old.example.test", "port": 443,
                        "password": "11111111-2222-3333-4444-555555555555",
                        "tls": { "enabled": true, "sni": "old.example.test" }
                    }
                }
            ]
        })";
        auto [res, cfg] = compose_ok(legacy_ws, "old1");
        require(!res.kdl.contains("tls-fragment"), "legacy must not emit tls-fragment");
        require(!res.kdl.contains("interrupt-exist-connections"), "legacy must not emit interrupt-exist-connections");
        require(!res.kdl.contains("auto-detect-interface"), "legacy must not emit auto-detect-interface");
        require(!res.kdl.contains("find-process"), "legacy must not emit find-process");
        require(!cfg.defaults.auto_detect_interface && !cfg.defaults.find_process, "legacy defaults false");

        // Share export/import round-trip preserves new fields automatically via Glaze reflection.
        constexpr std::string_view full_ws = R"({
            "schema_version": 1,
            "profiles": [
                {
                    "id": "s1", "remarks": "ShareNode", "kind": "node",
                    "node": {
                        "protocol": "vless", "server": "sh.example.test", "port": 443,
                        "password": "11111111-2222-3333-4444-555555555555",
                        "tls": { "enabled": true, "sni": "sh.example.test", "fragment": true, "record_fragment": true },
                        "transport": { "type": "grpc", "service_name": "s", "grpc_idle_timeout_ms": 15000, "grpc_permit_without_stream": true },
                        "multiplex": { "enabled": true, "protocol": "h2mux" }
                    }
                }
            ]
        })";
        auto exp = provider::export_workspace_share(full_ws, {"s1"});
        require(exp.ok && exp.exported_count == 1, "share export ok");
        auto imp = provider::import_workspace_share(R"({"schema_version":1,"profiles":[]})", exp.uri);
        require(imp.ok && imp.imported_ids.size() == 1, "share import ok");
        auto [imp_res, _] = compose_ok(imp.workspace_json, imp.imported_ids[0]);
        require(imp_res.kdl.contains("record-fragment #true"), "share roundtrip preserves record_fragment");
        require(imp_res.kdl.contains("idle-timeout-ms 15000"), "share roundtrip preserves grpc_idle_timeout_ms");
        require(imp_res.kdl.contains("permit-without-stream #true"), "share roundtrip preserves grpc_permit_without_stream");
        require(imp_res.kdl.contains("protocol \"h2mux\""), "share roundtrip preserves h2mux");
    }
}

auto main() -> int {
    test_h2mux_preservation();
    test_policy_group_and_routing_profile_fields();
    test_tls_fragment_and_ech_query_sni();
    test_transport_ws_early_data_and_grpc_keepalive();
    test_legacy_backwards_compat_and_share_roundtrip();
    std::cout << "wave32_workspace_schema_unit OK\n";
    return 0;
}
