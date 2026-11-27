// Round 3 provider/importer/expansion audit regression tests:
// - R3 P1-1: failed import must never overwrite or delete pre-existing secret files
// - R3 P1-3: multi-provider same-named nodes must preserve provider ownership for `use`
// - R3 P1-4: forward-referenced sub-groups in Clash YAML / sing-box JSON must not expand to all nodes
// - R3 P2-3: `use` and explicit `member`/`members` must deduplicate regardless of declaration order
#if !defined(_WIN32)
#include <sys/stat.h>
#include <unistd.h>
#endif

import std;
import cli.proxy_providers;
import config;
import provider;
import rulefile;

namespace {
    int g_failures = 0;

    auto check(bool ok, std::string_view msg) -> void {
        if (!ok) {
            ++g_failures;
            std::cerr << "FAIL: " << msg << '\n';
        }
    }

    struct TempDir {
        std::filesystem::path path;
        explicit TempDir(std::string_view stem) {
#if !defined(_WIN32)
            auto pid = static_cast<std::uint64_t>(::getpid());
#else
            auto pid = std::uint64_t{0};
#endif
            auto tick = static_cast<std::uint64_t>(std::chrono::steady_clock::now().time_since_epoch().count());
            path = std::filesystem::temp_directory_path() / std::format("{}-{}-{}", stem, pid, tick);
            std::error_code ec;
            std::filesystem::remove_all(path, ec);
            std::filesystem::create_directories(path);
        }
        ~TempDir() {
            std::error_code ec;
            std::filesystem::remove_all(path, ec);
        }
    };

    auto write_text(std::filesystem::path const& p, std::string_view content) -> void {
        std::ofstream f(p, std::ios::out | std::ios::binary | std::ios::trunc);
        f.write(content.data(), static_cast<std::streamsize>(content.size()));
    }

    auto find_selector(config::Config const& cfg, std::string_view name) -> config::OutboundSelector const* {
        auto it = std::ranges::find(cfg.selectors, name, &config::OutboundSelector::name);
        return it == cfg.selectors.end() ? nullptr : &*it;
    }

    auto find_socks5_port(config::Config const& cfg, std::string_view name) -> std::uint16_t {
        auto it = std::ranges::find(cfg.tcp_proxy_outbounds, name, &config::NamedTcpProxyOutbound::name);
        return it == cfg.tcp_proxy_outbounds.end() ? 0 : it->config.port;
    }

    auto test_r3_p1_1_failed_import_preserves_existing_secret(TempDir const& tmp) -> void {
        auto sec_dir = tmp.path / "secrets";
        constexpr std::string_view valid_uri =
            "vless://11111111-1111-1111-1111-111111111111@198.51.100.10:443?security=tls&sni=edge.test#edge\n";
        constexpr std::string_view bad_reality_uri =
            "vless://22222222-2222-2222-2222-222222222222@198.51.100.10:443?security=reality&sni=edge.test&pbk=NOT-VALID-KEY!!!#edge\n";

        auto first = provider::convert_config_to_kdl(valid_uri, {.secrets_dir = sec_dir.string()});
        check(bool(first), first ? "first valid import succeeds" : first.error());
        auto secret_file = sec_dir / "edge-uuid.secret";
        auto orig = rulefile::read_regular_file(secret_file.string());
        check(orig && *orig == "11111111-1111-1111-1111-111111111111", "initial secret file written with exact UUID");
#if !defined(_WIN32)
        struct stat st{};
        check(::stat(secret_file.c_str(), &st) == 0 && (st.st_mode & 0777) == 0600, "initial secret file mode 0600");
#endif

        auto second = provider::convert_config_to_kdl(bad_reality_uri, {.secrets_dir = sec_dir.string()});
        check(bool(second) && !second->second.empty(), "second invalid Reality import returns warning");
        auto after_kdl = rulefile::read_regular_file(secret_file.string());
        check(after_kdl && *after_kdl == "11111111-1111-1111-1111-111111111111",
              "R3 P1-1: failed convert_config_to_kdl must not delete or overwrite existing secret");

        auto third = provider::convert_config_to_nodes_json(bad_reality_uri, {.secrets_dir = sec_dir.string()});
        check(!third, "invalid-only nodes-json import fails");
        auto after_json = rulefile::read_regular_file(secret_file.string());
        check(after_json && *after_json == "11111111-1111-1111-1111-111111111111",
              "R3 P1-1: failed convert_config_to_nodes_json must not delete or overwrite existing secret");

        bool has_tmp = false;
        for (auto const& ent : std::filesystem::directory_iterator(sec_dir)) {
            if (ent.path().filename().string().contains(".tmp.")) has_tmp = true;
        }
        check(!has_tmp, "R3 P1-1: no leftover temp secret files after failed imports");

        // Also verify ProxyProviderManager reload failure preserves existing provider secret on disk.
        auto sub = tmp.path / "p1_sub.txt";
        auto pcache = tmp.path / "p1_cache";
        auto cfg_path = tmp.path / "p1.kdl";
        write_text(sub, valid_uri);
        auto raw_cfg = std::format(R"kdl(
schema-version 1
role "client"
proxy-providers {{
  provider "sub" {{ type "file"; path "{}"; cache-dir "{}"; }}
}}
inbounds {{ inbound "in" type="socks5" {{ listen "127.0.0.1:1080"; authentication "none"; }} }}
outbounds {{ direct; selector "proxy" {{ use "sub"; }}; }}
routing {{ default "proxy"; }}
)kdl", sub.string(), pcache.string());
        write_text(cfg_path, raw_cfg);
        cli::ProxyProviderManager mgr;
        auto exp = mgr.prepare_initial(raw_cfg, cfg_path.string(), true);
        check(bool(exp), exp ? "provider initial load succeeds" : exp.error());
        auto prov_sec = pcache / "secrets" / "sub-edge-uuid.secret";
        auto prov_before = rulefile::read_regular_file(prov_sec.string());
        check(prov_before && *prov_before == "11111111-1111-1111-1111-111111111111", "provider secret created");

        write_text(sub, bad_reality_uri);
        cli::ProxyProviderManager mgr2;
        auto exp2 = mgr2.prepare_initial(raw_cfg, cfg_path.string(), true);
        check(!exp2, "broken provider subscription rejected");
        auto prov_after = rulefile::read_regular_file(prov_sec.string());
        check(prov_after && *prov_after == "11111111-1111-1111-1111-111111111111",
              "R3 P1-1: failed provider load must preserve existing provider secret file");
    }

    auto test_r3_p1_3_multi_provider_collision(TempDir const& tmp) -> void {
        auto sub_a = tmp.path / "sub_a.yaml";
        auto sub_b = tmp.path / "sub_b.yaml";
        auto cfg_path = tmp.path / "multi.kdl";
        write_text(sub_a, "proxies:\n  - {name: \"edge\", type: socks5, server: 127.0.0.1, port: 18801}\n");
        write_text(sub_b, "proxies:\n  - {name: \"edge\", type: socks5, server: 127.0.0.1, port: 18802}\n");

        auto raw_cfg = std::format(R"kdl(
schema-version 1
role "client"
proxy-providers {{
  provider "a" {{ type "file"; path "{}"; cache-dir "{}"; }}
  provider "b" {{ type "file"; path "{}"; cache-dir "{}"; }}
}}
inbounds {{ inbound "in" type="socks5" {{ listen "127.0.0.1:1080"; authentication "none"; }} }}
outbounds {{
  direct
  selector "only-b" {{ use "b"; }}
  selector "only-a" {{ use "a"; }}
  selector "both" {{ use "a"; use "b"; }}
}}
routing {{ default "only-b"; }}
)kdl", sub_a.string(), (tmp.path / "ca").string(), sub_b.string(), (tmp.path / "cb").string());
        write_text(cfg_path, raw_cfg);

        cli::ProxyProviderManager mgr;
        auto expanded = mgr.prepare_initial(raw_cfg, cfg_path.string(), true);
        check(bool(expanded), expanded ? "multi-provider expand succeeds" : expanded.error());
        if (expanded) {
            auto parsed = config::parse_kdl(*expanded);
            check(bool(parsed), parsed ? "multi-provider expanded KDL parses" : parsed.error());
            if (parsed) {
                auto const* gb = find_selector(*parsed, "only-b");
                auto const* ga = find_selector(*parsed, "only-a");
                auto const* gboth = find_selector(*parsed, "both");
                check(gb && gb->members.size() == 1 && find_socks5_port(*parsed, gb->members[0]) == 18802,
                      "R3 P1-3: use \"b\" must route to provider b's port 18802, never provider a's 18801");
                check(ga && ga->members.size() == 1 && find_socks5_port(*parsed, ga->members[0]) == 18801,
                      "R3 P1-3: use \"a\" must route to provider a's port 18801");
                check(gboth && gboth->members.size() == 2 &&
                      find_socks5_port(*parsed, gboth->members[0]) == 18801 &&
                      find_socks5_port(*parsed, gboth->members[1]) == 18802,
                      "R3 P1-3: combined use \"a\" + use \"b\" retains both distinct servers");
            }
        }

        // Ambiguous bare `member "edge"` referencing a cross-provider colliding tag must fail explicitly.
        std::map<std::string, std::vector<std::pair<std::string, std::string>>> provs{
            {"a", {{"edge", "  outbound \"edge\" type=\"socks5\" {\n    server host=\"127.0.0.1\" port=18801\n  }\n"}}},
            {"b", {{"edge", "  outbound \"edge\" type=\"socks5\" {\n    server host=\"127.0.0.1\" port=18802\n  }\n"}}},
        };
        constexpr std::string_view ambig_kdl = R"kdl(
schema-version 1
role "client"
inbounds { inbound "in" type="socks5" { listen "127.0.0.1:1080"; authentication "none"; } }
outbounds { direct; selector "g" { member "edge"; }; }
routing { default "g"; }
)kdl";
        auto ambig = provider::expand_providers_in_kdl(ambig_kdl, provs);
        check(!ambig && ambig.error().contains("ambiguous"),
              "R3 P1-3: bare member referencing colliding multi-provider tag rejected explicitly");

        // Static outbound "edge" coexisting with provider "b" node "edge": static keeps bare name, `use "b"` gets 18802.
        constexpr std::string_view static_collision_kdl = R"kdl(
schema-version 1
role "client"
inbounds { inbound "in" type="socks5" { listen "127.0.0.1:1080"; authentication "none"; } }
outbounds {
  direct
  outbound "edge" type="socks5" { server host="127.0.0.1" port=18800; }
  selector "gb" { use "b"; }
  selector "gs" { member "edge"; }
}
routing { default "gb"; }
)kdl";
        std::map<std::string, std::vector<std::pair<std::string, std::string>>> only_b{
            {"b", {{"edge", "  outbound \"edge\" type=\"socks5\" {\n    server host=\"127.0.0.1\" port=18802\n  }\n"}}},
        };
        auto sc = provider::expand_providers_in_kdl(static_collision_kdl, only_b);
        check(bool(sc), sc ? "static+provider collision expands" : sc.error());
        if (sc) {
            auto parsed = config::parse_kdl(*sc);
            check(bool(parsed), parsed ? "static+provider expanded KDL parses" : parsed.error());
            if (parsed) {
                auto const* gb = find_selector(*parsed, "gb");
                auto const* gs = find_selector(*parsed, "gs");
                check(gb && gb->members.size() == 1 && find_socks5_port(*parsed, gb->members[0]) == 18802,
                      "R3 P1-3: use \"b\" routes to provider b (18802) even when static \"edge\" (18800) exists");
                check(gs && gs->members.size() == 1 && find_socks5_port(*parsed, gs->members[0]) == 18800,
                      "R3 P1-3: static \"edge\" preserves port 18800");
            }
        }
    }

    auto test_r3_p1_4_forward_referenced_subgroups(TempDir const& tmp) -> void {
        constexpr std::string_view clash_yaml = R"yaml(
proxies:
  - {name: "edgeA", type: trojan, server: 198.51.100.1, port: 443, password: "pwA", sni: "a.test"}
  - {name: "edgeB", type: trojan, server: 198.51.100.2, port: 443, password: "pwB", sni: "b.test"}
proxy-groups:
  - name: grandparent
    type: select
    proxies: [parent]
  - name: parent
    type: select
    proxies: [child]
  - name: child
    type: select
    proxies: [edgeB]
  - name: fallback-unknown
    type: select
    proxies: [nonexistent-group]
rules:
  - MATCH,grandparent
)yaml";
        auto converted = provider::convert_config_to_kdl(clash_yaml, {.secrets_dir = (tmp.path / "fg_sec").string()});
        check(bool(converted), converted ? "forward-group Clash YAML converts" : converted.error());
        if (converted) {
            auto parsed = config::parse_kdl(converted->first);
            check(bool(parsed), parsed ? "forward-group Clash KDL parses" : parsed.error());
            if (parsed) {
                auto const* gp = find_selector(*parsed, "grandparent");
                auto const* pa = find_selector(*parsed, "parent");
                auto const* ch = find_selector(*parsed, "child");
                auto const* unk = find_selector(*parsed, "fallback-unknown");
                check(gp && gp->members == std::vector<std::string>{"parent"},
                      "R3 P1-4: grandparent must reference forward-declared parent");
                check(pa && pa->members == std::vector<std::string>{"child"},
                      "R3 P1-4: parent must reference forward-declared child (not [edgeA, edgeB])");
                check(ch && ch->members == std::vector<std::string>{"edgeB"},
                      "R3 P1-4: child must reference only edgeB");
                check(unk && unk->members == std::vector<std::string>{"edgeA", "edgeB"},
                      "R3 P1-4: truly unknown group still falls back to all emitted nodes");
            }
        }

        constexpr std::string_view sb_json = R"json({
  "outbounds": [
    {"type": "direct", "tag": "direct"},
    {"type": "selector", "tag": "parent", "outbounds": ["child"]},
    {"type": "selector", "tag": "child", "outbounds": ["edgeB"]},
    {"type": "trojan", "tag": "edgeA", "server": "198.51.100.3", "server_port": 443, "password": "pwA", "tls": {"enabled": true, "server_name": "a.test"}},
    {"type": "trojan", "tag": "edgeB", "server": "198.51.100.4", "server_port": 443, "password": "pwB", "tls": {"enabled": true, "server_name": "b.test"}}
  ],
  "route": {"final": "parent"}
})json";
        auto sb_conv = provider::convert_config_to_kdl(sb_json, {.secrets_dir = (tmp.path / "sb_fg_sec").string()});
        check(bool(sb_conv), sb_conv ? "forward-group sing-box JSON converts" : sb_conv.error());
        if (sb_conv) {
            auto parsed = config::parse_kdl(sb_conv->first);
            check(bool(parsed), parsed ? "forward-group sing-box KDL parses" : parsed.error());
            if (parsed) {
                auto const* pa = find_selector(*parsed, "parent");
                auto const* ch = find_selector(*parsed, "child");
                check(pa && pa->members == std::vector<std::string>{"child"},
                      "R3 P1-4: sing-box parent must reference forward-declared child");
                check(ch && ch->members == std::vector<std::string>{"edgeB"},
                      "R3 P1-4: sing-box child must reference edgeB");
            }
        }
    }

    auto test_r3_p2_3_use_and_member_order_independence(TempDir const& tmp) -> void {
        auto sub = tmp.path / "order_sub.yaml";
        auto cfg_path = tmp.path / "order.kdl";
        write_text(sub, R"yaml(
proxies:
  - {name: "edge", type: socks5, server: 127.0.0.1, port: 18811}
  - {name: "backup", type: socks5, server: 127.0.0.1, port: 18812}
)yaml");

        auto check_order = [&](std::string_view group_body, std::vector<std::string> const& expected, std::string_view label) {
            auto raw_cfg = std::format(R"kdl(
schema-version 1
role "client"
proxy-providers {{
  provider "a" {{ type "file"; path "{}"; cache-dir "{}"; }}
}}
inbounds {{ inbound "in" type="socks5" {{ listen "127.0.0.1:1080"; authentication "none"; }} }}
outbounds {{
  direct
  selector "g" {{
    {}
  }}
}}
routing {{ default "g"; }}
)kdl", sub.string(), (tmp.path / "ord_cache").string(), group_body);
            write_text(cfg_path, raw_cfg);
            cli::ProxyProviderManager mgr;
            auto exp = mgr.prepare_initial(raw_cfg, cfg_path.string(), true);
            check(bool(exp), exp ? std::string(label) + " expands" : std::string(label) + " expand failed: " + exp.error());
            if (!exp) return;
            auto parsed = config::parse_kdl(*exp);
            check(bool(parsed), parsed ? std::string(label) + " parses" : std::string(label) + " parse failed: " + parsed.error());
            if (!parsed) return;
            auto const* g = find_selector(*parsed, "g");
            check(g && g->members == expected, std::string(label) + " deduplicated members match");
        };

        check_order("member \"edge\"\n    use \"a\"", {"edge", "backup"}, "R3 P2-3: member before use");
        check_order("use \"a\"\n    member \"edge\"", {"edge", "backup"}, "R3 P2-3: use before member");
        check_order("use \"a\"\n    members \"edge\" \"direct\"", {"edge", "backup", "direct"},
                    "R3 P2-3: use before plural members");
        check_order("members \"direct\" \"edge\"\n    use \"a\"", {"direct", "edge", "backup"},
                    "R3 P2-3: plural members before use");
    }
}

int main() {
    TempDir tmp("nexus-w34-prov");
    test_r3_p1_1_failed_import_preserves_existing_secret(tmp);
    test_r3_p1_3_multi_provider_collision(tmp);
    test_r3_p1_4_forward_referenced_subgroups(tmp);
    test_r3_p2_3_use_and_member_order_independence(tmp);
    if (g_failures == 0) std::cout << "WAVE 34 PROVIDER AUDIT TESTS PASSED\n";
    return g_failures == 0 ? 0 : 1;
}
