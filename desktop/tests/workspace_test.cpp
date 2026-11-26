#ifndef _WIN32
#include <sys/stat.h>
#endif

import std;
import desktop.desktop_host_config;
import desktop.mini_json;
import desktop.share_link;
import desktop.telemetry_store;
import desktop.workspace_composer;
import desktop.workspace_models;
import desktop.workspace_store;

#include "../src/workspace_ui_helpers.hpp"

namespace {
    auto expect(bool cond, std::string_view msg) -> void {
        if (!cond) throw std::runtime_error(std::string(msg));
    }

    auto make_temp_dir(std::string_view suffix) -> std::filesystem::path {
        auto dir = std::filesystem::temp_directory_path() / ("nexus-ws-test-" + std::string(suffix));
        std::error_code ec;
        std::filesystem::remove_all(dir, ec);
        std::filesystem::create_directories(dir, ec);
        return dir;
    }

    auto test_workspace_5kind_roundtrip_and_0600() -> void {
        auto dir = make_temp_dir("roundtrip");
        auto ws_path = dir / "workspace.json";

        auto doc = desktop::make_default_workspace();
        doc.revision = 7;
        doc.updated_at_ms = 1764000000000LL;

        desktop::WorkspaceProfileItem p_node{
            .id = "n-hk-1", .remarks = "HK Edge 01", .subscription_id = "sub-main", .is_from_sub = true, .kind = "node",
        };
        p_node.node.protocol = "vless";
        p_node.node.server = "hk1.example.net";
        p_node.node.port = 443;
        p_node.node.password = "secret-uuid-token";
        p_node.node.flow = "xtls-rprx-vision";
        p_node.node.tls.enabled = true;
        p_node.node.tls.sni = "cdn.example.net";
        p_node.node.tls.cert_sha256 = {"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"};
        p_node.node.tls.reality_public_key = "pub-key-123";
        p_node.node.transport.type = "tcp"; // P1 #2: must normalize to "" on decode!
        p_node.node.transport.path = "/stream";
        p_node.node.multiplex = {.enabled = true, .protocol = "h2mux", .max_connections = 4, .padding = true};
        p_node.node.extra.hy2_ports = "20000-20100";
        p_node.node.extra.tuic_udp_over_stream = true;
        doc.profiles.push_back(std::move(p_node));

        doc.profiles.push_back({
            .id = "co-1", .remarks = "Custom Out", .subscription_id = "manual", .is_from_sub = false,
            .kind = "custom_outbound", .custom_outbound_kdl = "outbound \"{{tag}}\" type=\"direct\" {}\n",
        });
        doc.profiles.push_back({
            .id = "grp-auto", .remarks = "Auto Fastest", .subscription_id = "manual", .is_from_sub = false,
            .kind = "policy_group",
            .policy_group = {.strategy = "url-test", .member_ids = {"n-hk-1"}, .tolerance_ms = 80},
        });
        doc.profiles.push_back({
            .id = "chain-1", .remarks = "Relay -> Exit", .subscription_id = "manual", .is_from_sub = false,
            .kind = "proxy_chain", .proxy_chain = {.hop_ids = {"n-hk-1", "co-1"}},
        });
        doc.profiles.push_back({
            .id = "full-1", .remarks = "Full Lab", .subscription_id = "manual", .is_from_sub = false,
            .kind = "full_custom_kdl", .full_custom_kdl = "schema-version 2\noutbound \"direct\" type=\"direct\" {}\n",
        });

        doc.subscriptions.push_back({
            .id = "sub-main", .remarks = "Main Sub", .url = "https://sub.example.net/feed",
            .more_urls = {"https://backup.example.net/feed", "javascript:alert(1)"},
            .enabled = true, .auto_update_minutes = 60, .prev_profile_id = "co-1", .next_profile_id = "grp-auto",
            .usage = {.upload_bytes = 1024, .download_bytes = 4096, .total_bytes = 1048576, .expire_unix_sec = 1893456000,
                      .web_page_url = "https://portal.example.net", .support_url = "ftp://evil.example.net/support"},
        });

        doc.routing_profiles[0].rules.push_back({
            .id = "r-dev", .enabled = true, .scope = "both", .target_type = "profile_id", .target_profile_id = "chain-1",
            .domains = {"dev.example.org"}, .desktop_process = {"curl", "git"}, .android_packages = {"org.example.app"},
            .tls_fragment = true,
        });

        doc.dns.mode = "simple";
        doc.dns.simple.fake_ip_enabled = true;
        doc.dns.simple.strategy = "prefer_ipv4";

        expect(desktop::save_workspace_atomic(ws_path, doc), "save_workspace_atomic succeeds");
#ifndef _WIN32
        struct stat st{};
        expect(::stat(ws_path.c_str(), &st) == 0 && (st.st_mode & 0777) == 0600, "workspace.json written with 0600 mode");
#endif
        auto loaded = desktop::load_workspace(ws_path);
        expect(loaded.has_value(), "load_workspace succeeds");
        expect(loaded->schema_version == 1 && loaded->revision == 7, "schema_version and revision preserved");
        expect(loaded->profiles.size() == 5, "all 5 polymorphic profile kinds preserved");
        expect(loaded->profiles[0].node.transport.type.empty(), "P1 #2: transport.type='tcp' normalized to empty on JSON decode");
        expect(loaded->profiles[0].node.tls.cert_sha256.size() == 1 && loaded->profiles[0].node.extra.tuic_udp_over_stream,
            "nested node TLS + extra fields round-tripped");
        expect(loaded->profiles[2].policy_group.strategy == "url-test" && loaded->profiles[2].policy_group.tolerance_ms == 80,
            "policy_group round-tripped");
        expect(loaded->profiles[3].proxy_chain.hop_ids.size() == 2, "proxy_chain hops round-tripped");
        expect(loaded->subscriptions.size() == 2 && loaded->subscriptions[1].prev_profile_id == "co-1" &&
               loaded->subscriptions[1].next_profile_id == "grp-auto", "subscription chain preserved");
        expect(loaded->subscriptions[1].more_urls.size() == 1 && loaded->subscriptions[1].usage.support_url.empty(),
            "P2 #7: unsafe subscription URLs stripped on workspace_from_json");
        expect(loaded->routing_profiles[0].rules.back().desktop_process.size() == 2 &&
               loaded->routing_profiles[0].rules.back().target_profile_id == "chain-1", "desktop_process & target_profile_id preserved");
        expect(loaded->dns.simple.fake_ip_v4_pool == "198.18.0.0/16" && loaded->dns.simple.strategy == "prefer_ipv4",
            "SimpleDNS invariants preserved");

        auto raw_ws = desktop::workspace_to_json(*loaded);
        expect(!raw_ws.contains("mixed_listen") && !raw_ws.contains("tun_strict_route") && !raw_ws.contains("delay_ms"),
            "workspace.json excludes host and telemetry fields");

        // P2 #8: out-of-range double in json_get_i64 falls back safely
        auto parsed_big = desktop::json_parse(R"({"big": 1e300, "ok": 42.0})");
        expect(parsed_big.has_value() && parsed_big->is_object(), "json_parse big double");
        auto const& bobj = std::get<desktop::JsonObject>(parsed_big->data);
        expect(desktop::json_get_i64(bobj, "big", -9) == -9 && desktop::json_get_i64(bobj, "ok", -9) == 42,
            "P2 #8: json_get_i64 range-checks double before int64 cast");

        std::error_code ec;
        std::filesystem::remove_all(dir, ec);
    }

    auto test_5tier_replacement_uniqueness_and_fail_closed_gc() -> void {
        auto dir = make_temp_dir("subreplace");
        auto sec_dir = dir / "secrets";
        std::filesystem::create_directories(sec_dir);
        {
            std::ofstream(sec_dir / "keep-me.secret") << "tok";
            std::ofstream(sec_dir / "orphan-old.secret") << "old";
            std::ofstream(sec_dir / "orphan-ca.pem") << "pem";
            std::ofstream(sec_dir / "orphan-ech.ech") << "ech";
            std::ofstream(sec_dir / "keep-ca.pem") << "pem2";
            std::ofstream(sec_dir / "control-http.token") << "ctrl";
        }

        auto doc = desktop::make_default_workspace();
        auto mk_node = [](std::string id, std::string rem, std::string srv, std::string pw) {
            desktop::WorkspaceProfileItem p{.id = std::move(id), .remarks = std::move(rem), .subscription_id = "s1", .is_from_sub = true, .kind = "node"};
            p.node.protocol = "vless"; p.node.server = std::move(srv); p.node.port = 443; p.node.password = std::move(pw);
            return p;
        };
        doc.profiles.push_back(mk_node("id-exact", "HK-1", "hk1.example.net", "pw1"));
        doc.profiles.push_back(mk_node("id-rename", "Old-SG", "sg1.example.net", "pw2"));
        doc.profiles.push_back(mk_node("id-rotpw", "JP-1", "jp1.example.net", "pw-old"));
        doc.profiles.push_back(mk_node("id-migrate", "US-West", "old-us.example.net", "pw4"));
        doc.profiles.push_back(mk_node("id-ambig", "DupName", "old-dup.example.net", "pw-d"));
        doc.profiles.push_back(mk_node("id-removed", "Dead-Node", "dead.example.net", "pw5"));
        doc.profiles.push_back({.id = "grp-manual", .remarks = "User Group", .subscription_id = "s1", .is_from_sub = false, .kind = "policy_group"});
        doc.profiles.push_back({.id = "chain-manual", .remarks = "User Chain", .subscription_id = "manual", .is_from_sub = false, .kind = "proxy_chain"});

        std::string active = "id-rename";
        // Fail-closed 1: empty incoming must NOT wipe existing nodes or secrets
        auto fail = desktop::replace_subscription_profiles(doc, "s1", {}, active, sec_dir, {}, true);
        expect(!fail.ok && doc.profiles.size() == 8, "empty incoming fails closed without deleting nodes");
        expect(std::filesystem::exists(sec_dir / "orphan-old.secret"), "fail-closed preserves secrets on error");

        std::vector<desktop::WorkspaceProfileItem> incoming;
        incoming.push_back(mk_node("", "HK-1", "hk1.example.net", "pw1"));           // Tier 1 exact
        incoming.push_back(mk_node("", "New-SG-Name", "sg1.example.net", "pw2"));    // Tier 2 renamed
        incoming.push_back(mk_node("", "JP-1", "jp1.example.net", "pw-rotated"));    // Tier 3 cred rotated
        incoming.push_back(mk_node("", "US-West", "new-us.example.net", "pw4new"));  // Tier 5 unique rename
        incoming.push_back(mk_node("", "DupName", "dup-a.example.net", "pw-a"));     // P2 #9: duplicate incoming Tier 5 -> must NOT steal id-ambig
        incoming.push_back(mk_node("", "DupName", "dup-b.example.net", "pw-b"));     // P2 #9: duplicate incoming Tier 5

        // P1 #6: fail-closed GC when allow_secret_gc=false OR referenced_secret_paths={} with live credentialed nodes!
        auto doc_copy = doc;
        std::string active_copy = active;
        auto no_gc = desktop::replace_subscription_profiles(doc_copy, "s1", incoming, active_copy, sec_dir, {}, true);
        expect(no_gc.ok && no_gc.secrets_pruned == 0 && std::filesystem::exists(sec_dir / "orphan-old.secret"),
            "P1 #6: GC fails closed when referenced_secret_paths is empty with credentialed nodes");

        std::unordered_set<std::string> ref_secrets{"keep-me.secret", "keep-ca.pem"};
        auto ok = desktop::replace_subscription_profiles(doc, "s1", std::move(incoming), active, sec_dir, ref_secrets, true);
        expect(ok.ok && ok.matched_count == 4 && ok.added_count == 2 && ok.removed_count == 2,
            "P2 #9: 5-tier replacement matched 4 unique items, rejected ambiguous incoming Tier 5");
        expect(active == "id-rename", "active profile ID preserved across Tier-2 rename");
        expect(ok.secrets_pruned == 3, "P1 #6: pruned orphan .secret + .pem + .ech");
        expect(std::filesystem::exists(sec_dir / "keep-me.secret") && std::filesystem::exists(sec_dir / "keep-ca.pem"),
            "referenced .secret and .pem kept");
        expect(std::filesystem::exists(sec_dir / "control-http.token"), "non-secret control token untouched");
        expect(!std::filesystem::exists(sec_dir / "orphan-old.secret") &&
               !std::filesystem::exists(sec_dir / "orphan-ca.pem") &&
               !std::filesystem::exists(sec_dir / "orphan-ech.ech"), "all orphan .secret/.pem/.ech removed");

        bool has_ambig = false, has_grp = false, has_chain = false;
        for (auto const& p : doc.profiles) {
            if (p.id == "id-ambig") has_ambig = true;
            if (p.id == "grp-manual") has_grp = true;
            if (p.id == "chain-manual") has_chain = true;
        }
        expect(!has_ambig && has_grp && has_chain, "ambiguous duplicate incoming did not steal id-ambig; manual group/chain kept");

        std::error_code ec;
        std::filesystem::remove_all(dir, ec);
    }

    auto test_subscription_header_parser() -> void {
        std::vector<std::pair<std::string, std::string>> headers{
            {"Subscription-Userinfo", "upload=1048576; download=2097152; total=10737418240; expire=1893456000"},
            {"Profile-Title", "base64:TmV4dXMg5Li75Yqb"},
            {"Profile-Web-Page-Url", "HTTPS://portal.example.net/dashboard"},
            {"Support-Url", "javascript:alert(1)"},
        };
        auto u = desktop::parse_subscription_headers(headers);
        expect(u.upload_bytes == 1048576 && u.download_bytes == 2097152 && u.total_bytes == 10737418240LL && u.expire_unix_sec == 1893456000LL,
            "Subscription-Userinfo fields parsed");
        expect(u.profile_title == "Nexus 主力", "base64 Profile-Title decoded");
        expect(u.web_page_url == "HTTPS://portal.example.net/dashboard", "case-insensitive HTTPS accepted");
        expect(u.support_url.empty(), "unsafe javascript: support_url rejected");
        expect(!desktop::is_safe_subscription_link("ftp://evil.example.net/feed") &&
               !desktop::is_safe_subscription_link("data:text/html,<script>") &&
               desktop::is_safe_subscription_link("TG://resolve?domain=nexus"),
            "zero-alloc is_safe_subscription_link accurate");
    }

    auto test_host_bearer_token_strict_route_and_telemetry() -> void {
        auto dir = make_temp_dir("host");
        auto cfg = desktop::make_default_desktop_host_config(dir, "/run/nexus.sock");
        // P1 #1: control_bearer_file MUST exist with valid 64-hex token and 0600 perms
        expect(!cfg.control_bearer_file.empty(), "default host has control_bearer_file");
        std::filesystem::path token_p(cfg.control_bearer_file);
        expect(std::filesystem::is_regular_file(token_p), "P1 #1: control-http.token provisioned on disk");
#ifndef _WIN32
        struct stat st{};
        expect(::stat(token_p.c_str(), &st) == 0 && (st.st_mode & 0777) == 0600, "P1 #1: control-http.token is 0600");
#endif
        std::string first_tok;
        { std::ifstream in(token_p); std::getline(in, first_tok); }
        expect(first_tok.size() == 64, "P1 #1: control-http.token is 32-byte (64-hex) random token");
        expect(desktop::ensure_control_bearer_token(token_p), "ensure_control_bearer_token idempotent");
        std::string second_tok;
        { std::ifstream in(token_p); std::getline(in, second_tok); }
        expect(first_tok == second_tok, "existing bearer token never overwritten");

        // P2 #9: Linux strict_route notice with mixed=false + lan_listen set, plus no-inbound warning
        cfg.platform = "desktop-linux";
        cfg.enable_mixed = false;
        cfg.lan_listen = "0.0.0.0:7891";
        cfg.enable_tun = true;
        cfg.tun_strict_route = true;
        auto lan_notices = desktop::normalize_desktop_host_config(cfg, true);
        expect(lan_notices.size() == 1, "P2 #9: Linux strict_route emits notice when lan_listen is suppressed");

        cfg.enable_mixed = true;
        auto mix_notices = desktop::normalize_desktop_host_config(cfg, true);
        expect(!cfg.enable_mixed && mix_notices.size() == 1, "Linux strict_route auto-disables enable_mixed with notice");

        desktop::DesktopHostConfig none_cfg = cfg;
        none_cfg.enable_mixed = false; none_cfg.enable_tun = false; none_cfg.lan_listen.clear(); none_cfg.second_local_listen.clear();
        auto none_notices = desktop::normalize_desktop_host_config(none_cfg, true);
        expect(none_notices.size() == 1, "P2 #9: warns when both enable_mixed and enable_tun are disabled");

        auto host_path = dir / "host.json";
        expect(desktop::save_desktop_host_config(host_path, cfg), "save host.json succeeds");
        auto raw_host = desktop::desktop_host_to_json(cfg);
        expect(!raw_host.contains("profiles") && !raw_host.contains("subscriptions"), "host.json never embeds workspace profiles/subs");

        desktop::TelemetryStoreData tel{.schema_version = 1, .active_profile_id = "p1"};
        tel.entries.push_back({.profile_id = "p1", .delay_ms = 42});
        tel.entries.push_back({.profile_id = "p-stale", .delay_ms = 99});
        expect(desktop::save_telemetry_store(dir / "telemetry.json", tel), "save telemetry.json succeeds");
        auto loaded_tel = desktop::load_telemetry_store(dir / "telemetry.json");
        expect(desktop::prune_telemetry_entries(loaded_tel, {"p1"}) == 1 && loaded_tel.entries.size() == 1, "stale telemetry pruned");

        std::error_code ec;
        std::filesystem::remove_all(dir, ec);
    }

    auto test_composer_core_tags_live_switch_and_draft_validation() -> void {
        // P1 #3: Core tag mirroring & unambiguous live switch resolution
        expect(desktop::sanitize_core_tag("HK Edge 01") == "HK-Edge-01", "sanitize_core_tag preserves case and replaces spaces");
        expect(desktop::sanitize_core_tag("direct") == "direct-node", "sanitize_core_tag suffixes reserved direct");
        expect(desktop::sanitize_core_tag("香港 节点", "node") == "node", "sanitize_core_tag strips CJK to fallback");

        auto doc = desktop::make_default_workspace();
        doc.profiles.push_back({.id = "hk-edge-01", .remarks = "HK Edge 01", .subscription_id = "manual", .kind = "node"});
        doc.profiles.push_back({.id = "sg-edge-02", .remarks = "SG Edge 02", .subscription_id = "sub-chain", .kind = "node"});
        doc.profiles.push_back({.id = "dup-1", .remarks = "JP Node", .subscription_id = "manual", .kind = "node"});
        doc.profiles.push_back({.id = "dup-2", .remarks = "JP.Node", .subscription_id = "manual", .kind = "node"});
        doc.subscriptions.push_back({.id = "sub-chain", .remarks = "Chained", .prev_profile_id = "hk-edge-01"});

        expect(desktop::resolve_live_switch_tag(doc, "hk-edge-01") == "HK-Edge-01", "P1 #3: resolves remarks-derived Core tag");
        expect(desktop::resolve_live_switch_tag(doc, "sg-edge-02").empty(), "P1 #3: declines sub-chained profile");
        expect(desktop::resolve_live_switch_tag(doc, "dup-1").empty(), "P1 #3: declines ambiguous sanitized tag collision");

        auto sample = R"({"ok":true,"active_tag":"HK-Edge-01","selector_tag":"proxy","selector_members":["HK-Edge-01","SG-02"],"warnings":[],"errors":[],"secret_files":[],"kdl":"schema-version 1\n"})";
        auto res = desktop::parse_workspace_compose_json(sample);
        auto live_yes = desktop::decide_tun_live_switch(true, true, res.selector_tag, res.selector_members,
                                                        desktop::resolve_live_switch_tag(doc, "hk-edge-01"));
        expect(live_yes.can_live_switch && live_yes.target_tag == "HK-Edge-01", "TUN live switch hits Core tag");

        // P1 #5: argv without --emit-kdl omits --emit-kdl cleanly
        auto argv_no_emit = desktop::build_workspace_compose_argv("/usr/bin/nexus", "/cfg/ws.json", "/cfg/host.json", "/cfg/sec", "hk-edge-01");
        expect(argv_no_emit.size() == 12 && argv_no_emit.back() == "--json-result", "P1 #5: compose argv omits --emit-kdl when empty");

        // P1 #2 + P2 #7: Draft validation (VLESS+Reality ?type=tcp, empty payload rejection, malformed URI error, IPv6 brackets, IP/CIDR classifier)
        std::unordered_set<std::string> ids;
        auto vless_ok = desktop_ui_helpers::build_workspace_profile_from_draft(
            "node", "", "vless://11111111-2222-3333-4444-555555555555@example.com:443?type=tcp&security=reality&flow=xtls-rprx-vision&sni=cdn.example.com&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA#HK%20Vision",
            "", ids, 0);
        expect(vless_ok.has_value() && vless_ok->node.transport.type.empty() && vless_ok->node.flow == "xtls-rprx-vision" &&
               vless_ok->node.tls.enabled && vless_ok->node.tls.reality_public_key == "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" &&
               vless_ok->remarks == "HK-Vision",
            "P1 #2: VLESS+Reality+Vision with ?type=tcp normalizes transport.type to empty");

        expect(!desktop_ui_helpers::build_workspace_profile_from_draft("node", "Empty", "   ", "", ids, 0).has_value(),
            "P2 #7: empty node payload rejected");
        expect(!desktop_ui_helpers::build_workspace_profile_from_draft("node", "Bad", "vless://broken", "", ids, 0).has_value(),
            "P2 #7: malformed share URI surfaces parse error instead of fabricating node");

        auto v6 = desktop_ui_helpers::build_workspace_profile_from_draft("node", "V6", "[2001:db8::1]:8443", "", ids, 0);
        expect(v6.has_value() && v6->node.server == "2001:db8::1" && v6->node.port == 8443,
            "P2 #7: bracketed IPv6 host:port stripped cleanly");

        expect(desktop_ui_helpers::is_ip_or_cidr_rule_token("1.1.1.1") &&
               desktop_ui_helpers::is_ip_or_cidr_rule_token("10.0.0.0/8") &&
               desktop_ui_helpers::is_ip_or_cidr_rule_token("2001:db8::1") &&
               desktop_ui_helpers::is_ip_or_cidr_rule_token("fc00::/18") &&
               desktop_ui_helpers::is_ip_or_cidr_rule_token("private") &&
               !desktop_ui_helpers::is_ip_or_cidr_rule_token("example.com"),
            "P2 #7: routing token classifier routes bare IPv4/IPv6/CIDR/private to ips");
    }
}

auto main() -> int {
    try {
        test_workspace_5kind_roundtrip_and_0600();
        test_5tier_replacement_uniqueness_and_fail_closed_gc();
        test_subscription_header_parser();
        test_host_bearer_token_strict_route_and_telemetry();
        test_composer_core_tags_live_switch_and_draft_validation();
        std::println("nexus-desktop-workspace-tests: ALL PASSED");
        return 0;
    } catch (std::exception const& e) {
        std::println(std::cerr, "FAIL: {}", e.what());
        return 1;
    }
}
