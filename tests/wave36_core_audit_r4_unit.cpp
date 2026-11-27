#include "../include/nexus/core_c_api.h"

#include <cstdlib>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

import std;
import cli.control;
import cli.route_files;
import config;
import control_api;
import control_api.types;
import platform.system_proxy;
import platform.tun_bridge;

auto nexus_check(int argc, char** argv) -> int;
auto nexus_state(int argc, char** argv) -> int;

namespace {
    auto require(bool cond, std::string_view msg) -> void {
        if (!cond) {
            std::cerr << "FAIL: " << msg << '\n';
            std::exit(1);
        }
    }

    struct TempDir {
        std::filesystem::path path;
        explicit TempDir(std::string_view tag) {
            path = std::filesystem::temp_directory_path() /
                (std::string("nexus-w36-r4-") + std::string(tag) + "-" + std::to_string(::getpid()));
            std::error_code ec;
            std::filesystem::remove_all(path, ec);
            std::filesystem::create_directories(path, ec);
        }
        ~TempDir() {
            std::error_code ec;
            std::filesystem::remove_all(path, ec);
        }
    };

    auto write_text(std::filesystem::path const& p, std::string_view text) -> void {
        std::filesystem::create_directories(p.parent_path());
        std::ofstream out(p, std::ios::binary | std::ios::trunc);
        out << text;
        require(out.good(), "write_text: " + p.string());
    }

    auto pick_free_port() -> std::uint16_t {
        int fd = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (fd < 0) return 19432;
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        std::uint16_t port = 19432;
        if (::bind(fd, reinterpret_cast<sockaddr const*>(&addr), sizeof(addr)) == 0) {
            socklen_t len = sizeof(addr);
            if (::getsockname(fd, reinterpret_cast<sockaddr*>(&addr), &len) == 0)
                port = ntohs(addr.sin_port);
        }
        ::close(fd);
        return port ? port : 19432;
    }

    auto make_http_req(std::string_view method, std::string_view target, std::string_view body = {}) -> std::string {
        return std::format("{} {} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: {}\r\n\r\n{}",
            method, target, body.size(), body);
    }

    auto test_r4_p1_1_clear_cache_validation() -> void {
        control_api::HttpControlServer http;
        int calls = 0;
        std::string last_target;
        auto snap = [](control_api::SnapshotFields, std::optional<std::uint64_t>) {
            return control_api::ControlSnapshot{};
        };
        auto cmd = [&](std::span<std::string_view const> args) -> std::expected<std::string, std::string> {
            ++calls;
            require(args.size() == 2 && args[0] == "clear-cache", "clear-cache args");
            last_target = std::string(args[1]);
            return "cleared=" + last_target + "\n";
        };
        auto send = [&](std::string_view target, std::string_view body) {
            return http.handle_direct_http_for_test(make_http_req("POST", target, body), snap, cmd);
        };

        auto r_empty = send("/v1/state/clear-cache", "");
        require(r_empty.starts_with("HTTP/1.1 200") && calls == 1 && last_target == "all", "empty body defaults to all");
        auto r_obj = send("/v1/state/clear-cache", "{}");
        require(r_obj.starts_with("HTTP/1.1 200") && calls == 2 && last_target == "all", "{} defaults to all");
        auto r_dns = send("/v1/state/clear-cache", R"({"target":"dns"})");
        require(r_dns.starts_with("HTTP/1.1 200") && calls == 3 && last_target == "dns", "target=dns clears dns");
        auto r_scope = send("/v1/state/clear-cache?scope=rulesets", "{}");
        require(r_scope.starts_with("HTTP/1.1 200") && calls == 4 && last_target == "rulesets", "scope=rulesets works");

        calls = 0;
        for (std::string_view bad : {
            std::string_view(R"({"target":123})"),
            std::string_view(R"({"target":true})"),
            std::string_view(R"({"target":null})"),
            std::string_view(R"({"target":[]})"),
            std::string_view(R"({"target":""})"),
            std::string_view(R"({"target":"invalid"})"),
            std::string_view("{bad json"),
            std::string_view("[]"),
        }) {
            auto resp = send("/v1/state/clear-cache", bad);
            require(resp.starts_with("HTTP/1.1 400"), "invalid clear-cache body returns 400: " + std::string(bad));
        }
        auto r_bad_scope = send("/v1/state/clear-cache?scope=%ZZ", "");
        require(r_bad_scope.starts_with("HTTP/1.1 400"), "malformed scope query returns 400");
        require(calls == 0, "invalid clear-cache requests must invoke callback 0 times");
        std::println("  [PASS] R4 P1-1 clear-cache rejects invalid/malformed target with 400 and 0 clear calls");
    }

    auto test_r4_p2_1_check_validates_dns_rulesets() -> void {
        TempDir dir("p2-1");
        auto cfg_path = dir.path / "dns_missing.kdl";
        write_text(cfg_path, R"kdl(
schema-version 1
role "client"
inbounds { inbound "s" type="socks5" { listen host="127.0.0.1" port=1080; authentication "none"; }; }
outbounds { outbound "direct" type="direct"; }
dns {
    servers { server "local" type="udp" host="127.0.0.1" port=5353; }
    rulesets { "dns-local" path="missing_dns_rules.kdl" format="kdl"; }
    rules { - rule-set="dns-local" server="local"; }
    final "local"
}
routing { final "direct"; }
)kdl");
        std::string a0 = "check", a1 = cfg_path.string();
        char* argv[] = {a0.data(), a1.data(), nullptr};
        require(nexus_check(2, argv) != 0, "nexus check must fail when local DNS rule-set is missing");

        write_text(dir.path / "missing_dns_rules.kdl", "schema-version 2\nkind \"predicate\"\nrule type=\"domain\" value=\"example.test\"\n");
        require(nexus_check(2, argv) == 0, "nexus check must succeed once local DNS rule-set exists");

        write_text(dir.path / "missing_dns_rules.kdl", "schema-version 2\nkind \"predicate\"\nrule type=\"ip-cidr\" value=\"192.0.2.0/24\"\n");
        require(nexus_check(2, argv) != 0, "nexus check must fail when local DNS rule-set has unsupported condition");

        auto remote_cfg = dir.path / "dns_remote.kdl";
        auto fake_ca = dir.path / "ca.pem";
        write_text(fake_ca, "-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n");
        write_text(remote_cfg, std::format(R"kdl(
schema-version 1
role "client"
inbounds {{ inbound "s" type="socks5" {{ listen host="127.0.0.1" port=1080; authentication "none"; }}; }}
outbounds {{ outbound "direct" type="direct"; }}
dns {{
    servers {{ server "local" type="udp" host="127.0.0.1" port=5353; }}
    rulesets {{ "dns-remote" url="https://example.test/dns.kdl" format="kdl" http-client="updates"; }}
    rules {{ - rule-set="dns-remote" server="local"; }}
    final "local"
}}
http-clients {{ updates {{ outbound "direct"; domain-resolver "local"; ca-file "{}"; }} }}
routing {{ final "direct"; }}
)kdl", fake_ca.string()));
        std::string r1 = remote_cfg.string();
        char* rargv[] = {a0.data(), r1.data(), nullptr};
        require(nexus_check(2, rargv) == 0, "nexus check keeps offline placeholder support for remote DNS rule-set");
        std::println("  [PASS] R4 P2-1 nexus check validates local DNS rule-sets (and keeps offline remote check)");
    }

    auto test_r4_p2_2_state_cli_respects_directory() -> void {
        TempDir dir("p2-2");
        auto cfg_path = dir.path / "rel_state.kdl";
        write_text(cfg_path, R"kdl(
schema-version 1
role "client"
inbounds { inbound "s" type="socks5" { listen host="127.0.0.1" port=1080; authentication "none"; }; }
outbounds { outbound "direct" type="direct"; }
routing { final "direct"; }
)kdl");
        auto prev_wd = cli::working_directory();
        cli::set_working_directory(dir.path);
        std::string a0 = "state", a1 = "inspect", a2 = "--config", a3 = "rel_state.kdl";
        char* argv[] = {a0.data(), a1.data(), a2.data(), a3.data(), nullptr};
        int rc_inspect = nexus_state(4, argv);
        std::string c1 = "clear-cache";
        char* cargv[] = {a0.data(), c1.data(), a2.data(), a3.data(), nullptr};
        int rc_clear = nexus_state(4, cargv);
        cli::restore_working_directory(prev_wd);
        require(rc_inspect == 0, "state inspect honors -D working directory");
        require(rc_clear == 0, "state clear-cache honors -D working directory");
        std::println("  [PASS] R4 P2-2 state subcommands honor global -D working directory");
    }

    auto test_r4_p2_3_core_c_api_restores_directory() -> void {
        TempDir dir("p2-3");
        auto port = pick_free_port();
        auto cfg_path = dir.path / "only_in_dir.kdl";
        write_text(cfg_path, std::format(
            "schema-version 1\nrole \"client\"\n"
            "inbounds {{ inbound \"s\" type=\"socks5\" {{ listen host=\"127.0.0.1\" port={}; authentication \"none\"; }}; }}\n"
            "outbounds {{ outbound \"direct\" type=\"direct\"; }}\n"
            "routing {{ final \"direct\"; }}\n", port));
        auto prev_wd = cli::working_directory();
        cli::restore_working_directory(std::nullopt);
        require(!cli::working_directory().has_value(), "baseline working_directory empty");
        require(nexus_core_check_config("only_in_dir.kdl") != 0, "relative file absent from caller cwd");

        std::string a0 = "run", a1 = "--config", a2 = "only_in_dir.kdl", a3 = "-D", a4 = dir.path.string();
        char* const argv[] = {a0.data(), a1.data(), a2.data(), a3.data(), a4.data()};
        std::jthread stopper([] {
            std::this_thread::sleep_for(std::chrono::milliseconds(40));
            nexus_core_request_stop();
        });
        require(nexus_core_run_args(5, argv) == 0, "nexus_core_run_args with -D exits cleanly");
        stopper.join();
        require(!cli::working_directory().has_value(), "working_directory restored after nexus_core_run_args");
        require(nexus_core_check_config("only_in_dir.kdl") != 0, "subsequent check_config does not leak previous -D");
        cli::restore_working_directory(prev_wd);
        std::println("  [PASS] R4 P2-3 nexus_core_run_args restores working directory via RAII on exit");
    }

    auto test_r4_p2_4_tun_outbound_short_buffer_preserves_packet() -> void {
        require(nexus_core_tun_bridge_enable(1, 1500, nullptr, nullptr) == 0, "enable tun bridge");
        auto br = platform::global_tun_bridge();
        require(br != nullptr, "global tun bridge non-null");

        std::array<std::uint8_t, 128> pkt{};
        for (std::size_t i = 0; i < pkt.size(); ++i) pkt[i] = static_cast<std::uint8_t>((i * 7 + 3) & 0xff);
        pkt[0] = 0x45;
        require(br->write_packet(pkt).has_value(), "queue 128-byte outbound packet");

        std::array<unsigned char, 64> small{};
        size_t out_len = 0;
        int rc_short = nexus_core_tun_bridge_pop_outbound(small.data(), small.size(), &out_len);
        require(rc_short == -4 && out_len == 128, "short buffer returns -4 with required out_len=128");

        out_len = 0;
        int rc_probe = nexus_core_tun_bridge_pop_outbound(nullptr, 0, &out_len);
        require(rc_probe == -4 && out_len == 128, "null/0 size probe returns -4 with required out_len=128");

        // Direct C++ pop_outbound with short span must also preserve front packet.
        std::array<std::uint8_t, 32> short_cpp{};
        require(!br->pop_outbound(short_cpp).has_value(), "C++ pop_outbound short span returns nullopt without dropping");

        std::array<unsigned char, 128> exact{};
        out_len = 0;
        int rc_ok = nexus_core_tun_bridge_pop_outbound(exact.data(), exact.size(), &out_len);
        require(rc_ok == 0 && out_len == 128 && std::ranges::equal(pkt, exact),
            "retry with 128-byte buffer pops exact preserved packet");

        out_len = 99;
        int rc_empty = nexus_core_tun_bridge_pop_outbound(exact.data(), exact.size(), &out_len);
        require(rc_empty == 1 && out_len == 0, "subsequent pop reports empty queue (1)");
        require(nexus_core_tun_bridge_enable(0, 0, nullptr, nullptr) == 0, "disable tun bridge");
        std::println("  [PASS] R4 P2-4 TUN outbound short buffer preserves packet, reports -4 & required length");
    }

    auto test_r4_p2_6_host_override_inside_config_dir() -> void {
        TempDir dir("p2-6");
        auto conf_d = dir.path / "conf.d";
        auto base = conf_d / "00-base.kdl";
        auto ov = conf_d / "99-override.kdl";
        write_text(base, R"kdl(
schema-version 1
role "client"
workers 1
inbounds { inbound "s" type="socks5" { listen host="127.0.0.1" port=1080; authentication "none"; }; }
outbounds { outbound "direct" type="direct"; }
routing { final "direct"; }
)kdl");
        write_text(ov, "workers 2\n");

        auto merged = cli::read_config_source(conf_d.string(), true, ov.string());
        require(merged.has_value(), "read_config_source skips explicit host-override inside config-dir: " +
            (merged ? std::string{} : merged.error()));
        auto parsed = config::parse_kdl(*merged);
        require(parsed.has_value() && parsed->workers == 2, "merged config applies override workers=2");

        std::string a0 = "check", a1 = "-C", a2 = conf_d.string(), a3 = "--host-override", a4 = ov.string();
        char* argv[] = {a0.data(), a1.data(), a2.data(), a3.data(), a4.data(), nullptr};
        require(nexus_check(5, argv) == 0, "nexus check -C dir --host-override dir/99-override.kdl succeeds");
        std::println("  [PASS] R4 P2-6 explicit --host-override inside config-dir is excluded from shard scan");
    }

    auto test_r4_p2_7_posix_logs_follow_cursor() -> void {
        std::string cursor = "0";
        for (int seq = 1; seq <= 5; ++seq) {
            auto page = std::format("latest=5 evicted=0\nseq={} ts=100 level=info domain=core event=1 session=0 msg=\"m{}\"\n", seq, seq);
            cursor = cli::advance_control_logs_cursor(cursor, page);
            require(cursor == std::to_string(seq), "follow cursor advances to last printed seq=" + std::to_string(seq));
        }
        auto empty_same = std::string_view("latest=5 evicted=0\n");
        cursor = cli::advance_control_logs_cursor(cursor, empty_same);
        require(cursor == "5", "empty page keeps cursor at 5");

        auto filtered_empty = std::string_view("latest=12 evicted=0\n");
        cursor = cli::advance_control_logs_cursor(cursor, filtered_empty);
        require(cursor == "12", "filtered-empty page advances cursor to latest=12");
        std::println("  [PASS] R4 P2-7 POSIX logs --follow advances cursor to last printed seq without skips");
    }

    auto test_r4_p2_8_http_group_select_auto_and_resolved() -> void {
        control_api::HttpControlServer http;
        int cmd_calls = 0, snap_calls = 0;
        std::vector<std::string> last_args;
        std::string wire_reply = "group=auto selected=direct override=0\n";
        auto snap = [&](control_api::SnapshotFields, std::optional<std::uint64_t>) {
            ++snap_calls;
            control_api::ControlSnapshot s{};
            s.groups.push_back(control_api::GroupMetric{.name = "auto", .mode = "url-test", .selected = "direct"});
            return s;
        };
        auto cmd = [&](std::span<std::string_view const> args) -> std::expected<std::string, std::string> {
            ++cmd_calls;
            last_args.clear();
            for (auto a : args) last_args.emplace_back(a);
            return wire_reply;
        };
        auto send = [&](std::string_view method, std::string_view target, std::string_view body) {
            return http.handle_direct_http_for_test(make_http_req(method, target, body), snap, cmd);
        };

        // 1. POST /v1/groups/{tag}/select with {"auto":true}
        auto r1 = send("POST", "/v1/groups/auto/select", R"({"auto":true})");
        require(r1.starts_with("HTTP/1.1 200") && r1.contains(R"("selected":"direct")") && !r1.contains(R"("selected":"--auto")"),
            "POST /select {\"auto\":true} resolves actual member");
        require(last_args.size() == 3 && last_args[0] == "select" && last_args[1] == "auto" && last_args[2] == "--auto",
            "POST /select {\"auto\":true} invokes select <tag> --auto");
        require(snap_calls == 0, "wire selected=direct avoids extra snapshot call");

        // 2. PUT /v1/groups/{tag} with {"member":"--auto"}
        auto r2 = send("PUT", "/v1/groups/auto", R"({"member":"--auto"})");
        require(r2.starts_with("HTTP/1.1 200") && r2.contains(R"("selected":"direct")") && !r2.contains(R"("selected":"--auto")"),
            "PUT {\"member\":\"--auto\"} resolves actual member, never echoes --auto");

        // 3. Fallback to snapshot when command reply has no selected= field
        wire_reply = "ok\n";
        auto r3 = send("PUT", "/v1/groups/auto", R"({"auto":true})");
        require(r3.starts_with("HTTP/1.1 200") && r3.contains(R"("selected":"direct")") && snap_calls == 1,
            "fallback snapshot resolves active member for --auto");

        // 4. Normal member selection still uses 0 snapshots
        snap_calls = 0;
        auto r4 = send("PUT", "/v1/groups/auto", R"({"member":"node-a"})");
        require(r4.starts_with("HTTP/1.1 200") && r4.contains(R"("selected":"node-a")") && snap_calls == 0,
            "normal member select uses 0 snapshots");

        // 5. Invalid bodies return 400 with 0 command invocations
        cmd_calls = 0;
        for (std::string_view bad : {
            std::string_view(R"({"auto":"yes"})"),
            std::string_view(R"({"auto":1})"),
            std::string_view(R"({"auto":false})"),
            std::string_view(R"({"auto":true,"member":"node-a"})"),
            std::string_view(R"({"member":123})"),
            std::string_view(R"({})"),
            std::string_view("{bad"),
        }) {
            auto resp = send("POST", "/v1/groups/auto/select", bad);
            require(resp.starts_with("HTTP/1.1 400"), "invalid group select body returns 400: " + std::string(bad));
        }
        require(cmd_calls == 0, "invalid group select bodies invoke command 0 times");
        std::println("  [PASS] R4 P2-8 HTTP group select supports {{\"auto\":true}} & resolves actual active member");
    }

    auto test_r4_p3_1_http_logs_query_encoded_slash() -> void {
        control_api::HttpControlServer http;
        int cmd_calls = 0;
        std::vector<std::string> last_args;
        auto snap = [](control_api::SnapshotFields, std::optional<std::uint64_t>) {
            return control_api::ControlSnapshot{};
        };
        auto cmd = [&](std::span<std::string_view const> args) -> std::expected<std::string, std::string> {
            ++cmd_calls;
            last_args.clear();
            for (auto a : args) last_args.emplace_back(a);
            return "latest=1 evicted=0\n";
        };
        auto send = [&](std::string_view method, std::string_view target, std::string_view body = {}) {
            return http.handle_direct_http_for_test(make_http_req(method, target, body), snap, cmd);
        };

        auto r_ok = send("GET", "/v1/logs?search=foo%2Fbar&limit=5");
        require(r_ok.starts_with("HTTP/1.1 200") && cmd_calls == 1, "GET /v1/logs?search=foo%2Fbar succeeds");
        require(std::ranges::find(last_args, "search=foo/bar") != last_args.end(),
            "decoded search=foo/bar passed to logs command");
        require(std::ranges::find(last_args, "limit=5") != last_args.end(), "limit=5 passed to logs command");

        cmd_calls = 0;
        for (std::string_view bad_q : {
            std::string_view("/v1/logs?search=%ZZ"),
            std::string_view("/v1/logs?search=%2"),
            std::string_view("/v1/logs?search=foo%00bar"),
        }) {
            auto r_bad = send("GET", bad_q);
            require(r_bad.starts_with("HTTP/1.1 400"), "malformed percent encoding returns 400: " + std::string(bad_q));
        }
        require(cmd_calls == 0, "malformed log query invokes command 0 times");

        // Path segment decoding must still reject %2F
        auto r_path_slash = send("PUT", "/v1/groups/a%2Fb", R"({"member":"direct"})");
        require(r_path_slash.starts_with("HTTP/1.1 400") && cmd_calls == 0,
            "path segment %2F remains rejected with 400");
        std::println("  [PASS] R4 P3-1 HTTP log search decodes %2F and returns 400 on malformed percent-encoding");
    }

    auto test_r6_p2_5_windows_control_instance_id() -> void {
        std::set<std::string> ids;
        for (int i = 0; i < 8; ++i) {
            auto id = cli::generate_control_instance_id(static_cast<std::uint64_t>(1000 + i));
            require(id.size() == 32 && std::ranges::all_of(id, [](unsigned char c) {
                return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
            }), "control instance id is 32-char lowercase hex");
            require(ids.insert(id).second, "consecutive control instance ids must be unique");
        }
        std::println("  [PASS] R6 P2-5 control instance_id generator produces distinct 32-hex IDs");
    }

    auto test_r6_p2_6_kde_pac_url_roundtrip() -> void {
        TempDir dir("r6-p2-6");
        auto bin_dir = dir.path / "bin", st_dir = dir.path / "state";
        std::filesystem::create_directories(bin_dir);
        std::filesystem::create_directories(st_dir);
        auto make_exec = [](std::filesystem::path const& p, std::string_view body) {
            write_text(p, body);
            std::filesystem::permissions(p, std::filesystem::perms::owner_all);
        };
        make_exec(bin_dir / "which", std::format("#!/bin/sh\n[ -x '{}/'$1 ] && printf '%s\\n' '{}/'$1\n", bin_dir.string(), bin_dir.string()));
        make_exec(bin_dir / "kreadconfig6", std::format(
            "#!/bin/sh\nk=''\nwhile [ $# -gt 0 ]; do\n"
            "  if [ \"$1\" = '--key' ]; then k=\"$2\"; shift 2; else shift; fi\n"
            "done\n[ -f '{}/'\"$k\" ] && IFS= read -r v < '{}/'\"$k\" && printf '%s\\n' \"$v\"\nexit 0\n",
            st_dir.string(), st_dir.string()));
        make_exec(bin_dir / "kwriteconfig6", std::format(
            "#!/bin/sh\n[ -f '{}/.fail' ] && exit 1\nk=''\nv=''\nwhile [ $# -gt 0 ]; do\n"
            "  case \"$1\" in --file|--group) shift 2;; --key) k=\"$2\"; shift 2;; *) v=\"$1\"; shift;; esac\n"
            "done\nprintf '%s\\n' \"$v\" > '{}/'\"$k\"\nexit 0\n", st_dir.string(), st_dir.string()));
        write_text(st_dir / "ProxyType", "2\n");
        write_text(st_dir / "Proxy Config Script", "https://corp.example/init.pac\n");
        auto read_key = [&](std::string_view k) -> std::string {
            std::ifstream in(st_dir / k); std::string line; std::getline(in, line); return line;
        };
        struct PathGuard {
            std::optional<std::string> prev;
            explicit PathGuard(std::string const& p) {
                if (auto* cur = std::getenv("PATH")) prev = cur;
                ::setenv("PATH", p.c_str(), 1);
            }
            ~PathGuard() { if (prev) ::setenv("PATH", prev->c_str(), 1); else ::unsetenv("PATH"); }
        } guard(bin_dir.string());

        auto en = platform::enable_system_proxy({.pac_url = "https://127.0.0.1/nexus.pac"});
        require(en.has_value(), "KDE enable --pac-url succeeds: " + (en ? std::string{} : en.error()));
        require(read_key("Proxy Config Script") == "https://127.0.0.1/nexus.pac", "KDE wrote Proxy Config Script");
        require(read_key("ProxyType") == "2", "KDE wrote ProxyType=2");
        auto st = platform::query_system_proxy();
        require(st.supported && st.enabled && st.pac_url == "https://127.0.0.1/nexus.pac", "KDE status reads PAC URL");
        auto dis = platform::disable_system_proxy();
        require(dis.has_value(), "KDE disable succeeds");
        require(read_key("Proxy Config Script") == "https://corp.example/init.pac" && read_key("ProxyType") == "2",
            "KDE disable restores prior Proxy Config Script and ProxyType");
        write_text(st_dir / ".fail", "1\n");
        require(!platform::enable_system_proxy({.pac_url = "https://127.0.0.1/fail.pac"}).has_value(),
            "KDE write failure propagates error");
        std::println("  [PASS] R6 P2-6 KDE backend writes/queries/restores Proxy Config Script & fails on write error");
    }
}

int main() {
    test_r4_p1_1_clear_cache_validation();
    test_r4_p2_1_check_validates_dns_rulesets();
    test_r4_p2_2_state_cli_respects_directory();
    test_r4_p2_3_core_c_api_restores_directory();
    test_r4_p2_4_tun_outbound_short_buffer_preserves_packet();
    test_r4_p2_6_host_override_inside_config_dir();
    test_r4_p2_7_posix_logs_follow_cursor();
    test_r4_p2_8_http_group_select_auto_and_resolved();
    test_r4_p3_1_http_logs_query_encoded_slash();
    test_r6_p2_5_windows_control_instance_id();
    test_r6_p2_6_kde_pac_url_roundtrip();
    std::println("ALL Wave 36 Round 4 + Round 6 Track D Core Audit regression tests PASSED (11/11)");
    return 0;
}
