#ifndef _WIN32
#include <cstddef>
#include <cstring>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#endif

import std;
import desktop.async_worker;
import desktop.core_supervisor;
import desktop.firewall_helper;
import desktop.http_control;
import desktop.ipc_client;
import desktop.profile_store;
import desktop.service_installer;
import desktop.share_link;
import desktop.single_instance;
import desktop.system_proxy;
import desktop.tray_controller;

namespace {
    auto expect(bool cond, std::string_view msg) -> void {
        if (!cond) {
            throw std::runtime_error(std::string(msg));
        }
    }

    auto test_frame_builder() -> void {
        std::string_view single[] = {"status"};
        auto f1 = desktop::build_nexus1_frame(single);
        expect(f1.has_value() && *f1 == "NEXUS/1 status", "single token NEXUS/1 frame");

        std::string_view multi[] = {"select", "proxy", "hk-01"};
        auto f2 = desktop::build_nexus1_frame(multi);
        expect(f2.has_value() && *f2 == std::string("NEXUS/1 select\0proxy\0hk-01", 26),
            "NUL-delimited multi-token NEXUS/1 frame");

        std::string_view bad_empty[] = {"select", ""};
        expect(!desktop::build_nexus1_frame(bad_empty).has_value(), "reject empty token");

        std::string embedded_nul("a\0b", 3);
        std::string_view bad_nul[] = {embedded_nul};
        expect(!desktop::build_nexus1_frame(bad_nul).has_value(), "reject embedded NUL");
    }

#ifndef _WIN32
    auto test_unix_ipc_roundtrip() -> void {
        auto sock_path = (std::filesystem::temp_directory_path() /
            std::format("nexus-desktop-ipc-test-{}.sock", ::getpid())).string();
        ::unlink(sock_path.c_str());

        sockaddr_un addr{};
        addr.sun_family = AF_UNIX;
        std::memcpy(addr.sun_path, sock_path.data(), sock_path.size());
        auto addr_len = static_cast<socklen_t>(offsetof(sockaddr_un, sun_path) + sock_path.size() + 1);

        int srv = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        expect(srv >= 0, "create test UDS");
        expect(::bind(srv, reinterpret_cast<sockaddr const*>(&addr), addr_len) == 0, "bind test UDS");
        expect(::listen(srv, 4) == 0, "listen test UDS");

        std::string captured;
        std::jthread server([&] {
            int c = ::accept4(srv, nullptr, nullptr, SOCK_CLOEXEC);
            if (c >= 0) {
                char buf[256]{};
                auto n = ::recv(c, buf, sizeof(buf), 0);
                if (n > 0) captured.assign(buf, static_cast<std::size_t>(n));
                std::string_view resp = "OK reloaded\n";
                (void)::send(c, resp.data(), resp.size(), MSG_NOSIGNAL);
                ::close(c);
            }
            ::close(srv);
        });

        desktop::IpcClient client(sock_path);
        auto reply = client.reload();
        server.join();
        ::unlink(sock_path.c_str());

        expect(reply.ok && reply.body == "OK reloaded\n", "UDS reload reply");
        expect(captured == "NEXUS/1 reload", "UDS captured request");
    }

    auto test_single_instance_wakeup() -> void {
        auto app_id = std::format("nexus-desktop-test-{}", ::getpid());
        std::atomic<bool> woken{false};
        auto first = desktop::SingleInstanceGuard::acquire(app_id, [&] { woken.store(true); });
        expect(first != nullptr, "first instance acquired");

        auto second = desktop::SingleInstanceGuard::acquire(app_id, [] {});
        expect(second == nullptr, "second instance rejected");

        for (int i = 0; i < 40 && !woken.load(); ++i) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        expect(woken.load(), "first instance received wakeup callback");
    }
#endif

    auto test_supervisor_missing_binary() -> void {
        desktop::CoreSupervisor sup("/nonexistent/nexus-binary");
        expect(!sup.running(), "not running initially");
        auto res = sup.validate_config("/nonexistent/config.kdl");
        expect(!res.ok, "validate fails when binary missing");
    }

    auto test_async_worker_fifo_and_drain() -> void {
        std::vector<int> order;
        {
            desktop::AsyncWorker worker;
            for (int i = 1; i <= 5; ++i) {
                expect(worker.post([&order, i] { order.push_back(i); }), "post task");
            }
            worker.stop();
            expect(!worker.post([] {}), "reject task after stop");
        }
        expect(order == std::vector<int>({1, 2, 3, 4, 5}), "async worker drains in FIFO order");
    }

    auto test_share_links() -> void {
        auto vless = desktop::parse_share_link(
            "vless://11111111-2222-3333-4444-555555555555@edge.example.com:443"
            "?security=reality&sni=www.example.com&fp=chrome-133&pbk=0123abcd&sid=cafe&type=xhttp&path=%2Fapi&mode=stream-one#HK%20Edge");
        expect(vless.has_value(), "parse vless reality+xhttp");
        expect(vless->tag == "HK-Edge" && vless->port == 443 && vless->transport == "xhttp" && vless->path == "/api",
            "vless fields decoded");
        auto kdl = desktop::render_kdl_outbound(*vless, "/etc/nexus/secrets/hk.uuid");
        expect(kdl.contains("outbound \"HK-Edge\" type=\"vless\""), "KDL 2.0 outbound node header");
        expect(kdl.contains("uuid-file \"/etc/nexus/secrets/hk.uuid\""), "secret file reference");
        expect(!kdl.contains("11111111-2222"), "never embed plaintext UUID in KDL");
        expect(kdl.contains("public-key \"0123abcd\"") && kdl.contains("transport \"xhttp\""), "reality+xhttp KDL");

        auto trojan = desktop::parse_share_link("trojan://secretpass@tr.example.com:443?sni=tr.example.com&type=ws&path=%2Fws&host=cdn.example.com&certificate-sha256=abcdef01#TR");
        expect(trojan.has_value(), "parse trojan share link");
        auto tkdl = desktop::render_kdl_outbound(*trojan, "/etc/nexus/secrets/tr.pass");
        expect(tkdl.contains("outbound \"TR\" type=\"trojan\"") && tkdl.contains("authentication {\n        password-file \"/etc/nexus/secrets/tr.pass\""),
            "trojan KDL 2.0 authentication block");
        expect(tkdl.contains("certificate-sha256 \"abcdef01\"") && tkdl.contains("transport \"websocket\""),
            "trojan pin + websocket KDL");

        auto anytls = desktop::parse_share_link("anytls://anypass@any.example.com:443?sni=any.example.com&type=grpc&serviceName=tun&authority=any.example.com#AnyNode");
        expect(anytls.has_value(), "parse anytls grpc share link");
        auto akdl = desktop::render_kdl_outbound(*anytls, "/etc/nexus/secrets/any.pass");
        expect(akdl.contains("outbound \"AnyNode\" type=\"anytls\"") && akdl.contains("transport \"grpc\"") && akdl.contains("service-name \"tun\""),
            "anytls grpc KDL");

        auto tuic = desktop::parse_share_link("tuic://11111111-2222-3333-4444-555555555555:tuicpass@t.example.com:8443?sni=t.example.com&congestion_control=bbr#TUIC");
        expect(tuic.has_value(), "parse tuic share link");
        auto tukdl = desktop::render_kdl_outbound(*tuic, "/etc/nexus/secrets/tuic.pass");
        expect(tukdl.contains("outbound \"TUIC\" type=\"tuic\"") && tukdl.contains("uuid \"11111111-2222-3333-4444-555555555555\"") && tukdl.contains("congestion-control \"bbr\""),
            "tuic KDL");

        auto snell = desktop::parse_share_link("snell://pskvalue@sn.example.com:6160?version=5&obfs=http&obfs-host=bing.com#Snell5");
        expect(snell.has_value(), "parse snell v5 share link");
        auto skdl = desktop::render_kdl_outbound(*snell, "/etc/nexus/secrets/sn.psk");
        expect(skdl.contains("outbound \"Snell5\" type=\"snell\"") && skdl.contains("version 5") && skdl.contains("psk-file \"/etc/nexus/secrets/sn.psk\"") && skdl.contains("obfs \"http\""),
            "snell v5 KDL");

        auto ss = desktop::parse_share_link("ss://MjAyMi1ibGFrZTMtYWVzLTEyOC1nY206c2VjcmV0a2V5@[2001:db8::1]:8443#JP_SS");
        expect(ss.has_value() && ss->method == "2022-blake3-aes-128-gcm" && ss->secret == "secretkey" && ss->host == "2001:db8::1",
            "parse ss SIP002 IPv6");

        auto ssh_pw = desktop::parse_share_link("ssh://alice:s3cr3t@bastion.example.com:2222?host-key-sha256=SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU&cipher=chacha20-poly1305@openssh.com#Bastion");
        expect(ssh_pw.has_value() && ssh_pw->scheme == desktop::OutboundScheme::ssh && ssh_pw->username == "alice" && ssh_pw->secret == "s3cr3t" && ssh_pw->port == 2222,
            "parse ssh password link");
        auto ssh_pw_kdl = desktop::render_kdl_outbound(*ssh_pw, "/etc/nexus/secrets/ssh.pass");
        expect(ssh_pw_kdl.contains("outbound \"Bastion\" type=\"ssh\"") && ssh_pw_kdl.contains("user \"alice\"") &&
               ssh_pw_kdl.contains("password-file \"/etc/nexus/secrets/ssh.pass\"") &&
               ssh_pw_kdl.contains("host-key-sha256 \"SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU\"") &&
               ssh_pw_kdl.contains("cipher \"chacha20-poly1305@openssh.com\"") && !ssh_pw_kdl.contains("s3cr3t"),
            "ssh password KDL");

        auto ssh_key = desktop::parse_share_link("ssh://git@ssh.example.com:22?private-key-file=/etc/nexus/secrets/id_ed25519&host-key-sha256=SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU#KeyJump");
        expect(ssh_key.has_value() && ssh_key->username == "git" && ssh_key->secret.empty(), "parse ssh key link");
        auto ssh_key_kdl = desktop::render_kdl_outbound(*ssh_key, {});
        expect(ssh_key_kdl.contains("private-key-file \"/etc/nexus/secrets/id_ed25519\""), "ssh key KDL");

        auto nh2 = desktop::parse_share_link("naive+https://alice:s3cr3t@naive.example.com:443?sni=naive.example.com&fp=chrome#NaiveH2");
        expect(nh2.has_value() && nh2->scheme == desktop::OutboundScheme::naive && nh2->protocol == "h2" && nh2->padding, "parse naive+https");
        auto nh2_kdl = desktop::render_kdl_outbound(*nh2, "/etc/nexus/secrets/n2.pass");
        expect(nh2_kdl.contains("outbound \"NaiveH2\" type=\"naive\"") && nh2_kdl.contains("protocol \"h2\"") &&
               nh2_kdl.contains("verify #true") && !nh2_kdl.contains("s3cr3t"), "naive+https KDL");

        auto nh3 = desktop::parse_share_link("naive+quic://bob:pw@nq.example.com:8443?padding=0#NaiveH3");
        expect(nh3.has_value() && nh3->scheme == desktop::OutboundScheme::naive && nh3->protocol == "h3" && !nh3->padding, "parse naive+quic");
        auto nh3_kdl = desktop::render_kdl_outbound(*nh3, "/etc/nexus/secrets/n3.pass");
        expect(nh3_kdl.contains("protocol \"h3\"") && nh3_kdl.contains("padding #false"), "naive+quic KDL");

        auto h3p = desktop::parse_share_link("https://u:p@h3p.example.com:443?h3=1&udp=1&fp=chrome#H3Proxy");
        expect(h3p.has_value() && h3p->scheme == desktop::OutboundScheme::http_connect && h3p->http_version == "h3" && h3p->udp, "parse https h3+udp");
        auto h3p_kdl = desktop::render_kdl_outbound(*h3p, "/etc/nexus/secrets/h3p.pass");
        expect(h3p_kdl.contains("type=\"http-connect\"") && h3p_kdl.contains("http-version \"h3\"") &&
               h3p_kdl.contains("udp #true") && h3p_kdl.contains("verify #true"), "https h3+udp KDL");

        auto h2p = desktop::parse_share_link("https://h2p.example.com:8443?h2=1#H2Proxy");
        expect(h2p.has_value() && h2p->scheme == desktop::OutboundScheme::http_connect && h2p->http_version == "h2" && !h2p->udp, "parse anonymous https h2");

        expect(!desktop::parse_share_link("http://example.com").has_value(), "reject unsupported scheme");
    }

    auto test_tray_controller() -> void {
        bool showed = false, reloaded = false, quitted = false;
        desktop::TrayController tray({
            .on_show = [&] { showed = true; },
            .on_reload = [&] { reloaded = true; },
            .on_quit = [&] { quitted = true; },
        });
        expect(tray.state() == desktop::TrayState::offline, "initial tray offline");
        tray.set_status(desktop::TrayState::tun_active, "ready");
        expect(tray.state() == desktop::TrayState::tun_active && tray.tooltip().contains("TUN"), "tray tun status");
        tray.trigger_show();
        tray.trigger_reload();
        tray.trigger_quit();
        expect(showed && reloaded && quitted && tray.quit_requested(), "tray callbacks & atomic quit");
        tray.stop();
    }

    auto test_http_control_parsers() -> void {
        constexpr std::string_view kMetrics =
            "# HELP nexus_control_generation gen\n"
            "nexus_control_generation 4\n"
            "nexus_active_sessions{listener=\"0\"} 3\n"
            "nexus_traffic_upload_bytes_total{listener=\"0\"} 1024\n"
            "nexus_traffic_download_bytes_total{listener=\"0\"} 4096\n";
        auto m = desktop::parse_openmetrics_summary(kMetrics);
        expect(m.control_generation == 4 && m.active_sessions == 3 &&
               m.upload_bytes == 1024 && m.download_bytes == 4096, "OpenMetrics summary parser");

        constexpr std::string_view kOutbounds =
            R"({"groups":[{"name":"auto","mode":"url-test","selected":"hk-01","override":true,"members":[{"name":"hk-01","state":"up","latency_ms":42},{"name":"jp-02","state":"up","latency_ms":68}]}]})";
        auto groups = desktop::parse_outbounds_json(kOutbounds);
        expect(groups.size() == 1 && groups[0].tag == "auto" && groups[0].manual_override &&
               groups[0].members.size() == 2 && groups[0].members[0].selected &&
               groups[0].members[0].overridden && groups[0].members[0].latency_ms == 42,
               "Outbounds JSON parser");

        constexpr std::string_view kConns =
            R"({"connections":[{"id":"77","listener":0,"inbound":"socks","protocol":"socks5","path":"direct","outbound":"direct","target":"1.1.1.1:443","destination_port":443,"duration_ms":"250","upload_bytes":"2048","download_bytes":"16384","can_close":true}]})";
        auto conns = desktop::parse_connections_json(kConns);
        expect(conns.size() == 1 && conns[0].id == 77 && conns[0].protocol == "socks5" &&
               conns[0].inbound == "socks" && conns[0].outbound == "direct" && conns[0].duration_ms == 250 &&
               conns[0].destination_port == 443 && conns[0].download_bytes == 16384 && conns[0].can_close,
               "Connections JSON parser");
        auto det = desktop::parse_connection_detail_json(
            R"({"id":"77","listener":0,"inbound":"socks","protocol":"socks5","path":"direct","source":"127.0.0.1:50000","target":"1.1.1.1:443","outbound":"direct","route_mode":"ordered","route_rule":"1","process_path":"/usr/bin/curl","source_uid":1000,"destination_port":443,"duration_ms":"321","upload_bytes":"512","download_bytes":"4096","can_close":true})");
        expect(det.has_value() && det->id == 77 && det->process_path == "/usr/bin/curl" && det->source_uid == 1000 && det->route_mode == "ordered",
               "Connection detail JSON parser");
        auto logs = desktop::parse_logs_json(
            R"({"latest_seq":"12","evicted":"2","entries":[{"seq":"11","level":"info","domain":"core","event_code":100,"message":"proxy started"},{"seq":"12","level":"trace","domain":"route","event_code":102,"message":"matched"}]})");
        expect(logs.latest_seq == 12 && logs.evicted == 2 && logs.entries.size() == 2 &&
               logs.entries[0].seq == 11 && logs.entries[0].domain == "core" && logs.entries[1].level == "trace",
               "Logs JSON parser");
    }

    auto test_firewall_and_diagnostic_guard() -> void {
        expect(desktop::normalize_firewall_executable_path(R"(\\?\C:\Program Files\Nexus\nexus.exe)") ==
               R"(C:\Program Files\Nexus\nexus.exe)", "strip Windows extended-length prefix");
        expect(desktop::normalize_firewall_executable_path(R"(\\?\UNC\srv\share\nexus.exe)") ==
               R"(\\srv\share\nexus.exe)", "strip Windows UNC extended prefix");
        auto fw_diag = desktop::ensure_loopback_firewall_rule("/usr/bin/nexus", "Nexus Test", true);
        expect(fw_diag.ok && fw_diag.skipped, "firewall helper skips in diagnostic mode");
#ifndef _WIN32
        auto fw_nonwin = desktop::ensure_loopback_firewall_rule("/usr/bin/nexus", "Nexus Test", false);
        expect(fw_nonwin.ok, "firewall helper safe on non-Windows");
#else
        auto fw_empty = desktop::ensure_loopback_firewall_rule("", "Nexus Test", false);
        expect(!fw_empty.ok && !fw_empty.skipped, "firewall helper rejects empty executable path");
#endif

        desktop::SystemProxyController proxy;
        proxy.set_diagnostic_mode(true);
        expect(proxy.diagnostic_mode(), "diagnostic mode active");
        expect(!proxy.enable("127.0.0.1", 10808), "diagnostic mode refuses system proxy mutation");
        expect(!proxy.active(), "system proxy remains inactive under diagnostic mode");
    }

    auto test_profile_store() -> void {
        auto tmp = std::filesystem::temp_directory_path() / "nexus-desktop-profile-store-test";
        std::error_code ec;
        std::filesystem::remove_all(tmp, ec);
        desktop::ProfileStore store(tmp);
        auto saved = store.save_profile("HK Edge!", "schema-version 1\n");
        expect(saved.has_value() && saved->id == "HK-Edge", "save sanitized profile");
        expect(store.set_active("HK-Edge") && store.active_id() == "HK-Edge", "persist active profile");
        auto secret_path = store.write_secret("HK Edge", "super-secret-key");
        expect(secret_path.has_value() && std::filesystem::exists(*secret_path), "write private secret file");
        auto list = store.list();
        expect(list.size() == 1 && list[0].id == "HK-Edge", "list saved profiles");
        expect(store.remove_profile("HK-Edge") && store.list().empty(), "remove profile");
        std::filesystem::remove_all(tmp, ec);
    }

    auto test_service_installer() -> void {
        auto tmp = std::filesystem::temp_directory_path() / "nexus-desktop-svc-test";
        std::error_code ec;
        std::filesystem::remove_all(tmp, ec);
        std::filesystem::create_directories(tmp, ec);
        {
            std::ofstream w(tmp / "wintun.dll", std::ios::binary);
            w << "stub";
        }
        expect(desktop::detect_wintun_dll(tmp).has_value(), "detect wintun.dll when present");
        desktop::ServiceSpec spec{
            .service_name = "nexus-user",
            .description = "Nexus User Proxy",
            .binary_path = "/usr/local/bin/nexus",
            .config_path = tmp / "config.kdl",
            .data_dir = tmp / "data",
        };
        auto unit_path = desktop::install_systemd_user_unit(spec, tmp / "systemd");
        expect(unit_path.has_value() && std::filesystem::is_regular_file(*unit_path), "install systemd user unit");
        auto args = desktop::build_windows_sc_create_args(spec);
        expect(args.has_value() && args->size() >= 6 && (*args)[0] == "sc.exe" && (*args)[2] == "nexus-user",
            "build sc.exe create arguments");
        std::filesystem::remove_all(tmp, ec);
    }

#ifndef _WIN32
    auto reserve_loopback_port() -> std::uint16_t {
        int s = ::socket(AF_INET, SOCK_STREAM, 0);
        expect(s >= 0, "reserve socket");
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = 0;
        expect(::bind(s, reinterpret_cast<sockaddr const*>(&addr), sizeof(addr)) == 0, "bind reserve");
        socklen_t len = sizeof(addr);
        expect(::getsockname(s, reinterpret_cast<sockaddr*>(&addr), &len) == 0, "getsockname reserve");
        auto port = ntohs(addr.sin_port);
        ::close(s);
        return port;
    }

    auto test_live_nexus_control_plane() -> void {
        char const* bin = std::getenv("NEXUS_CORE_BIN");
        if (!bin || !*bin) return;
        auto tmp = std::filesystem::temp_directory_path() / std::format("nexus-desktop-live-{}", ::getpid());
        std::filesystem::create_directories(tmp);
        auto socks_port = reserve_loopback_port();
        auto http_port = reserve_loopback_port();
        auto token_path = tmp / "bearer.tok";
        auto cfg_path = tmp / "config.kdl";
        {
            std::ofstream tf(token_path);
            tf << "desktop-live-secret-token\n";
        }
        std::filesystem::permissions(token_path, std::filesystem::perms::owner_read | std::filesystem::perms::owner_write);
        {
            std::ofstream cf(cfg_path);
            cf << std::format(
                "schema-version 1\nrole \"client\"\n"
                "control http-listen=\"127.0.0.1:{}\" bearer-token-file=\"{}\" metrics=#true\n"
                "inbound \"local\" type=\"socks5\" {{ listen host=\"127.0.0.1\" port={}; authentication \"none\"; }}\n"
                "outbound \"direct\" type=\"direct\"\n"
                "outbound \"alt\" type=\"socks5\" {{ server host=\"127.0.0.1\" port=18081; }}\n"
                "outbound \"proxy\" type=\"selector\" {{ member \"direct\"; member \"alt\"; selected \"direct\"; }}\n"
                "routing {{ default-outbound \"proxy\"; }}\n",
                http_port, token_path.string(), socks_port);
        }

        desktop::CoreSupervisor sup(bin);
        auto val = sup.validate_config(cfg_path);
        expect(val.ok, "live CoreSupervisor::validate_config: " + val.message);
        auto exp_ok = sup.explain_rule(cfg_path, "local", "tcp", "example.com:443", "resolved-ip=93.184.216.34 --expect-outbound=direct");
        expect(exp_ok.ok && exp_ok.message.contains("outbound=direct"), "live CoreSupervisor::explain_rule: " + exp_ok.message);
        expect(sup.start(cfg_path), "live CoreSupervisor::start");

        desktop::HttpControlClient unauth("127.0.0.1", http_port);
        desktop::HttpControlClient authed("127.0.0.1", http_port, "desktop-live-secret-token");
        bool ready = false;
        for (int i = 0; i < 60; ++i) {
            if (authed.health().ok) { ready = true; break; }
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
        expect(ready, "live Nexus /v1/health reachable");
        expect(unauth.status().status_code == 401, "unauthenticated /v1/status rejected with 401");
        auto st = authed.status();
        expect(st.ok && st.status_code == 200, "authenticated /v1/status 200 OK");
        auto ob1 = authed.outbounds();
        expect(ob1.ok, "authenticated /v1/outbounds 200 OK");
        auto g1 = desktop::parse_outbounds_json(ob1.body);
        expect(g1.size() == 1 && g1[0].tag == "proxy" && g1[0].active == "direct",
            "initial group active=direct (got body: " + ob1.body + ")");
        auto sel_b = authed.select_group("proxy", "alt");
        expect(sel_b.ok, "PUT /v1/groups/proxy member=alt (status=" + std::to_string(sel_b.status_code) + " body=" + sel_b.body + ")");
        auto ob2 = authed.outbounds();
        auto g2 = desktop::parse_outbounds_json(ob2.body);
        expect(g2.size() == 1 && g2[0].active == "alt",
            "switched group active=alt (got body: " + ob2.body + ")");
        expect(authed.select_group("proxy", "direct").ok, "PUT /v1/groups/proxy member=direct");
        expect(authed.set_log_level("debug").ok, "POST /v1/log-level debug 200 OK");
        expect(authed.set_log_level("info").ok, "POST /v1/log-level info 200 OK");
        auto conns = authed.connections();
        expect(conns.ok && conns.body.contains("\"connections\""), "GET /v1/connections 200 OK");
        auto miss_detail = authed.connection_detail(999999);
        expect(miss_detail.status_code == 404, "GET /v1/connections/999999 returns 404");
        auto live_logs = authed.logs("trace", "all", {}, 0, 32);
        expect(live_logs.ok && live_logs.body.contains("\"entries\":["), "GET /v1/logs 200 OK");
        auto parsed_logs = desktop::parse_logs_json(live_logs.body);
        expect(!parsed_logs.entries.empty(), "live /v1/logs backlog contains startup entries");
        auto m1 = authed.metrics();
        expect(m1.ok && m1.body.contains("nexus_control_generation"), "authenticated /metrics 200 OK");
        auto gen1 = desktop::parse_openmetrics_summary(m1.body).control_generation;
        auto clr = authed.clear_cache();
        expect(clr.ok && clr.body.contains("\"cleared\":true"), "authenticated POST /v1/state/clear-cache 200 OK");
        auto nc = authed.notify_network_change(12);
        expect(nc.ok && nc.body.contains("\"accepted\":true"), "authenticated POST /v1/network-change 200 OK");
        auto close_miss = authed.close_connection(999999);
        expect(close_miss.status_code == 404, "DELETE /v1/connections/999999 returns 404");
        auto close_all = authed.close_all_connections();
        expect(close_all.ok && close_all.body.contains("\"closed\":"), "DELETE /v1/connections returns 200 OK");
        auto probe_sel = authed.probe_group("proxy");
        expect(probe_sel.status_code == 409, "POST /v1/groups/proxy/probe returns 409 on plain selector");
        auto diag = authed.diagnostics();
        expect(diag.ok && diag.body.contains("\"authorized_requests\":"), "GET /v1/diagnostics 200 OK");
        auto ev = authed.events();
        expect(ev.ok && ev.body.contains("\"events\":["), "GET /v1/events 200 OK");
        expect(authed.reload().ok, "authenticated POST /v1/reload 200 OK");
        auto m2 = authed.metrics();
        expect(desktop::parse_openmetrics_summary(m2.body).control_generation > gen1, "control_generation incremented after clear-cache");
        sup.stop();
        std::error_code ec;
        std::filesystem::remove_all(tmp, ec);
        std::println("Desktop C++26 live integration against real Nexus binary PASSED (http_port={})", http_port);
    }
#endif
}

auto main() -> int {
    try {
        test_frame_builder();
#ifndef _WIN32
        test_unix_ipc_roundtrip();
        test_single_instance_wakeup();
#endif
        test_supervisor_missing_binary();
        test_async_worker_fifo_and_drain();
        test_share_links();
        test_tray_controller();
        test_http_control_parsers();
        test_firewall_and_diagnostic_guard();
        test_profile_store();
        test_service_installer();
#ifndef _WIN32
        test_live_nexus_control_plane();
#endif
        std::println("nexus-desktop-tests: ALL PASSED (C++26 + CMake 4.5 import std)");
        return 0;
    } catch (std::exception const& e) {
        std::println(std::cerr, "FAIL: {}", e.what());
        return 1;
    }
}
