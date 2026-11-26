#include "../include/nexus/core_c_api.h"

#include <cassert>
#include <cerrno>
#include <csignal>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

import std;
import platform.socket_options;
import platform.tun_bridge;

namespace {
    std::atomic<bool> g_sigint_called{false};
    extern "C" void custom_sigint_handler(int) {
        g_sigint_called.store(true, std::memory_order_relaxed);
    }

    auto make_temp_dir(std::string_view tag) -> std::filesystem::path {
        auto dir = std::filesystem::temp_directory_path() /
            (std::string(tag) + "-" + std::to_string(::getpid()));
        std::error_code ec;
        std::filesystem::remove_all(dir, ec);
        std::filesystem::create_directories(dir, ec);
        return dir;
    }

    auto pick_free_port() -> std::uint16_t {
        int fd = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (fd < 0) return 18943;
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        std::uint16_t port = 18943;
        if (::bind(fd, reinterpret_cast<sockaddr const*>(&addr), sizeof(addr)) == 0) {
            socklen_t len = sizeof(addr);
            if (::getsockname(fd, reinterpret_cast<sockaddr*>(&addr), &len) == 0)
                port = ntohs(addr.sin_port);
        }
        ::close(fd);
        return port ? port : 18943;
    }

    auto test_directory_flag_and_signals(std::filesystem::path const& dir) -> void {
        auto cfg_path = dir / "sub.kdl";
        auto port = pick_free_port();
        {
            std::ofstream out(cfg_path, std::ios::binary | std::ios::trunc);
            out << "schema-version 1\nrole \"client\"\n"
                << "inbounds { inbound \"s\" type=\"socks5\" { listen host=\"127.0.0.1\" port=" << port << "; authentication \"none\"; }; }\n"
                << "outbounds { outbound \"direct\" type=\"direct\"; }\n"
                << "routing { default-outbound \"direct\"; }\n";
        }
        auto prev = std::signal(SIGINT, custom_sigint_handler);

        std::string a0 = "run", a1 = "--config", a2 = cfg_path.filename().string(), a3 = "-D", a4 = dir.string();
        char* const missing_dir_argv[] = {a0.data(), a1.data(), a2.data(), a3.data(), nullptr};
        assert(nexus_core_run_args(4, missing_dir_argv) == 2);

        char* const argv[] = {a0.data(), a1.data(), a2.data(), a3.data(), a4.data()};
        std::jthread stopper([] {
            std::this_thread::sleep_for(std::chrono::milliseconds(40));
            nexus_core_request_stop();
        });
        assert(nexus_core_run_args(5, argv) == 0);
        stopper.join();

        assert(std::signal(SIGINT, prev) == custom_sigint_handler);
        assert(!g_sigint_called.load(std::memory_order_relaxed));

        // Concurrent start + stop race stress (no lost stop signal).
        for (int i = 0; i < 12; ++i) {
            std::jthread t([&] {
                assert(nexus_core_run_args(5, argv) == 0);
            });
            nexus_core_request_stop();
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
            nexus_core_request_stop();
            t.join();
        }
        assert(nexus_core_is_running() == 0);
    }

    auto test_callback_drain_barriers_and_fd_adopt() -> void {
        struct BridgeCtx {
            std::atomic<bool> entered{false};
            std::atomic<bool> finished{false};
        } bctx;
        auto slow_out = +[](unsigned char const*, size_t, void* p) {
            auto* c = static_cast<BridgeCtx*>(p);
            c->entered.store(true, std::memory_order_release);
            std::this_thread::sleep_for(std::chrono::milliseconds(40));
            c->finished.store(true, std::memory_order_release);
        };
        assert(nexus_core_tun_bridge_enable(1, 1500, slow_out, &bctx) == 0);
        auto br = platform::global_tun_bridge();
        assert(br != nullptr);
        std::uint8_t pkt[20]{0x45};
        std::jthread writer([&] { (void)br->write_packet(pkt); });
        while (!bctx.entered.load(std::memory_order_acquire)) std::this_thread::yield();
        assert(nexus_core_tun_bridge_enable(0, 0, nullptr, nullptr) == 0);
        assert(bctx.finished.load(std::memory_order_acquire));
        writer.join();
        br.reset();

        struct ProtCtx {
            std::atomic<bool> entered{false};
            std::atomic<bool> finished{false};
        } pctx;
        auto slow_prot = +[](int, void* p) -> int {
            auto* c = static_cast<ProtCtx*>(p);
            c->entered.store(true, std::memory_order_release);
            std::this_thread::sleep_for(std::chrono::milliseconds(40));
            c->finished.store(true, std::memory_order_release);
            return 0;
        };
        nexus_core_set_protect_fd_callback(slow_prot, &pctx);
        std::jthread invoker([] { (void)platform::invoke_protect_fd(1); });
        while (!pctx.entered.load(std::memory_order_acquire)) std::this_thread::yield();
        nexus_core_set_protect_fd_callback(nullptr, nullptr);
        assert(pctx.finished.load(std::memory_order_acquire));
        invoker.join();

        int fds[2]{-1, -1};
        assert(::pipe(fds) == 0);
        nexus_core_set_tun_fd(fds[0], 1, 1);
        nexus_core_set_tun_fd(-1, 0, 0);
        assert(::fcntl(fds[0], F_GETFD) == -1 && errno == EBADF);
        ::close(fds[1]);
    }
}

int main() {
    assert(nexus_core_version() != nullptr);
    assert(nexus_core_is_running() == 0);
    nexus_core_request_reload();
    nexus_core_request_stop();
    assert(nexus_core_check_config(nullptr) != 0);
    assert(nexus_core_check_config("") != 0);
    assert(nexus_core_run_args(0, nullptr) != 0);
    assert(nexus_core_is_running() == 0);

    auto dummy_protect = +[](int fd, void* ctx) -> int {
        if (ctx) *static_cast<int*>(ctx) = fd;
        return 0;
    };
    int seen_fd = -1;
    nexus_core_set_protect_fd_callback(dummy_protect, &seen_fd);
    nexus_core_set_protect_fd_callback(nullptr, nullptr);
    nexus_core_set_tun_fd(7, 0, 1);
    nexus_core_set_tun_fd(-1, 0, 0);

    assert(nexus_core_tun_bridge_enable(1, 1500, nullptr, nullptr) == 0);
    const unsigned char fake_pkt[] = {0x45, 0x00, 0x00, 0x14, 0, 0, 0, 0, 64, 17, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2};
    assert(nexus_core_tun_bridge_inject(fake_pkt, sizeof(fake_pkt)) == 0);
    unsigned char out_buf[64]{};
    size_t out_len = 99;
    assert(nexus_core_tun_bridge_pop_outbound(out_buf, sizeof(out_buf), &out_len) == 1);
    assert(out_len == 0);
    assert(nexus_core_tun_bridge_enable(0, 0, nullptr, nullptr) == 0);
    assert(nexus_core_tun_bridge_inject(fake_pkt, sizeof(fake_pkt)) != 0);

    assert(nexus_core_build_features() != nullptr);
    char err_buf[256]{};
    const char* ok_kdl = "schema-version 1\nrole \"client\"\ninbounds { inbound \"s\" type=\"socks5\" { listen host=\"127.0.0.1\" port=1080; authentication \"none\"; }; }\noutbounds { outbound \"direct\" type=\"direct\"; }\nrouting { default-outbound \"direct\"; }\n";
    assert(nexus_core_check_config_text(ok_kdl, err_buf, sizeof(err_buf)) == 0);
    assert(nexus_core_check_config_text("bad {", err_buf, sizeof(err_buf)) != 0);

    size_t conv_len = 0;
    const char* uri = "ss://YWVzLTEyOC1nY206c2VjcmV0@198.51.100.3:8388#node1\n";
    assert(nexus_core_convert_config("uri", uri, nullptr, 0, &conv_len, err_buf, sizeof(err_buf)) == -4);
    assert(conv_len > 16 && conv_len < 4096);
    char conv_buf[4096]{};
    assert(nexus_core_convert_config("uri", uri, conv_buf, sizeof(conv_buf), &conv_len, err_buf, sizeof(err_buf)) == 0);
    assert(nexus_core_check_config_text(conv_buf, err_buf, sizeof(err_buf)) == 0);

    char info_json[512]{};
    size_t info_len = 0;
    assert(nexus_core_runtime_info_json(info_json, sizeof(info_json), &info_len) == 0 && info_len > 20);

    auto tmp_dir = make_temp_dir("nexus-capi");
    {
        auto ws_sec = tmp_dir / "ws-secrets";
        const char* ws_json = R"json({
            "schema_version": 1,
            "profiles": [
                {"id": "n1", "remarks": "HK-1", "kind": "node", "node": {
                    "protocol": "vless", "server": "edge.example.test", "port": 443,
                    "password": "11111111-2222-3333-4444-555555555555",
                    "tls": {"enabled": true, "sni": "edge.example.test"}
                }}
            ],
            "routing_profiles": [{"id": "r1", "is_active": true, "default_outbound": "proxy"}]
        })json";
        const char* host_json = R"json({
            "schema_version": 1, "platform": "desktop-linux",
            "desktop": {"enable_mixed": true, "mixed_listen": "127.0.0.1:7890"}
        })json";
        assert(nexus_core_compose_workspace(nullptr, host_json, ws_sec.c_str(), "n1", nullptr, 0, nullptr, err_buf, sizeof(err_buf)) == -1);
        size_t comp_len = 0;
        assert(nexus_core_compose_workspace(ws_json, host_json, ws_sec.c_str(), "n1", nullptr, 0, &comp_len, err_buf, sizeof(err_buf)) == -4);
        assert(comp_len > 64);
        std::string comp_buf(comp_len + 1, '\0');
        assert(nexus_core_compose_workspace(ws_json, host_json, ws_sec.c_str(), "n1", comp_buf.data(), comp_buf.size(), &comp_len, err_buf, sizeof(err_buf)) == 0);
        assert(comp_buf.find("\"ok\":true") != std::string::npos);
        assert(comp_buf.find("\"selector_tag\":\"proxy\"") != std::string::npos);
        // Fail-closed missing chain hop returns -2 with structured errors[] and cleans up secrets
        auto fail_sec = tmp_dir / "ws-fail-secrets";
        const char* bad_ws = R"json({
            "schema_version": 1,
            "profiles": [
                {"id": "n1", "remarks": "Hop1", "kind": "node", "node": {
                    "protocol": "trojan", "server": "198.51.100.1", "port": 443, "password": "pw",
                    "tls": {"enabled": true, "sni": "h1.test"}
                }},
                {"id": "c1", "remarks": "BrokenChain", "kind": "proxy_chain", "proxy_chain": {"hop_ids": ["n1", "missing"]}}
            ]
        })json";
        size_t bad_len = 0;
        assert(nexus_core_compose_workspace(bad_ws, host_json, fail_sec.c_str(), "c1", nullptr, 0, &bad_len, err_buf, sizeof(err_buf)) == -4);
        std::string bad_buf(bad_len + 1, '\0');
        assert(nexus_core_compose_workspace(bad_ws, host_json, fail_sec.c_str(), "c1", bad_buf.data(), bad_buf.size(), &bad_len, err_buf, sizeof(err_buf)) == -2);
        assert(bad_buf.find("\"ok\":false") != std::string::npos && bad_buf.find("missing") != std::string::npos);
        assert(!std::filesystem::exists(fail_sec) || std::filesystem::is_empty(fail_sec));

        // Wave 23 C APIs: export-share / import-share / seal-sync / open-sync
        assert(nexus_core_workspace_export_share(nullptr, "n1", nullptr, 0, nullptr, err_buf, sizeof(err_buf)) == -1);
        size_t exp_len = 0;
        assert(nexus_core_workspace_export_share(ws_json, "n1", nullptr, 0, &exp_len, err_buf, sizeof(err_buf)) == -4);
        std::string exp_buf(exp_len + 1, '\0');
        assert(nexus_core_workspace_export_share(ws_json, "n1", exp_buf.data(), exp_buf.size(), &exp_len, err_buf, sizeof(err_buf)) == 0);
        auto uri_pos = exp_buf.find("nexus://share/v1/");
        assert(uri_pos != std::string::npos);
        auto uri_end = exp_buf.find('"', uri_pos);
        std::string share_uri = exp_buf.substr(uri_pos, uri_end - uri_pos);

        size_t imp_len = 0;
        assert(nexus_core_workspace_import_share(ws_json, share_uri.c_str(), nullptr, nullptr, 0, &imp_len, err_buf, sizeof(err_buf)) == -4);
        std::string imp_buf(imp_len + 1, '\0');
        assert(nexus_core_workspace_import_share(ws_json, share_uri.c_str(), nullptr, imp_buf.data(), imp_buf.size(), &imp_len, err_buf, sizeof(err_buf)) == 0);
        assert(imp_buf.find("\"ok\":true") != std::string::npos && imp_buf.find("sh-") != std::string::npos);
        // Oversized >256 KiB share URI must fail cleanly with -2
        std::string big_uri = "nexus://share/v1/" + std::string(360000, 'A');
        size_t big_len = 0;
        assert(nexus_core_workspace_import_share(ws_json, big_uri.c_str(), nullptr, nullptr, 0, &big_len, err_buf, sizeof(err_buf)) == -4);
        std::string big_buf(big_len + 1, '\0');
        assert(nexus_core_workspace_import_share(ws_json, big_uri.c_str(), nullptr, big_buf.data(), big_buf.size(), &big_len, err_buf, sizeof(err_buf)) == -2);
        assert(big_buf.find("\"ok\":false") != std::string::npos);

        assert(nexus_core_workspace_seal_sync(ws_json, nullptr, "unit", nullptr, 0, nullptr, err_buf, sizeof(err_buf)) == -1);
        size_t seal_len = 0;
        assert(nexus_core_workspace_seal_sync(ws_json, "correct-horse-battery", "unit-box", nullptr, 0, &seal_len, err_buf, sizeof(err_buf)) == -4);
        std::string seal_buf(seal_len + 1, '\0');
        assert(nexus_core_workspace_seal_sync(ws_json, "correct-horse-battery", "unit-box", seal_buf.data(), seal_buf.size(), &seal_len, err_buf, sizeof(err_buf)) == 0);
        assert(seal_buf.find("\"ok\":true") != std::string::npos && seal_buf.find("nexus-sync-v1") != std::string::npos);
        // Extract unescaped envelope_json from seal result via a simple raw-envelope round-trip check
        auto ek = seal_buf.find("\"envelope_json\":\"");
        assert(ek != std::string::npos);
        std::string env_json;
        for (std::size_t i = ek + 17; i < seal_buf.size() && seal_buf[i] != '"'; ++i) {
            if (seal_buf[i] == '\\' && i + 1 < seal_buf.size()) { env_json.push_back(seal_buf[++i]); }
            else env_json.push_back(seal_buf[i]);
        }
        size_t open_len = 0;
        assert(nexus_core_workspace_open_sync(env_json.c_str(), "correct-horse-battery", nullptr, 0, &open_len, err_buf, sizeof(err_buf)) == -4);
        std::string open_buf(open_len + 1, '\0');
        assert(nexus_core_workspace_open_sync(env_json.c_str(), "correct-horse-battery", open_buf.data(), open_buf.size(), &open_len, err_buf, sizeof(err_buf)) == 0);
        assert(open_buf.find("\"ok\":true") != std::string::npos && open_buf.find("unit-box") != std::string::npos);
        size_t bad_open_len = 0;
        assert(nexus_core_workspace_open_sync(env_json.c_str(), "wrong-pass", nullptr, 0, &bad_open_len, err_buf, sizeof(err_buf)) == -4);
        std::string bad_open_buf(bad_open_len + 1, '\0');
        assert(nexus_core_workspace_open_sync(env_json.c_str(), "wrong-pass", bad_open_buf.data(), bad_open_buf.size(), &bad_open_len, err_buf, sizeof(err_buf)) == -2);
        assert(bad_open_buf.find("\"ok\":false") != std::string::npos);
    }
    test_directory_flag_and_signals(tmp_dir);
    test_callback_drain_barriers_and_fd_adopt();
    std::error_code ec;
    std::filesystem::remove_all(tmp_dir, ec);
    return 0;
}
