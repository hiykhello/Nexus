#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <cerrno>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>
#endif

import std;
import desktop.desktop_host_config;
import desktop.workspace_models;
import desktop.workspace_store;
import desktop.workspace_sync;

namespace {
    auto expect(bool cond, std::string_view msg) -> void {
        if (!cond) throw std::runtime_error(std::string(msg));
    }

    auto make_temp_dir(std::string_view suffix) -> std::filesystem::path {
        auto dir = std::filesystem::temp_directory_path() / ("nexus-ws-sync-test-" + std::string(suffix));
        std::error_code ec;
        std::filesystem::remove_all(dir, ec);
        std::filesystem::create_directories(dir, ec);
        return dir;
    }

#ifdef _WIN32
    using SockFd = SOCKET;
    constexpr SockFd kInvalidSock = INVALID_SOCKET;
    auto close_sock(SockFd s) -> void { if (s != INVALID_SOCKET) ::closesocket(s); }
#else
    using SockFd = int;
    constexpr SockFd kInvalidSock = -1;
    auto close_sock(SockFd s) -> void { if (s >= 0) ::close(s); }
#endif

    // Local loopback HTTP/1.1 mock WebDAV server supporting HEAD/GET/PUT/MKCOL, Basic Auth, ETag & If-Match/If-None-Match.
    class MockWebDavServer {
        SockFd listen_fd_ = kInvalidSock;
        std::uint16_t port_ = 0;
        std::atomic<bool> stop_{false};
        std::thread thread_;

        std::mutex mu_;
        std::string expected_auth_ = "Basic ZGF2dXNlcjpkYXZwYXNz"; // davuser:davpass
        bool exists_ = false;
        bool mkcol_seen_ = false;
        std::string etag_;
        std::string body_;
        int put_seq_ = 0;
        bool force_next_put_412_ = false;
        bool omit_etag_ = false;
        bool fail_next_get_500_ = false;

        auto handle_client(SockFd cfd) -> void {
            std::string raw;
            char buf[4096];
            std::size_t hdr_end = std::string::npos;
            std::size_t content_len = 0;
            for (;;) {
                auto n = ::recv(cfd, buf, sizeof(buf), 0);
                if (n <= 0) break;
                raw.append(buf, static_cast<std::size_t>(n));
                if (hdr_end == std::string::npos) {
                    hdr_end = raw.find("\r\n\r\n");
                    if (hdr_end != std::string::npos) {
                        auto h = std::string_view(raw).substr(0, hdr_end);
                        std::size_t p = 0;
                        while (p < h.size()) {
                            auto nl = h.find("\r\n", p);
                            auto line = (nl == std::string_view::npos) ? h.substr(p) : h.substr(p, nl - p);
                            p = (nl == std::string_view::npos) ? h.size() : nl + 2;
                            if (line.size() > 15) {
                                std::string low(line.substr(0, 15));
                                for (char& c : low) if (c >= 'A' && c <= 'Z') c = static_cast<char>(c + 32);
                                if (low == "content-length:") {
                                    auto v = line.substr(15);
                                    while (!v.empty() && v.front() == ' ') v.remove_prefix(1);
                                    (void)std::from_chars(v.data(), v.data() + v.size(), content_len);
                                }
                            }
                        }
                    }
                }
                if (hdr_end != std::string::npos && raw.size() >= hdr_end + 4 + content_len) break;
            }
            if (hdr_end == std::string::npos) { close_sock(cfd); return; }

            auto head_sv = std::string_view(raw).substr(0, hdr_end);
            auto req_body = raw.substr(hdr_end + 4, content_len);
            auto first_nl = head_sv.find("\r\n");
            auto req_line = first_nl == std::string_view::npos ? head_sv : head_sv.substr(0, first_nl);
            auto sp = req_line.find(' ');
            std::string method = sp == std::string_view::npos ? "" : std::string(req_line.substr(0, sp));

            std::string auth, if_match, if_none_match;
            std::size_t pos = first_nl == std::string_view::npos ? head_sv.size() : first_nl + 2;
            while (pos < head_sv.size()) {
                auto nl = head_sv.find("\r\n", pos);
                auto line = (nl == std::string_view::npos) ? head_sv.substr(pos) : head_sv.substr(pos, nl - pos);
                pos = (nl == std::string_view::npos) ? head_sv.size() : nl + 2;
                auto col = line.find(':');
                if (col == std::string_view::npos) continue;
                std::string k(line.substr(0, col));
                for (char& c : k) if (c >= 'A' && c <= 'Z') c = static_cast<char>(c + 32);
                auto v = line.substr(col + 1);
                while (!v.empty() && (v.front() == ' ' || v.front() == '\t')) v.remove_prefix(1);
                if (k == "authorization") auth = std::string(v);
                else if (k == "if-match") if_match = std::string(v);
                else if (k == "if-none-match") if_none_match = std::string(v);
            }

            std::string resp;
            {
                std::lock_guard lk(mu_);
                if (auth != expected_auth_) {
                    resp = "HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                } else if (method == "MKCOL") {
                    mkcol_seen_ = true;
                    resp = "HTTP/1.1 201 Created\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                } else if (method == "HEAD") {
                    if (!exists_) resp = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                    else if (omit_etag_) resp = std::format("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body_.size());
                    else resp = std::format("HTTP/1.1 200 OK\r\nETag: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", etag_, body_.size());
                } else if (method == "GET") {
                    if (fail_next_get_500_) {
                        fail_next_get_500_ = false;
                        resp = "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                    } else if (!exists_) resp = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                    else if (omit_etag_) resp = std::format("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body_.size(), body_);
                    else resp = std::format("HTTP/1.1 200 OK\r\nETag: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", etag_, body_.size(), body_);
                } else if (method == "PUT") {
                    bool precond_fail = force_next_put_412_;
                    force_next_put_412_ = false;
                    if (!precond_fail && if_none_match == "*" && exists_) precond_fail = true;
                    if (!precond_fail && !if_match.empty() && (!exists_ || if_match != etag_)) precond_fail = true;
                    if (precond_fail) {
                        resp = "HTTP/1.1 412 Precondition Failed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                    } else {
                        exists_ = true;
                        body_ = req_body;
                        etag_ = std::format("\"etag-{}\"", ++put_seq_);
                        resp = std::format("HTTP/1.1 201 Created\r\nETag: {}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", etag_);
                    }
                } else {
                    resp = "HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                }
            }
            (void)::send(cfd, resp.data(), static_cast<int>(resp.size()), 0);
            close_sock(cfd);
        }

    public:
        MockWebDavServer() {
#ifdef _WIN32
            WSADATA wd{};
            (void)::WSAStartup(MAKEWORD(2, 2), &wd);
#endif
            listen_fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
            expect(listen_fd_ != kInvalidSock, "mock WebDAV socket creation");
            int one = 1;
            (void)::setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<char const*>(&one), sizeof(one));
#ifdef _WIN32
            DWORD tv = 100;
            (void)::setsockopt(listen_fd_, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<char const*>(&tv), sizeof(tv));
#else
            struct timeval tv{0, 100000};
            (void)::setsockopt(listen_fd_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
#endif
            sockaddr_in addr{};
            addr.sin_family = AF_INET;
            addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            addr.sin_port = 0;
            expect(::bind(listen_fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0, "mock WebDAV bind");
            expect(::listen(listen_fd_, 16) == 0, "mock WebDAV listen");
            socklen_t alen = sizeof(addr);
            expect(::getsockname(listen_fd_, reinterpret_cast<sockaddr*>(&addr), &alen) == 0, "mock WebDAV getsockname");
            port_ = ntohs(addr.sin_port);
            thread_ = std::thread([this] {
                while (!stop_.load(std::memory_order_acquire)) {
                    SockFd cfd = ::accept(listen_fd_, nullptr, nullptr);
                    if (cfd == kInvalidSock) continue;
                    handle_client(cfd);
                }
            });
        }

        ~MockWebDavServer() {
            stop_.store(true, std::memory_order_release);
            close_sock(listen_fd_);
            if (thread_.joinable()) thread_.join();
        }

        auto base_url() const -> std::string { return std::format("http://127.0.0.1:{}/dav/", port_); }
        auto saw_mkcol() -> bool { std::lock_guard lk(mu_); return mkcol_seen_; }
        auto current_body() -> std::string { std::lock_guard lk(mu_); return body_; }
        auto set_remote_state(std::string etag, std::string body) -> void {
            std::lock_guard lk(mu_);
            exists_ = true; etag_ = std::move(etag); body_ = std::move(body);
        }
        auto set_omit_etag(bool on) -> void { std::lock_guard lk(mu_); omit_etag_ = on; }
        auto trigger_next_put_412() -> void { std::lock_guard lk(mu_); force_next_put_412_ = true; }
        auto trigger_next_get_500() -> void { std::lock_guard lk(mu_); fail_next_get_500_ = true; }
    };

    auto make_fake_envelope(std::int64_t rev, std::string_view device) -> std::string {
        return std::format(
            R"({{"format":"nexus-sync-v1","kdf":"scrypt","kdf_n":32768,"kdf_r":8,"kdf_p":1,"aead":"xchacha20-poly1305","salt_b64":"AAAA","nonce_b64":"BBBB","revision":{},"updated_at_ms":1764000000000,"device_label":"{}","plaintext_sha256":"{}","ciphertext_b64":"Q0lQSEVSVEVYVA=="}})",
            rev, device, std::string(64, 'a'));
    }

    auto test_webdav_url_validation() -> void {
        expect(desktop::validate_webdav_url("https://dav.example.net/nexus/").has_value(), "HTTPS WebDAV accepted");
        expect(desktop::validate_webdav_url("http://127.0.0.1:8080/dav/").has_value(), "loopback IPv4 HTTP accepted for tests");
        expect(desktop::validate_webdav_url("http://localhost:8080/dav/").has_value(), "localhost HTTP accepted for tests");
        expect(desktop::validate_webdav_url("http://[::1]:8080/dav/").has_value(), "loopback IPv6 HTTP accepted for tests");
        expect(!desktop::validate_webdav_url("http://dav.example.net/nexus/").has_value(), "non-loopback plaintext HTTP rejected");
        expect(!desktop::validate_webdav_url("https://user:pass@dav.example.net/").has_value(), "embedded URL credentials rejected");
        expect(!desktop::validate_webdav_url("ftp://dav.example.net/").has_value(), "non-HTTP scheme rejected");
        expect(!desktop::validate_webdav_url("https://dav.example.net/\r\nX-Inject: 1").has_value(), "CRLF injection rejected");
    }

    auto test_webdav_push_conflict_412_and_pull_backup() -> void {
        MockWebDavServer srv;
        auto dir = make_temp_dir("webdav");
        auto ws_path = dir / "workspace.json";
        auto backups = dir / "backups";
        { std::ofstream(ws_path) << R"({"schema_version":1,"revision":3})"; }

        desktop::WebDavConfig cfg{srv.base_url(), "davuser", "davpass", "", 0};
        // 1. Initial push (404 -> MKCOL + PUT w/ If-None-Match: *)
        auto env_v3 = make_fake_envelope(3, "Desktop-Linux");
        auto p1 = desktop::webdav_push_envelope(cfg, env_v3, 3, false);
        expect(p1.status == desktop::WebDavSyncStatus::ok && p1.remote_etag == "\"etag-1\"" && srv.saw_mkcol(),
            "initial WebDAV push ran MKCOL and returned ETag");
        cfg.last_etag = p1.remote_etag;
        cfg.last_revision = 3;

        // 2. Another device updates remote -> ETag & revision diverge -> push MUST detect conflict!
        auto env_remote_v5 = make_fake_envelope(5, "Android-Pixel");
        srv.set_remote_state("\"etag-remote-5\"", env_remote_v5);
        auto p_conflict = desktop::webdav_push_envelope(cfg, make_fake_envelope(4, "Desktop-Linux"), 4, false);
        expect(p_conflict.status == desktop::WebDavSyncStatus::conflict &&
               p_conflict.remote_etag == "\"etag-remote-5\"" &&
               p_conflict.remote_revision == 5 &&
               p_conflict.remote_device_label == "Android-Pixel",
            "ETag/revision divergence returns Conflict with remote metadata without overwriting");
        expect(srv.current_body() == env_remote_v5, "remote envelope untouched after conflict");

        // 3. Explicit force_overwrite succeeds!
        auto env_force_v6 = make_fake_envelope(6, "Desktop-Linux");
        auto p_force = desktop::webdav_push_envelope(cfg, env_force_v6, 6, true);
        expect(p_force.status == desktop::WebDavSyncStatus::ok && srv.current_body() == env_force_v6,
            "force_overwrite push succeeds");
        cfg.last_etag = p_force.remote_etag;
        cfg.last_revision = 6;

        // 4. Concurrent race: HEAD matches ETag, then PUT gets 412 Precondition Failed -> returns Conflict!
        srv.trigger_next_put_412();
        auto p_412 = desktop::webdav_push_envelope(cfg, make_fake_envelope(7, "Desktop-Linux"), 7, false);
        expect(p_412.status == desktop::WebDavSyncStatus::conflict, "HTTP 412 race returns Conflict cleanly");

        // 5. Pull conflict: BOTH higher remote rev AND equal-revision divergence (last=6, local=7, remote=7) MUST return Conflict!
        srv.set_remote_state("\"etag-remote-7\"", make_fake_envelope(7, "MacBook"));
        auto pull_eq_conflict = desktop::webdav_pull_envelope(cfg, ws_path, backups, 7, false);
        expect(pull_eq_conflict.status == desktop::WebDavSyncStatus::conflict && pull_eq_conflict.remote_revision == 7,
            "pull detects equal-revision post-sync divergence conflict");

        srv.set_remote_state("\"etag-remote-9\"", make_fake_envelope(9, "MacBook"));
        auto pull_conflict = desktop::webdav_pull_envelope(cfg, ws_path, backups, 8, false);
        expect(pull_conflict.status == desktop::WebDavSyncStatus::conflict && pull_conflict.remote_revision == 9,
            "pull detects local unsynced edit conflict");

        // 6. Pull with force_pull=true creates 0600 timestamped local backup and rotates oldest beyond max_keep=5
        auto pull_ok = desktop::webdav_pull_envelope(cfg, ws_path, backups, 8, true);
        expect(pull_ok.status == desktop::WebDavSyncStatus::ok && !pull_ok.backup_path.empty() &&
               pull_ok.remote_device_label == "MacBook" && pull_ok.remote_revision == 9,
            "forced pull creates backup and returns remote envelope");
        std::filesystem::path bp(std::u8string_view(reinterpret_cast<char8_t const*>(pull_ok.backup_path.data()), pull_ok.backup_path.size()));
        expect(std::filesystem::is_regular_file(bp), "pre-pull backup file exists on disk");
#ifndef _WIN32
        struct stat st{};
        expect(::stat(bp.c_str(), &st) == 0 && (st.st_mode & 0777) == 0600, "pre-pull backup written with 0600 mode");
#endif
        for (int i = 0; i < 7; ++i) expect(!desktop::backup_workspace_file_0600(ws_path, backups, 5).empty(), "backup rotation write");
        std::size_t bcount = 0;
        for (auto const& _ : std::filesystem::directory_iterator(backups)) ++bcount;
        expect(bcount == 5, "pre-pull backups rotated to 5 newest files");

        // 7. P1 #2: Fail-closed on missing ETag, corrupt remote, and failed GET (HTTP 500 -> error, NOT conflict!)
        srv.set_remote_state("\"etag-x\"", make_fake_envelope(6, "Phone"));
        srv.set_omit_etag(true);
        auto p_no_etag = desktop::webdav_push_envelope(cfg, make_fake_envelope(7, "Desktop-Linux"), 7, false);
        expect(p_no_etag.status == desktop::WebDavSyncStatus::conflict, "missing ETag with non-empty last_etag fails closed as conflict");

        srv.set_remote_state("", "CORRUPT-NON-JSON-REMOTE");
        desktop::WebDavConfig no_etag_cfg{srv.base_url(), "davuser", "davpass", "", 6};
        auto p_corrupt = desktop::webdav_push_envelope(no_etag_cfg, make_fake_envelope(7, "Desktop-Linux"), 7, false);
        expect(p_corrupt.status == desktop::WebDavSyncStatus::conflict && srv.current_body() == "CORRUPT-NON-JSON-REMOTE",
            "corrupt remote file fails closed without overwrite");

        srv.trigger_next_get_500();
        auto p_get_err = desktop::webdav_push_envelope(cfg, make_fake_envelope(7, "Desktop-Linux"), 7, false);
        expect(p_get_err.status == desktop::WebDavSyncStatus::error && p_get_err.message.contains("500"),
            "failed GET during conflict check returns error (not bogus conflict)");
        srv.set_omit_etag(false);

        // 8. P2: Pull first-time pristine (rev=1, last=0 -> ok), first-time dirty (rev=3, last=0 -> conflict), and rollback (meta<local -> conflict)
        srv.set_remote_state("\"etag-rb-4\"", make_fake_envelope(4, "OldDevice"));
        desktop::WebDavConfig fresh_cfg{srv.base_url(), "davuser", "davpass", "", 0};
        expect(desktop::webdav_pull_envelope(fresh_cfg, ws_path, backups, 1, false).status == desktop::WebDavSyncStatus::ok,
            "pristine rev=1 workspace pulls cleanly without conflict");
        expect(desktop::webdav_pull_envelope(fresh_cfg, ws_path, backups, 3, false).status == desktop::WebDavSyncStatus::conflict,
            "unsynced first-time rev=3 workspace prompts conflict before pull overwrite");
        expect(desktop::webdav_pull_envelope(cfg, ws_path, backups, 6, false).status == desktop::WebDavSyncStatus::conflict,
            "remote rollback (meta.rev 4 < local 6) prompts conflict");

        // 9. Wrong credentials fail with HTTP 401
        desktop::WebDavConfig bad_cfg{srv.base_url(), "davuser", "wrongpass", "", 0};
        auto p_unauth = desktop::webdav_push_envelope(bad_cfg, env_v3, 3, false);
        expect(p_unauth.status == desktop::WebDavSyncStatus::error && p_unauth.message.contains("401"),
            "wrong WebDAV password returns 401 auth error");

        std::error_code ec;
        std::filesystem::remove_all(dir, ec);
    }

    auto test_passphrase_and_webdav_isolation_from_workspace() -> void {
        auto dir = make_temp_dir("isolation");
        auto host = desktop::make_default_desktop_host_config(dir, "/run/nexus.sock");
        host.webdav_url = "https://dav.example.net/nexus/";
        host.webdav_username = "alice";
        host.webdav_password = "super-secret-dav-password";
        host.sync_passphrase = "ultra-secret-e2ee-passphrase";
        host.sync_device_label = "Linux-Workstation";
        host.webdav_last_etag = "\"etag-42\"";
        host.webdav_last_revision = 12;

        auto host_path = dir / "host.json";
        expect(desktop::save_desktop_host_config(host_path, host), "save host.json with WebDAV creds");
#ifndef _WIN32
        struct stat st{};
        expect(::stat(host_path.c_str(), &st) == 0 && (st.st_mode & 0777) == 0600, "host.json written 0600");
#endif
        auto reloaded = desktop::load_desktop_host_config(host_path, dir, "/run/nexus.sock");
        expect(reloaded.webdav_url == host.webdav_url && reloaded.webdav_password == host.webdav_password &&
               reloaded.sync_passphrase == host.sync_passphrase && reloaded.webdav_last_etag == "\"etag-42\"" &&
               reloaded.webdav_last_revision == 12, "host.json round-trips WebDAV & sync passphrase");

        auto ws = desktop::make_default_workspace();
        auto ws_json = desktop::workspace_to_json(ws);
        expect(!ws_json.contains("webdav_url") && !ws_json.contains("webdav_password") &&
               !ws_json.contains("sync_passphrase") && !ws_json.contains("super-secret-dav-password") &&
               !ws_json.contains("ultra-secret-e2ee-passphrase"),
            "workspace.json NEVER contains WebDAV credentials or E2EE sync passphrase");

        std::error_code ec;
        std::filesystem::remove_all(dir, ec);
    }

    auto test_share_sync_and_udp_probe_parsers_and_argvs() -> void {
        auto ex = desktop::parse_share_export_json(
            R"({"ok":true,"uri":"nexus://share/v1/eyJzY2hlbWFfdmVyc2lvbiI6MX0","exported_count":2,"warnings":[],"errors":[]})");
        expect(ex.ok && ex.uri.starts_with("nexus://share/v1/") && ex.exported_count == 2, "export-share JSON parsed");

        auto im = desktop::parse_share_import_json(
            R"({"ok":true,"imported_ids":["p1","p2"],"warnings":["remapped"],"errors":[],"workspace_json":"{}"})");
        expect(im.ok && im.imported_ids.size() == 2 && im.workspace_json == "{}", "import-share JSON parsed");

        auto seal = desktop::parse_sync_seal_json(
            R"({"ok":true,"revision":9,"updated_at_ms":1764000001000,"envelope_sha256":"abcd","warnings":[],"errors":[],"envelope_json":"{\"format\":\"nexus-sync-v1\"}"})");
        expect(seal.ok && seal.revision == 9 && !seal.envelope_json.empty(), "seal-sync JSON parsed");

        auto open = desktop::parse_sync_open_json(
            R"({"ok":true,"revision":9,"updated_at_ms":1764000001000,"device_label":"Phone","warnings":[],"errors":[],"workspace_json":"{\"schema_version\":1}"})");
        expect(open.ok && open.revision == 9 && open.device_label == "Phone", "open-sync JSON parsed");

        auto stun = desktop::parse_udp_probe_json(
            R"({"ok":true,"kind":"stun","via_socks5":true,"rtt_ms":24,"attempts":1,"detail":"mapped 203.0.113.9:51820","error":""})");
        expect(stun.ok && stun.kind == "stun" && stun.via_socks5 && stun.rtt_ms == 24 && stun.detail.contains("203.0.113.9"),
            "udp-probe STUN JSON parsed");

        std::array<std::string, 2> ids{"p-a", "p-b"};
        auto ex_argv = desktop::build_export_share_argv("/usr/bin/nexus", "/cfg/ws.json", ids);
        expect(ex_argv.size() == 10 && ex_argv[2] == "export-share" && ex_argv.back() == "--json-result", "export-share argv");

        auto im_argv = desktop::build_import_share_argv("/usr/bin/nexus", "/cfg/ws.json", "/cfg/secrets/uri.tmp", "manual");
        expect(im_argv.size() == 10 && im_argv[2] == "import-share" && im_argv[5] == "--uri-file" && im_argv.back() == "--json-result",
            "P1 #1: import-share argv uses --uri-file (never raw secret URI on argv)");

        auto udp_argv = desktop::build_udp_probe_argv("/usr/bin/nexus", "stun", "", "127.0.0.1:7890", 3000, 2);
        expect(udp_argv.size() == 12 && udp_argv[1] == "tools" && udp_argv[2] == "udp-probe" && udp_argv.back() == "--json",
            "udp-probe argv");

        // Verify transient passphrase & share-URI files are cleaned up on failure
        auto dir = make_temp_dir("passwipe");
        auto sec = dir / "secrets";
        std::filesystem::create_directories(sec);
        auto bad_seal = desktop::seal_sync_via_core(dir / "missing-nexus", dir / "ws.json", "my-passphrase", "dev", sec);
        expect(!bad_seal.ok, "missing binary fails closed");
        auto bad_imp = desktop::import_share_via_core(dir / "missing-nexus", dir / "ws.json", "nexus://share/v1/abc", "manual", {}, sec);
        expect(!bad_imp.ok, "missing binary import-share fails closed");
        std::size_t leftover = 0;
        for (auto const& _ : std::filesystem::directory_iterator(sec)) ++leftover;
        expect(leftover == 0, "zero leftover transient passphrase/URI files in secrets_dir");

        std::error_code ec;
        std::filesystem::remove_all(dir, ec);
    }
}

auto main() -> int {
    try {
        test_webdav_url_validation();
        test_webdav_push_conflict_412_and_pull_backup();
        test_passphrase_and_webdav_isolation_from_workspace();
        test_share_sync_and_udp_probe_parsers_and_argvs();
        std::println("nexus-desktop-workspace-sync-tests: ALL PASSED");
        return 0;
    } catch (std::exception const& e) {
        std::println(std::cerr, "FAIL: {}", e.what());
        return 1;
    }
}
