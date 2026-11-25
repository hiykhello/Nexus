// Private WebDAV URL validation and cross-platform HTTP/HTTPS transport included by desktop/src/webdav_client.cpp.
#pragma once

namespace desktop::webdav_detail {
    constexpr std::size_t kMaxDavResponseBytes = 16u * 1024u * 1024u;
    constexpr auto kDavTimeout = std::chrono::seconds(15);

    struct ParsedDavUrl {
        bool is_https = false;
        std::string host;
        std::uint16_t port = 443;
        std::string path;
    };

    inline auto lower_ascii(std::string_view s) -> std::string {
        std::string out(s);
        for (char& c : out) if (c >= 'A' && c <= 'Z') c = static_cast<char>(c + ('a' - 'A'));
        return out;
    }

    inline auto trim(std::string_view s) noexcept -> std::string_view {
        while (!s.empty() && std::isspace(static_cast<unsigned char>(s.front()))) s.remove_prefix(1);
        while (!s.empty() && std::isspace(static_cast<unsigned char>(s.back()))) s.remove_suffix(1);
        return s;
    }

    inline auto has_ctl(std::string_view s) noexcept -> bool {
        for (unsigned char c : s) if (c < 0x20u || c == 0x7Fu) return true;
        return false;
    }

    inline auto is_loopback_host(std::string_view host) noexcept -> bool {
        if (host == "127.0.0.1" || host == "::1") return true;
        if (host.size() == 9) {
            constexpr std::string_view lh = "localhost";
            for (std::size_t i = 0; i < 9; ++i) {
                char c = host[i];
                if (c >= 'A' && c <= 'Z') c = static_cast<char>(c + ('a' - 'A'));
                if (c != lh[i]) return false;
            }
            return true;
        }
        return false;
    }

    inline auto parse_dav_url(std::string_view raw) -> std::expected<ParsedDavUrl, std::string> {
        auto sv = trim(raw);
        if (sv.empty() || sv.size() > 2048) return std::unexpected("WebDAV URL empty or too long");
        for (unsigned char c : sv) {
            if (c <= 0x20u || c == 0x7Fu || c == '"' || c == '\'' || c == '\\') {
                return std::unexpected("WebDAV URL contains forbidden whitespace or quote characters");
            }
        }
        ParsedDavUrl out{};
        std::string_view rest;
        if (sv.size() >= 8 && lower_ascii(sv.substr(0, 8)) == "https://") {
            out.is_https = true; out.port = 443; rest = sv.substr(8);
        } else if (sv.size() >= 7 && lower_ascii(sv.substr(0, 7)) == "http://") {
            out.is_https = false; out.port = 80; rest = sv.substr(7);
        } else {
            return std::unexpected("WebDAV URL must use https:// (http:// only allowed on loopback)");
        }
        auto slash = rest.find('/');
        auto authority = (slash == std::string_view::npos) ? rest : rest.substr(0, slash);
        out.path = (slash == std::string_view::npos) ? std::string("/") : std::string(rest.substr(slash));
        if (authority.empty() || authority.contains('@')) {
            return std::unexpected("WebDAV URL must not embed credentials in authority");
        }
        if (authority.front() == '[') {
            auto close = authority.find(']');
            if (close == std::string_view::npos || close <= 1) return std::unexpected("invalid IPv6 WebDAV host");
            out.host = std::string(authority.substr(1, close - 1));
            auto tail = authority.substr(close + 1);
            if (!tail.empty()) {
                if (tail.front() != ':' || tail.size() == 1) return std::unexpected("invalid WebDAV port");
                unsigned p = 0;
                auto ps = tail.substr(1);
                auto [e, ec] = std::from_chars(ps.data(), ps.data() + ps.size(), p);
                if (ec != std::errc{} || e != ps.data() + ps.size() || p < 1 || p > 65535) return std::unexpected("WebDAV port out of range");
                out.port = static_cast<std::uint16_t>(p);
            }
        } else {
            auto colon = authority.rfind(':');
            if (colon != std::string_view::npos) {
                out.host = std::string(authority.substr(0, colon));
                auto ps = authority.substr(colon + 1);
                unsigned p = 0;
                auto [e, ec] = std::from_chars(ps.data(), ps.data() + ps.size(), p);
                if (ec != std::errc{} || e != ps.data() + ps.size() || p < 1 || p > 65535) return std::unexpected("WebDAV port out of range");
                out.port = static_cast<std::uint16_t>(p);
            } else {
                out.host = std::string(authority);
            }
        }
        if (out.host.empty()) return std::unexpected("WebDAV host required");
        if (!out.is_https && !is_loopback_host(out.host)) {
            return std::unexpected("Plaintext http:// WebDAV is forbidden for non-loopback hosts; use https://");
        }
        return out;
    }

    inline auto base64_encode(std::string_view input) -> std::string {
        static constexpr char kTab[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        std::string out;
        out.reserve(((input.size() + 2) / 3) * 4);
        std::size_t i = 0;
        while (i + 3 <= input.size()) {
            std::uint32_t v = (static_cast<std::uint32_t>(static_cast<unsigned char>(input[i])) << 16) |
                              (static_cast<std::uint32_t>(static_cast<unsigned char>(input[i + 1])) << 8) |
                              static_cast<std::uint32_t>(static_cast<unsigned char>(input[i + 2]));
            out.push_back(kTab[(v >> 18) & 0x3Fu]); out.push_back(kTab[(v >> 12) & 0x3Fu]);
            out.push_back(kTab[(v >> 6) & 0x3Fu]);  out.push_back(kTab[v & 0x3Fu]);
            i += 3;
        }
        if (i < input.size()) {
            std::uint32_t v = static_cast<std::uint32_t>(static_cast<unsigned char>(input[i])) << 16;
            if (i + 1 < input.size()) v |= static_cast<std::uint32_t>(static_cast<unsigned char>(input[i + 1])) << 8;
            out.push_back(kTab[(v >> 18) & 0x3Fu]); out.push_back(kTab[(v >> 12) & 0x3Fu]);
            out.push_back(i + 1 < input.size() ? kTab[(v >> 6) & 0x3Fu] : '=');
            out.push_back('=');
        }
        return out;
    }

    inline auto parse_http_headers(std::string_view raw_headers, int& out_status, std::string& out_etag) -> bool {
        out_status = 0;
        out_etag.clear();
        bool parsed_status = false;
        std::size_t pos = 0;
        while (pos < raw_headers.size()) {
            auto nl = raw_headers.find('\n', pos);
            auto line = (nl == std::string_view::npos) ? raw_headers.substr(pos) : raw_headers.substr(pos, nl - pos);
            if (!line.empty() && line.back() == '\r') line.remove_suffix(1);
            pos = (nl == std::string_view::npos) ? raw_headers.size() : nl + 1;
            if (line.starts_with("HTTP/")) {
                auto sp = line.find(' ');
                if (sp != std::string_view::npos) {
                    auto code_sv = trim(line.substr(sp + 1));
                    int code = 0;
                    auto [ptr, ec] = std::from_chars(code_sv.data(), code_sv.data() + std::min<std::size_t>(3, code_sv.size()), code);
                    if (ec == std::errc{}) { out_status = code; out_etag.clear(); parsed_status = true; }
                }
                continue;
            }
            auto colon = line.find(':');
            if (colon == std::string_view::npos) continue;
            if (lower_ascii(trim(line.substr(0, colon))) == "etag") out_etag = std::string(trim(line.substr(colon + 1)));
        }
        return parsed_status;
    }

#ifdef _WIN32
    inline auto utf8_to_wide(std::string_view s) -> std::wstring {
        if (s.empty()) return {};
        int n = ::MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
        if (n <= 0) return {};
        std::wstring out(static_cast<std::size_t>(n), L'\0');
        ::MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), out.data(), n);
        return out;
    }

    inline auto wide_to_utf8(std::wstring_view w) -> std::string {
        if (w.empty()) return {};
        int n = ::WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), nullptr, 0, nullptr, nullptr);
        if (n <= 0) return {};
        std::string out(static_cast<std::size_t>(n), '\0');
        ::WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), out.data(), n, nullptr, nullptr);
        return out;
    }

    inline auto execute_http(
        ParsedDavUrl const& u, std::string_view method, std::string_view,
        std::string_view username, std::string_view password,
        std::span<std::pair<std::string, std::string> const> extra_headers,
        std::string_view body) -> WebDavResponse {
        WebDavResponse res{};
        DWORD open_type = u.is_https ? INTERNET_OPEN_TYPE_PRECONFIG : INTERNET_OPEN_TYPE_DIRECT;
        HINTERNET hInet = ::InternetOpenW(L"NexusDesktop/1.0", open_type, nullptr, nullptr, 0);
        if (!hInet) { res.error = "InternetOpenW failed"; return res; }
        DWORD to_ms = 15000;
        (void)::InternetSetOptionW(hInet, INTERNET_OPTION_CONNECT_TIMEOUT, &to_ms, sizeof(to_ms));
        (void)::InternetSetOptionW(hInet, INTERNET_OPTION_RECEIVE_TIMEOUT, &to_ms, sizeof(to_ms));
        (void)::InternetSetOptionW(hInet, INTERNET_OPTION_SEND_TIMEOUT, &to_ms, sizeof(to_ms));
        auto host_w = utf8_to_wide(u.host);
        HINTERNET hConn = ::InternetConnectW(hInet, host_w.c_str(), u.port, nullptr, nullptr, INTERNET_SERVICE_HTTP, 0, 0);
        if (!hConn) { ::InternetCloseHandle(hInet); res.error = "InternetConnectW failed"; return res; }
        DWORD flags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_NO_COOKIES | INTERNET_FLAG_NO_AUTO_REDIRECT;
        if (u.is_https) flags |= INTERNET_FLAG_SECURE;
        auto verb_w = utf8_to_wide(method);
        auto path_w = utf8_to_wide(u.path);
        HINTERNET hReq = ::HttpOpenRequestW(hConn, verb_w.c_str(), path_w.c_str(), nullptr, nullptr, nullptr, flags, 0);
        if (!hReq) { ::InternetCloseHandle(hConn); ::InternetCloseHandle(hInet); res.error = "HttpOpenRequestW failed"; return res; }

        auto add_one_header = [&](std::string const& line) -> bool {
            auto hw = utf8_to_wide(line + "\r\n");
            return ::HttpAddRequestHeadersW(hReq, hw.c_str(), static_cast<DWORD>(hw.size()),
                                            HTTP_ADDREQ_FLAG_ADD | HTTP_ADDREQ_FLAG_REPLACE) != FALSE;
        };
        if (!username.empty() || !password.empty()) {
            std::string creds = std::string(username) + ":" + std::string(password);
            std::string auth_hdr = "Authorization: Basic " + base64_encode(creds);
            for (volatile char& ch : creds) ch = '\0';
            bool ok_auth = add_one_header(auth_hdr);
            for (volatile char& ch : auth_hdr) ch = '\0';
            if (!ok_auth) {
                res.error = std::format("HttpAddRequestHeadersW failed ({})", ::GetLastError());
                ::InternetCloseHandle(hReq); ::InternetCloseHandle(hConn); ::InternetCloseHandle(hInet);
                return res;
            }
        }
        for (auto const& [k, v] : extra_headers) {
            if (!add_one_header(k + ": " + v)) {
                res.error = std::format("HttpAddRequestHeadersW failed ({})", ::GetLastError());
                ::InternetCloseHandle(hReq); ::InternetCloseHandle(hConn); ::InternetCloseHandle(hInet);
                return res;
            }
        }
        BOOL sent = ::HttpSendRequestW(hReq, nullptr, 0, body.empty() ? nullptr : const_cast<char*>(body.data()), static_cast<DWORD>(body.size()));
        if (!sent) {
            res.error = std::format("HttpSendRequestW failed ({})", ::GetLastError());
            ::InternetCloseHandle(hReq); ::InternetCloseHandle(hConn); ::InternetCloseHandle(hInet);
            return res;
        }
        DWORD status = 0, status_sz = sizeof(status);
        if (::HttpQueryInfoW(hReq, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &status, &status_sz, nullptr)) {
            res.status_code = static_cast<int>(status);
            res.transport_ok = true;
        }
        wchar_t etag_buf[512]{};
        DWORD etag_sz = sizeof(etag_buf);
        if (::HttpQueryInfoW(hReq, HTTP_QUERY_ETAG, etag_buf, &etag_sz, nullptr)) {
            res.etag = wide_to_utf8(std::wstring_view(etag_buf, etag_sz / sizeof(wchar_t)));
        }
        if (method != "HEAD" && res.transport_ok) {
            char buf[4096];
            for (;;) {
                DWORD rd = 0;
                if (!::InternetReadFile(hReq, buf, sizeof(buf), &rd)) {
                    res.transport_ok = false;
                    res.body.clear();
                    res.error = std::format("InternetReadFile failed ({})", ::GetLastError());
                    break;
                }
                if (rd == 0) break;
                if (res.body.size() < kMaxDavResponseBytes) {
                    res.body.append(buf, std::min<std::size_t>(rd, kMaxDavResponseBytes - res.body.size()));
                }
            }
        }
        ::InternetCloseHandle(hReq); ::InternetCloseHandle(hConn); ::InternetCloseHandle(hInet);
        return res;
    }
#else
    inline auto execute_loopback_http(
        ParsedDavUrl const& u, std::string_view method,
        std::string_view username, std::string_view password,
        std::span<std::pair<std::string, std::string> const> extra_headers,
        std::string_view body) -> WebDavResponse {
        WebDavResponse res{};
        struct addrinfo hints{};
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_family = AF_UNSPEC;
        struct addrinfo* ai = nullptr;
        auto port_str = std::to_string(u.port);
        if (::getaddrinfo(u.host.c_str(), port_str.c_str(), &hints, &ai) != 0 || !ai) {
            res.error = "getaddrinfo failed for loopback WebDAV host";
            return res;
        }
        int fd = -1;
        for (auto* p = ai; p; p = p->ai_next) {
            fd = ::socket(p->ai_family, p->ai_socktype | SOCK_CLOEXEC, p->ai_protocol);
            if (fd < 0) continue;
            struct timeval tv{10, 0};
            (void)::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            (void)::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
            if (::connect(fd, p->ai_addr, p->ai_addrlen) == 0) break;
            ::close(fd); fd = -1;
        }
        ::freeaddrinfo(ai);
        if (fd < 0) { res.error = "failed to connect to loopback WebDAV server"; return res; }

        std::string host_hdr = u.host.contains(':') ? std::format("[{}]:{}", u.host, u.port) : std::format("{}:{}", u.host, u.port);
        std::string req = std::format("{} {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nContent-Length: {}\r\n",
                                      method, u.path, host_hdr, body.size());
        if (!username.empty() || !password.empty()) {
            req += "Authorization: Basic " + base64_encode(std::string(username) + ":" + std::string(password)) + "\r\n";
        }
        for (auto const& [k, v] : extra_headers) req += k + ": " + v + "\r\n";
        req += "\r\n";
        req.append(body.data(), body.size());

        int send_flags = 0;
#ifdef MSG_NOSIGNAL
        send_flags = MSG_NOSIGNAL;
#endif
        std::size_t off = 0;
        while (off < req.size()) {
            auto n = ::send(fd, req.data() + off, req.size() - off, send_flags);
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) { ::close(fd); res.error = "send failed"; return res; }
            off += static_cast<std::size_t>(n);
        }
        std::string raw;
        char buf[4096];
        for (;;) {
            auto n = ::recv(fd, buf, sizeof(buf), 0);
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) break;
            if (raw.size() < kMaxDavResponseBytes) {
                raw.append(buf, std::min<std::size_t>(static_cast<std::size_t>(n), kMaxDavResponseBytes - raw.size()));
            }
        }
        ::close(fd);
        auto sep = raw.find("\r\n\r\n");
        if (sep == std::string::npos) { res.error = "malformed HTTP response"; return res; }
        res.transport_ok = parse_http_headers(std::string_view(raw).substr(0, sep), res.status_code, res.etag);
        if (method != "HEAD") res.body = raw.substr(sep + 4);
        return res;
    }

    inline auto execute_https_curl(
        std::string_view method, std::string_view full_url,
        std::string_view username, std::string_view password,
        std::span<std::pair<std::string, std::string> const> extra_headers,
        std::string_view body) -> WebDavResponse {
        WebDavResponse res{};
        std::string curl_bin;
        std::error_code ec;
        for (char const* cand : {"/usr/bin/curl", "/usr/local/bin/curl", "/opt/homebrew/bin/curl"}) {
            if (std::filesystem::is_regular_file(cand, ec)) { curl_bin = cand; break; }
        }
        if (curl_bin.empty()) { res.error = "curl binary required for HTTPS WebDAV on POSIX"; return res; }

        auto tmp_dir = std::filesystem::temp_directory_path(ec);
        static std::atomic<std::uint64_t> seq{0};
        auto const n = seq.fetch_add(1, std::memory_order_relaxed);
        std::random_device rd;
        std::uint64_t const rnd = (static_cast<std::uint64_t>(rd()) << 32) ^ static_cast<std::uint64_t>(rd());
        auto cfg_p = tmp_dir / std::format(".nexus-dav-cfg.{}.{:016x}.{}", ::getpid(), rnd, n);
        auto hdr_p = tmp_dir / std::format(".nexus-dav-hdr.{}.{:016x}.{}", ::getpid(), rnd, n);
        auto body_p = tmp_dir / std::format(".nexus-dav-body.{}.{:016x}.{}", ::getpid(), rnd, n);
        std::size_t cfg_len = 0;
        auto cleanup = [&] {
            std::error_code cec;
            if (int wfd = ::open(cfg_p.c_str(), O_WRONLY | O_NOFOLLOW | O_CLOEXEC); wfd >= 0) {
                std::array<char, 512> zeros{};
                std::size_t rem = std::max<std::size_t>(cfg_len, zeros.size());
                while (rem > 0) {
                    auto w = ::write(wfd, zeros.data(), std::min(rem, zeros.size()));
                    if (w <= 0) break;
                    rem -= static_cast<std::size_t>(w);
                }
                (void)::ftruncate(wfd, 0);
                ::close(wfd);
            }
            std::filesystem::remove(cfg_p, cec);
            std::filesystem::remove(hdr_p, cec);
            std::filesystem::remove(body_p, cec);
        };
        auto esc_cfg = [](std::string_view sv) -> std::string {
            std::string o; o.reserve(sv.size() + 4);
            for (char c : sv) { if (c == '\\' || c == '"') o.push_back('\\'); o.push_back(c); }
            return o;
        };
        auto write_0600 = [](std::filesystem::path const& p, std::string_view data) -> bool {
            int fd = ::open(p.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
            if (fd < 0) return false;
            if (::fchmod(fd, 0600) != 0) { ::close(fd); ::unlink(p.c_str()); return false; }
            std::size_t off = 0;
            while (off < data.size()) {
                auto w = ::write(fd, data.data() + off, data.size() - off);
                if (w < 0 && errno == EINTR) continue;
                if (w <= 0) { ::close(fd); ::unlink(p.c_str()); return false; }
                off += static_cast<std::size_t>(w);
            }
            return ::close(fd) == 0;
        };
        std::string cfg = std::format("url = \"{}\"\nrequest = \"{}\"\n", esc_cfg(full_url), esc_cfg(method));
        if (!username.empty() || !password.empty()) {
            std::string creds = std::string(username) + ":" + std::string(password);
            cfg += "header = \"Authorization: Basic " + base64_encode(creds) + "\"\n";
            for (volatile char& ch : creds) ch = '\0';
        }
        for (auto const& [k, v] : extra_headers) cfg += std::format("header = \"{}: {}\"\n", esc_cfg(k), esc_cfg(v));
        cfg_len = cfg.size();
        bool staged_ok = write_0600(cfg_p, cfg) && write_0600(hdr_p, "");
        for (volatile char& ch : cfg) ch = '\0';
        cfg.clear();
        if (!staged_ok) { cleanup(); res.error = "failed to stage curl files"; return res; }
        if (!body.empty() && !write_0600(body_p, body)) { cleanup(); res.error = "failed to stage request body"; return res; }

        std::vector<std::string> args{
            curl_bin, "-q", "--silent", "--show-error", "--proto", "=https", "--proto-redir", "=https",
            "--max-redirs", "0", "--connect-timeout", "10", "--max-time", "15", "-D", hdr_p.string(), "-K", cfg_p.string(),
        };
        if (method == "HEAD") args.push_back("--head");
        if (!body.empty()) { args.push_back("--data-binary"); args.push_back("@" + body_p.string()); }

        int pipefd[2]{-1, -1};
        if (::pipe(pipefd) != 0) { cleanup(); res.error = "pipe failed"; return res; }
        (void)::fcntl(pipefd[0], F_SETFD, FD_CLOEXEC);
        (void)::fcntl(pipefd[1], F_SETFD, FD_CLOEXEC);
        std::vector<char*> argv;
        for (auto const& a : args) argv.push_back(const_cast<char*>(a.c_str()));
        argv.push_back(nullptr);
        int devnull = ::open("/dev/null", O_RDWR | O_CLOEXEC);
        pid_t child = ::fork();
        if (child < 0) {
            if (devnull >= 0) ::close(devnull);
            ::close(pipefd[0]); ::close(pipefd[1]); cleanup();
            res.error = "fork failed";
            return res;
        }
        if (child == 0) {
            ::close(pipefd[0]);
            if (devnull >= 0) {
                if (devnull == STDIN_FILENO) (void)::fcntl(devnull, F_SETFD, 0); else (void)::dup2(devnull, STDIN_FILENO);
                if (devnull == STDERR_FILENO) (void)::fcntl(devnull, F_SETFD, 0); else (void)::dup2(devnull, STDERR_FILENO);
            }
            if (pipefd[1] == STDOUT_FILENO) (void)::fcntl(pipefd[1], F_SETFD, 0); else (void)::dup2(pipefd[1], STDOUT_FILENO);
            ::execv(args[0].c_str(), argv.data());
            ::_exit(127);
        }
        if (devnull >= 0) ::close(devnull);
        ::close(pipefd[1]);
        int fl = ::fcntl(pipefd[0], F_GETFL, 0);
        if (fl >= 0) (void)::fcntl(pipefd[0], F_SETFL, fl | O_NONBLOCK);
        auto deadline = std::chrono::steady_clock::now() + kDavTimeout;
        char buf[4096];
        bool timed_out = false, eof = false;
        while (!eof) {
            if (std::chrono::steady_clock::now() >= deadline) { timed_out = true; break; }
            struct pollfd pfd{pipefd[0], POLLIN, 0};
            int pr = ::poll(&pfd, 1, 200);
            if (pr < 0 && errno == EINTR) continue;
            if (pr <= 0) continue;
            for (;;) {
                auto rd_n = ::read(pipefd[0], buf, sizeof(buf));
                if (rd_n > 0) {
                    if (res.body.size() < kMaxDavResponseBytes) {
                        res.body.append(buf, std::min<std::size_t>(static_cast<std::size_t>(rd_n), kMaxDavResponseBytes - res.body.size()));
                    }
                    continue;
                }
                if (rd_n == 0) { eof = true; break; }
                if (errno == EINTR) continue;
                if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                eof = true; break;
            }
            if (!eof && (pfd.revents & (POLLHUP | POLLERR | POLLNVAL))) eof = true;
        }
        ::close(pipefd[0]);
        int st = 0;
        bool reaped = false;
        if (!timed_out) {
            for (;;) {
                pid_t w = ::waitpid(child, &st, WNOHANG);
                if (w == child || (w < 0 && errno != EINTR)) { reaped = true; break; }
                if (std::chrono::steady_clock::now() >= deadline) { timed_out = true; break; }
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }
        }
        if (timed_out) { (void)::kill(child, SIGKILL); }
        if (!reaped) while (::waitpid(child, &st, 0) < 0 && errno == EINTR) {}
        std::ifstream hin(hdr_p, std::ios::binary);
        std::ostringstream hss;
        if (hin) hss << hin.rdbuf();
        cleanup();
        if (timed_out) { res.body.clear(); res.error = "HTTPS WebDAV request timed out"; return res; }
        if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) {
            res.body.clear();
            res.error = std::format("HTTPS WebDAV transport failed (curl exit {})", WIFEXITED(st) ? WEXITSTATUS(st) : -1);
            return res;
        }
        res.transport_ok = parse_http_headers(hss.str(), res.status_code, res.etag);
        if (!res.transport_ok) { res.body.clear(); res.error = "HTTPS WebDAV request failed (TLS or network error)"; }
        return res;
    }

    inline auto execute_http(
        ParsedDavUrl const& u, std::string_view method, std::string_view full_url,
        std::string_view username, std::string_view password,
        std::span<std::pair<std::string, std::string> const> extra_headers,
        std::string_view body) -> WebDavResponse {
        if (!u.is_https) return execute_loopback_http(u, method, username, password, extra_headers, body);
        return execute_https_curl(method, full_url, username, password, extra_headers, body);
    }
#endif
}
