// Private desktop UI rate tracker & log snapshot formatting helpers included by desktop/src/main.cpp.
#pragma once
#include "speed_wave.hpp"

namespace desktop_ui_helpers {
    inline auto default_config_dir() -> std::filesystem::path {
        std::error_code ec;
#ifdef _WIN32
        char const* appdata = std::getenv("LOCALAPPDATA");
        auto base = (appdata && *appdata) ? std::filesystem::path(appdata) : std::filesystem::temp_directory_path(ec);
        return (ec || base.empty() ? std::filesystem::path(".") : base) / "Nexus";
#else
        if (char const* xdg = std::getenv("XDG_CONFIG_HOME"); xdg && *xdg) return std::filesystem::path(xdg) / "nexus";
        char const* home = std::getenv("HOME");
        auto base = (home && *home) ? std::filesystem::path(home) : std::filesystem::temp_directory_path(ec);
        return (ec || base.empty() ? std::filesystem::path("/tmp") : base) / ".config" / "nexus";
#endif
    }

    inline auto default_control_endpoint(std::filesystem::path const& cfg_dir) -> std::string {
#ifdef _WIN32
        (void)cfg_dir;
        return R"(\\.\pipe\nexus-control)";
#else
        char const* run = std::getenv("XDG_RUNTIME_DIR");
        if (run && *run) return (std::filesystem::path(run) / "nexus-control.sock").string();
        auto run_dir = cfg_dir / "run";
        std::error_code ec;
        std::filesystem::create_directories(run_dir, ec);
        std::filesystem::permissions(run_dir,
            std::filesystem::perms::owner_read | std::filesystem::perms::owner_write | std::filesystem::perms::owner_exec, ec);
        return (run_dir / "control.sock").string();
#endif
    }

    inline auto read_file_text(std::filesystem::path const& path) -> std::string {
        std::ifstream in(path, std::ios::binary);
        if (!in) return {};
        std::ostringstream ss;
        ss << in.rdbuf();
        return ss.str();
    }

    inline auto write_file_atomic(std::filesystem::path const& path, std::string const& text) -> bool {
        auto tmp = path;
        tmp += ".tmp";
        std::error_code ec;
        {
            std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
            if (!out) return false;
            out.write(text.data(), static_cast<std::streamsize>(text.size()));
            if (!out.good()) {
                out.close();
                std::filesystem::remove(tmp, ec);
                return false;
            }
        }
        std::filesystem::rename(tmp, path, ec);
        if (ec) {
            std::filesystem::remove(tmp, ec);
            return false;
        }
        return true;
    }

    inline auto open_with_system_editor(std::filesystem::path const& path) -> void {
#ifdef _WIN32
        ::ShellExecuteW(nullptr, L"open", path.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
#else
        auto arg = path.string();
        pid_t child = ::fork();
        if (child < 0) return;
        if (child == 0) {
            pid_t grand = ::fork();
            if (grand == 0) {
                int devnull = ::open("/dev/null", O_RDWR | O_CLOEXEC);
                if (devnull >= 0) {
                    (void)::dup2(devnull, STDIN_FILENO);
                    (void)::dup2(devnull, STDOUT_FILENO);
                    (void)::dup2(devnull, STDERR_FILENO);
                }
#ifdef __APPLE__
                char* argv[] = {const_cast<char*>("open"), arg.data(), nullptr};
                ::execvp("open", argv);
#else
                char* argv[] = {const_cast<char*>("xdg-open"), arg.data(), nullptr};
                ::execvp("xdg-open", argv);
#endif
                ::_exit(127);
            }
            ::_exit(0);
        }
        int status = 0;
        while (::waitpid(child, &status, 0) < 0 && errno == EINTR) {}
#endif
    }

#ifndef _WIN32
    inline auto run_clipboard_tool(char const* const argv[], std::string const& text) -> bool {
        int pipefd[2]{-1, -1};
        if (::pipe(pipefd) != 0) return false;
        (void)::fcntl(pipefd[0], F_SETFD, FD_CLOEXEC);
        (void)::fcntl(pipefd[1], F_SETFD, FD_CLOEXEC);
        pid_t child = ::fork();
        if (child < 0) {
            ::close(pipefd[0]);
            ::close(pipefd[1]);
            return false;
        }
        if (child == 0) {
            ::close(pipefd[1]);
            if (pipefd[0] == STDIN_FILENO) (void)::fcntl(pipefd[0], F_SETFD, 0);
            else (void)::dup2(pipefd[0], STDIN_FILENO);
            int devnull = ::open("/dev/null", O_WRONLY | O_CLOEXEC);
            if (devnull >= 0) {
                (void)::dup2(devnull, STDOUT_FILENO);
                (void)::dup2(devnull, STDERR_FILENO);
            }
            ::execvp(argv[0], const_cast<char* const*>(argv));
            ::_exit(127);
        }
        ::close(pipefd[0]);
        std::size_t off = 0;
        while (off < text.size()) {
            auto n = ::write(pipefd[1], text.data() + off, text.size() - off);
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) break;
            off += static_cast<std::size_t>(n);
        }
        ::close(pipefd[1]);
        int status = 0;
        while (::waitpid(child, &status, 0) < 0) { if (errno != EINTR) return false; }
        return WIFEXITED(status) && WEXITSTATUS(status) == 0;
    }
#endif

    inline auto copy_text_to_clipboard(std::string const& text) -> bool {
        if (text.empty()) return false;
#ifdef _WIN32
        int wlen = ::MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0);
        if (wlen <= 0) return false;
        if (!::OpenClipboard(nullptr)) return false;
        ::EmptyClipboard();
        HGLOBAL hmem = ::GlobalAlloc(GMEM_MOVEABLE, static_cast<SIZE_T>(wlen + 1) * sizeof(wchar_t));
        if (!hmem) { ::CloseClipboard(); return false; }
        auto* dst = static_cast<wchar_t*>(::GlobalLock(hmem));
        if (!dst) { ::GlobalFree(hmem); ::CloseClipboard(); return false; }
        ::MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), dst, wlen);
        dst[wlen] = L'\0';
        ::GlobalUnlock(hmem);
        if (!::SetClipboardData(CF_UNICODETEXT, hmem)) { ::GlobalFree(hmem); ::CloseClipboard(); return false; }
        ::CloseClipboard();
        return true;
#else
#ifdef __APPLE__
        char const* const pbcopy_argv[] = {"pbcopy", nullptr};
        if (run_clipboard_tool(pbcopy_argv, text)) return true;
#else
        if (char const* wl = std::getenv("WAYLAND_DISPLAY"); wl && *wl) {
            char const* const wl_argv[] = {"wl-copy", nullptr};
            if (run_clipboard_tool(wl_argv, text)) return true;
        }
        if (char const* x11 = std::getenv("DISPLAY"); x11 && *x11) {
            char const* const xclip_argv[] = {"xclip", "-selection", "clipboard", nullptr};
            if (run_clipboard_tool(xclip_argv, text)) return true;
            char const* const xsel_argv[] = {"xsel", "--clipboard", "--input", nullptr};
            if (run_clipboard_tool(xsel_argv, text)) return true;
        }
#endif
        return false;
#endif
    }

    inline auto tr(bool en, std::string_view zh, std::string_view en_s) -> std::string {
        return std::string(en ? en_s : zh);
    }

    inline auto format_bytes_human(std::uint64_t b) -> std::string {
        if (b >= 1024ULL * 1024 * 1024) {
            return std::format("{:.2f} GB", static_cast<double>(b) / (1024.0 * 1024.0 * 1024.0));
        }
        if (b >= 1024ULL * 1024) {
            return std::format("{:.1f} MB", static_cast<double>(b) / (1024.0 * 1024.0));
        }
        if (b >= 1024ULL) {
            return std::format("{} KB", b / 1024ULL);
        }
        return std::format("{} B", b);
    }

    inline auto format_rate_human(double kib_s) -> std::string {
        if (kib_s >= 1024.0) {
            return std::format("{:.1f} MB/s", kib_s / 1024.0);
        }
        return std::format("{:.1f} KB/s", kib_s);
    }

    inline auto format_uptime(std::chrono::seconds elapsed) -> std::string {
        auto total = std::max<long long>(0, elapsed.count());
        auto hrs = total / 3600;
        auto mins = (total % 3600) / 60;
        auto secs = total % 60;
        return std::format("{:02}:{:02}:{:02}", hrs, mins, secs);
    }

    struct RateTracker {
        static constexpr std::size_t kSlots = 24;
        static constexpr std::size_t kHistory = kSlots + 5;
        using Clock = std::chrono::steady_clock;
        bool has_prev = false;
        std::uint64_t prev_up = 0, prev_down = 0;
        Clock::time_point prev_ts{};
        std::vector<double> down_kib_s, up_kib_s;

        struct Update {
            std::string up_rate;
            std::string down_rate;
            std::string down_value, down_unit, down_peak, down_wave_area, down_wave_line;
            std::string up_value, up_unit, up_peak, up_wave_area, up_wave_line;
        };

        auto reset() -> void {
            has_prev = false; prev_up = 0; prev_down = 0;
            down_kib_s.clear(); up_kib_s.clear();
        }

        auto record(std::uint64_t up_bytes, std::uint64_t down_bytes) -> Update {
            auto now = Clock::now();
            double up_kib = 0.0, down_kib = 0.0;
            if (has_prev && now > prev_ts) {
                double dt = std::chrono::duration<double>(now - prev_ts).count();
                if (dt > 0.05) {
                    up_kib = up_bytes >= prev_up ? static_cast<double>(up_bytes - prev_up) / 1024.0 / dt : 0.0;
                    down_kib = down_bytes >= prev_down ? static_cast<double>(down_bytes - prev_down) / 1024.0 / dt : 0.0;
                }
            }
            has_prev = true; prev_up = up_bytes; prev_down = down_bytes; prev_ts = now;
            down_kib_s.push_back(down_kib); up_kib_s.push_back(up_kib);
            if (down_kib_s.size() > kHistory) down_kib_s.erase(down_kib_s.begin());
            if (up_kib_s.size() > kHistory) up_kib_s.erase(up_kib_s.begin());

            std::size_t vis_n = std::min(down_kib_s.size(), kSlots);
            std::size_t vis_off = down_kib_s.size() - vis_n;
            double max_dl = 0.0, max_ul = 0.0;
            for (std::size_t i = 0; i < vis_n; ++i) {
                max_dl = std::max(max_dl, down_kib_s[vis_off + i]);
                max_ul = std::max(max_ul, up_kib_s[vis_off + i]);
            }
            auto dl_parts = split_rate_parts(down_kib);
            auto ul_parts = split_rate_parts(up_kib);
            auto dl_wave = build_speed_wave_paths(down_kib_s, kSlots);
            auto ul_wave = build_speed_wave_paths(up_kib_s, kSlots);
            return {
                format_rate_human(up_kib), format_rate_human(down_kib),
                std::move(dl_parts.value), std::move(dl_parts.unit), format_rate_human(max_dl),
                std::move(dl_wave.area_cmd), std::move(dl_wave.line_cmd),
                std::move(ul_parts.value), std::move(ul_parts.unit), format_rate_human(max_ul),
                std::move(ul_wave.area_cmd), std::move(ul_wave.line_cmd),
            };
        }
    };

    inline auto format_logs_snapshot(std::vector<desktop::LogEntrySnapshot> const& entries) -> std::string {
        std::string out;
        for (auto const& e : entries)
            out += std::format("#{} [{}] ({}) {}\n", e.seq, e.level, e.domain, e.message);
        return out;
    }

    inline constexpr std::string_view kManagedTunMarker = "// nexus-desktop managed-tun\n";
    inline constexpr std::string_view kManagedTunBlock =
        "// nexus-desktop managed-tun\n"
        "inbound \"tun-in\" type=\"tun\" {\n"
        "    interface-name \"nexus-tun0\"\n"
        "    address \"172.19.0.1/30\"\n"
        "    mtu 1400\n"
        "    auto-route #true\n"
        "}\n"
        "// /nexus-desktop managed-tun\n";

    inline auto kdl_has_tun_inbound(std::string_view kdl) -> bool {
        return kdl.contains("type=\"tun\"") || kdl.contains("type \"tun\"");
    }

    inline auto toggle_tun_in_kdl(std::string_view kdl, bool enable, bool is_en = false) -> std::pair<bool, std::string> {
        constexpr std::string_view kEnd = "// /nexus-desktop managed-tun\n";
        std::string out(kdl);
        auto start = out.find(kManagedTunMarker);
        if (!enable) {
            if (start != std::string::npos) {
                auto end = out.find(kEnd, start);
                if (end != std::string::npos) out.erase(start, (end + kEnd.size()) - start);
                return {true, std::move(out)};
            }
            if (kdl_has_tun_inbound(out)) {
                return {false, tr(is_en, "检测到自定义 TUN 入站，请在外部编辑器中手动修改", "Custom TUN inbound detected; edit manually in external editor")};
            }
            return {true, std::move(out)};
        }
        if (kdl_has_tun_inbound(out)) return {true, std::move(out)};
        if (!out.empty() && out.back() != '\n') out.push_back('\n');
        out.append("\n").append(kManagedTunBlock);
        return {true, std::move(out)};
    }

    inline auto validate_draft_config(
        std::filesystem::path const& cfg_dir,
        desktop::CoreSupervisor const& supervisor,
        std::string const& payload,
        bool is_en) -> desktop::ValidationResult {
        auto tmp = cfg_dir / ".validate-draft.kdl";
        if (!write_file_atomic(tmp, payload)) {
            return {false, tr(is_en, "无法写入临时校验文件", "Failed to write temp file")};
        }
        auto res = supervisor.validate_config(tmp);
        std::error_code ec;
        std::filesystem::remove(tmp, ec);
        return res;
    }

    struct ControlConfigParsed {
        std::string socket;
        std::string http_host = "127.0.0.1";
        std::uint16_t http_port = 9090;
        std::string bearer_token;
    };

    struct StartPrepResult {
        bool ok = false;
        bool synthesized_default = false;
        std::string kdl_text;
        std::string error_message;
        ControlConfigParsed control;
    };

    inline auto build_default_desktop_config(std::string_view control_socket) -> std::string {
        std::string ctl_line = "control http-listen=\"127.0.0.1:9090\" metrics=#true\n";
        if (!control_socket.empty() && control_socket.front() == '/' &&
            !control_socket.contains('"') && !control_socket.contains('\\')) {
            ctl_line = std::format("control socket=\"{}\" http-listen=\"127.0.0.1:9090\" metrics=#true\n", control_socket);
        }
        return std::format(
            "schema-version 1\n"
            "role \"client\"\n"
            "{}"
            "// nexus-desktop managed-inbound mixed\n"
            "inbound \"local-mixed\" type=\"mixed\" {{\n"
            "    listen host=\"127.0.0.1\" port=7890\n"
            "    authentication \"none\"\n"
            "}}\n"
            "// /nexus-desktop managed-inbound mixed\n"
            "// nexus-desktop managed-inbound socks5\n"
            "inbound \"local-socks5\" type=\"socks5\" {{\n"
            "    listen host=\"127.0.0.1\" port=1080\n"
            "    authentication \"none\"\n"
            "}}\n"
            "// /nexus-desktop managed-inbound socks5\n"
            "outbound \"direct\" type=\"direct\"\n"
            "routing {{ default-outbound \"direct\"; }}\n",
            ctl_line);
    }

    inline auto parse_control_config(std::string_view kdl, std::string_view fallback_socket,
                                     std::filesystem::path const& base_dir = {}) -> ControlConfigParsed {
        ControlConfigParsed out{};
        out.socket = std::string(fallback_socket);
        auto extract_q = [](std::string_view line, std::string_view key) -> std::optional<std::string> {
            auto p = line.find(key);
            if (p == std::string_view::npos) return std::nullopt;
            p += key.size();
            auto e = line.find('"', p);
            if (e == std::string_view::npos) return std::nullopt;
            return std::string(line.substr(p, e - p));
        };
        while (!kdl.empty()) {
            auto nl = kdl.find('\n');
            auto line = nl == std::string_view::npos ? kdl : kdl.substr(0, nl);
            kdl = nl == std::string_view::npos ? std::string_view{} : kdl.substr(nl + 1);
            while (!line.empty() && (line.front() == ' ' || line.front() == '\t')) line.remove_prefix(1);
            if (line.starts_with("//") || !(line == "control" || line.starts_with("control ") || line.starts_with("control\t"))) {
                continue;
            }
            if (auto s = extract_q(line, "socket=\""); s && !s->empty()) out.socket = *s;
            if (auto hl = extract_q(line, "http-listen=\""); hl && !hl->empty()) {
                if (auto colon = hl->rfind(':'); colon != std::string::npos) {
                    if (auto port = desktop::parse_port_u16(std::string_view(*hl).substr(colon + 1))) {
                        auto h = hl->substr(0, colon);
                        if (h.size() >= 2 && h.front() == '[' && h.back() == ']') h = h.substr(1, h.size() - 2);
                        if (h == "0.0.0.0") h = "127.0.0.1";
                        else if (h == "::") h = "::1";
                        out.http_host = std::move(h);
                        out.http_port = *port;
                    }
                }
            }
            if (auto tf = extract_q(line, "bearer-token-file=\""); tf && !tf->empty()) {
                std::filesystem::path tok_path(*tf);
                if (tok_path.is_relative() && !base_dir.empty()) tok_path = base_dir / tok_path;
                auto tok = read_file_text(tok_path);
                while (!tok.empty() && (tok.back() == '\n' || tok.back() == '\r' || tok.back() == ' ')) tok.pop_back();
                while (!tok.empty() && tok.front() == ' ') tok.erase(tok.begin());
                out.bearer_token = std::move(tok);
            }
            break;
        }
        return out;
    }

    inline auto prepare_config_before_start(
        std::filesystem::path const& cfg_dir,
        std::filesystem::path const& config_path,
        desktop::CoreSupervisor const& supervisor,
        std::string draft_kdl,
        std::string_view fallback_socket,
        bool is_en) -> StartPrepResult {
        StartPrepResult res{};
        std::error_code ec;
        if (draft_kdl.empty()) {
            if (std::filesystem::exists(config_path, ec)) draft_kdl = read_file_text(config_path);
            if (draft_kdl.empty()) {
                draft_kdl = build_default_desktop_config(fallback_socket);
                res.synthesized_default = true;
            }
        }
        bool needs_write = !std::filesystem::exists(config_path, ec) || read_file_text(config_path) != draft_kdl;
        if (needs_write) {
            auto val = validate_draft_config(cfg_dir, supervisor, draft_kdl, is_en);
            if (!val.ok) {
                res.error_message = std::move(val.message);
                return res;
            }
            if (!write_file_atomic(config_path, draft_kdl)) {
                res.error_message = tr(is_en, "写入配置文件失败", "Failed to write config file");
                return res;
            }
        }
        res.control = parse_control_config(draft_kdl, fallback_socket, cfg_dir);
        res.kdl_text = std::move(draft_kdl);
        res.ok = true;
        return res;
    }
}
