// Private desktop UI rate tracker & log snapshot formatting helpers included by desktop/src/main.cpp.
#pragma once

namespace desktop_ui_helpers {
    inline auto default_config_dir() -> std::filesystem::path {
#ifdef _WIN32
        char const* appdata = std::getenv("LOCALAPPDATA");
        return (appdata && *appdata ? std::filesystem::path(appdata) : std::filesystem::temp_directory_path()) / "Nexus";
#else
        char const* xdg = std::getenv("XDG_CONFIG_HOME");
        if (xdg && *xdg) return std::filesystem::path(xdg) / "nexus";
        char const* home = std::getenv("HOME");
        return (home && *home ? std::filesystem::path(home) : std::filesystem::temp_directory_path()) / ".config" / "nexus";
#endif
    }

    inline auto default_control_endpoint(std::filesystem::path const& cfg_dir) -> std::string {
#ifdef _WIN32
        (void)cfg_dir;
        return R"(\\.\pipe\nexus-control)";
#else
        char const* run = std::getenv("XDG_RUNTIME_DIR");
        if (run && *run) return (std::filesystem::path(run) / "nexus-control.sock").string();
        return (cfg_dir / "control.sock").string();
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
        {
            std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
            if (!out) return false;
            out.write(text.data(), static_cast<std::streamsize>(text.size()));
            if (!out.good()) return false;
        }
        std::error_code ec;
        std::filesystem::rename(tmp, path, ec);
        return !ec;
    }

    inline auto open_with_system_editor(std::filesystem::path const& path) -> void {
#ifdef _WIN32
        ::ShellExecuteW(nullptr, L"open", path.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
#else
        pid_t child = ::fork();
        if (child == 0) {
            auto arg = path.string();
            char* argv[] = {const_cast<char*>("xdg-open"), arg.data(), nullptr};
            ::execvp("xdg-open", argv);
            ::_exit(127);
        }
#endif
    }

    struct RateTracker {
        using Clock = std::chrono::steady_clock;
        bool has_prev = false;
        std::uint64_t prev_up = 0, prev_down = 0;
        Clock::time_point prev_ts{};
        std::deque<double> combined_kib_s;

        struct Update {
            std::string summary;
            std::vector<float> bars;
        };

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
            has_prev = true;
            prev_up = up_bytes;
            prev_down = down_bytes;
            prev_ts = now;
            combined_kib_s.push_back(up_kib + down_kib);
            if (combined_kib_s.size() > 20) combined_kib_s.pop_front();
            double peak = 1.0;
            for (double v : combined_kib_s) peak = std::max(peak, v);
            std::vector<float> bars;
            bars.reserve(combined_kib_s.size());
            for (double v : combined_kib_s) bars.push_back(static_cast<float>(std::clamp(v / peak, 0.0, 1.0)));
            return {std::format("实时速率: ↑ {:.1f} KiB/s · ↓ {:.1f} KiB/s", up_kib, down_kib), std::move(bars)};
        }
    };

    inline auto format_logs_snapshot(std::vector<desktop::LogRingEntry> const& entries) -> std::string {
        std::string out;
        for (auto const& e : entries)
            out += std::format("#{} [{}] ({}) {}\n", e.seq, e.level, e.domain, e.message);
        return out;
    }

    inline constexpr std::string_view kManagedTunMarker = "# nexus-desktop managed-tun\n";
    inline constexpr std::string_view kManagedTunBlock =
        "# nexus-desktop managed-tun\n"
        "inbound \"tun-in\" type=\"tun\" {\n"
        "    interface-name \"nexus-tun0\"\n"
        "    address \"172.19.0.1/30\"\n"
        "    mtu 1400\n"
        "    auto-route #true\n"
        "}\n"
        "# /nexus-desktop managed-tun\n";

    inline auto kdl_has_tun_inbound(std::string_view kdl) -> bool {
        return kdl.contains("type=\"tun\"") || kdl.contains("type \"tun\"");
    }

    inline auto toggle_tun_in_kdl(std::string_view kdl, bool enable) -> std::pair<bool, std::string> {
        constexpr std::string_view kEnd = "# /nexus-desktop managed-tun\n";
        std::string out(kdl);
        auto start = out.find(kManagedTunMarker);
        if (!enable) {
            if (start != std::string::npos) {
                auto end = out.find(kEnd, start);
                if (end != std::string::npos) out.erase(start, (end + kEnd.size()) - start);
                return {true, std::move(out)};
            }
            if (kdl_has_tun_inbound(out)) return {false, "检测到自定义 TUN 入站，请在 KDL 编辑器中手动修改"};
            return {true, std::move(out)};
        }
        if (kdl_has_tun_inbound(out)) return {true, std::move(out)};
        if (!out.empty() && out.back() != '\n') out.push_back('\n');
        out.append("\n").append(kManagedTunBlock);
        return {true, std::move(out)};
    }

    inline auto format_connection_detail(desktop::ActiveConnectionSnapshot const& c) -> std::string {
        return std::format("#{} [{}] {} → {} · 出站: {} · 模式: {} · 规则: {} · 耗时: {}ms · 进程: {}",
            c.id, c.inbound.empty() ? c.protocol : c.inbound,
            c.source.empty() ? "-" : c.source,
            c.target.empty() ? std::format(":{}", c.destination_port) : c.target,
            c.outbound.empty() ? c.path : c.outbound,
            c.route_mode.empty() ? "-" : c.route_mode,
            c.route_rule.empty() ? "-" : c.route_rule,
            c.duration_ms, c.process_path.empty() ? "-" : c.process_path);
    }

    inline auto build_ui_connection_items(std::vector<desktop::ActiveConnectionSnapshot> const& parsed, std::string filter)
        -> std::vector<nexus_ui::ActiveConnectionItem> {
        for (char& ch : filter) ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
        std::vector<nexus_ui::ActiveConnectionItem> items;
        for (auto const& c : parsed) {
            auto hay = std::format("{} {} {} {} {} {}", c.id, c.protocol, c.path, c.outbound, c.target, c.destination_port);
            for (char& ch : hay) ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
            if (!filter.empty() && !hay.contains(filter)) continue;
            items.push_back({slint::SharedString(std::to_string(c.id)), slint::SharedString(c.protocol),
                slint::SharedString(c.path), static_cast<int>(c.destination_port),
                static_cast<int>(c.upload_bytes), static_cast<int>(c.download_bytes)});
        }
        return items;
    }
}
