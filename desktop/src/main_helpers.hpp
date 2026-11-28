// Private desktop UI rate tracker, control config, TUN privilege & log snapshot helpers for desktop/src/main.cpp.
#pragma once
#include "speed_wave.hpp"
#include "flagship_helpers.hpp"
#include "clipboard_helpers.hpp"

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
        OnsetMarkerTracker onset;

        struct Update {
            std::string up_rate;
            std::string down_rate;
            std::string down_value, down_unit, up_value, up_unit;
            std::string rx_area, rx_line, tx_dashed_line, scale_peak;
            bool has_onset = false;
            float onset_ratio = -1.0f;
            std::string onset_label;
        };

        auto mark_onset(std::string label) -> void {
            onset.mark(std::move(label));
        }

        auto reset() -> void {
            has_prev = false; prev_up = 0; prev_down = 0;
            down_kib_s.clear(); up_kib_s.clear();
            onset.reset();
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

            bool const has_onset = onset.active();
            float const onset_ratio = onset.ratio(kSlots);
            std::string onset_lbl = onset.label;
            onset.advance(kSlots);

            auto dl_parts = split_rate_parts(down_kib);
            auto ul_parts = split_rate_parts(up_kib);
            auto dual = build_dual_speed_wave_paths(down_kib_s, up_kib_s, kSlots, 8.0, 560.0, 56.0);
            return {
                format_rate_human(up_kib), format_rate_human(down_kib),
                std::move(dl_parts.value), std::move(dl_parts.unit),
                std::move(ul_parts.value), std::move(ul_parts.unit),
                std::move(dual.rx_area), std::move(dual.rx_line), std::move(dual.tx_dashed_line),
                format_rate_human(dual.scale_top_kib),
                has_onset, onset_ratio, std::move(onset_lbl),
            };
        }
    };

    struct CpuUsageTracker {
        using Clock = std::chrono::steady_clock;
        bool has_prev = false;
        std::uint64_t prev_cpu_ns = 0;
        Clock::time_point prev_ts{};
        double cores = static_cast<double>(std::max(1u, std::thread::hardware_concurrency()));

        struct Sample {
            std::string text;
            float ratio = 0.0f;
        };

        auto reset() noexcept -> void {
            has_prev = false;
            prev_cpu_ns = 0;
        }

        auto record(std::uint64_t cpu_ns) -> Sample {
            auto now = Clock::now();
            double pct = 0.0;
            if (has_prev && now > prev_ts && cpu_ns >= prev_cpu_ns) {
                double dt_ns = std::chrono::duration<double, std::nano>(now - prev_ts).count();
                if (dt_ns > 50'000'000.0) {
                    pct = std::clamp((static_cast<double>(cpu_ns - prev_cpu_ns) / (dt_ns * cores)) * 100.0, 0.0, 100.0);
                }
            }
            has_prev = true;
            prev_cpu_ns = cpu_ns;
            prev_ts = now;
            return {std::format("{:.1f}%", pct), static_cast<float>(pct / 100.0)};
        }
    };

    inline auto format_logs_snapshot(std::vector<desktop::LogEntrySnapshot> const& entries) -> std::string {
        std::string out;
        for (auto const& e : entries)
            out += std::format("#{} [{}] ({}) {}\n", e.seq, e.level, e.domain, e.message);
        return out;
    }

    inline auto config_has_tun_inbound(std::string_view cfg_text) noexcept -> bool {
        return cfg_text.contains("type=\"tun\"") || cfg_text.contains("type \"tun\"");
    }

    inline auto validate_draft_config(
        std::filesystem::path const& cfg_dir,
        desktop::CoreSupervisor const& supervisor,
        std::string const& payload,
        bool is_en) -> desktop::ValidationResult {
        auto tmp = cfg_dir / ".validate-draft.kdl";
        if (!write_file_atomic(tmp, payload)) {
            return {false, tr(is_en, "无法写入临时校验文件", "Failed to write temporary validation file")};
        }
        auto res = supervisor.validate_config(tmp);
        std::error_code ec;
        std::filesystem::remove(tmp, ec);
        return res;
    }

    struct ControlConfigParsed {
        std::string http_host = "127.0.0.1";
        std::uint16_t http_port = 19090;
        std::string bearer_token;
    };

    struct StartPrepResult {
        bool ok = false;
        std::string composed_text;
        std::string error_message;
        ControlConfigParsed control;
    };

    inline auto parse_http_listen_spec(std::string_view listen, ControlConfigParsed& out) -> void {
        if (auto colon = listen.rfind(':'); colon != std::string_view::npos) {
            if (auto port = desktop::parse_port_u16(listen.substr(colon + 1))) {
                std::string h(listen.substr(0, colon));
                if (h.size() >= 2 && h.front() == '[' && h.back() == ']') h = h.substr(1, h.size() - 2);
                if (h.empty() || h == "0.0.0.0") h = "127.0.0.1";
                else if (h == "::") h = "::1";
                out.http_host = std::move(h);
                out.http_port = *port;
            }
        }
    }

    inline auto read_trimmed_token(std::filesystem::path const& tok_path) -> std::string {
        auto tok = read_file_text(tok_path);
        while (!tok.empty() && (tok.back() == '\n' || tok.back() == '\r' || tok.back() == ' ')) tok.pop_back();
        while (!tok.empty() && tok.front() == ' ') tok.erase(tok.begin());
        return tok;
    }

    inline auto parse_host_control_config(desktop::DesktopHostConfig const& host) -> ControlConfigParsed {
        ControlConfigParsed out{};
        if (!host.control_http_listen.empty()) parse_http_listen_spec(host.control_http_listen, out);
        if (!host.control_bearer_file.empty()) {
            std::filesystem::path bp(std::u8string_view(
                reinterpret_cast<char8_t const*>(host.control_bearer_file.data()), host.control_bearer_file.size()));
            out.bearer_token = read_trimmed_token(bp);
        }
        return out;
    }

    inline auto parse_control_config(std::string_view cfg_text, std::filesystem::path const& base_dir = {}) -> ControlConfigParsed {
        ControlConfigParsed out{};
        auto extract_q = [](std::string_view line, std::string_view key) -> std::optional<std::string> {
            auto p = line.find(key);
            if (p == std::string_view::npos) return std::nullopt;
            p += key.size();
            auto e = line.find('"', p);
            if (e == std::string_view::npos) return std::nullopt;
            return std::string(line.substr(p, e - p));
        };
        while (!cfg_text.empty()) {
            auto nl = cfg_text.find('\n');
            auto line = nl == std::string_view::npos ? cfg_text : cfg_text.substr(0, nl);
            cfg_text = nl == std::string_view::npos ? std::string_view{} : cfg_text.substr(nl + 1);
            while (!line.empty() && (line.front() == ' ' || line.front() == '\t')) line.remove_prefix(1);
            if (line.starts_with("//") || !(line == "control" || line.starts_with("control ") || line.starts_with("control\t"))) {
                continue;
            }
            if (auto hl = extract_q(line, "http-listen=\""); hl && !hl->empty()) {
                parse_http_listen_spec(*hl, out);
            }
            if (auto tf = extract_q(line, "bearer-token-file=\""); tf && !tf->empty()) {
                std::filesystem::path tok_path(*tf);
                if (tok_path.is_relative() && !base_dir.empty()) tok_path = base_dir / tok_path;
                out.bearer_token = read_trimmed_token(tok_path);
            }
            break;
        }
        return out;
    }

    inline auto prepare_config_before_start(
        std::filesystem::path const& cfg_dir,
        std::filesystem::path const& config_path,
        desktop::CoreSupervisor const& supervisor,
        std::string composed_text,
        bool is_en) -> StartPrepResult {
        StartPrepResult res{};
        std::error_code ec;
        if (composed_text.empty()) {
            if (std::filesystem::exists(config_path, ec)) composed_text = read_file_text(config_path);
            if (composed_text.empty()) {
                res.error_message = tr(is_en, "请先在工作区添加至少一个配置项", "Add at least one profile in Workspace first");
                return res;
            }
        }
        bool needs_write = !std::filesystem::exists(config_path, ec) || read_file_text(config_path) != composed_text;
        if (needs_write) {
            auto val = validate_draft_config(cfg_dir, supervisor, composed_text, is_en);
            if (!val.ok) {
                res.error_message = std::move(val.message);
                return res;
            }
            if (!write_file_atomic(config_path, composed_text)) {
                res.error_message = tr(is_en, "写入运行配置失败", "Failed to write runtime configuration");
                return res;
            }
        }
        res.control = parse_control_config(composed_text, cfg_dir);
        res.composed_text = std::move(composed_text);
        res.ok = true;
        return res;
    }

    inline auto tun_status_to_ui_string(desktop::TunPrivilegeStatus st) noexcept -> std::string_view {
        switch (st) {
        case desktop::TunPrivilegeStatus::ready_root_or_admin: return "ready_root";
        case desktop::TunPrivilegeStatus::ready_persistent_cap: return "ready_persistent";
        case desktop::TunPrivilegeStatus::needs_elevation: return "needs_elevation";
        case desktop::TunPrivilegeStatus::unavailable: return "unavailable";
        }
        return "unavailable";
    }

    inline auto apply_tun_probe_to_ui(nexus_ui::AppWindow& ui, desktop::TunPrivilegeProbe const& p) -> void {
        ui.set_tun_privilege_status(slint::SharedString(tun_status_to_ui_string(p.status)));
        ui.set_tun_persistent_granted(p.has_persistent_grant);
        ui.set_tun_can_persist(p.supports_persistent);
    }

    inline auto resolve_tun_elevation_for_start(
        std::filesystem::path const& binary_path,
        std::filesystem::path const& config_path,
        std::filesystem::path const& workdir,
        bool prefer_persistent,
        bool en,
        desktop::CoreStartOptions& out_opts,
        desktop::TunPrivilegeProbe& out_probe) -> desktop::ElevationResult {
        out_opts = {};
        out_probe = desktop::probe_tun_privilege(binary_path);
        if (out_probe.status == desktop::TunPrivilegeStatus::ready_root_or_admin) {
            return {true, false, {}};
        }
        if (out_probe.status == desktop::TunPrivilegeStatus::ready_persistent_cap) {
            out_opts.use_persistent_helper = out_probe.helper_required_for_persistent;
            return {true, false, {}};
        }
        if (out_probe.status == desktop::TunPrivilegeStatus::unavailable) {
            return {false, false, out_probe.detail.empty()
                ? tr(en, "当前环境不支持 TUN 提权", "TUN elevation is unavailable on this host")
                : out_probe.detail};
        }
        if (prefer_persistent && out_probe.supports_persistent) {
            auto grant = desktop::grant_persistent_tun_privilege(binary_path, en, config_path, workdir);
            out_probe = desktop::probe_tun_privilege(binary_path);
            if (!grant.ok) return grant;
            if (out_probe.status == desktop::TunPrivilegeStatus::ready_persistent_cap) {
                out_opts.use_persistent_helper = out_probe.helper_required_for_persistent;
                return {true, false, grant.message};
            }
            if (out_probe.status == desktop::TunPrivilegeStatus::ready_root_or_admin) {
                return {true, false, grant.message};
            }
            if (out_probe.supports_session_only) {
                out_opts.elevate_session = true;
                return {true, false, grant.message};
            }
            return {false, false, grant.message};
        }
        if (out_probe.supports_session_only) {
            out_opts.elevate_session = true;
            return {true, false, {}};
        }
        return {false, false, out_probe.detail.empty()
            ? tr(en, "缺少按次提权所需系统工具", "Session-only elevation helper unavailable on host")
            : out_probe.detail};
    }
}
