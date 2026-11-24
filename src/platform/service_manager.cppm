export module platform.service_manager;
import std;

export namespace platform {
    struct ServiceSpec {
        std::string name = "nexus";
        std::string binary_path;
        std::string config_path;
        std::string working_dir;
        std::string description = "Nexus Network Proxy Service";
        std::string log_path;
        bool user_scope = false;
    };

    enum class ServiceTarget { native, systemd, launchd, windows };
    enum class ServiceState { not_installed, stopped, running, unknown };

    struct ServiceStatus {
        bool installed = false;
        ServiceState state = ServiceState::not_installed;
        std::string unit_path;
        std::string backend;
        std::string detail;
    };

    [[nodiscard]] inline auto validate_service_spec(ServiceSpec const& spec, bool require_paths = true)
        -> std::expected<void, std::string> {
        if (spec.name.empty() || spec.name.size() > 64 ||
            !std::ranges::all_of(spec.name, [](unsigned char c) {
                return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                       (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-' || c == '@';
            }))
            return std::unexpected("invalid service name");
        auto bad_line = [](std::string_view s) noexcept -> bool {
            return std::ranges::any_of(s, [](unsigned char c) { return c == '\0' || c == '\r' || c == '\n'; });
        };
        if (bad_line(spec.binary_path) || bad_line(spec.config_path) ||
            bad_line(spec.working_dir) || bad_line(spec.description) || bad_line(spec.log_path))
            return std::unexpected("service specification contains forbidden control characters");
        if (require_paths && (spec.binary_path.empty() || spec.config_path.empty()))
            return std::unexpected("service requires both binary_path and config_path");
        return {};
    }

    [[nodiscard]] inline auto effective_service_target(ServiceTarget target) noexcept -> ServiceTarget {
        if (target != ServiceTarget::native) return target;
#if defined(_WIN32)
        return ServiceTarget::windows;
#elif defined(__APPLE__)
        return ServiceTarget::launchd;
#else
        return ServiceTarget::systemd;
#endif
    }

    [[nodiscard]] inline auto default_unit_path(ServiceSpec const& spec,
        ServiceTarget target = ServiceTarget::native) -> std::string {
        auto resolved = effective_service_target(target);
        if (resolved == ServiceTarget::windows) return spec.name;
        if (resolved == ServiceTarget::launchd) {
            if (spec.user_scope) {
                char const* home = std::getenv("HOME");
                std::string base = (home && home[0]) ? std::string(home) : "~";
                return std::format("{}/Library/LaunchAgents/io.nexus.{}.plist", base, spec.name);
            }
            return std::format("/Library/LaunchDaemons/io.nexus.{}.plist", spec.name);
        }
        if (spec.user_scope) {
            char const* home = std::getenv("HOME");
            std::string base = (home && home[0]) ? std::string(home) : "~";
            return std::format("{}/.config/systemd/user/{}.service", base, spec.name);
        }
        return std::format("/etc/systemd/system/{}.service", spec.name);
    }

    [[nodiscard]] inline auto render_systemd_unit(ServiceSpec const& spec)
        -> std::expected<std::string, std::string> {
        if (auto ok = validate_service_spec(spec); !ok) return std::unexpected(ok.error());
        std::string out;
        out += "[Unit]\n";
        out += std::format("Description={}\n", spec.description);
        out += "After=network-online.target nss-lookup.target\n";
        out += "Wants=network-online.target\n\n";
        out += "[Service]\n";
        out += "Type=simple\n";
        if (!spec.user_scope) {
            out += "DynamicUser=yes\n";
            out += "AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_ADMIN\n";
            out += "CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_ADMIN\n";
            out += "NoNewPrivileges=yes\n";
            out += "PrivateTmp=yes\n";
            out += "ProtectSystem=strict\n";
        }
        if (!spec.working_dir.empty())
            out += std::format("WorkingDirectory={}\n", spec.working_dir);
        out += std::format("ExecStartPre=\"{}\" check --config \"{}\"\n", spec.binary_path, spec.config_path);
        out += std::format("ExecStart=\"{}\" run --config \"{}\"\n", spec.binary_path, spec.config_path);
        out += "ExecReload=/bin/kill -HUP $MAINPID\n";
        out += "Restart=on-failure\nRestartSec=3s\nTimeoutStopSec=15s\n";
        if (!spec.log_path.empty()) {
            out += std::format("StandardOutput=append:{}\nStandardError=append:{}\n", spec.log_path, spec.log_path);
        }
        out += "\n[Install]\n";
        out += spec.user_scope ? "WantedBy=default.target\n" : "WantedBy=multi-user.target\n";
        return out;
    }

    [[nodiscard]] inline auto render_launchd_plist(ServiceSpec const& spec)
        -> std::expected<std::string, std::string> {
        if (auto ok = validate_service_spec(spec); !ok) return std::unexpected(ok.error());
        auto xml_escape = [](std::string_view s) {
            std::string out;
            out.reserve(s.size());
            for (char c : s) {
                switch (c) {
                case '&': out += "&amp;"; break;
                case '<': out += "&lt;"; break;
                case '>': out += "&gt;"; break;
                case '"': out += "&quot;"; break;
                case '\'': out += "&apos;"; break;
                default: out.push_back(c); break;
                }
            }
            return out;
        };
        std::string out =
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
            "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
            "<plist version=\"1.0\">\n<dict>\n";
        out += std::format("    <key>Label</key>\n    <string>io.nexus.{}</string>\n", xml_escape(spec.name));
        out += "    <key>ProgramArguments</key>\n    <array>\n";
        out += std::format("        <string>{}</string>\n", xml_escape(spec.binary_path));
        out += "        <string>run</string>\n        <string>--config</string>\n";
        out += std::format("        <string>{}</string>\n", xml_escape(spec.config_path));
        out += "    </array>\n";
        if (!spec.working_dir.empty())
            out += std::format("    <key>WorkingDirectory</key>\n    <string>{}</string>\n", xml_escape(spec.working_dir));
        if (!spec.log_path.empty()) {
            auto escaped = xml_escape(spec.log_path);
            out += std::format("    <key>StandardOutPath</key>\n    <string>{}</string>\n", escaped);
            out += std::format("    <key>StandardErrorPath</key>\n    <string>{}</string>\n", escaped);
        }
        out += "    <key>RunAtLoad</key>\n    <true/>\n    <key>KeepAlive</key>\n    <true/>\n</dict>\n</plist>\n";
        return out;
    }

    [[nodiscard]] inline auto render_windows_service_command(ServiceSpec const& spec)
        -> std::expected<std::string, std::string> {
        if (auto ok = validate_service_spec(spec); !ok) return std::unexpected(ok.error());
        return std::format("\"{}\" run --config \"{}\"", spec.binary_path, spec.config_path);
    }

    [[nodiscard]] auto install_service(ServiceSpec const& spec, std::string const& output_dir_override = {},
        bool dry_run = false) -> std::expected<std::string, std::string>;
    [[nodiscard]] auto uninstall_service(std::string const& name, bool user_scope,
        bool dry_run = false) -> std::expected<void, std::string>;
    [[nodiscard]] auto control_service(std::string const& name, std::string_view action,
        bool user_scope) -> std::expected<void, std::string>;
    [[nodiscard]] auto query_service_status(std::string const& name, bool user_scope) -> ServiceStatus;
}
