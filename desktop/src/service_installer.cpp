module desktop.service_installer;
import std;

namespace desktop {
    namespace {
        [[nodiscard]] auto is_safe_service_name(std::string_view name) noexcept -> bool {
            if (name.empty() || name.size() > 64) return false;
            return std::ranges::all_of(name, [](char c) {
                return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                       (c >= '0' && c <= '9') || c == '-' || c == '_';
            });
        }

        [[nodiscard]] auto has_control_char(std::string_view text) noexcept -> bool {
            for (unsigned char c : text) {
                if (c < 0x20 || c == 0x7F) return true;
            }
            return false;
        }

        [[nodiscard]] auto sanitize_unit_field(std::string_view text) -> std::string {
            std::string out;
            out.reserve(text.size());
            for (unsigned char c : text) {
                if (c >= 0x20 && c != 0x7F) out.push_back(static_cast<char>(c));
            }
            return out;
        }

        [[nodiscard]] auto escape_systemd_exec_arg(std::string_view text) -> std::string {
            std::string out;
            out.reserve(text.size() + 4);
            for (unsigned char c : text) {
                if (c < 0x20 || c == 0x7F) continue;
                if (c == '\\' || c == '"') { out.push_back('\\'); out.push_back(static_cast<char>(c)); }
                else if (c == '%') out += "%%";
                else if (c == '$') out += "$$";
                else out.push_back(static_cast<char>(c));
            }
            return out;
        }

        [[nodiscard]] auto quote_windows_cmdline_arg(std::string_view text) -> std::string {
            std::string out;
            out.reserve(text.size() + 4);
            out.push_back('"');
            std::size_t backslashes = 0;
            for (char c : text) {
                if (c == '\\') {
                    ++backslashes;
                } else if (c == '"') {
                    out.append(backslashes * 2 + 1, '\\');
                    out.push_back('"');
                    backslashes = 0;
                } else {
                    if (backslashes > 0) { out.append(backslashes, '\\'); backslashes = 0; }
                    out.push_back(c);
                }
            }
            if (backslashes > 0) out.append(backslashes * 2, '\\');
            out.push_back('"');
            return out;
        }
    }

    auto validate_service_spec(ServiceSpec const& spec) -> std::expected<void, std::string> {
        if (!is_safe_service_name(spec.service_name)) {
            return std::unexpected("invalid service name");
        }
        if (spec.binary_path.empty() || spec.config_path.empty()) {
            return std::unexpected("binary_path and config_path are required");
        }
        if (has_control_char(spec.binary_path.string()) ||
            has_control_char(spec.config_path.string()) ||
            has_control_char(spec.data_dir.string())) {
            return std::unexpected("service paths must not contain control characters");
        }
        return {};
    }

    auto render_systemd_user_unit(ServiceSpec const& spec) -> std::expected<std::string, std::string> {
        if (auto ok = validate_service_spec(spec); !ok) return std::unexpected(ok.error());
        auto const bin = escape_systemd_exec_arg(spec.binary_path.string());
        auto const cfg = escape_systemd_exec_arg(spec.config_path.string());
        auto const data = escape_systemd_exec_arg(spec.data_dir.empty() ? spec.config_path.parent_path().string()
                                                                        : spec.data_dir.string());
        return std::format(
            "[Unit]\n"
            "Description={}\n"
            "After=network-online.target\n"
            "Wants=network-online.target\n\n"
            "[Service]\n"
            "Type=simple\n"
            "ExecStartPre=\"{}\" check --config \"{}\"\n"
            "ExecStart=\"{}\" run --config \"{}\" -D \"{}\"\n"
            "ExecReload=/bin/kill -HUP $MAINPID\n"
            "Restart=on-failure\n"
            "RestartSec=3s\n\n"
            "[Install]\n"
            "WantedBy=default.target\n",
            sanitize_unit_field(spec.description), bin, cfg, bin, cfg, data);
    }

    auto install_systemd_user_unit(ServiceSpec const& spec, std::filesystem::path const& unit_dir)
        -> std::expected<std::filesystem::path, std::string> {
        auto unit = render_systemd_user_unit(spec);
        if (!unit) return std::unexpected(unit.error());
        std::error_code ec;
        std::filesystem::create_directories(unit_dir, ec);
        if (ec) return std::unexpected("create_directories failed: " + ec.message());
        auto dest = unit_dir / (spec.service_name + ".service");
        auto tmp = unit_dir / (spec.service_name + ".service.tmp");
        {
            std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
            if (!out) return std::unexpected("failed to open unit staging file");
            out.write(unit->data(), static_cast<std::streamsize>(unit->size()));
            if (!out.good()) return std::unexpected("failed to write unit staging file");
        }
        std::filesystem::rename(tmp, dest, ec);
        if (ec) {
            std::filesystem::remove(tmp, ec);
            return std::unexpected("failed to rename unit file: " + ec.message());
        }
        return dest;
    }

    auto build_windows_sc_create_args(ServiceSpec const& spec)
        -> std::expected<std::vector<std::string>, std::string> {
        if (auto ok = validate_service_spec(spec); !ok) return std::unexpected(ok.error());
        auto const data = spec.data_dir.empty() ? spec.config_path.parent_path() : spec.data_dir;
        auto bin_path_arg = std::format("{} run --config {} -D {}",
            quote_windows_cmdline_arg(spec.binary_path.string()),
            quote_windows_cmdline_arg(spec.config_path.string()),
            quote_windows_cmdline_arg(data.string()));
        return std::vector<std::string>{
            "sc.exe", "create", spec.service_name,
            "binPath=", std::move(bin_path_arg),
            "start=", "auto",
            "DisplayName=", sanitize_unit_field(spec.description),
        };
    }

    auto detect_wintun_dll(std::filesystem::path const& search_dir)
        -> std::optional<std::filesystem::path> {
        std::error_code ec;
        auto candidate = search_dir / "wintun.dll";
        if (std::filesystem::is_regular_file(candidate, ec)) return candidate;
        return std::nullopt;
    }
}
