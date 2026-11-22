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

        [[nodiscard]] auto sanitize_unit_field(std::string_view text) -> std::string {
            std::string out;
            out.reserve(text.size());
            for (char c : text) {
                if (c != '\r' && c != '\n') out.push_back(c);
            }
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
        return {};
    }

    auto render_systemd_user_unit(ServiceSpec const& spec) -> std::expected<std::string, std::string> {
        if (auto ok = validate_service_spec(spec); !ok) return std::unexpected(ok.error());
        auto const bin = sanitize_unit_field(spec.binary_path.string());
        auto const cfg = sanitize_unit_field(spec.config_path.string());
        auto const data = sanitize_unit_field(spec.data_dir.empty() ? spec.config_path.parent_path().string()
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
        auto bin_path_arg = std::format("\"{}\" run --config \"{}\" -D \"{}\"",
            spec.binary_path.string(), spec.config_path.string(), data.string());
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
