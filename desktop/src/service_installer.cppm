export module desktop.service_installer;
import std;

export namespace desktop {
    struct ServiceSpec {
        std::string service_name{"nexus"};
        std::string description{"Nexus Proxy Service"};
        std::filesystem::path binary_path;
        std::filesystem::path config_path;
        std::filesystem::path data_dir;
    };

    [[nodiscard]] auto validate_service_spec(ServiceSpec const& spec) -> std::expected<void, std::string>;
    [[nodiscard]] auto render_systemd_user_unit(ServiceSpec const& spec) -> std::expected<std::string, std::string>;
    [[nodiscard]] auto install_systemd_user_unit(ServiceSpec const& spec, std::filesystem::path const& unit_dir)
        -> std::expected<std::filesystem::path, std::string>;
    [[nodiscard]] auto build_windows_sc_create_args(ServiceSpec const& spec)
        -> std::expected<std::vector<std::string>, std::string>;
    [[nodiscard]] auto detect_wintun_dll(std::filesystem::path const& search_dir)
        -> std::optional<std::filesystem::path>;
}
