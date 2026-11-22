export module platform.netns_config;
import std;

export namespace platform::netns {
    struct RouteSpec {
        std::string destination;
        std::string gateway;
        std::uint32_t metric = 0;
        auto operator==(RouteSpec const&) const -> bool = default;
    };

    struct NamespaceSpec {
        std::string name;
        std::vector<std::string> interfaces;
        std::vector<RouteSpec> routes;
        bool isolate_loopback = true;
        auto operator==(NamespaceSpec const&) const -> bool = default;
    };

    struct PlanAction {
        enum class Kind { create_ns, bind_interface, add_route, delete_ns };
        Kind kind;
        std::string ns_name;
        std::string detail;
        auto operator==(PlanAction const&) const -> bool = default;
    };

    [[nodiscard]] auto validate_name(std::string_view name) noexcept -> bool;
    [[nodiscard]] auto validate_spec(NamespaceSpec const& spec) -> std::expected<void, std::string>;
    [[nodiscard]] auto validate_plan(std::span<NamespaceSpec const> specs) -> std::expected<void, std::string>;
    [[nodiscard]] auto namespace_path(std::string_view name) -> std::filesystem::path;
    [[nodiscard]] auto plan_reconcile(std::span<NamespaceSpec const> desired,
                                      std::span<NamespaceSpec const> current) -> std::vector<PlanAction>;
    [[nodiscard]] auto probe_namespace_exists(std::string_view name) noexcept -> bool;
}
