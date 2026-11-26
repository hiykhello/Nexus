// Global routing default options for config module.
export module config.routing_defaults_types;
import std;
import platform.socket_options;

export namespace config {
    struct RoutingDefaults {
        bool auto_detect_interface = false;
        std::string default_interface;
        std::optional<std::uint32_t> default_mark;
        std::optional<std::string> default_domain_resolver;
        std::optional<std::size_t> default_domain_resolver_index;
        std::optional<platform::network::Policy> default_network_strategy;
        std::optional<platform::network::Type> default_network_type;
        bool find_process = false;

        [[nodiscard]] auto configured() const noexcept -> bool {
            return auto_detect_interface || !default_interface.empty() || default_mark.has_value() ||
                default_domain_resolver.has_value() || default_network_strategy.has_value() ||
                default_network_type.has_value() || find_process;
        }
        auto operator==(RoutingDefaults const&) const -> bool = default;
    };
}
