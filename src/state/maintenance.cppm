export module state.maintenance;
import std;
import state.core;

export namespace state {
    struct Inventory {
        std::string_view version;
        std::uint64_t entries=0, bytes=0;
        std::string_view health="missing";
    };
    auto inspect_selectors(std::filesystem::path const& directory) -> Inventory;
    auto inspect_route_mode(std::filesystem::path const& directory) -> Inventory;
    auto inspect_fakeip(std::filesystem::path const& directory,bool unified) -> Inventory;
    auto inspect_dns(std::filesystem::path const& root) -> Inventory;
    auto inspect_rules(std::filesystem::path const& root) -> Inventory;
    auto reset_selectors(std::filesystem::path const& directory) -> std::expected<std::string,StateError>;
    auto reset_fakeip(std::filesystem::path const& root) -> std::expected<std::string,StateError>;
}
