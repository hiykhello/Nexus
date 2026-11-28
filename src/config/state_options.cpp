// State & cache directory configuration parser implementation.
module config;
import std;
import glaze;
import config.kdl_common;

namespace config {
    using namespace config::kdl;

    auto parse_state_options(Node const& node) -> std::expected<StateOptions, std::string> {
        if (node.tag || !node.arguments.empty() || !node.properties.empty())
            return error("invalid state block");
        StateOptions options;
        std::set<std::string_view> seen;
        for (auto const& child : node.children) {
            if (child.tag || child.arguments.size() != 1 || !child.properties.empty() ||
                !child.children.empty() || !seen.insert(child.name).second)
                return error("invalid or duplicate state option");
            if (child.name == "directory" || child.name == "cache-directory") {
                auto path = scalar(child);
                if (!path || !absolute_path(*path) || path->ends_with('/')) return error("state paths must be absolute");
                std::filesystem::path parsed(*path);
                if (std::ranges::any_of(parsed, [](auto const& part) {
                    return part == "." || part == "..";
                })) return error("state paths must use canonical components");
                (child.name == "directory" ? options.directory : options.cache_directory) = parsed.lexically_normal().string();
            } else if (child.name == "fakeip-crash-mode") {
                auto mode = scalar(child);
                if (!mode || (*mode != "range-reserve" && *mode != "per-mapping"))
                    return error("invalid state fakeip-crash-mode");
                options.fakeip_per_mapping = *mode == "per-mapping";
            } else if (child.name == "dns-cache-max-bytes" || child.name == "ruleset-cache-max-bytes") {
                auto bytes = integer(child.arguments.front());
                if (!bytes || *bytes < 4096 || *bytes > 1024ull * 1024 * 1024)
                    return error("state cache byte limit must be 4096..1073741824");
                (child.name == "dns-cache-max-bytes" ? options.dns_cache_max_bytes :
                    options.ruleset_cache_max_bytes) = *bytes;
            } else return error("unknown state option");
        }
        return options;
    }

    auto apply_state_options(Config& config) -> std::expected<void, std::string> {
        auto const* options = config.state ? &*config.state : nullptr;
        if (options && !options->directory.empty() && config.selector_state_directory.empty())
            config.selector_state_directory = options->directory;
        if (options && !options->cache_directory.empty()) {
            auto cache = std::filesystem::path(options->cache_directory);
            for (auto path : {std::string_view(options->directory), std::string_view(config.selector_state_directory)}) {
                if (path.empty()) continue;
                auto authority = std::filesystem::path(path).lexically_normal();
                for (auto name : {"dns", "rulesets", "nxmm"}) {
                    auto managed = cache / name;
                    if (std::ranges::mismatch(managed, authority).in1 == managed.end())
                        return error("state cache overlaps an authority directory");
                }
            }
        }
        if (options && !options->directory.empty()) {
            auto fakeip = std::filesystem::path(options->directory) / "fakeip";
            for (auto path : {std::string_view(options->cache_directory), std::string_view(config.selector_state_directory)}) {
                if (path.empty()) continue;
                auto configured = std::filesystem::path(path).lexically_normal();
                if (std::ranges::mismatch(fakeip, configured).in1 == fakeip.end())
                    return error("state directory overlaps the unified FakeIP store");
            }
        }
        if (!config.dns) return {};
        if (auto& fake = config.dns->fakeip; fake) {
            if (!options || options->directory.empty()) return error("fake-ip requires state { directory ... }");
            fake->per_mapping = options->fakeip_per_mapping;
            fake->state_directory = (std::filesystem::path(options->directory) / "fakeip").string();
        }
        if (options && !options->cache_directory.empty() && config.dns->listen && !config.dns->disable_cache) {
            config.dns->unified_cache_root = options->cache_directory;
            config.dns->unified_cache_bytes = options->dns_cache_max_bytes;
        }
        return {};
    }
}
