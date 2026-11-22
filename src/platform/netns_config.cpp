module platform.netns_config;
import std;

namespace platform::netns {
    namespace {
        [[nodiscard]] auto is_safe_ident_char(char c) noexcept -> bool {
            return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
                   c == '_' || c == '-' || c == '.';
        }
    }

    auto validate_name(std::string_view name) noexcept -> bool {
        if (name.empty() || name.size() > 63 || name == "." || name == ".." || name.contains("..")) return false;
        return std::ranges::all_of(name, is_safe_ident_char);
    }

    auto validate_spec(NamespaceSpec const& spec) -> std::expected<void, std::string> {
        if (!validate_name(spec.name)) {
            return std::unexpected(std::format("invalid network-namespace name '{}'", spec.name));
        }
        std::set<std::string_view> seen_ifs;
        for (auto const& iface : spec.interfaces) {
            if (iface.empty() || iface.size() > 15 || !std::ranges::all_of(iface, is_safe_ident_char)) {
                return std::unexpected(std::format("invalid interface '{}' in namespace '{}'", iface, spec.name));
            }
            if (!seen_ifs.insert(iface).second) {
                return std::unexpected(std::format("duplicate interface '{}' in namespace '{}'", iface, spec.name));
            }
        }
        for (auto const& route : spec.routes) {
            if (route.destination.empty()) {
                return std::unexpected(std::format("empty route destination in namespace '{}'", spec.name));
            }
        }
        return {};
    }

    auto validate_plan(std::span<NamespaceSpec const> specs) -> std::expected<void, std::string> {
        std::set<std::string_view> seen_ns, seen_ifs;
        for (auto const& spec : specs) {
            if (auto r = validate_spec(spec); !r) return r;
            if (!seen_ns.insert(spec.name).second) {
                return std::unexpected(std::format("duplicate network-namespace '{}'", spec.name));
            }
            for (auto const& iface : spec.interfaces) {
                if (!seen_ifs.insert(iface).second) {
                    return std::unexpected(std::format("interface '{}' bound to multiple namespaces", iface));
                }
            }
        }
        return {};
    }

    auto namespace_path(std::string_view name) -> std::filesystem::path {
        if (!validate_name(name)) return {};
        return std::filesystem::path("/var/run/netns") / name;
    }

    auto plan_reconcile(std::span<NamespaceSpec const> desired,
                        std::span<NamespaceSpec const> current) -> std::vector<PlanAction> {
        std::vector<PlanAction> actions;
        auto find_by_name = [](std::span<NamespaceSpec const> list, std::string_view name) -> NamespaceSpec const* {
            for (auto const& s : list) {
                if (s.name == name) return &s;
            }
            return nullptr;
        };

        for (auto const& cur : current) {
            if (!find_by_name(desired, cur.name)) {
                actions.push_back({PlanAction::Kind::delete_ns, cur.name, "remove stale netns"});
            }
        }
        for (auto const& want : desired) {
            auto const* prev = find_by_name(current, want.name);
            if (!prev) {
                actions.push_back({PlanAction::Kind::create_ns, want.name,
                    want.isolate_loopback ? "lo=isolated" : "lo=shared"});
                for (auto const& iface : want.interfaces) {
                    actions.push_back({PlanAction::Kind::bind_interface, want.name, iface});
                }
                for (auto const& rt : want.routes) {
                    actions.push_back({PlanAction::Kind::add_route, want.name, rt.destination + " via " + rt.gateway});
                }
                continue;
            }
            for (auto const& iface : want.interfaces) {
                if (std::ranges::find(prev->interfaces, iface) == prev->interfaces.end()) {
                    actions.push_back({PlanAction::Kind::bind_interface, want.name, iface});
                }
            }
            for (auto const& rt : want.routes) {
                if (std::ranges::find(prev->routes, rt) == prev->routes.end()) {
                    actions.push_back({PlanAction::Kind::add_route, want.name, rt.destination + " via " + rt.gateway});
                }
            }
        }
        return actions;
    }

    auto probe_namespace_exists(std::string_view name) noexcept -> bool {
#ifdef __linux__
        auto p = namespace_path(name);
        if (p.empty()) return false;
        std::error_code ec;
        return std::filesystem::exists(p, ec);
#else
        (void)name;
        return false;
#endif
    }
}
