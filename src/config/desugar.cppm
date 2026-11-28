// KDL configuration desugaring helpers module.
export module config.desugar;
import std;
import glaze;
import config.kdl_common;
import platform.ip_address;

export namespace config::desugar_detail {
    using namespace config::kdl;

    inline auto parse_host_port(std::string_view spec)
        -> std::optional<std::pair<std::string, std::uint16_t>> {
        if (spec.empty() || spec.size() > 260) return {};
        for (unsigned char c : spec)
            if (c < 33 || c > 126) return {};
        auto parsed = platform::split_host_port(spec, true);
        if (!parsed || !endpoint_name(parsed->host)) return {};
        return std::pair{std::string(parsed->host), parsed->port};
    }

    inline auto desugar_endpoints(Node& node) -> std::expected<void, std::string> {
        for (auto& child : node.children) {
            if (child.name == "listen" || child.name == "server" ||
                child.name == "fallback" || child.name == "target") {
                if (!child.tag && child.properties.empty() && child.children.empty() &&
                    child.arguments.size() == 1) {
                    if (auto raw = string(child.arguments.front())) {
                        auto parsed = parse_host_port(*raw);
                        if (!parsed) return error("invalid " + child.name + " host:port endpoint");
                        child.arguments.clear();
                        child.properties.push_back({"host", {std::move(parsed->first), {}}});
                        child.properties.push_back({"port", {std::int64_t{parsed->second}, {}}});
                        continue;
                    }
                }
            }
            if (auto ok = desugar_endpoints(child); !ok) return ok;
        }
        return {};
    }

    inline auto desugar_group_members(Node& outbound) -> std::expected<void, std::string> {
        auto type = text_property(outbound, "type");
        if (!type || (*type != "selector" && *type != "fallback" &&
                      *type != "url-test" && *type != "load-balance"))
            return {};
        std::vector<Node> expanded;
        expanded.reserve(outbound.children.size());
        for (auto& child : outbound.children) {
            if (child.name == "members" || child.name == "use") {
                if (child.tag || !child.properties.empty() || !child.children.empty() ||
                    child.arguments.empty())
                    return error(child.name + " requires one or more names");
                auto singular = child.name == "members" ? "member" : "use";
                for (auto const& arg : child.arguments) {
                    if (!string(arg)) return error(child.name + " arguments must be strings");
                    expanded.push_back(Node{.name = singular, .arguments = {arg}});
                }
            } else {
                expanded.push_back(std::move(child));
            }
        }
        outbound.children = std::move(expanded);
        return {};
    }

    inline auto is_implicit_true_predicate(std::string_view kw) noexcept -> bool {
        return kw == "ip-is-private" || kw == "source-ip-is-private" ||
               kw == "ip-is-cgnat" || kw == "source-ip-is-cgnat" ||
               kw == "ip-accept-any" || kw == "source-ip-accept-any";
    }

    inline auto desugar_route_predicate_children(Node& node) -> std::expected<void, std::string> {
        for (auto& c : node.children) {
            if (c.name == "action" || c.name == "rule") continue;
            if (c.tag) return error("tagged predicate node in routing rule");
            if (c.name == "and" || c.name == "or" || c.name == "not" ||
                c.name == "all" || c.name == "any") {
                if (auto ok = desugar_route_predicate_children(c); !ok) return ok;
                continue;
            }
            if (is_implicit_true_predicate(c.name) && c.arguments.empty() &&
                c.properties.empty() && c.children.empty()) {
                c.arguments.push_back(Value{true, {}});
                continue;
            }
            if (c.name != "dscp" && c.properties.empty() && c.children.empty() && c.arguments.size() > 1) {
                for (auto const& arg : c.arguments)
                    if (arg.tag) return error("tagged predicate argument");
                Node any{.name = "or"};
                any.children.reserve(c.arguments.size());
                for (auto& arg : c.arguments)
                    any.children.push_back(Node{.name = c.name, .arguments = {std::move(arg)}});
                c = std::move(any);
            }
        }
        return {};
    }

    inline auto canonicalize_rule_props(Node& rule) -> void {
        std::vector<std::pair<std::string, Value>> ordered;
        ordered.reserve(rule.properties.size());
        for (std::string_view key : {"action", "rule-set", "outbound"}) {
            for (auto& kv : rule.properties)
                if (kv.first == key) ordered.push_back(std::move(kv));
        }
        for (auto& kv : rule.properties)
            if (!kv.first.empty() && kv.first != "action" && kv.first != "rule-set" && kv.first != "outbound")
                ordered.push_back(std::move(kv));
        rule.properties = std::move(ordered);
    }

    using SubRuleMap = std::map<std::string, std::vector<Node>, std::less<>>;

    inline auto wrap_negated_predicates(Node& r) -> std::expected<void, std::string> {
        std::vector<Node> preds, actions;
        for (auto& c : r.children) {
            if (c.name == "action") actions.push_back(std::move(c));
            else preds.push_back(std::move(c));
        }
        if (preds.empty()) return error("invert=#true requires a predicate");
        Node inv{.name = "not"};
        if (preds.size() == 1) inv.children.push_back(std::move(preds.front()));
        else inv.children.push_back(Node{.name = "and", .children = std::move(preds)});
        r.children.clear();
        r.children.push_back(std::move(inv));
        for (auto& a : actions) r.children.push_back(std::move(a));
        return {};
    }

    inline auto push_multi_arg_predicate(Node& r, std::string_view kw, std::size_t start_arg) -> void {
        if (kw == "dscp") {
            Node pred{.name = "dscp"};
            pred.arguments.assign(r.arguments.begin() + static_cast<std::ptrdiff_t>(start_arg), r.arguments.end());
            r.children.push_back(std::move(pred));
        } else if (r.arguments.size() == start_arg + 1) {
            r.children.push_back(Node{.name = std::string(kw), .arguments = {r.arguments[start_arg]}});
        } else {
            Node any{.name = "or"};
            for (std::size_t i = start_arg; i < r.arguments.size(); ++i)
                any.children.push_back(Node{.name = std::string(kw), .arguments = {r.arguments[i]}});
            r.children.push_back(std::move(any));
        }
    }

    inline auto desugar_ergonomic_route_rule(Node& r, std::vector<Node>& defaults_out,
        std::vector<Node>& program_out, SubRuleMap const& sub_rules,
        std::vector<std::string_view>& visiting, bool allow_default, bool force_child_ruleset = false,
        std::vector<Node> const& inherited_guards = {}) -> std::expected<void, std::string> {
        if (r.tag) return error("tagged rule node in routing rules");
        bool invert = false;
        if (auto it = std::ranges::find_if(r.properties, [](auto const& kv) { return kv.first == "invert"; });
            it != r.properties.end()) {
            if (it->second.tag || !std::holds_alternative<bool>(it->second.data))
                return error("invert property requires boolean value");
            invert = std::get<bool>(it->second.data);
            r.properties.erase(it);
        }
        auto it_to = std::ranges::find_if(r.properties, [](auto const& kv) { return kv.first == "to"; });
        if (it_to != r.properties.end()) {
            if (property(r, "outbound")) return error("routing rule cannot specify both to and outbound");
            it_to->first = "outbound";
        }
        std::optional<std::string> sub_target;
        if (auto it = std::ranges::find_if(r.properties, [](auto const& kv) { return kv.first == "sub-rule"; });
            it != r.properties.end()) {
            auto s = string(it->second);
            if (!s) return error("sub-rule property requires string name");
            sub_target = *s;
            r.properties.erase(it);
        } else if (r.arguments.size() == 2) {
            if (auto kw = string(r.arguments.front()); kw && *kw == "sub-rule") {
                auto s = string(r.arguments[1]);
                if (!s) return error("sub-rule requires string name");
                sub_target = *s;
                r.arguments.clear();
            }
        }
        if (sub_target) {
            if (property(r, "action") || property(r, "outbound") || visiting.size() >= 8)
                return error("invalid sub-rule invocation or nesting exceeds limit");
            auto found = sub_rules.find(*sub_target);
            if (found == sub_rules.end()) return error("unknown sub-rule: " + *sub_target);
            if (std::ranges::contains(visiting, std::string_view(*sub_target)))
                return error("cyclic sub-rule reference: " + *sub_target);
            if (!r.arguments.empty()) {
                auto kw = string(r.arguments.front());
                if (!kw || *kw == "rule" || *kw == "default" || *kw == "final")
                    return error("invalid guard predicate in sub-rule invocation");
                for (auto const& arg : r.arguments) if (arg.tag) return error("tagged guard argument");
                if (r.arguments.size() == 1 && is_implicit_true_predicate(*kw)) {
                    r.children.push_back(Node{.name = *kw, .arguments = {Value{true, {}}}});
                } else if (r.arguments.size() >= 2) {
                    push_multi_arg_predicate(r, *kw, 1);
                } else {
                    return error("invalid guard predicate in sub-rule invocation");
                }
                r.arguments.clear();
            }
            if (auto ok = desugar_route_predicate_children(r); !ok) return ok;
            if (invert) {
                if (auto ok = wrap_negated_predicates(r); !ok) return ok;
            }
            if (!r.properties.empty()) return error("unsupported property on sub-rule invocation");
            std::vector<Node> combined = inherited_guards;
            for (auto& g : r.children) {
                if (g.name == "action") return error("action not allowed on sub-rule invocation");
                combined.push_back(std::move(g));
            }
            visiting.push_back(found->first);
            for (auto const& sub_item : found->second) {
                Node copy = sub_item;
                if (auto ok = desugar_ergonomic_route_rule(copy, defaults_out, program_out, sub_rules,
                        visiting, false, true, combined); !ok) {
                    visiting.pop_back();
                    return ok;
                }
            }
            visiting.pop_back();
            return {};
        }

        if (!r.arguments.empty()) {
            auto kw = string(r.arguments.front());
            if (!kw) return error("ergonomic routing rule must begin with a string keyword");
            for (std::size_t i = 1; i < r.arguments.size(); ++i)
                if (r.arguments[i].tag) return error("tagged argument in ergonomic routing rule");
            if (*kw == "default")
                return error("use routing { final \"<outbound>\" }");
            if (*kw == "final") {
                if (!allow_default || invert || r.arguments.size() != 2 || !r.properties.empty() || !r.children.empty() ||
                    !string(r.arguments[1]))
                    return error("final rule requires one outbound name and no options");
                defaults_out.push_back(Node{.name = "default-outbound", .arguments = {r.arguments[1]}});
                return {};
            }
            if (*kw == "sniff" || *kw == "resolve" || *kw == "route-options" || *kw == "hijack-dns" || *kw == "reject") {
                if (r.arguments.size() != 1 || property(r, "action"))
                    return error("invalid ergonomic " + *kw + " rule");
                r.properties.push_back({"action", {*kw, {}}});
            } else if (*kw == "bypass" || *kw == "route") {
                if (property(r, "action") || r.arguments.size() > 2)
                    return error("invalid ergonomic " + *kw + " rule");
                if (r.arguments.size() == 2) {
                    if (!string(r.arguments[1]) || property(r, "outbound"))
                        return error("invalid outbound argument in ergonomic " + *kw + " rule");
                    r.properties.push_back({"outbound", r.arguments[1]});
                }
                r.properties.push_back({"action", {*kw, {}}});
            } else if (*kw == "rule-set") {
                if (r.arguments.size() < 2 || property(r, "rule-set"))
                    return error("invalid ergonomic rule-set routing rule");
                for (std::size_t i = 1; i < r.arguments.size(); ++i)
                    if (!string(r.arguments[i])) return error("rule-set name must be a string");
                if (r.arguments.size() == 2 && !invert && !force_child_ruleset && inherited_guards.empty() && r.children.empty()) {
                    r.properties.push_back({"rule-set", r.arguments[1]});
                } else {
                    push_multi_arg_predicate(r, "rule-set", 1);
                }
                if (!property(r, "action")) {
                    if (!property(r, "outbound"))
                        return error("ergonomic rule-set rule requires to/outbound or action");
                    r.properties.push_back({"action", {std::string("route"), {}}});
                }
            } else if (r.arguments.size() == 1 && is_implicit_true_predicate(*kw)) {
                if (!r.children.empty())
                    return error("invalid ergonomic " + *kw + " rule");
                r.children.push_back(Node{.name = *kw, .arguments = {Value{true, {}}}});
                if (!property(r, "action")) {
                    if (!property(r, "outbound"))
                        return error("ergonomic routing rule requires action or to/outbound");
                    r.properties.push_back({"action", {std::string("route"), {}}});
                }
            } else {
                if (r.arguments.size() < 2 || !r.children.empty() || *kw == "rule")
                    return error("unknown ergonomic routing rule or missing predicate value");
                push_multi_arg_predicate(r, *kw, 1);
                if (!property(r, "action")) {
                    if (!property(r, "outbound"))
                        return error("ergonomic routing rule requires action or to/outbound");
                    r.properties.push_back({"action", {std::string("route"), {}}});
                }
            }
            r.arguments.clear();
        } else {
            if (invert) {
                if (auto rs = std::ranges::find_if(r.properties, [](auto const& kv) { return kv.first == "rule-set"; });
                    rs != r.properties.end()) {
                    if (property(r, "ip-cidr-match-source"))
                        return error("invert=#true cannot be combined with rule-set ip-cidr-match-source property");
                    r.children.push_back(Node{.name = "rule-set", .arguments = {rs->second}});
                    r.properties.erase(rs);
                }
            }
            if (!property(r, "action") && property(r, "outbound"))
                r.properties.push_back({"action", {std::string("route"), {}}});
        }
        if (auto ok = desugar_route_predicate_children(r); !ok) return ok;
        if (invert) {
            if (auto ok = wrap_negated_predicates(r); !ok) return ok;
        }
        if (!inherited_guards.empty()) {
            if (auto rs = std::ranges::find_if(r.properties, [](auto const& kv) { return kv.first == "rule-set"; });
                rs != r.properties.end()) {
                r.children.push_back(Node{.name = "rule-set", .arguments = {rs->second}});
                r.properties.erase(rs);
            }
            for (auto it = inherited_guards.rbegin(); it != inherited_guards.rend(); ++it)
                r.children.insert(r.children.begin(), *it);
        }
        if (program_out.size() >= 65535u) return error("expanded routing rules exceed 65535 limit");
        canonicalize_rule_props(r);
        r.name = "rule";
        program_out.push_back(std::move(r));
        return {};
    }

    inline auto is_rule_set_meta_field(std::string_view name) noexcept -> bool {
        return name == "type" || name == "url" || name == "path" || name == "format" ||
               name == "http-client" || name == "sha256" || name == "update-interval-ms";
    }

    inline auto canonicalize_rule_set_props(Node& rule_set) -> void {
        if (rule_set.properties.size() <= 1) return;
        std::vector<std::pair<std::string, Value>> ordered;
        ordered.reserve(rule_set.properties.size());
        for (std::string_view key : {"type", "url", "path", "format", "http-client", "sha256", "update-interval-ms"}) {
            for (auto& kv : rule_set.properties)
                if (kv.first == key) ordered.push_back(std::move(kv));
        }
        for (auto& kv : rule_set.properties)
            if (!kv.first.empty() && !is_rule_set_meta_field(kv.first))
                ordered.push_back(std::move(kv));
        rule_set.properties = std::move(ordered);
    }

    inline auto desugar_rule_set_fields(Node& rule_set) -> std::expected<void, std::string> {
        if (!rule_set.children.empty()) {
            std::vector<Node> kept;
            kept.reserve(rule_set.children.size());
            for (auto& child : rule_set.children) {
                if (!is_rule_set_meta_field(child.name)) {
                    kept.push_back(std::move(child));
                    continue;
                }
                if (child.tag || !child.properties.empty() || !child.children.empty() ||
                    child.arguments.size() != 1)
                    return error("rule-set field " + child.name + " requires one value");
                if (property(rule_set, child.name))
                    return error("duplicate rule-set field " + child.name);
                rule_set.properties.push_back({std::move(child.name), std::move(child.arguments.front())});
            }
            rule_set.children = std::move(kept);
            if (auto ok = desugar_route_predicate_children(rule_set); !ok) return ok;
        }
        canonicalize_rule_set_props(rule_set);
        return {};
    }

    inline auto desugar_rulesets_block(Node& block, bool& seen, std::vector<Node>& out)
        -> std::expected<void, std::string> {
        if (seen || block.tag || !block.arguments.empty() || !block.properties.empty())
            return error("invalid or duplicate rulesets block");
        seen = true;
        for (auto& item : block.children) {
            if (item.tag) return error("tagged rule-set node in rulesets");
            if (item.name == "-")
                return error("rulesets uses named nodes <name> instead of - entries");
            if (!item.arguments.empty())
                return error("rulesets entries must be named nodes with no positional arguments");
            item.arguments.push_back({std::move(item.name), {}});
            item.name = "rule-set";
            if (auto ok = desugar_rule_set_fields(item); !ok) return ok;
            out.push_back(std::move(item));
        }
        return {};
    }

    inline auto desugar_routing(Node& routing) -> std::expected<void, std::string> {
        bool rules_seen = false;
        bool rulesets_seen = false;
        bool has_tcp_program = std::ranges::any_of(routing.children,
            [](Node const& c) { return c.name == "tcp-program"; });
        SubRuleMap sub_rules;
        for (auto const& child : routing.children) {
            if (child.name != "sub-rule") continue;
            auto name = child.tag || !child.properties.empty() ? nullptr : argument(child);
            if (!name || !valid_name(*name) || child.children.empty())
                return error("invalid sub-rule declaration");
            for (auto const& item : child.children)
                if (item.name != "-") return error("sub-rule accepts only - nodes");
            if (!sub_rules.emplace(*name, child.children).second)
                return error("duplicate sub-rule: " + *name);
        }
        std::vector<Node> out_children;
        out_children.reserve(routing.children.size());
        for (auto& child : routing.children) {
            if (child.name == "sub-rule") continue;
            if (child.name == "final") {
                auto v = (child.properties.empty() && child.children.empty()) ? argument(child) : nullptr;
                if (!v || !valid_name(*v)) return error("final requires one outbound name");
                child.name = "default-outbound";
                out_children.push_back(std::move(child));
                continue;
            }
            if (child.name == "default-outbound" || child.name == "default")
                return error("use routing { final \"<outbound>\" }");
            if (child.name == "rule-set")
                return error("use routing { rulesets { <name> ... } }");
            if (child.name == "rule-sets")
                return error("use rulesets { ... }");
            if (child.name == "default-http-client")
                return error("use http-clients { default \"<name>\" }");
            if (child.name == "default-domain-resolver")
                return error("use dns { default \"<server>\" }");
            if (child.name == "auto-detect-interface" || child.name == "default-interface" ||
                child.name == "default-mark" || child.name == "default-network-type" ||
                child.name == "default-network-strategy")
                return error("move outbound dial defaults into outbounds { ... }");
            if (child.name == "rulesets") {
                if (auto ok = desugar_rulesets_block(child, rulesets_seen, out_children); !ok) return ok;
                continue;
            }
            if (child.name != "rules") {
                if (child.name == "rule")
                    return error("bare routing rule is removed; use routing { rules { - ... } } or tcp-program");
                out_children.push_back(std::move(child));
                continue;
            }
            if (rules_seen || child.tag || !child.arguments.empty())
                return error("invalid or duplicate rules block");
            rules_seen = true;
            for (auto const& r : child.children) {
                if (r.name != "-") return error("rules accepts only - nodes");
                if (property(r, "kind"))
                    return error("legacy kind=\"rule-set\" routing rule is removed; use - rule-set=\"<name>\" to=\"<outbound>\"");
            }
            if (has_tcp_program) return error("cannot mix rules block and tcp-program node");
            Value const* p_timeout = property(child, "sniff-timeout-ms");
            Value const* p_unknown = property(child, "unknown");
            Value const* p_udp = property(child, "udp");
            std::size_t expected_props = std::size_t{bool(p_timeout)} + bool(p_unknown) + bool(p_udp);
            if (child.properties.size() != expected_props)
                return error("unsupported property on routing rules block");
            Node prog{.name = "tcp-program"};
            prog.properties.push_back({"sniff-timeout-ms",
                p_timeout ? *p_timeout : Value{std::int64_t{300}, {}}});
            prog.properties.push_back({"unknown",
                p_unknown ? *p_unknown : Value{std::string("skip"), {}}});
            prog.properties.push_back({"udp", p_udp ? *p_udp : Value{true, {}}});
            std::vector<Node> lifted_defaults;
            std::vector<std::string_view> visiting;
            for (auto& r : child.children) {
                if (auto ok = desugar_ergonomic_route_rule(r, lifted_defaults, prog.children, sub_rules, visiting, true); !ok)
                    return ok;
            }
            out_children.push_back(std::move(prog));
            for (auto& d : lifted_defaults) out_children.push_back(std::move(d));
        }
        routing.children = std::move(out_children);
        return {};
    }
}
