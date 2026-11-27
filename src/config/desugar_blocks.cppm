// Strict Wave 38 KDL 2.0 domain-block desugaring helpers module.
export module config.desugar_blocks;
import std;
import glaze;
import config.kdl_common;
import config.desugar;

export namespace config::desugar_detail {
    using namespace config::kdl;

    inline auto extract_outbound_defaults(Node& outbounds, std::vector<Node>& hoisted,
        std::unordered_set<std::string_view>& hoisted_keys) -> std::expected<void, std::string> {
        std::vector<Node> kept;
        kept.reserve(outbounds.children.size());
        for (auto& child : outbounds.children) {
            if (child.name == "default-interface" || child.name == "default-mark" ||
                child.name == "default-network-type" || child.name == "default-network-strategy") {
                return error("omit default- prefix inside outbounds; use interface, mark, network-type or network-strategy");
            }
            std::string_view canonical;
            if (child.name == "auto-detect-interface") canonical = "auto-detect-interface";
            else if (child.name == "interface") canonical = "default-interface";
            else if (child.name == "mark") canonical = "default-mark";
            else if (child.name == "network-type") canonical = "default-network-type";
            else if (child.name == "network-strategy") canonical = "default-network-strategy";
            else {
                kept.push_back(std::move(child));
                continue;
            }
            if (!hoisted_keys.insert(canonical).second)
                return error("duplicate outbound dial default: " + child.name);
            child.name = std::string(canonical);
            hoisted.push_back(std::move(child));
        }
        outbounds.children = std::move(kept);
        return {};
    }

    inline auto desugar_vless_outbound_auth(Node& outbound) -> std::expected<void, std::string> {
        auto type = text_property(outbound, "type");
        if (!type || *type != "vless") return {};
        bool has_auth = false;
        bool has_direct_uuid = false;
        std::vector<Node> children;
        children.reserve(outbound.children.size());
        for (auto& child : outbound.children) {
            if (child.name == "authentication") {
                if (has_direct_uuid)
                    return error("vless cannot specify both authentication and direct uuid-file");
                has_auth = true;
                children.push_back(std::move(child));
            } else if (child.name == "uuid-file") {
                if (has_auth || has_direct_uuid)
                    return error("vless cannot specify duplicate authentication or uuid-file");
                has_direct_uuid = true;
                Node auth{.name = "authentication"};
                auth.children.push_back(std::move(child));
                children.push_back(std::move(auth));
            } else {
                children.push_back(std::move(child));
            }
        }
        outbound.children = std::move(children);
        return {};
    }

    inline auto desugar_http_clients(Node& group, std::vector<Node>& hoisted,
        std::unordered_set<std::string_view>& hoisted_keys) -> std::expected<void, std::string> {
        if (group.tag || !group.arguments.empty() || !group.properties.empty())
            return error("invalid http-clients block");
        bool default_seen = false;
        std::vector<Node> clients;
        clients.reserve(group.children.size());
        for (auto& child : group.children) {
            if (child.name == "default") {
                auto v = (child.properties.empty() && child.children.empty()) ? argument(child) : nullptr;
                if (default_seen || !v || !valid_name(*v))
                    return error("invalid or duplicate default in http-clients");
                default_seen = true;
                if (!hoisted_keys.insert("default-http-client").second)
                    return error("duplicate http-clients default");
                hoisted.push_back(Node{.name = "default-http-client", .arguments = {std::move(child.arguments.front())}});
                continue;
            }
            if (child.name == "client") {
                return error("use http-clients { <name> { ... } } instead of client \"<name>\"");
            }
            for (auto& field : child.children) {
                if (field.name == "detour") field.name = "outbound";
            }
            clients.push_back(std::move(child));
        }
        group.children = std::move(clients);
        return {};
    }

    inline auto is_dns_bool_context_predicate(std::string_view kw) noexcept -> bool {
        return kw == "source-ip-is-private" || kw == "source-ip-is-cgnat" || kw == "source-ip-accept-any";
    }

    inline auto is_dns_shorthand_predicate(std::string_view kw) noexcept -> bool {
        return kw == "domain" || kw == "domain-suffix" || kw == "domain-keyword" ||
               kw == "domain-wildcard" || kw == "domain-regex" || kw == "query-type" ||
               kw == "network" || kw == "source-ip-cidr" || is_dns_bool_context_predicate(kw) ||
               kw == "source-port" || kw == "source-port-range" || kw == "source-interface" ||
               kw == "inbound" || kw == "auth-user" || kw == "network-type" ||
               kw == "network-is-expensive" || kw == "network-is-constrained" ||
               kw == "wifi-ssid" || kw == "wifi-bssid" || kw == "default-interface-address" ||
               kw == "network-interface-address" || kw == "source-uid" || kw == "source-gid" ||
               kw == "source-user" || kw == "process-name" || kw == "process-path" ||
               kw == "process-path-regex" || kw == "package-name" || kw == "package-name-regex" ||
               kw == "route-mode" || kw == "client";
    }

    inline auto desugar_dns_predicate_child(Node& node) -> std::expected<void, std::string> {
        if (node.tag) return error("tagged predicate node in DNS rule");
        if (node.name == "and" || node.name == "or" || node.name == "not" ||
            node.name == "all" || node.name == "any") {
            for (auto& sub : node.children) {
                if (sub.name == "rule-set")
                    return error("rule-set cannot be nested inside logical DNS predicate");
                if (auto ok = desugar_dns_predicate_child(sub); !ok) return ok;
            }
            return {};
        }
        if (node.name == "-" || node.name == "rule") return {};
        if (is_dns_bool_context_predicate(node.name) && node.arguments.empty() &&
            node.properties.empty() && node.children.empty()) {
            node.arguments.push_back(Value{true, {}});
            return {};
        }
        if (node.properties.empty() && node.children.empty() && node.arguments.size() > 1) {
            for (auto const& arg : node.arguments)
                if (arg.tag) return error("tagged argument in DNS predicate");
            Node any{.name = "or"};
            any.children.reserve(node.arguments.size());
            for (auto& arg : node.arguments)
                any.children.push_back(Node{.name = node.name, .arguments = {std::move(arg)}});
            node = std::move(any);
        }
        return {};
    }

    inline auto desugar_dns_rule_expanded(Node& rule, std::vector<Node>& out)
        -> std::expected<void, std::string> {
        if (rule.tag) return error("tagged rule node in DNS rules");
        auto it_to = std::ranges::find_if(rule.properties,
            [](auto const& kv) { return kv.first == "to"; });
        if (it_to != rule.properties.end()) {
            if (property(rule, "server"))
                return error("DNS rule cannot specify both to and server");
            it_to->first = "server";
        }
        if (auto it_rc = std::ranges::find_if(rule.properties,
                [](auto const& kv) { return kv.first == "rcode"; });
            it_rc != rule.properties.end()) {
            auto act = text_property(rule, "action");
            if (act && *act == "predefined") {
                if (property(rule, "predefined-rcode"))
                    return error("DNS rule cannot specify both rcode and predefined-rcode");
                it_rc->first = "predefined-rcode";
            } else if (act && *act == "reject") {
                if (property(rule, "reject-rcode"))
                    return error("DNS rule cannot specify both rcode and reject-rcode");
                it_rc->first = "reject-rcode";
            }
        }
        std::vector<Value> rule_set_values;
        if (!rule.arguments.empty()) {
            auto key = string(rule.arguments.front());
            if (!key) return error("invalid DNS rule shorthand");
            for (std::size_t i = 1; i < rule.arguments.size(); ++i)
                if (rule.arguments[i].tag) return error("tagged argument in DNS rule shorthand");
            if (rule.arguments.size() == 1) {
                if (!is_dns_bool_context_predicate(*key) || property(rule, *key))
                    return error("invalid DNS rule shorthand");
                rule.properties.insert(rule.properties.begin(), {*key, Value{true, {}}});
            } else if (*key == "rule-set") {
                if (property(rule, "rule-set"))
                    return error("duplicate rule-set in DNS rule");
                for (std::size_t i = 1; i < rule.arguments.size(); ++i)
                    if (!string(rule.arguments[i])) return error("DNS rule-set name must be a string");
                if (rule.arguments.size() == 2 && rule.children.empty()) {
                    rule.properties.insert(rule.properties.begin(), {"rule-set", std::move(rule.arguments[1])});
                } else {
                    for (std::size_t i = 1; i < rule.arguments.size(); ++i)
                        rule_set_values.push_back(std::move(rule.arguments[i]));
                }
            } else if (rule.arguments.size() == 2 && rule.children.empty() &&
                       (*key == "domain" || *key == "domain-suffix" || *key == "domain-keyword" ||
                        *key == "domain-wildcard" || *key == "domain-regex" || *key == "query-type")) {
                if ((*key != "query-type" && !string(rule.arguments[1])) || property(rule, *key))
                    return error("invalid DNS rule shorthand field");
                rule.properties.insert(rule.properties.begin(), {*key, std::move(rule.arguments[1])});
            } else if (is_dns_shorthand_predicate(*key)) {
                if (rule.arguments.size() == 2) {
                    rule.children.push_back(Node{.name = *key, .arguments = {std::move(rule.arguments[1])}});
                } else {
                    Node any{.name = "or"};
                    any.children.reserve(rule.arguments.size() - 1);
                    for (std::size_t i = 1; i < rule.arguments.size(); ++i)
                        any.children.push_back(Node{.name = *key, .arguments = {std::move(rule.arguments[i])}});
                    rule.children.push_back(std::move(any));
                }
            } else {
                return error("invalid DNS rule shorthand field");
            }
            rule.arguments.clear();
        }
        std::vector<Node> kept_children;
        kept_children.reserve(rule.children.size());
        for (auto& c : rule.children) {
            if (c.name == "record") {
                kept_children.push_back(std::move(c));
                continue;
            }
            if (c.name == "rule-set") {
                if (c.tag || !c.properties.empty() || !c.children.empty() || c.arguments.empty())
                    return error("DNS rule-set child requires one or more names");
                if (property(rule, "rule-set") || !rule_set_values.empty())
                    return error("duplicate rule-set in DNS rule");
                for (auto& arg : c.arguments) {
                    if (!string(arg)) return error("DNS rule-set name must be a string");
                    rule_set_values.push_back(std::move(arg));
                }
                continue;
            }
            if (auto ok = desugar_dns_predicate_child(c); !ok) return ok;
            kept_children.push_back(std::move(c));
        }
        rule.children = std::move(kept_children);
        if (rule_set_values.empty()) {
            rule.name = "rule";
            out.push_back(std::move(rule));
            return {};
        }
        if (rule_set_values.size() == 1) {
            rule.properties.insert(rule.properties.begin(), {"rule-set", std::move(rule_set_values.front())});
            rule.name = "rule";
            out.push_back(std::move(rule));
            return {};
        }
        if (auto inv = property(rule, "invert"); inv && !inv->tag &&
            std::holds_alternative<bool>(inv->data) && std::get<bool>(inv->data))
            return error("multi-value rule-set in DNS rule cannot be combined with invert=#true");
        if (property(rule, "tag"))
            return error("multi-value rule-set in DNS rule cannot be combined with evaluate tag");
        if (auto logic = text_property(rule, "logic"); logic && *logic == "or")
            return error("multi-value rule-set in DNS rule cannot be combined with logic=\"or\"");
        if (out.size() + rule_set_values.size() > 256u)
            return error("expanded DNS rules exceed 256 limit");
        for (auto& rs : rule_set_values) {
            Node copy = rule;
            copy.name = "rule";
            copy.properties.insert(copy.properties.begin(), {"rule-set", std::move(rs)});
            out.push_back(std::move(copy));
        }
        return {};
    }

    inline auto desugar_dns_block(Node& dns, std::vector<Node>& hoisted,
        std::unordered_set<std::string_view>& hoisted_keys) -> std::expected<void, std::string> {
        bool rules_seen = false;
        bool rulesets_seen = false;
        bool default_seen = false;
        std::vector<Node> children;
        children.reserve(dns.children.size());
        constexpr std::array<std::string_view, 10> server_types{
            "local", "hosts", "udp", "tcp", "tls", "https", "quic", "https3", "dhcp", "mdns"
        };
        for (auto& child : dns.children) {
            if (child.name == "servers") {
                for (auto& srv : child.children) {
                    if (srv.name == "server") continue;
                    if (std::ranges::find(server_types, srv.name) == server_types.end() || property(srv, "type"))
                        return error("unsupported type in servers");
                    srv.properties.push_back({"type", {srv.name, {}}});
                    srv.name = "server";
                }
                children.push_back(std::move(child));
            } else if (child.name == "default") {
                auto v = (child.properties.empty() && child.children.empty()) ? argument(child) : nullptr;
                if (default_seen || !v || !valid_name(*v))
                    return error("invalid or duplicate default in dns");
                default_seen = true;
                if (!hoisted_keys.insert("default-domain-resolver").second)
                    return error("duplicate dns default resolver");
                hoisted.push_back(Node{.name = "default-domain-resolver", .arguments = {std::move(child.arguments.front())}});
            } else if (child.name == "domain-resolver") {
                return error("use dns { default \"<server>\" } instead of dns { domain-resolver ... }");
            } else if (child.name == "rulesets") {
                if (auto ok = desugar_rulesets_block(child, rulesets_seen, children); !ok) return ok;
            } else if (child.name == "rule-sets") {
                return error("use rulesets { ... }");
            } else if (child.name == "rule-set") {
                return error("use dns { rulesets { <name> ... } }");
            } else if (child.name == "rules") {
                if (rules_seen || child.tag || !child.arguments.empty() || !child.properties.empty())
                    return error("invalid or duplicate rules block");
                rules_seen = true;
                std::vector<Node> expanded_rules;
                for (auto& rule : child.children) {
                    if (rule.name != "-") return error("rules accepts only - nodes");
                    if (auto ok = desugar_dns_rule_expanded(rule, expanded_rules); !ok) return ok;
                }
                for (auto& r : expanded_rules) children.push_back(std::move(r));
            } else if (child.name == "rule") {
                return error("bare DNS rule is removed; use dns { rules { - ... } }");
            } else {
                children.push_back(std::move(child));
            }
        }
        dns.children = std::move(children);
        return {};
    }
}
