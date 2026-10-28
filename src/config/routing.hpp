// Private implementation: included after the KDL helpers.
#pragma once
        struct NamedRouteFile { std::string name; BlockRules file; };
        struct PendingRouteRule { std::string set, outbound; };
        struct Route {
            std::vector<NamedRouteFile> files;
            std::vector<PendingRouteRule> rules;
            std::optional<std::string> default_outbound;
        };
        auto routing(Node const& node) -> std::expected<Route, std::string> {
            if (node.tag || !node.arguments.empty() || !node.properties.empty()) return error("routing takes no arguments or properties");
            Route route;
            for (auto const& child : node.children) {
                if (child.name == "rule-set") {
                    auto name=argument(child), path=text_property(child,"path"), format=text_property(child,"format");
                    if (!name || !valid_name(*name) || !child.children.empty() || child.properties.size()!=2 ||
                        !path || path->empty() || path->find('\0')!=std::string::npos || !format ||
                        (*format!="kdl" && *format!="beve") || route.files.size()>=256 ||
                        std::ranges::any_of(route.files,[&](auto const& file) { return file.name==*name; }))
                        return error("invalid or duplicate rule-set");
                    route.files.push_back({*name,{*path,*format=="kdl" ? RuleFormat::kdl : RuleFormat::beve}});
                } else if (child.name == "rule") {
                    auto kind=text_property(child,"kind"), value=text_property(child,"value"), outbound=text_property(child,"outbound");
                    if (child.tag || !child.arguments.empty() || !child.children.empty() || child.properties.size()!=3 ||
                        !kind || *kind!="rule-set" || !value || !valid_name(*value) || !outbound || !valid_name(*outbound) ||
                        route.rules.size()>=256) return error("invalid rule-set rule");
                    route.rules.push_back({*value,*outbound});
                } else if (child.name == "default-outbound") {
                    auto value=scalar(child);
                    if (route.default_outbound || !value || !valid_name(*value)) return error("one default-outbound is required");
                    route.default_outbound=*value;
                } else return error("unsupported routing node: " + child.name);
            }
            if (!route.default_outbound) return error("routing requires default-outbound");
            for (auto const& rule : route.rules)
                if (std::ranges::find(route.files,rule.set,&NamedRouteFile::name)==route.files.end())
                    return error("rule-set reference not found");
            for (auto const& file : route.files)
                if (std::ranges::none_of(route.rules,[&](auto const& rule) { return rule.set==file.name; }))
                    return error("unreferenced rule-set");
            return route;
        }
