// Private implementation: included within nexus::config after KDL helpers.
#pragma once
    auto normalize_groups(g::KdlDocument& document) -> std::expected<void,std::string> {
        auto typed=[](Node& group, std::string_view canonical, std::initializer_list<std::string_view> allowed)
            -> std::expected<void,std::string> {
            for (auto& child : group.children) {
                if (child.name==canonical) continue;
                if (std::ranges::find(allowed,child.name)==allowed.end() || property(child,"type"))
                    return error("unsupported type in " + group.name);
                child.properties.push_back({"type",{child.name,{}}});
                child.name=canonical;
            }
            return {};
        };
        for (auto& node : document) {
            if (node.name=="inbounds" || node.name=="outbounds") {
                auto result=node.name=="inbounds" ? typed(node,"inbound",{"socks5","mixed","vless","shadowsocks"}) :
                    typed(node,"outbound",{"direct","block","vless","shadowsocks"});
                if (!result) return result;
            } else if (node.name=="dns" || node.name=="routing") {
                bool rules_seen=false, legacy=false;
                std::vector<Node> children;
                for (auto& child : node.children) {
                    if (node.name=="dns" && child.name=="servers") {
                        if (auto result=typed(child,"server",{"local","udp","tcp"}); !result) return result;
                    }
                    if (child.name=="rules") {
                        if (rules_seen || legacy || child.tag || !child.arguments.empty() || !child.properties.empty())
                            return error("invalid or duplicate rules block");
                        rules_seen=true;
                        for (auto& rule : child.children) {
                            if (rule.name!="-") return error("rules accepts only - nodes");
                            rule.name="rule";
                            children.push_back(std::move(rule));
                        }
                    } else {
                        if (child.name=="rule") {
                            if (rules_seen) return error("cannot mix rules block and rule nodes");
                            legacy=true;
                        }
                        children.push_back(std::move(child));
                    }
                }
                node.children=std::move(children);
            }
        }
        return {};
    }
