module provider;
import std;
import glaze;
import :detail;

namespace provider {
    auto expand_providers_in_kdl(
        std::string_view raw_kdl,
        std::map<std::string, std::vector<std::pair<std::string, std::string>>> const& provider_outbounds_kdl)
        -> std::expected<std::string, std::string> {
        auto doc = glaze::read_kdl<glaze::KdlDocument>(raw_kdl);
        if (!doc) return std::unexpected(glaze::format_error(doc.error(), raw_kdl));
        std::erase_if(*doc, [](glaze::KdlNode const& n) {
            return n.name == "proxy-providers" || n.name == "proxy-provider";
        });

        auto node_str = [](glaze::KdlValue const& v) -> std::string const* {
            return v.tag ? nullptr : std::get_if<std::string>(&v.data);
        };
        auto outbound_name = [&](glaze::KdlNode const& n) -> std::string {
            if (!n.tag && n.arguments.size() == 1)
                if (auto* s = node_str(n.arguments.front())) return *s;
            return {};
        };

        std::set<std::string> existing_outbounds;
        glaze::KdlNode* outbounds_node = nullptr;
        auto scan_existing = [&](glaze::KdlNode const& n) {
            auto tag = outbound_name(n);
            if (!tag.empty()) existing_outbounds.insert(tag);
        };
        for (auto& top : *doc) {
            if (top.name == "outbounds") {
                if (!outbounds_node) outbounds_node = &top;
                for (auto const& ch : top.children) scan_existing(ch);
            } else if (top.name == "outbound" || top.name == "direct" || top.name == "block") {
                scan_existing(top);
            }
        }
        if (!outbounds_node) {
            doc->push_back(glaze::KdlNode{.name = "outbounds"});
            outbounds_node = &doc->back();
        }
        for (auto const& [pname, items] : provider_outbounds_kdl) {
            (void)pname;
            for (auto const& [tag, kdl] : items) {
                if (!existing_outbounds.insert(tag).second) continue;
                auto sub = glaze::read_kdl<glaze::KdlDocument>(kdl);
                if (!sub || sub->empty()) return std::unexpected("internal error parsing provider outbound " + tag);
                for (auto& ob : *sub) outbounds_node->children.push_back(std::move(ob));
            }
        }

        auto expand_group = [&](glaze::KdlNode& group) {
            bool is_group = group.name == "selector" || group.name == "fallback" ||
                            group.name == "url-test" || group.name == "load-balance";
            if (!is_group && group.name == "outbound") {
                for (auto const& [k, v] : group.properties) {
                    if (k == "type") {
                        if (auto* ts = node_str(v); ts && (*ts == "selector" || *ts == "fallback" ||
                            *ts == "url-test" || *ts == "load-balance")) is_group = true;
                    }
                }
            }
            if (!is_group) return;
            std::set<std::string> seen_members;
            std::vector<glaze::KdlNode> next_children;
            for (auto& c : group.children) {
                if (c.name == "member" || c.name == "members") {
                    for (auto const& a : c.arguments) if (auto* s = node_str(a)) seen_members.insert(*s);
                    next_children.push_back(std::move(c));
                } else if (c.name == "use") {
                    for (auto const& a : c.arguments) {
                        auto* pn = node_str(a);
                        if (!pn) continue;
                        if (auto it = provider_outbounds_kdl.find(*pn); it != provider_outbounds_kdl.end()) {
                            for (auto const& [tag, _] : it->second) {
                                if (seen_members.insert(tag).second) {
                                    next_children.push_back(glaze::KdlNode{
                                        .name = "member",
                                        .arguments = {glaze::KdlValue{tag, {}}}});
                                }
                            }
                        }
                    }
                } else {
                    next_children.push_back(std::move(c));
                }
            }
            group.children = std::move(next_children);
        };

        for (auto& top : *doc) {
            if (top.name == "outbounds") {
                for (auto& ch : top.children) expand_group(ch);
            } else if (top.name == "outbound") {
                expand_group(top);
            }
        }
        auto written = glaze::write_kdl(*doc);
        if (!written) return std::unexpected("cannot serialize expanded KDL configuration");
        return *written;
    }
}
