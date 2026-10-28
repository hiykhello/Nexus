// Private implementation: included within nexus::config after KDL helpers.
#pragma once
        auto shadowsocks_outbound(Node const& node) -> std::expected<ShadowsocksOutbound, std::string> {
            ShadowsocksOutbound result;
            bool server=false, method=false, key=false;
            for (auto const& child : node.children) {
                if (child.name=="server") {
                    auto host=text_property(child,"host");
                    auto value=property(child,"port");
                    auto port=value ? integer(*value) : std::nullopt;
                    if (server || child.tag || !child.arguments.empty() || !child.children.empty() || child.properties.size()!=2 ||
                        !host || !endpoint_name(*host) || !port || !*port || *port>65535)
                        return error("shadowsocks requires one server with host and port 1..65535");
                    result.host=*host; result.port=static_cast<std::uint16_t>(*port); server=true;
                } else if (child.name=="bootstrap-resolver") {
                    auto value=scalar(child);
                    if (result.bootstrap_resolver || !value || !valid_name(*value)) return error("invalid shadowsocks bootstrap-resolver");
                    result.bootstrap_resolver=*value;
                } else if (child.name=="method") {
                    auto value=scalar(child);
                    if (method || !value || (*value!="2022-blake3-aes-128-gcm" && *value!="2022-blake3-aes-256-gcm"))
                        return error("unsupported shadowsocks method");
                    result.method=*value; method=true;
                } else if (child.name=="key-file") {
                    auto value=scalar(child);
                    if (key || !value || !absolute_path(*value)) return error("shadowsocks key-file must be absolute");
                    result.key_file=*value; key=true;
                } else return error("unsupported shadowsocks node: " + child.name);
            }
            if (!server || !method || !key) return error("shadowsocks requires server, method and key-file");
            return result;
        }
    template<class Routing>
    auto validate_shadowsocks(Config& result, std::string const& direct,
            std::optional<std::string> const& block, Routing const& route) -> std::expected<void,std::string> {
        for (std::size_t i=0;i<result.shadowsocks_outbounds.size();++i) {
            auto& outbound=result.shadowsocks_outbounds[i].config;
            if (outbound.bootstrap_resolver) {
                if (!result.dns || !dns_domain(outbound.host) || ipv4(outbound.host))
                    return error("shadowsocks bootstrap-resolver requires DNS configuration and a domain server host");
                auto found=std::ranges::find(result.dns->servers,*outbound.bootstrap_resolver,&DnsServer::name);
                if (found==result.dns->servers.end()) return error("shadowsocks bootstrap-resolver not found");
                outbound.bootstrap_index=static_cast<std::size_t>(found-result.dns->servers.begin());
            }
            auto const& name=result.shadowsocks_outbounds[i].name;
            if (name==direct || (block && name==*block) ||
                std::ranges::any_of(result.vless_outbounds,[&](auto const& other) { return other.name==name; }) ||
                std::ranges::any_of(std::span(result.shadowsocks_outbounds).first(i),[&](auto const& other) { return other.name==name; }))
                return error("outbound names must be unique");
            if (route.default_outbound!=name && std::ranges::none_of(route.rules,[&](auto const& rule) { return rule.outbound==name; }))
                return error("shadowsocks must be referenced by routing");
        }
        return {};
    }
