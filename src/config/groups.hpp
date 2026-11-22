// Private implementation: included within config after KDL helpers.
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
                auto result=node.name=="inbounds" ? typed(node,"inbound",{"socks5","mixed","http","fixed-tcp","fixed-udp","vless","shadowsocks","trojan","anytls","hysteria2","snell","masque","redirect","tproxy","tun"}) :
                    typed(node,"outbound",{"direct","block","vless","shadowsocks","trojan","anytls","hysteria2","snell","socks5","socks4","socks4a","http-connect","selector","fallback","url-test","load-balance"});
                if (!result) return result;
            } else if (node.name=="dns" || node.name=="routing") {
                bool rules_seen=false, legacy=false;
                std::vector<Node> children;
                for (auto& child : node.children) {
                    if (node.name=="dns" && child.name=="servers") {
                        if (auto result=typed(child,"server",{"local","udp","tcp","tls","https","quic","https3"}); !result) return result;
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

    auto parse_probe_status_item(g::KdlValue const& value) -> std::expected<OutboundStatusRange,std::string> {
        if (value.tag) return error("invalid outbound probe-expected-status");
        auto parse_code=[](std::string_view text) -> std::optional<std::uint16_t> {
            std::uint16_t code=0;
            auto [end,ec]=std::from_chars(text.data(),text.data()+text.size(),code);
            if (ec!=std::errc{} || end!=text.data()+text.size() || code<100 || code>599) return {};
            return code;
        };
        if (auto n=std::get_if<std::uint64_t>(&value.data)) {
            if (*n<100 || *n>599) return error("outbound probe-expected-status must be 100..599");
            auto c=static_cast<std::uint16_t>(*n);
            return OutboundStatusRange{c,c};
        }
        if (auto n=std::get_if<std::int64_t>(&value.data)) {
            if (*n<100 || *n>599) return error("outbound probe-expected-status must be 100..599");
            auto c=static_cast<std::uint16_t>(*n);
            return OutboundStatusRange{c,c};
        }
        if (auto s=std::get_if<std::string>(&value.data)) {
            auto sv=std::string_view(*s);
            if (auto sep=sv.find(".."); sep!=sv.npos) {
                auto lo=parse_code(sv.substr(0,sep));
                auto hi=parse_code(sv.substr(sep+2));
                if (!lo || !hi || *lo>*hi) return error("invalid outbound probe-expected-status range");
                return OutboundStatusRange{*lo,*hi};
            }
            auto single=parse_code(sv);
            if (!single) return error("invalid outbound probe-expected-status value");
            return OutboundStatusRange{*single,*single};
        }
        return error("invalid outbound probe-expected-status type");
    }

    auto parse_outbound_selector(g::KdlNode const& node,std::string_view name,std::string_view type)
        -> std::expected<OutboundSelector,std::string> {
        using namespace kdl;
        OutboundSelector result;
        result.name=name;
        if (type=="fallback") result.mode=OutboundGroupMode::fallback;
        if (type=="url-test") result.mode=OutboundGroupMode::url_test;
        if (type=="load-balance") result.mode=OutboundGroupMode::load_balance;
        auto automatic=result.mode==OutboundGroupMode::fallback || result.mode==OutboundGroupMode::url_test;
        std::optional<std::uint64_t> interval,timeout,tolerance;
        bool mode_seen=false, status_seen=false;
        for (auto const& child : node.children) {
            if (child.name=="member" || (result.mode==OutboundGroupMode::select && child.name=="selected")) {
                auto value=scalar(child);
                if (!value || !valid_name(*value)) return error("invalid outbound group member");
                if (child.name=="member" && result.members.size()<16 &&
                    std::ranges::find(result.members,*value)==result.members.end()) result.members.push_back(*value);
                else if (child.name=="selected" && result.selected.empty()) result.selected=*value;
                else return error("invalid or duplicate selector field");
            } else if (automatic && child.name=="probe-url" && result.probe.url.empty()) {
                auto url=scalar(child);
                if (!url || (!url->starts_with("http://") && !url->starts_with("https://")) || url->size()>1024)
                    return error("outbound probe-url requires an HTTP or HTTPS URL");
                result.probe.url=*url;
            } else if (automatic && child.name=="probe-mode" && !mode_seen) {
                auto mode=scalar(child);
                if (!mode) return error("invalid outbound probe-mode");
                if (*mode=="http") result.probe.mode=OutboundProbeMode::http;
                else if (*mode=="h2-ping") result.probe.mode=OutboundProbeMode::h2_ping;
                else return error("outbound probe-mode must be http or h2-ping");
                mode_seen=true;
            } else if (automatic && child.name=="probe-expected-status" && !status_seen) {
                if (child.tag || !child.properties.empty() || !child.children.empty() ||
                    child.arguments.empty() || child.arguments.size()>16)
                    return error("invalid outbound probe-expected-status");
                for (auto const& arg : child.arguments) {
                    auto parsed=parse_probe_status_item(arg);
                    if (!parsed) return std::unexpected(parsed.error());
                    result.probe.expected_status.push_back(*parsed);
                }
                status_seen=true;
            } else if (automatic && child.name=="probe-ca-file" && result.probe.ca_file.empty()) {
                auto ca=scalar(child);
                if (!ca || ca->empty() || ca->front()!='/' || ca->size()>1024 || ca->contains('\0'))
                    return error("invalid outbound probe-ca-file");
                result.probe.ca_file=*ca;
            } else if (automatic && child.name=="probe-server-name" && result.probe.server_name.empty()) {
                auto sni=scalar(child);
                if (!sni || sni->empty() || sni->size()>253 || sni->contains('\0'))
                    return error("invalid outbound probe-server-name");
                result.probe.server_name=*sni;
            } else if (automatic && child.name=="probe-interval-ms" && !interval) {
                interval=integer(child);
                if (!interval || *interval<500 || *interval>3600000)
                    return error("invalid outbound probe-interval-ms");
            } else if (automatic && child.name=="probe-timeout-ms" && !timeout) {
                timeout=integer(child);
                if (!timeout || *timeout<100 || *timeout>10000)
                    return error("invalid outbound probe-timeout-ms");
            } else if (result.mode==OutboundGroupMode::url_test && child.name=="tolerance-ms" && !tolerance) {
                tolerance=integer(child);
                if (!tolerance || *tolerance>10000) return error("invalid url-test tolerance-ms");
            } else return error("invalid or duplicate outbound group field");
        }
        if (result.members.empty()) return error("selector requires at least one member");
        if (result.selected.empty()) result.selected=result.members.front();
        if (std::ranges::find(result.members,result.selected)==result.members.end())
            return error("selector selected outbound must be a member");
        if (automatic && result.probe.url.empty()) return error("outbound group requires probe-url");
        if (automatic && result.probe.mode==OutboundProbeMode::http && result.probe.url.starts_with("https://"))
            return error("outbound HTTP probe-url requires http:// (use probe-mode \"h2-ping\" for https://)");
        if (automatic && result.probe.mode==OutboundProbeMode::h2_ping && !result.probe.expected_status.empty())
            return error("outbound probe-expected-status is only valid with http probe-mode");
        if (automatic && (!result.probe.ca_file.empty() || !result.probe.server_name.empty()) &&
            (result.probe.mode!=OutboundProbeMode::h2_ping || !result.probe.url.starts_with("https://")))
            return error("outbound probe TLS options require probe-mode \"h2-ping\" with an https:// probe-url");
        if (interval) result.probe.interval_ms=static_cast<std::uint32_t>(*interval);
        if (timeout) result.probe.timeout_ms=static_cast<std::uint32_t>(*timeout);
        if (tolerance) result.probe.tolerance_ms=static_cast<std::uint32_t>(*tolerance);
        return result;
    }
