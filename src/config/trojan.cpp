module config;
import std;
import glaze;
import platform.ip_address;

namespace config {
    auto parse_tcp_dial_option(glaze::KdlNode const&,TcpSocketOptions&) -> std::expected<bool,std::string>;
    auto dns_ipv4(std::string_view) -> std::optional<std::array<std::uint8_t,4>>;
    auto dns_ipv6(std::string_view) -> std::optional<std::array<std::uint8_t,16>>;
    auto dns_hostname(std::string_view) -> bool;
    auto parse_quic_ech_field(glaze::KdlNode const&, QuicEchOptions&) -> bool;
    auto validate_quic_ech(QuicEchOptions const&, std::string_view, bool) -> std::expected<void, std::string>;
    auto parse_outbound_tls_fragment(glaze::KdlNode const&, OutboundTlsFragment&) -> std::expected<void, std::string>;
    auto parse_alpn_list(glaze::KdlNode const&, std::vector<std::string>&) -> std::expected<void, std::string>;
    auto parse_vless_transport(glaze::KdlNode const&,bool)
        -> std::expected<std::variant<HttpUpgradeTransport,GrpcTransport,xhttp::Profile>,std::string>;
    auto parse_outbound_multiplex(glaze::KdlNode const&) -> std::expected<MultiplexConfig,std::string>;
    auto parse_inbound_multiplex(glaze::KdlNode const&) -> std::expected<InboundMultiplexConfig,std::string>;
    namespace {
        using Node=glaze::KdlNode;
        using Value=glaze::KdlValue;
        auto error(std::string value) -> std::unexpected<std::string> { return std::unexpected(std::move(value)); }
        auto text(Value const& value) -> std::string const* { return value.tag ? nullptr : std::get_if<std::string>(&value.data); }
        auto argument(Node const& node) -> std::string const* { return !node.tag && node.arguments.size()==1 ? text(node.arguments[0]) : nullptr; }
        auto scalar(Node const& node) -> std::string const* { return node.properties.empty() && node.children.empty() ? argument(node) : nullptr; }
        auto property(Node const& node,std::string_view name) -> Value const* {
            for (auto const& [key,value]:node.properties) if (key==name) return &value; return nullptr;
        }
        auto string_property(Node const& node,std::string_view name) -> std::string const* { auto value=property(node,name); return value ? text(*value) : nullptr; }
        auto integer(Value const& value) -> std::optional<std::uint64_t> {
            if (value.tag) return {};
            if (auto number=std::get_if<std::uint64_t>(&value.data)) return *number;
            if (auto number=std::get_if<std::int64_t>(&value.data); number && *number>=0) return static_cast<std::uint64_t>(*number);
            return {};
        }
        auto boolean(Node const& node) -> std::optional<bool> {
            if (node.tag || !node.properties.empty() || !node.children.empty() || node.arguments.size()!=1 || node.arguments[0].tag) return {};
            auto flag=std::get_if<bool>(&node.arguments[0].data);
            return flag ? std::optional(*flag) : std::nullopt;
        }
        auto name(std::string_view value) -> bool { return !value.empty() && value.size()<=255 && value.find('\0')==value.npos; }
        auto path(std::string_view value) -> bool { return !value.empty() && value.front()=='/' && value.find('\0')==value.npos; }
        auto endpoint(std::string_view value) -> bool {
            return !value.empty() && value.size()<=253 && std::ranges::all_of(value,[](unsigned char c) { return c>=33 && c<=126; });
        }
        auto parse_host_port_target(std::string_view spec) -> std::optional<FallbackTarget> {
            if (spec.empty() || spec.size()>260) return {};
            for (unsigned char c : spec) if (c<33 || c>126) return {};
            auto parsed=platform::split_host_port(spec,true);
            if (!parsed || !endpoint(parsed->host) || !parsed->port) return {};
            return FallbackTarget{std::string(parsed->host),parsed->port};
        }
        auto parse_fallback_node(Node const& node,std::size_t arg_idx,std::string_view label) -> std::expected<FallbackTarget,std::string> {
            if (node.tag || !node.children.empty()) return error("invalid "+std::string(label));
            if (node.properties.empty() && node.arguments.size()==arg_idx+1) {
                auto raw=text(node.arguments[arg_idx]);
                auto parsed=raw ? parse_host_port_target(*raw) : std::nullopt;
                if (!parsed) return error("invalid "+std::string(label)+" endpoint");
                return *parsed;
            }
            if (node.arguments.size()==arg_idx && node.properties.size()==2) {
                auto host=string_property(node,"host"); auto pv=property(node,"port");
                auto port=pv ? integer(*pv) : std::nullopt;
                if (!host || !endpoint(*host) || !port || !*port || *port>65535)
                    return error("invalid "+std::string(label)+" endpoint");
                return FallbackTarget{*host,static_cast<std::uint16_t>(*port)};
            }
            return error("invalid "+std::string(label)+" syntax");
        }
        auto parse_alpn_fallback_entry(Node const& node,std::string_view alpn_raw,std::size_t target_idx,
            std::vector<std::pair<std::string,FallbackTarget>>& out) -> std::expected<void,std::string> {
            if (out.size()>=16 || alpn_raw.empty() || alpn_raw.size()>255 ||
                !std::ranges::all_of(alpn_raw,[](unsigned char c) { return c>=33 && c<=126; }) ||
                std::ranges::any_of(out,[&](auto const& kv) { return kv.first==alpn_raw; }))
                return error("invalid or duplicate Trojan fallback-for-alpn");
            auto target=parse_fallback_node(node,target_idx,"Trojan fallback-for-alpn");
            if (!target) return std::unexpected(target.error());
            out.emplace_back(std::string(alpn_raw),std::move(*target));
            return {};
        }
    }
    auto parse_password_tls_inbound(Node const& node,std::string_view kind,Inbound mode,std::string_view extra={}) -> std::expected<InboundConfig,std::string> {
        std::string label(kind=="anytls" ? "AnyTLS" : kind=="hysteria2" ? "Hysteria2" : "Trojan");
        auto tag=argument(node),type=string_property(node,"type");
        if (!tag || !name(*tag) || node.properties.size()!=1 || !type || *type!=kind) return error("invalid "+label+" inbound");
        InboundConfig result{*tag,0,mode};
        PasswordTlsInbound config;
        std::string listen_host;
        std::array<std::uint8_t,16> listen_address{};
        bool listen=false,auth=false,tls=false;
        for (auto const& child:node.children) {
            if((!extra.empty() && child.name==extra) || (mode==Inbound::hysteria2 && child.name=="masquerade"))continue;
            if (child.name=="listen") {
                auto host=string_property(child,"host"); auto value=property(child,"port");
                auto port=value ? integer(*value) : std::nullopt;
                if (listen || child.tag || !child.arguments.empty() || !child.children.empty() || child.properties.size()!=2 ||
                    !host || !port || !*port || *port>65535) return error("invalid "+label+" listen endpoint");
                if (mode==Inbound::hysteria2) {
                    if (auto address=dns_ipv4(*host)) std::ranges::copy(*address,listen_address.begin());
                    else if (auto address=dns_ipv6(*host)) { listen_address=*address;result.listen_ipv6=true; }
                    else return error("Hysteria2 listen host must be a numeric IP without a zone");
                    listen_host=*host;
                } else {
                    if (*host!="127.0.0.1" && *host!="::1") return error("invalid "+label+" listen endpoint");
                    result.listen_ipv6=*host=="::1";
                }
                result.port=static_cast<std::uint16_t>(*port);listen=true;
            } else if (child.name=="authentication") {
                if (auth || child.tag || !child.arguments.empty() || !child.properties.empty()) return error("invalid "+label+" authentication");
                for (auto const& user:child.children) {
                    auto tag=argument(user),file=string_property(user,"password-file");
                    if (user.name!="user" || !tag || !name(*tag) || !file || !path(*file) || user.properties.size()!=1 ||
                        !user.children.empty() || config.users.size()>=64 || std::ranges::any_of(config.users,[&](auto const& item) { return item.name==*tag; }))
                        return error("invalid or duplicate "+label+" user");
                    config.users.push_back({*tag,*file});
                }
                if (config.users.empty()) return error(label+" requires at least one user");
                auth=true;
            } else if (child.name=="tls") {
                if (tls || child.tag || !child.arguments.empty() || !child.properties.empty()) return error("invalid "+label+" TLS");
                bool reload_seen=false;
                for (auto const& field:child.children) {
                    if (field.name=="alpn") {
                        if (auto ok=parse_alpn_list(field,config.alpn); !ok) return std::unexpected(ok.error());
                    } else if (field.name=="cert-hot-reload") {
                        auto flag=boolean(field);
                        if (reload_seen || !flag) return error("invalid "+label+" TLS cert-hot-reload");
                        config.cert_hot_reload=*flag; reload_seen=true;
                    } else if (field.name=="certificate-provider") {
                        auto prov=scalar(field);
                        if (!config.certificate_provider.empty() || !prov || !name(*prov))
                            return error("invalid or duplicate "+label+" TLS certificate-provider");
                        config.certificate_provider=*prov;
                    } else {
                        auto file=scalar(field);
                        if (!file || !path(*file)) return error(label+" TLS requires absolute file paths");
                        if (field.name=="certificate-file" && config.certificate_file.empty()) config.certificate_file=*file;
                        else if (field.name=="private-key-file" && config.private_key_file.empty()) config.private_key_file=*file;
                        else if (field.name=="ech-key-file" && config.ech_key_file.empty()) config.ech_key_file=*file;
                        else return error("unsupported or duplicate "+label+" TLS field");
                    }
                }
                bool const has_files=!config.certificate_file.empty() || !config.private_key_file.empty();
                bool const has_prov=!config.certificate_provider.empty();
                if ((has_files && has_prov) || (!has_prov && (config.certificate_file.empty() || config.private_key_file.empty())))
                    return error(label+" TLS requires certificate and key or certificate-provider");
                if (has_prov && config.cert_hot_reload)
                    return error(label+" TLS cert-hot-reload cannot be combined with certificate-provider");
                tls=true;
            } else if (child.name=="fallback" && mode==Inbound::trojan) {
                if (config.fallback) return error("duplicate Trojan fallback");
                auto parsed=parse_fallback_node(child,0,"Trojan fallback");
                if (!parsed) return std::unexpected(parsed.error());
                config.fallback=std::move(*parsed);
            } else if (child.name=="fallback-for-alpn" && mode==Inbound::trojan) {
                if (!child.children.empty()) {
                    if (child.tag || !child.arguments.empty() || !child.properties.empty())
                        return error("invalid Trojan fallback-for-alpn block");
                    for (auto const& entry:child.children) {
                        if (auto ok=parse_alpn_fallback_entry(entry,entry.name,0,config.fallback_for_alpn); !ok) return std::unexpected(ok.error());
                    }
                } else {
                    auto alpn=child.arguments.empty() ? nullptr : text(child.arguments.front());
                    if (!alpn) return error("invalid Trojan fallback-for-alpn");
                    if (auto ok=parse_alpn_fallback_entry(child,*alpn,1,config.fallback_for_alpn); !ok) return std::unexpected(ok.error());
                }
            } else if (child.name=="transport" && (mode==Inbound::trojan || mode==Inbound::anytls)) {
                if (config.transport || config.grpc) return error("duplicate "+label+" transport");
                auto parsed=parse_vless_transport(child,false);
                if (!parsed) return std::unexpected(parsed.error());
                if (auto* gr=std::get_if<GrpcTransport>(&*parsed)) config.grpc=std::move(*gr);
                else if (auto* hu=std::get_if<HttpUpgradeTransport>(&*parsed)) config.transport=std::move(*hu);
                else return error(label+" transport supports websocket, httpupgrade or grpc");
            } else if (child.name=="multiplex" && mode==Inbound::trojan) {
                if (config.multiplex) return error("duplicate "+label+" multiplex");
                auto parsed=parse_inbound_multiplex(child);
                if (!parsed) return std::unexpected(parsed.error());
                config.multiplex=std::move(*parsed);
            } else return error("unsupported "+label+" inbound field: "+child.name);
        }
        if (!listen || !auth || !tls) return error(label+" inbound requires listen, authentication and TLS");
        if (mode==Inbound::hysteria2) {
            Hysteria2Inbound hy2{std::move(config),{},std::move(listen_host),listen_address};
            hy2.certificate_provider=hy2.connection.certificate_provider;
            hy2.ech_key_file=hy2.connection.ech_key_file;
            hy2.alpn=hy2.connection.alpn;
            hy2.cert_hot_reload=hy2.connection.cert_hot_reload;
            result.hysteria2=std::move(hy2);
        } else if (mode==Inbound::anytls) result.anytls=std::move(config);
        else result.trojan=std::move(config);
        return result;
    }
    auto parse_password_tls_outbound(Node const& node,std::string_view kind,std::string_view extra) -> std::expected<PasswordTlsOutbound,std::string> {
        std::string label(kind);
        PasswordTlsOutbound result;
        bool server=false,auth=false,tls=false,timeout=false,frag=false;
        for (auto const& child:node.children) {
            if (!extra.empty() && child.name==extra) continue;
            if (child.name=="server") {
                auto host=string_property(child,"host"); auto value=property(child,"port");
                auto port=value ? integer(*value) : std::nullopt;
                if (server || child.tag || !child.arguments.empty() || !child.children.empty() || child.properties.size()!=2 ||
                    !host || !endpoint(*host) || !port || !*port || *port>65535) return error("invalid "+label+" server");
                result.host=*host; result.port=static_cast<std::uint16_t>(*port); server=true;
            } else if (child.name=="authentication") {
                if (auth || child.tag || !child.arguments.empty() || !child.properties.empty() || child.children.size()!=1 || child.children[0].name!="password-file")
                    return error(label+" requires one password-file");
                auto file=scalar(child.children[0]);
                if (!file || !path(*file)) return error(label+" password-file must be absolute");
                result.password_file=*file; auth=true;
            } else if (child.name=="tls") {
                if (tls || child.tag || !child.arguments.empty() || !child.properties.empty()) return error("invalid "+label+" TLS");
                bool verify=false,exchange=false,fingerprint=false,record_size=false;
                for (auto const& field:child.children) {
                    auto value=scalar(field);
                    if (field.name=="server-name" && result.server_name.empty() && value && endpoint(*value)) result.server_name=*value;
                    else if (field.name=="ca-file" && result.ca_file.empty() && value && path(*value)) result.ca_file=*value;
                    else if (field.name=="alpn") {
                        if (auto ok=parse_alpn_list(field,result.alpn); !ok) return std::unexpected(ok.error());
                    } else if (field.name=="tls-fragment") {
                        if (kind=="Hysteria2") return error("tls-fragment is not valid for Hysteria2 QUIC");
                        if (std::exchange(frag,true)) return error("duplicate "+label+" tls-fragment");
                        if (auto ok=parse_outbound_tls_fragment(field,result.tls_fragment); !ok) return std::unexpected(ok.error());
                    } else if (field.name=="certificate-sha256") {
                        if (field.tag || !field.properties.empty() || !field.children.empty() ||
                            field.arguments.empty() || field.arguments.size()>16-result.certificate_sha256.size())
                            return error("certificate-sha256 requires up to 16 hexadecimal fingerprints");
                        for (auto const& argument:field.arguments) {
                            auto text=argument.tag ? nullptr : std::get_if<std::string>(&argument.data);
                            if (!text || (text->size()!=64 && text->size()!=95))
                                return error("invalid certificate-sha256 fingerprint length");
                            std::array<std::uint8_t,32> bytes{};
                            auto stride=text->size()==64 ? 2u : 3u;
                            for (std::size_t i=0;i<bytes.size();++i) {
                                auto begin=text->data()+i*stride;
                                auto [end,ec]=std::from_chars(begin,begin+2,bytes[i],16);
                                if (ec!=std::errc{} || end!=begin+2 ||
                                    (stride==3 && i+1<bytes.size() && begin[2]!=':'))
                                    return error("invalid certificate-sha256 fingerprint");
                            }
                            result.certificate_sha256.push_back(bytes);
                        }
                    }
                    else if (field.name=="key-exchange" && !exchange && value) {
                        if (*value!="x25519" && *value!="x25519-mlkem768" && *value!="x25519-mlkem768-only") return error("invalid "+label+" TLS key exchange");
                        result.key_exchange=*value=="x25519" ? TlsKeyExchange::x25519 :
                            *value=="x25519-mlkem768" ? TlsKeyExchange::x25519_mlkem768 : TlsKeyExchange::x25519_mlkem768_only;
                        exchange=true;
                    } else if (field.name=="fingerprint" && !fingerprint && value && (kind=="Trojan" || kind=="AnyTLS" || kind=="Hysteria2")) {
                        auto parsed=parse_tls_fingerprint(*value);
                        if (!parsed) return error("invalid "+label+" TLS fingerprint");
                        result.fingerprint=*parsed;
                        fingerprint=true;
                    } else if (field.name=="record-size-limit" && (kind=="Trojan" || kind=="AnyTLS")) {
                        auto limit=field.arguments.size()==1 ? integer(field.arguments.front()) : std::nullopt;
                        if (record_size || field.tag || !field.properties.empty() || !field.children.empty() || !limit || *limit<64 || *limit>16385)
                            return error("invalid "+label+" TLS record-size-limit");
                        result.record_size_limit=static_cast<std::uint16_t>(*limit);record_size=true;
                    } else if (field.name=="verify" && !verify && !field.tag && field.properties.empty() && field.children.empty() &&
                        field.arguments.size()==1 && !field.arguments[0].tag && std::holds_alternative<bool>(field.arguments[0].data) && std::get<bool>(field.arguments[0].data)) verify=true;
                    else if ((kind != "Hysteria2" && kind != "AnyTLS" && (kind != "Trojan" || extra == "strict-tls13")) ||
                             !parse_quic_ech_field(field, result.ech))
                        return error("unsupported or duplicate "+label+" TLS field");
                }
                if ((result.ech.dns || !result.ech.config_file.empty()) && result.fingerprint==TlsFingerprint::tls12)
                    return error(label+" ECH requires TLS 1.3");
                if (result.fingerprint==TlsFingerprint::tls12 &&
                    (kind=="Hysteria2" || extra=="strict-tls13" || result.key_exchange!=TlsKeyExchange::x25519 || record_size))
                    return error("TLS 1.2 fingerprint requires a Trojan or AnyTLS TCP outbound with X25519");
                if (!verify || result.server_name.empty()) return error(label+" requires authenticated TLS");
                tls=true;
            } else if (child.name=="tls-fragment") {
                if (kind=="Hysteria2") return error("tls-fragment is not valid for Hysteria2 QUIC");
                if (std::exchange(frag,true)) return error("duplicate "+label+" tls-fragment");
                if (auto ok=parse_outbound_tls_fragment(child,result.tls_fragment); !ok) return std::unexpected(ok.error());
            } else if (child.name=="connect-timeout-ms") {
                auto value=child.arguments.size()==1 ? integer(child.arguments[0]) : std::nullopt;
                if (timeout || child.tag || !child.properties.empty() || !child.children.empty() || !value || !*value || *value>3600000) return error("invalid "+label+" connect-timeout-ms");
                result.connect_timeout_ms=static_cast<std::uint32_t>(*value); timeout=true;
            } else if (child.name=="bootstrap-resolver" || child.name=="domain-resolver" || child.name=="detour") {
                auto value=scalar(child); auto& target=child.name=="detour" ? result.detour : result.bootstrap_resolver;
                if (target || !value || !name(*value)) return error("invalid "+label+" outbound dependency"); target=*value;
            } else if (child.name=="transport" && (kind=="Trojan" || kind=="AnyTLS")) {
                if (result.transport || result.grpc) return error("duplicate "+label+" transport");
                auto parsed=parse_vless_transport(child,true);
                if (!parsed) return std::unexpected(parsed.error());
                if (auto* gr=std::get_if<GrpcTransport>(&*parsed)) result.grpc=std::move(*gr);
                else if (auto* hu=std::get_if<HttpUpgradeTransport>(&*parsed)) result.transport=std::move(*hu);
                else return error(label+" transport supports websocket, httpupgrade or grpc");
            } else if (child.name=="tcp-fast-open" && (kind=="Trojan" || kind=="AnyTLS")) {
                if (result.tcp_fast_open || child.tag || !child.properties.empty() || !child.children.empty() ||
                    child.arguments.size()!=1 || child.arguments[0].tag || !std::holds_alternative<bool>(child.arguments[0].data))
                    return error("tcp-fast-open requires one boolean and cannot repeat");
                result.tcp_fast_open=std::get<bool>(child.arguments[0].data);
            } else if (child.name=="multiplex" && kind=="Trojan") {
                if (result.multiplex) return error("duplicate "+label+" multiplex");
                auto parsed=parse_outbound_multiplex(child);
                if (!parsed) return std::unexpected(parsed.error());
                result.multiplex=std::move(*parsed);
            } else {
                auto option=parse_tcp_dial_option(child,result.tcp_options);
                if (!option) return std::unexpected(option.error());
                if (!*option) return error("unsupported "+label+" outbound field: "+child.name);
            }
        }
        if (!server || !auth || !tls) return error(label+" requires server, authentication and TLS");
        if (result.detour && result.tcp_fast_open) return error("tcp-fast-open belongs to the physical outbound, not a layered node");
        return result;
    }
    auto parse_trojan_inbound(Node const& node) -> std::expected<InboundConfig,std::string> {
        return parse_password_tls_inbound(node,"trojan",Inbound::trojan);
    }
    auto parse_trojan_outbound(Node const& node) -> std::expected<TrojanOutbound,std::string> {
        return parse_password_tls_outbound(node,"Trojan",{});
    }
    auto validate_password_tls_outbound(PasswordTlsOutbound& config,Config const& result,std::string_view kind) -> std::expected<void,std::string> {
        if (auto ok=validate_quic_ech(config.ech,config.server_name,result.dns.has_value()); !ok) return ok;
        if (!config.bootstrap_resolver) return {};
        if (!result.dns || !dns_hostname(config.host) || dns_ipv4(config.host))
            return error(std::string(kind)+" bootstrap-resolver requires a configured DNS server and domain host");
        config.bootstrap_index=result.dns->resolver_index(*config.bootstrap_resolver);
        if (!config.bootstrap_index) return error(std::string(kind)+" domain-resolver references unknown DNS server or view: "+*config.bootstrap_resolver);
        return {};
    }
    auto validate_trojan(Config& result,std::string_view direct,std::optional<std::string> const& block) -> std::expected<void,std::string> {
        for (std::size_t i=0;i<result.trojan_outbounds.size();++i) {
            auto& entry=result.trojan_outbounds[i];
            if (entry.name==direct || (block && entry.name==*block) ||
                std::ranges::any_of(result.vless_outbounds,[&](auto const& other) { return other.name==entry.name; }) ||
                std::ranges::any_of(result.shadowsocks_outbounds,[&](auto const& other) { return other.name==entry.name; }) ||
                std::ranges::any_of(std::span(result.trojan_outbounds).first(i),[&](auto const& other) { return other.name==entry.name; })) return error("outbound names must be unique");
            if (auto valid=validate_password_tls_outbound(entry.config,result,"Trojan"); !valid) return valid;
        }
        return {};
    }
}
