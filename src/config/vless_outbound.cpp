module config;
import std;
import config.kdl_common;
import platform.socket_options;
import glaze;

namespace config {
    using namespace config::kdl;

    auto parse_tcp_dial_option(Node const&,TcpSocketOptions&) -> std::expected<bool,std::string>;
    auto parse_quic_ech_field(Node const&,QuicEchOptions&) -> bool;
    auto parse_outbound_tls_fragment(Node const&,OutboundTlsFragment&) -> std::expected<void,std::string>;
    auto parse_alpn_list(Node const&,std::vector<std::string>&) -> std::expected<void,std::string>;
    auto parse_vless_transport(Node const&,bool) -> std::expected<std::variant<HttpUpgradeTransport,GrpcTransport,xhttp::Profile>,std::string>;
    auto parse_outbound_multiplex(Node const&) -> std::expected<MultiplexConfig,std::string>;

    auto parse_vless_outbound(Node const& node) -> std::expected<VlessOutbound, std::string> {
        VlessOutbound result;
        bool server_seen=false, auth_seen=false, tls_seen=false, flow_seen=false, timeout_seen=false, encoding_seen=false;
        std::optional<bool> fast_open;
        for (auto const& child : node.children) {
            if (child.name == "server") {
                auto host = text_property(child, "host");
                auto value = property(child, "port");
                auto port = value ? integer(*value) : std::nullopt;
                if (server_seen || child.tag || !child.arguments.empty() || !child.children.empty() ||
                    child.properties.size()!=2 || !host || !endpoint_name(*host) || !port || !*port || *port>65535)
                    return error("vless requires one server with host and port 1..65535");
                result.host=*host; result.port=static_cast<std::uint16_t>(*port); server_seen=true;
            } else if (child.name == "transport") {
                if (result.transport || result.grpc || result.xhttp) return error("duplicate vless transport");
                auto parsed=parse_vless_transport(child,true);
                if (!parsed) return std::unexpected(parsed.error());
                if (auto grpc=std::get_if<GrpcTransport>(&*parsed)) result.grpc=std::move(*grpc);
                else if (auto split=std::get_if<xhttp::Profile>(&*parsed)) result.xhttp=std::move(*split);
                else result.transport=std::move(std::get<HttpUpgradeTransport>(*parsed));
            } else if (child.name == "packet-encoding") {
                auto encoding=scalar(child);
                if (encoding_seen || !encoding || (*encoding!="packetaddr" && *encoding!="xudp" && *encoding!="fixed"))
                    return error("vless packet-encoding must be xudp, packetaddr or fixed");
                result.packetaddr=*encoding=="packetaddr";
                result.fixed_udp=*encoding=="fixed";
                encoding_seen=true;
            } else if (child.name == "flow") {
                auto value=scalar(child);
                if (flow_seen || !value || *value!="xtls-rprx-vision") return error("invalid vless flow");
                result.vision=true; flow_seen=true;
            } else if (child.name == "connect-timeout-ms") {
                auto value=connect_timeout(child);
                if (timeout_seen || !value) return error("invalid vless connect-timeout-ms");
                result.connect_timeout_ms=*value; timeout_seen=true;
            } else if (child.name == "detour") {
                auto value=scalar(child);
                if (result.detour || !value || !valid_name(*value)) return error("invalid vless detour");
                result.detour=*value;
            } else if (child.name == "bootstrap-resolver" || child.name=="domain-resolver") {
                auto value=scalar(child);
                if (result.bootstrap_resolver || !value || !valid_name(*value)) return error("invalid vless bootstrap-resolver");
                result.bootstrap_resolver=*value;
            } else if (child.name == "tcp-fast-open") {
                if (fast_open || child.tag || !child.properties.empty() || !child.children.empty() || child.arguments.size()!=1 ||
                    child.arguments[0].tag || !std::holds_alternative<bool>(child.arguments[0].data))
                    return error("tcp-fast-open requires one boolean and cannot repeat");
                fast_open=std::get<bool>(child.arguments[0].data);
            } else if (child.name == "multiplex") {
                if (result.multiplex) return error("duplicate vless multiplex");
                auto parsed = parse_outbound_multiplex(child);
                if (!parsed) return std::unexpected(parsed.error());
                result.multiplex = std::move(*parsed);
            } else if (child.name == "authentication") {
                if (auth_seen || child.tag || !child.arguments.empty() || !child.properties.empty() || child.children.size()!=1 ||
                    child.children.front().name!="uuid-file") return error("vless requires one uuid-file");
                auto path=scalar(child.children.front());
                if (!path || !absolute_path(*path)) return error("vless uuid-file must be absolute");
                result.uuid_file=*path; auth_seen=true;
            } else if (child.name == "tls") {
                if (tls_seen || child.tag || !child.arguments.empty() || !child.properties.empty()) return error("invalid vless tls");
                bool name_seen=false, ca_seen=false, verify_seen=false, key_exchange_seen=false, reality_seen=false, fingerprint_seen=false, record_size_seen=false, frag_seen=false;
                for (auto const& field : child.children) {
                    if (field.name=="server-name") {
                        auto value=scalar(field);
                        if (name_seen || !value || !endpoint_name(*value)) return error("invalid vless tls server-name");
                        result.server_name=*value; name_seen=true;
                    } else if (field.name=="ca-file") {
                        auto value=scalar(field);
                        if (ca_seen || !value || !absolute_path(*value)) return error("invalid vless tls ca-file");
                        result.ca_file=*value; ca_seen=true;
                    } else if (field.name=="certificate-sha256") {
                        if (auto ok=parse_certificate_sha256(field,result.certificate_sha256); !ok) return std::unexpected(ok.error());
                    } else if (field.name=="reality") {
                        if (reality_seen || field.tag || !field.arguments.empty() || !field.properties.empty()) return error("invalid vless reality");
                        VlessOutbound::Reality reality;
                        bool public_seen=false, short_seen=false;
                        auto decode=[](std::string_view text, auto& bytes, bool exact) {
                            if (text.size()%2 || text.size()>bytes.size()*2 || (exact && text.size()!=bytes.size()*2)) return false;
                            auto nib=[](char c)->int { if (c>='0' && c<='9') return c-'0'; if (c>='a' && c<='f') return c-'a'+10; if (c>='A' && c<='F') return c-'A'+10; return -1; };
                            for (std::size_t i=0;i<text.size()/2;++i) { auto a=nib(text[i*2]), b=nib(text[i*2+1]); if (a<0 || b<0) return false; bytes[i]=static_cast<std::uint8_t>(a*16+b); }
                            return true;
                        };
                        for (auto const& item : field.children) {
                            auto value=scalar(item);
                            if (item.name=="public-key" && !public_seen && value && decode(*value,reality.public_key,true)) public_seen=true;
                            else if (item.name=="short-id" && !short_seen && value && decode(*value,reality.short_id,false)) short_seen=true;
                            else return error("invalid vless reality field");
                        }
                        if (!public_seen) return error("vless reality requires public-key");
                        result.reality=reality; reality_seen=true;
                    } else if (field.name=="key-exchange") {
                        auto value=scalar(field);
                        if (key_exchange_seen || !value || (*value!="x25519" && *value!="x25519-mlkem768" && *value!="x25519-mlkem768-only"))
                            return error("vless tls key-exchange must be x25519, x25519-mlkem768 or x25519-mlkem768-only");
                        result.key_exchange=*value=="x25519" ? TlsKeyExchange::x25519 :
                            *value=="x25519-mlkem768" ? TlsKeyExchange::x25519_mlkem768 : TlsKeyExchange::x25519_mlkem768_only;
                        key_exchange_seen=true;
                    } else if (field.name=="fingerprint") {
                        auto value=scalar(field);
                        auto parsed=value ? parse_tls_fingerprint(*value) : std::nullopt;
                        if (fingerprint_seen || !parsed) return error("invalid vless tls fingerprint");
                        result.fingerprint=*parsed;
                        fingerprint_seen=true;
                    } else if (field.name=="record-size-limit") {
                        auto value=field.arguments.size()==1 ? integer(field.arguments.front()) : std::nullopt;
                        if (record_size_seen || field.tag || !field.properties.empty() || !field.children.empty() || !value || *value<64 || *value>16385)
                            return error("vless tls record-size-limit must be 64..16385");
                        result.record_size_limit=static_cast<std::uint16_t>(*value);record_size_seen=true;
                    } else if (field.name=="tls-fragment") {
                        if (std::exchange(frag_seen,true)) return error("duplicate vless tls-fragment");
                        if (auto ok=parse_outbound_tls_fragment(field,result.tls_fragment); !ok) return std::unexpected(ok.error());
                    } else if (field.name=="alpn") {
                        if (auto ok=parse_alpn_list(field,result.alpn); !ok) return std::unexpected(ok.error());
                    } else if (field.name=="verify") {
                        if (verify_seen || field.tag || !field.properties.empty() || !field.children.empty() || field.arguments.size()!=1 ||
                            field.arguments[0].tag || !std::holds_alternative<bool>(field.arguments[0].data) || !std::get<bool>(field.arguments[0].data))
                            return error("vless tls requires verify #true");
                        verify_seen=true;
                    } else if (!parse_quic_ech_field(field,result.ech)) return error("unsupported vless tls node: " + field.name);
                }
                if (!name_seen || (reality_seen ? (ca_seen || verify_seen || !result.certificate_sha256.empty()) : !verify_seen))
                    return error("invalid vless tls authentication configuration");
                if (reality_seen && (result.ech.dns || !result.ech.config_file.empty()))
                    return error("VLESS ECH cannot be combined with Reality");
                tls_seen=true;
            } else {
                auto option=parse_tcp_dial_option(child,result.tcp_options);
                if (!option) return std::unexpected(option.error());
                if (!*option) return error("unsupported vless node: " + child.name);
            }
        }
        if (!server_seen || !auth_seen || (!tls_seen && !result.xhttp)) return error("vless requires server, authentication and tls");
        if (result.xhttp && (result.vision || result.packetaddr || result.fixed_udp || result.detour ||
            fast_open.value_or(false) || result.fingerprint==TlsFingerprint::tls12 ||
            (result.xhttp->endpoint.version==xhttp::HttpVersion::http3 && (!tls_seen || result.reality))))
            return error("invalid VLESS XHTTP TLS, flow or socket options");
        if (result.xhttp && result.xhttp->endpoint.version==xhttp::HttpVersion::http3 &&
            (result.tls_fragment.enabled || result.tls_fragment.record_fragment))
            return error("VLESS XHTTP HTTP/3 cannot use TCP TLS fragmentation");
        if ((result.ech.dns || !result.ech.config_file.empty()) && result.fingerprint==TlsFingerprint::tls12)
            return error("VLESS ECH requires TLS 1.3");
        if (result.fingerprint==TlsFingerprint::tls12 &&
            (result.reality || result.vision || result.record_size_limit || result.key_exchange!=TlsKeyExchange::x25519))
            return error("VLESS TLS 1.2 requires ordinary TLS, X25519 and the default record size");
        if ((result.transport || result.grpc) && (result.vision || result.reality)) return error("HTTPUpgrade/gRPC requires ordinary VLESS TLS");
        if ((result.packetaddr || result.fixed_udp) && (result.vision || result.grpc))
            return error("VLESS packetaddr and fixed UDP require non-Vision TCP or HTTPUpgrade");
        if (result.multiplex && result.multiplex->enabled && (result.vision || result.xhttp))
            return error("VLESS multiplex cannot be combined with vision or xhttp");
        if (fast_open) {
            if (result.detour) return error("tcp-fast-open belongs to the physical outbound, not a layered node");
            result.tcp_fast_open=*fast_open;
            if (result.grpc) result.grpc->tcp_fast_open=*fast_open;
        }
        return result;
    }
}
