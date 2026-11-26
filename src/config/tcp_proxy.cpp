module config;
import std;
import config.kdl_common;
import glaze;

namespace config {
    auto parse_tcp_dial_option(kdl::Node const&,TcpSocketOptions&) -> std::expected<bool,std::string>;
    auto parse_quic_ech_field(kdl::Node const&,QuicEchOptions&) -> bool;

    namespace {
        auto parse_http_proxy_tls(kdl::Node const& node) -> std::optional<TcpProxyTls> {
            using namespace kdl;
            if (node.tag || !node.arguments.empty() || !node.properties.empty() || node.children.empty())
                return std::nullopt;
            TcpProxyTls result;
            bool verified=false,fp_seen=false;
            for (auto const& field:node.children) {
                auto value=scalar(field);
                if (field.name=="server-name" && result.server_name.empty() && value && endpoint_name(*value))
                    result.server_name=*value;
                else if (field.name=="ca-file" && result.ca_file.empty() && value && absolute_path(*value))
                    result.ca_file=*value;
                else if (field.name=="certificate-sha256") {
                    if (!parse_certificate_sha256(field,result.certificate_sha256)) return std::nullopt;
                }
                else if (field.name=="fingerprint" && !fp_seen && value) {
                    auto fp=parse_tls_fingerprint(*value);
                    if (!fp) return std::nullopt;
                    result.fingerprint=*fp;
                    fp_seen=true;
                }
                else if (field.name=="verify" && boolean(field).value_or(false))
                    verified=true;
                else if (!parse_quic_ech_field(field,result.ech)) return std::nullopt;
            }
            if (!verified || result.server_name.empty()) return std::nullopt;
            return result;
        }
    }

    auto parse_tcp_proxy_outbound(kdl::Node const& node,TcpProxyProtocol protocol)
        -> std::expected<TcpProxyOutbound,std::string> {
        using namespace kdl;
        TcpProxyOutbound result;
        result.protocol=protocol;
        bool timeout_seen=false,authentication_seen=false,udp_seen=false,ver_seen=false,max_seen=false,hs_seen=false,idle_seen=false,mem_seen=false;
        for (auto const& child:node.children) {
            if (child.name=="server") {
                auto host=text_property(child,"host");
                auto port=property(child,"port");
                auto number=port ? integer(*port) : std::nullopt;
                if (result.port || child.tag || !child.arguments.empty() || !child.children.empty() ||
                    child.properties.size()!=2 || !host || !endpoint_name(*host) || !number || !*number || *number>65535)
                    return error("invalid TCP proxy outbound server");
                result.host=*host;
                result.port=static_cast<std::uint16_t>(*number);
            } else if (child.name=="http-version" && protocol==TcpProxyProtocol::http_connect) {
                auto v=scalar(child);
                if (std::exchange(ver_seen,true) || !v) return error("invalid HTTP proxy http-version");
                if (*v=="h1" || *v=="http/1.1" || *v=="1.1") result.http_version=HttpProxyVersion::h1;
                else if (*v=="auto") result.http_version=HttpProxyVersion::auto_h2;
                else if (*v=="h2" || *v=="http/2") result.http_version=HttpProxyVersion::h2;
                else if (*v=="h3" || *v=="http/3") result.http_version=HttpProxyVersion::h3;
                else return error("HTTP proxy http-version must be h1, auto, h2 or h3");
            } else if (child.name=="max-sessions" && protocol==TcpProxyProtocol::http_connect) {
                auto v=integer(child);
                if (std::exchange(max_seen,true) || !v || *v<1 || *v>64) return error("HTTP proxy max-sessions must be 1..64");
                result.max_sessions=static_cast<std::size_t>(*v);
            } else if (child.name=="handshake-timeout-ms" && protocol==TcpProxyProtocol::http_connect) {
                auto v=integer(child);
                if (std::exchange(hs_seen,true) || !v || !*v || *v>3600000) return error("invalid HTTP proxy handshake-timeout-ms");
                result.handshake_timeout_ms=static_cast<std::uint32_t>(*v);
            } else if (child.name=="idle-timeout-ms" && protocol==TcpProxyProtocol::http_connect) {
                auto v=integer(child);
                if (std::exchange(idle_seen,true) || !v || !*v || *v>86400000) return error("invalid HTTP proxy idle-timeout-ms");
                result.idle_timeout_ms=static_cast<std::uint32_t>(*v);
            } else if (child.name=="native-bytes" && protocol==TcpProxyProtocol::http_connect) {
                auto v=integer(child);
                if (std::exchange(mem_seen,true) || !v || *v<65536 || *v>1024ull*1024*1024) return error("invalid HTTP proxy native-bytes");
                result.native_bytes=static_cast<std::size_t>(*v);
            } else if (child.name=="userid") {
                auto uid=scalar(child);
                if ((protocol!=TcpProxyProtocol::socks4 && protocol!=TcpProxyProtocol::socks4a) ||
                    authentication_seen || !uid || uid->size()>255 || uid->contains('\0'))
                    return error("SOCKS4/4a userid requires a string up to 255 bytes");
                result.username=*uid;
                authentication_seen=true;
            } else if (child.name=="authentication") {
                if (protocol==TcpProxyProtocol::socks4 || protocol==TcpProxyProtocol::socks4a)
                    return error("SOCKS4/4a does not support password authentication; use userid");
                auto username=text_property(child,"username");
                auto password=text_property(child,"password-file");
                if (authentication_seen || child.tag || !child.arguments.empty() || !child.children.empty() ||
                    child.properties.size()!=2 || !username || username->empty() || username->size()>255 ||
                    std::ranges::any_of(*username,[](unsigned char c) {return c<32 || c==127;}) ||
                    (protocol==TcpProxyProtocol::http_connect && username->contains(':')) ||
                    !password || !absolute_path(*password))
                    return error("TCP proxy authentication requires a valid username and absolute password-file");
                result.username=*username;
                result.password_file=*password;
                authentication_seen=true;
            } else if (child.name=="connect-timeout-ms") {
                auto timeout=connect_timeout(child);
                if (timeout_seen || !timeout) return error("invalid TCP proxy outbound connect timeout");
                result.connect_timeout_ms=*timeout;
                timeout_seen=true;
            } else if (child.name=="detour" || child.name=="bootstrap-resolver" || child.name=="domain-resolver") {
                auto& dependency=child.name=="detour" ? result.detour : result.bootstrap_resolver;
                auto name=scalar(child);
                if (dependency || !name || !valid_name(*name)) return error("invalid TCP proxy outbound dependency");
                dependency=*name;
            } else if (child.name=="tls") {
                if (protocol!=TcpProxyProtocol::http_connect || result.tls)
                    return error("TLS is supported once on an HTTP CONNECT outbound");
                result.tls=parse_http_proxy_tls(child);
                if (!result.tls) return error("HTTP CONNECT requires authenticated TLS");
            } else if (child.name=="udp") {
                auto enabled=boolean(child);
                if ((protocol!=TcpProxyProtocol::socks5 && protocol!=TcpProxyProtocol::http_connect) || udp_seen || !enabled)
                    return error("SOCKS5/HTTP3 outbound udp requires one boolean");
                result.udp=*enabled;
                udp_seen=true;
            } else if (child.name=="tcp-fast-open") {
                auto enabled=boolean(child);
                if (result.tcp_options.tcp_fast_open || !enabled) return error("invalid TCP proxy outbound tcp-fast-open");
                result.tcp_options.tcp_fast_open=*enabled;
            } else {
                auto option=parse_tcp_dial_option(child,result.tcp_options);
                if (!option) return std::unexpected(option.error());
                if (!*option) return error("unsupported TCP proxy outbound field: "+child.name);
            }
        }
        if (!result.port) return error("TCP proxy outbound requires a server");
        if (result.tls && (result.tls->ech.dns || !result.tls->ech.config_file.empty()) &&
            result.tls->fingerprint==TlsFingerprint::tls12)
            return error("HTTP CONNECT ECH requires TLS 1.3");
        if (result.http_version!=HttpProxyVersion::h1 && !result.tls)
            return error("HTTP/2 and HTTP/3 proxy outbounds require TLS");
        if (protocol==TcpProxyProtocol::http_connect && result.udp && result.http_version!=HttpProxyVersion::h3)
            return error("HTTP CONNECT UDP requires http-version \"h3\"");
        if (result.http_version==HttpProxyVersion::h3) {
            if (result.tls && result.tls->fingerprint==TlsFingerprint::tls12)
                return error("HTTP/3 proxy cannot use tls12 fingerprint");
            if (result.tcp_options.tcp_fast_open.value_or(false) || result.tcp_options.tcp_configured())
                return error("TCP-only dial options are not valid for HTTP/3");
        }
        return result;
    }
}
