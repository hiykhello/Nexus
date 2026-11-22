module config;
import std;
import nexus.thirdparty.glaze;
import config.kdl_common;

namespace config {
    auto parse_password_tls_inbound(nex::glaze::KdlNode const&,std::string_view,Inbound,std::string_view) -> std::expected<InboundConfig,std::string>;
    auto parse_password_tls_outbound(nex::glaze::KdlNode const&,std::string_view,std::string_view) -> std::expected<PasswordTlsOutbound,std::string>;
    auto validate_quic_ech(QuicEchOptions const&, std::string_view, bool) -> std::expected<void, std::string>;
    auto validate_password_tls_outbound(PasswordTlsOutbound&,Config const&,std::string_view) -> std::expected<void,std::string>;
    namespace {
        auto parse_quic_options(nex::glaze::KdlNode const& node,bool inbound) -> std::expected<Hysteria2Transport,std::string> {
            Hysteria2Transport result;bool block=false;std::array<bool,11> fields{};
            constexpr std::array<std::pair<std::string_view,std::size_t quic::ReceiveWindows::*>,4> windows{{
                {"init-stream-receive-window",&quic::ReceiveWindows::initial_stream},
                {"max-stream-receive-window",&quic::ReceiveWindows::max_stream},
                {"init-conn-receive-window",&quic::ReceiveWindows::initial_connection},
                {"max-conn-receive-window",&quic::ReceiveWindows::max_connection}
            }};
            for(auto const& child:node.children){
                if(child.name!="quic")continue;
                if(block || child.tag || !child.arguments.empty() || !child.properties.empty())return kdl::error("invalid or duplicate Hysteria2 quic block");
                block=true;
                for(auto const& field:child.children){
                    auto window=std::ranges::find(windows,field.name,[](auto const& entry) {return entry.first;});
                    if (window!=windows.end()) {
                        auto value=kdl::integer(field);
                        auto& slot=result.receive_windows.*(window->second);
                        if (slot || !value || *value<quic::ReceiveWindows::minimum || *value>quic::ReceiveWindows::maximum)
                            return kdl::error("invalid or duplicate Hysteria2 receive window: "+field.name);
                        slot=static_cast<std::size_t>(*value);
                        continue;
                    }
                    if(field.name=="salamander-password-file"){
                        auto path=kdl::scalar(field);
                        if(result.salamander_password_file || !path || !kdl::absolute_path(*path))
                            return kdl::error("invalid or duplicate Hysteria2 salamander password file");
                        result.salamander_password_file=*path;continue;
                    }
                    if(field.name=="udp"){
                        auto value=kdl::boolean(field);if(fields[0] || !value)return kdl::error("invalid or duplicate Hysteria2 UDP option");
                        fields[0]=true;result.udp=*value;continue;
                    }
                    if(field.name=="ignore-client-bandwidth" || field.name=="disable-loss-compensation") {
                        if(!inbound && field.name=="ignore-client-bandwidth")return kdl::error("Hysteria2 ignore-client-bandwidth is inbound only");
                        auto index=field.name=="ignore-client-bandwidth" ? 8u : 9u;
                        auto value=kdl::boolean(field);if(fields[index] || !value)return kdl::error("invalid or duplicate Hysteria2 congestion option");
                        fields[index]=true;
                        if(index==8)result.ignore_client_bandwidth=*value;else result.disable_compensation=*value;
                        continue;
                    }
                    if(field.name=="ports") {
                        if(inbound)return kdl::error("Hysteria2 ports hopping is outbound only");
                        auto spec=kdl::scalar(field);
                        if(!result.port_ranges.empty() || !spec || spec->empty() || spec->size()>512)
                            return kdl::error("invalid or duplicate Hysteria2 ports");
                        std::string_view rest(*spec);
                        while(!rest.empty()) {
                            auto comma=rest.find(',');
                            auto part=rest.substr(0,comma);
                            auto dash=part.find('-');
                            auto parse_p=[](std::string_view s)->std::optional<std::uint16_t>{
                                std::uint16_t p=0;auto [e,ec]=std::from_chars(s.data(),s.data()+s.size(),p);
                                return (!s.empty()&&ec==std::errc{}&&e==s.data()+s.size()&&p)?std::optional(p):std::nullopt;
                            };
                            std::optional<std::uint16_t> lo,hi;
                            if(dash==std::string_view::npos){lo=hi=parse_p(part);}
                            else {lo=parse_p(part.substr(0,dash));hi=parse_p(part.substr(dash+1));}
                            if(!lo||!hi||*lo>*hi||result.port_ranges.size()>=32)return kdl::error("invalid Hysteria2 port range");
                            result.port_ranges.push_back({*lo,*hi});
                            if(comma==std::string_view::npos)break;
                            rest.remove_prefix(comma+1);
                        }
                        continue;
                    }
                    if(field.name=="hop-interval-ms") {
                        if(inbound)return kdl::error("Hysteria2 hop-interval-ms is outbound only");
                        auto value=kdl::integer(field);
                        if(result.hop_interval_ms || !value || *value<500 || *value>86400000)
                            return kdl::error("Hysteria2 hop-interval-ms must be 500..86400000");
                        result.hop_interval_ms=static_cast<std::uint32_t>(*value);continue;
                    }
                    if(field.name=="lazy-tcp-response") {
                        if(inbound)return kdl::error("Hysteria2 lazy-tcp-response is outbound only");
                        auto value=kdl::boolean(field);
                        if(fields[10] || !value)return kdl::error("invalid or duplicate Hysteria2 lazy TCP response option");
                        fields[10]=true;result.lazy_tcp_response=*value;continue;
                    }
                    if(field.name=="send-bps" || field.name=="receive-bps") {
                        auto index=field.name=="send-bps" ? 6u : 7u;
                        auto value=kdl::integer(field);if(fields[index] || !value || *value>1000000000000ull)return kdl::error("invalid or duplicate Hysteria2 bandwidth");
                        fields[index]=true;
                        if(index==6)result.send_bps=*value;else result.receive_bps=*value;
                        continue;
                    }
                    if(field.name=="disable-path-mtu-discovery") {
                        auto value=kdl::boolean(field);if(fields[4] || !value)return kdl::error("invalid or duplicate Hysteria2 path MTU discovery option");
                        fields[4]=true;result.disable_path_mtu_discovery=*value;continue;
                    }
                    std::size_t index=field.name=="handshake-timeout-ms" ? 1 : field.name=="idle-timeout-ms" ? 2 : field.name=="native-bytes" ? 3 : field.name=="max-udp-payload-size" ? 5 : 6;
                    if(index==6)return kdl::error("unsupported Hysteria2 quic field: "+field.name);
                    auto value=kdl::integer(field);
                    if(fields[index] || !value || !*value || (index==1 && *value>3600000) || (index==2 && *value>86400000) ||
                        (index==3 && (*value<65536 || *value>1024ull*1024*1024)) || (index==5 && (*value<1200 || *value>1500)))return kdl::error("invalid or duplicate Hysteria2 quic field");
                    fields[index]=true;
                    if(index==1)result.handshake_timeout_ms=static_cast<std::uint32_t>(*value);
                    else if(index==2)result.idle_timeout_ms=static_cast<std::uint32_t>(*value);
                    else if(index==3)result.native_bytes=static_cast<std::size_t>(*value);
                    else result.max_udp_payload_size=static_cast<std::size_t>(*value);
                }
            }
            if(result.hop_interval_ms && result.port_ranges.empty())
                return kdl::error("Hysteria2 hop-interval-ms requires ports");
            if(!result.port_ranges.empty() && !result.hop_interval_ms)
                result.hop_interval_ms=30000;
            if(result.salamander_password_file && result.max_udp_payload_size && *result.max_udp_payload_size<1208)
                return kdl::error("Hysteria2 Salamander requires a UDP payload size of at least 1208");
            if (!result.receive_windows.valid(result.native_bytes))
                return kdl::error("Hysteria2 receive windows require all four fields, ordered limits and native-bytes headroom");
            return result;
        }
    }
    auto parse_hysteria2_inbound(nex::glaze::KdlNode const& node) -> std::expected<InboundConfig,std::string> {
        auto parsed=parse_password_tls_inbound(node,"hysteria2",Inbound::hysteria2,"quic");if(!parsed)return std::unexpected(parsed.error());
        auto options=parse_quic_options(node,true);if(!options)return std::unexpected(options.error());
        parsed->hysteria2->transport=*options;return parsed;
    }
    auto parse_hysteria2_outbound(nex::glaze::KdlNode const& node) -> std::expected<Hysteria2Outbound,std::string> {
        auto parsed=parse_password_tls_outbound(node,"Hysteria2","quic");if(!parsed)return std::unexpected(parsed.error());
        // Socket binding fields are shared with the existing dial schema.
        // TCP-only settings have no meaning on a physical QUIC UDP socket.
        if(parsed->tcp_options.tcp_configured())return kdl::error("TCP-only dial options are not valid for Hysteria2");
        auto options=parse_quic_options(node,false);if(!options)return std::unexpected(options.error());
        return Hysteria2Outbound{std::move(*parsed),*options};
    }
    auto validate_hysteria2(Config& config,std::string_view direct,std::optional<std::string> const& block) -> std::expected<void,std::string> {
        for(std::size_t i=0;i<config.hysteria2_outbounds.size();++i){
            auto& entry=config.hysteria2_outbounds[i];
            if(entry.name==direct || (block && entry.name==*block) ||
                std::ranges::any_of(config.vless_outbounds,[&](auto const& other){return other.name==entry.name;}) ||
                std::ranges::any_of(config.shadowsocks_outbounds,[&](auto const& other){return other.name==entry.name;}) ||
                std::ranges::any_of(config.trojan_outbounds,[&](auto const& other){return other.name==entry.name;}) ||
                std::ranges::any_of(config.anytls_outbounds,[&](auto const& other){return other.name==entry.name;}) ||
                std::ranges::any_of(std::span(config.hysteria2_outbounds).first(i),[&](auto const& other){return other.name==entry.name;}))return kdl::error("outbound names must be unique");
            if(auto valid=validate_password_tls_outbound(entry.config.connection,config,"Hysteria2");!valid)return valid;
            auto const& tls = entry.config.connection;
            if (auto valid = validate_quic_ech(tls.ech, tls.server_name, config.dns.has_value()); !valid) return valid;
            if(entry.config.connection.detour && *entry.config.connection.detour!=direct) {
                auto const& name=*entry.config.connection.detour;
                auto ss=std::ranges::find(config.shadowsocks_outbounds,name,&NamedShadowsocksOutbound::name);
                if(ss!=config.shadowsocks_outbounds.end() && !ss->config.udp_over_tcp && !ss->config.udp_native)
                    return kdl::error("Hysteria2 detour requires a Shadowsocks datagram transport");
                auto hy2=std::ranges::find(config.hysteria2_outbounds,name,&NamedHysteria2Outbound::name);
                if(hy2!=config.hysteria2_outbounds.end() && !hy2->config.transport.udp)
                    return kdl::error("Hysteria2 detour requires UDP on the lower Hysteria2 outbound");
            }
        }
        return {};
    }
}
