import std;
import config;
auto parse(std::string_view fields,bool inbound=false) {
    auto config=std::format(R"(schema-version 1
role "server"
inbounds {{ socks5 "s" {{listen host="127.0.0.1" port=1080;authentication "none";}} }}
outbound "direct" type="direct"
outbound "v" type="vless" {{server host="127.0.0.1" port=443; authentication {{uuid-file "/tmp/u";}}; tls {{server-name "localhost";ca-file "/tmp/c";verify #true;}}; {} }}
routing {{default-outbound "v";}}
)",fields);
    if (inbound) config=std::format(R"(schema-version 1
role "server"
inbound "v" type="vless" {{listen host="127.0.0.1" port=1080;authentication {{user "u" uuid-file="/tmp/u";}};tls {{certificate-file "/tmp/c";private-key-file "/tmp/k";}};{} }}
outbound "direct" type="direct"
routing {{default-outbound "direct";}}
)",fields);
    return config::parse_kdl(config);
}
auto main() -> int {
    auto out=parse(R"(bind-interface "lo"; inet4-bind-address "127.0.0.2"; tcp-keepalive #false; transport "grpc" {service-name "nexus.Service"; authority "localhost"; response-policy "sing-box-lite"; input-window 4096; message-bytes 2052; hunk-bytes 2048; output-bytes 8192; output-messages 4; library-bytes 1048576; max-sessions 2;};)");
    if (!out || !out->vless_outbounds.front().config.grpc) {if (!out) std::println("{}",out.error());return 1;}
    auto const& options=out->vless_outbounds.front().config.tcp_options;
    if (options.binding.interface_name()!="lo" || !options.binding.inet4_bind_address || (*options.binding.inet4_bind_address)[3]!=2 || options.keepalive!=false) return 4;
    auto const& g=*out->vless_outbounds.front().config.grpc;
    if (g.service_name!="nexus.Service" || g.authority!="localhost" || g.max_sessions!=2 || g.hunk_bytes!=2048 ||
        g.response_policy!=config::GrpcTransport::ResponsePolicy::sing_box_lite) return 2;
    for (auto flag:{"#true","#false"}) {
        auto fast=parse(std::string("tcp-fast-open ")+flag+"; transport \"grpc\";");
        if (!fast || fast->vless_outbounds.front().config.grpc->tcp_fast_open!=(std::string_view(flag)=="#true")) return 7;
        auto plain=parse(std::string("tcp-fast-open ")+flag+";");
        if (!plain || plain->vless_outbounds.front().config.tcp_fast_open!=(std::string_view(flag)=="#true")) return 7;
    }
    for (auto bad:{"tcp-fast-open 1; transport \"grpc\";",
                   "tcp-fast-open #true; tcp-fast-open #false; transport \"grpc\";",
                   "tcp-fast-open #true; detour \"direct\"; transport \"grpc\";"}) if (parse(bad)) return 8;
    for (auto bad:{R"(transport "grpc" {authority "x"; authority "x";};)",R"(transport "grpc" {service-name "a/b";};)",
        R"(transport "grpc" {response-policy "auto";};)",R"(transport "grpc" {hunk-bytes 0;};)",R"(transport "grpc" {hunk-bytes -1;};)",
        R"(transport "grpc" {max-sessions 257;};)",R"(transport "grpc" {library-bytes #true;};)",
        R"(transport "grpc" {input-window 1024;};)",R"(transport "grpc" {authority "a/b";};)",
        R"(transport "grpc"; transport "httpupgrade" {path "/";};)",R"(flow "xtls-rprx-vision"; transport "grpc";)",
        R"(transport "grpc" {unknown 1;};)",R"cfg(transport "grpc" {authority (x)"x";};)cfg"}) {
        if (parse(bad)) {std::println("accepted {}",bad);return 3;}
    }
    auto incoming=parse(R"(transport "grpc" {service-name "nexus.Service";authority "localhost";idle-timeout-ms 15000;ping-timeout-ms 5000;permit-without-stream #true;};)",true);
    if (!incoming || incoming->inbounds.empty() || !incoming->inbounds.front().vless || !incoming->inbounds.front().vless->grpc) return 5;
    auto const& ig=*incoming->inbounds.front().vless->grpc;
    if (ig.idle_timeout_ms!=15000 || ig.ping_timeout_ms!=5000 || !ig.permit_without_stream) return 9;
    auto out_ka=parse(R"(transport "grpc" {service-name "nexus.Service";authority "localhost";idle-timeout-ms 30000;ping-timeout-ms 10000;permit-without-stream #false;input-window 4096;message-bytes 2052;hunk-bytes 2048;output-bytes 8192;output-messages 4;library-bytes 1048576;max-sessions 2;};)");
    if (!out_ka || !out_ka->vless_outbounds.front().config.grpc) return 10;
    auto const& og=*out_ka->vless_outbounds.front().config.grpc;
    if (og.idle_timeout_ms!=30000 || og.ping_timeout_ms!=10000 || og.permit_without_stream) return 11;
    for (auto bad:{R"(transport "grpc";)",R"(transport "grpc" {authority "localhost";response-policy "standard";};)",
        R"(transport "grpc" {authority "localhost";max-sessions 1;};)",R"(transport "grpc" {authority "localhost";};transport "httpupgrade";)",
        R"(flow "xtls-rprx-vision"; transport "grpc" {authority "localhost";};)",
        R"(transport "grpc" {authority "localhost";idle-timeout-ms -1;};)",
        R"(transport "grpc" {authority "localhost";ping-timeout-ms 3600001;};)",
        R"(transport "grpc" {authority "localhost";permit-without-stream 1;};)"}) if (parse(bad,true)) return 6;
    std::println("gRPC configuration profile, keepalive PING fields, physical dial inheritance, limits, malformed/duplicate/unsupported fields and mutually exclusive Vision/Upgrade passed");
}
