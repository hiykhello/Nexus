import std;
import config;

namespace {
    auto document(std::string_view incoming,std::string_view outgoing,std::string_view inbound_extra={},std::string_view outbound_extra={}) {
        return config::parse_kdl(std::format(R"(schema-version 1
role "server"
inbounds {{ vless "edge-in" {{
 listen host="127.0.0.1" port=8443;
 authentication {{ user "alice" uuid-file="/tmp/uuid"; }}
 tls {{ certificate-file "/tmp/cert"; private-key-file "/tmp/key"; }}
 {} {}
}} }}
outbound "direct" type="direct"
outbound "edge" type="vless" {{
 server host="remote.test" port=443;
 authentication {{ uuid-file "/tmp/uuid"; }}
 tls {{ server-name "remote.test"; ca-file "/tmp/ca"; verify #true; }}
 {} {}
}}
routing {{ default-outbound "edge"; }}
)",incoming,inbound_extra,outgoing,outbound_extra));
    }
}
auto main() -> int {
    auto parsed=document(R"(transport "httpupgrade" { path "/nexus upgrade"; header "X-Response" "ready"; })",
        R"(transport "httpupgrade" { host "cover.example:443"; path "/nexus%20upgrade?x=1"; header "X-Request" "ready"; })");
    if (!parsed) { std::cerr<<parsed.error()<<'\n'; return 1; }
    auto const& input=parsed->inbounds[0].vless->transport;
    auto const& output=parsed->vless_outbounds[0].config.transport;
    if (!input || !output || !input->host.empty() || input->path!="/nexus upgrade" || input->headers.size()!=1 ||
        input->headers[0].name!="X-Response" || output->host!="cover.example:443" || output->path!="/nexus%20upgrade?x=1" ||
        output->headers.size()!=1 || output->headers[0].value!="ready") return 2;
    auto defaults=document("transport \"httpupgrade\";","transport \"httpupgrade\";");
    if (!defaults || defaults->vless_outbounds[0].config.transport->path!="/" ||
        !defaults->vless_outbounds[0].config.transport->host.empty() || defaults->inbounds[0].vless->transport->path!="/") return 3;
    for (auto bad:{R"(transport "unsupported")",R"(transport "httpupgrade" unknown=1)",
        R"(transport "httpupgrade" { unknown "x"; })",R"(transport "httpupgrade" { host "a"; host "b"; })",
        R"(transport "httpupgrade" { path "relative"; })",R"(transport "httpupgrade" { path "/a"; path "/b"; })",
        R"(transport "httpupgrade" { host "bad\r\nInjected: x"; })",R"(transport "httpupgrade" { header "" "x"; })",
        R"(transport "httpupgrade" { header "Name"; })",R"(transport "httpupgrade" { header "Name" "bad\nvalue"; })",
        R"(transport "httpupgrade"; transport "httpupgrade";)"}) {
        if (document(bad,{}) || document({},bad)) { std::cerr<<"accepted invalid Upgrade field: "<<bad<<'\n'; return 4; }
    }
    if (document("transport \"httpupgrade\";",{},"flow \"xtls-rprx-vision\";") ||
        document({},"transport \"httpupgrade\";",{},"flow \"xtls-rprx-vision\";")) return 5;
    std::string headers="transport \"httpupgrade\" {\n";
    for (unsigned i=0;i<65;++i) headers+="header \"X-Test\" \"value\";\n";
    headers+='}';
    if (document(headers,{}) || document({},headers)) return 6;
    // WebSocket Early Data (max-early-data, early-data-header-name, ?ed=<N>)
    auto ws_ed=document(
        R"(transport "websocket" { path "/ws"; max-early-data 2048; early-data-header-name "Sec-WebSocket-Protocol"; })",
        R"(transport "websocket" { host "ws.example"; path "/ws?ed=4096"; })");
    if (!ws_ed) { std::cerr<<ws_ed.error()<<'\n'; return 7; }
    auto const& ws_in=ws_ed->inbounds[0].vless->transport;
    auto const& ws_out=ws_ed->vless_outbounds[0].config.transport;
    if (!ws_in || !ws_out || !ws_in->websocket || !ws_out->websocket ||
        ws_in->max_early_data!=2048 || ws_in->early_data_header_name!="Sec-WebSocket-Protocol" ||
        ws_out->path!="/ws" || ws_out->max_early_data!=4096 || !ws_out->early_data_header_name.empty()) return 8;
    auto ws_ed_q=document(
        R"(transport "websocket" { path "/ws?foo=1&ed=1024&bar=2"; })",
        R"(transport "websocket" { path "/ws?ed=8192"; early-data-header-name "X-Early-Data"; })");
    if (!ws_ed_q || ws_ed_q->inbounds[0].vless->transport->path!="/ws?foo=1&bar=2" ||
        ws_ed_q->inbounds[0].vless->transport->max_early_data!=1024 ||
        ws_ed_q->vless_outbounds[0].config.transport->path!="/ws" ||
        ws_ed_q->vless_outbounds[0].config.transport->max_early_data!=8192 ||
        ws_ed_q->vless_outbounds[0].config.transport->early_data_header_name!="X-Early-Data") return 9;
    for (auto bad:{
        R"(transport "httpupgrade" { max-early-data 2048; })",
        R"(transport "httpupgrade" { early-data-header-name "Sec-WebSocket-Protocol"; })",
        R"(transport "websocket" { max-early-data 8193; })",
        R"(transport "websocket" { max-early-data -1; })",
        R"(transport "websocket" { max-early-data 1024; max-early-data 2048; })",
        R"(transport "websocket" { early-data-header-name "Host"; })",
        R"(transport "websocket" { early-data-header-name "Sec-WebSocket-Key"; })",
        R"(transport "websocket" { path "/ws?ed=9000"; })",
        R"(transport "websocket" { path "/ws?ed=abc"; })",
        R"(transport "websocket" { path "/ws?ed=1&ed=2"; })"}) {
        if (document(bad,{}) || document({},bad)) { std::cerr<<"accepted invalid WS early-data field: "<<bad<<'\n'; return 10; }
    }
    std::println("VLESS HTTPUpgrade/WebSocket owned configuration, early-data fields, ?ed=, bounds and rejection passed");
}
