import std;
import config;

namespace {
    auto parse(std::string_view protocol,std::string_view fields,std::string_view extra={}) {
        auto options=protocol=="direct" ? "" : protocol=="vless" ?
            R"(server host="127.0.0.1" port=443; authentication { uuid-file "/uuid"; }; tls { server-name "cover.example"; ca-file "/ca"; verify #true; };)" :
            protocol=="shadowsocks" ? R"(server host="127.0.0.1" port=443; method "2022-blake3-aes-128-gcm"; key-file "/key";)" :
            R"(server host="127.0.0.1" port=443; authentication { password-file "/password"; }; tls { server-name "cover.example"; ca-file "/ca"; verify #true; };)";
        auto direct=protocol=="direct" || extra.find("outbound \"direct\"")!=extra.npos ? "" : "outbound \"direct\" type=\"direct\"\n";
        return config::parse_kdl(std::format(R"(schema-version 1
role "client"
inbound "in" type="socks5" {{ listen host="127.0.0.1" port=1080; authentication "none"; }}
outbound "{}" type="{}" {{ {} {} }}
{}
{}
routing {{ default-outbound "{}"; }}
)",protocol=="direct" ? "direct" : "node",protocol,options,fields,direct,extra,protocol=="direct" ? "direct" : "node"));
    }
    auto options(config::Config const& config,std::string_view protocol) -> config::TcpSocketOptions const& {
        if (protocol=="direct") return config.direct_tcp_options;
        if (protocol=="vless") return config.vless_outbounds[0].config.tcp_options;
        if (protocol=="shadowsocks") return config.shadowsocks_outbounds[0].config.tcp_options;
        if (protocol=="trojan") return config.trojan_outbounds[0].config.tcp_options;
        return config.anytls_outbounds[0].config.connection.tcp_options;
    }
}

auto main() -> int {
    for (auto flag:{"#true","#false"}) {
        auto direct=parse("direct",std::string("tcp-fast-open ")+flag+";");
        if(!direct || direct->direct_tcp_options.tcp_fast_open!=(std::string_view(flag)=="#true"))return 34;
    }
    for (auto invalid:{"tcp-fast-open 1;", "tcp-fast-open #true; tcp-fast-open #false;"})
        if(parse("direct",invalid))return 35;
    for (auto protocol:{"direct","shadowsocks","vless","trojan","anytls"}) {
        auto defaults=parse(protocol,"");
        if (!defaults || options(*defaults,protocol).configured()) return 1;
        auto enabled=parse(protocol,"tcp-keepalive #true; tcp-keepalive-idle-seconds 17; tcp-keepalive-interval-seconds 3; tcp-keepalive-count 5;");
        if (!enabled) return 2;
        auto const& tcp=options(*enabled,protocol);
        if (!tcp.keepalive || !*tcp.keepalive || tcp.keepalive_idle_seconds!=17 || tcp.keepalive_interval_seconds!=3 || tcp.keepalive_count!=5) return 3;
        auto implicit=parse(protocol,"tcp-keepalive-count 127; tcp-keepalive-idle-seconds 32767; tcp-keepalive-interval-seconds 32767;");
        if (!implicit || !options(*implicit,protocol).valid() || options(*implicit,protocol).keepalive) return 4;
        auto disabled=parse(protocol,"tcp-keepalive #false;");
        if (!disabled || options(*disabled,protocol).keepalive!=false) return 5;
        for (auto port:{0U,1U,65535U}) {
            auto bound_port=parse(protocol,std::format("udp-bind-port {};",port));
            if (!bound_port || options(*bound_port,protocol).binding.udp_bind_port!=port) return 32;
        }
        for (auto invalid:{"udp-bind-port -1;", "udp-bind-port 65536;", "udp-bind-port 1.0;",
            "udp-bind-port #true;", "udp-bind-port 0; udp-bind-port 0;", "udp-bind-port 1 x=1;"})
            if (parse(protocol,invalid)) return 33;
        auto multipath=parse(protocol,"multipath-tcp #true;");
        if(!multipath || options(*multipath,protocol).multipath_tcp!=true) return 30;
        if(parse(protocol,"multipath-tcp #true; multipath-tcp #false;") || parse(protocol,"multipath-tcp 1;")) return 31;
        for (auto invalid:{"tcp-keepalive #false; tcp-keepalive #false;", "tcp-keepalive #true; tcp-keepalive #true;",
            "tcp-keepalive 1;", "tcp-keepalive \"false\";", "tcp-keepalive #true x=1;", "tcp-keepalive #true { x; };",
            "tcp-keepalive-idle-seconds 0;", "tcp-keepalive-idle-seconds 32768;", "tcp-keepalive-interval-seconds -1;",
            "tcp-keepalive-interval-seconds 32768;", "tcp-keepalive-count 128;", "tcp-keepalive-count 0;",
            "tcp-keepalive-count 1; tcp-keepalive-count 1;", "tcp-keepalive-count 2.0;", "tcp-keepalive-count (x)2;",
            "tcp-keepalive #false; tcp-keepalive-idle-seconds 1;", "tcp-keepalive-count 1; tcp-keepalive #false;"})
            if (parse(protocol,invalid)) return 6;
        auto bound=parse(protocol,R"(bind-interface "lo"; inet4-bind-address "127.0.0.2"; inet6-bind-address "::1"; bind-address-no-port #true; routing-mark 4294967295; reuse-addr #true; udp-fragment #true; tcp-keepalive #false;)" );
        if (!bound) { std::cerr<<bound.error()<<'\n';return 10; }
        auto const& physical=options(*bound,protocol);
        std::array<std::uint8_t,16> loopback6{};loopback6[15]=1;
        if (physical.binding.interface_name()!="lo" || physical.binding.inet4_bind_address!=std::array<std::uint8_t,4>{127,0,0,2} ||
            physical.binding.inet6_bind_address!=loopback6 || physical.binding.routing_mark!=4294967295U || physical.binding.reuse_addr!=true || physical.binding.udp_fragment!=true ||
            physical.bind_address_no_port!=true || physical.keepalive!=false || !physical.valid()) return 11;
        for (auto valid:{R"(routing-mark 0;)",R"(routing-mark 0x4201;)",R"(reuse-addr #false;)",R"(bind-address-no-port #false;)",
            R"(udp-fragment #true;)",R"(udp-fragment #false;)",R"(inet4-bind-address "0.0.0.0";)",R"(inet6-bind-address "::";)"}) {
            auto value=parse(protocol,valid);if (!value || !options(*value,protocol).configured()) return 12;
        }
        for (auto invalid:{R"(bind-interface "";)",R"(bind-interface "abcdefghijklmnop";)",R"(bind-interface "lo 1";)",R"(bind-interface "lo:x";)",
            R"(bind-interface ".";)",R"(bind-interface "..";)",R"(bind-interface "a/b";)",R"(bind-interface "lo"; bind-interface "lo";)",
            R"(bind-interface #true;)",R"(bind-interface "lo" flag=1;)",R"(bind-interface "lo" { x; };)",
            R"(inet4-bind-address "::1";)",R"(inet6-bind-address "127.0.0.1";)",R"(inet4-bind-address "127.1";)",
            R"(inet4-bind-address "127.00.0.1";)",R"(inet4-bind-address "256.0.0.1";)",R"(inet4-bind-address "127.0.0.1:0";)",
            R"(inet4-bind-address "127.0.0.1/32";)",R"(inet6-bind-address "[::1]";)",R"(inet6-bind-address "[::1]:0";)",
            R"(inet6-bind-address "fe80::1%lo";)",R"(inet6-bind-address "::ffff:127.0.0.1";)",R"(inet6-bind-address "a.test";)",
            R"(inet4-bind-address "127.0.0.1"; inet4-bind-address "127.0.0.2";)",R"(inet6-bind-address "::1"; inet6-bind-address "::";)",
            R"(routing-mark -1;)",R"(routing-mark 4294967296;)",R"(routing-mark 0; routing-mark 0;)",R"(routing-mark "1";)",
            R"(reuse-addr 1;)",R"(reuse-addr #false; reuse-addr #false;)",R"(bind-address-no-port #false; bind-address-no-port #true;)",
            R"(bind-address-no-port "true";)",R"(udp-fragment 0;)",R"(udp-fragment "false";)",
            R"(udp-fragment #false; udp-fragment #false;)",R"(udp-fragment #true x=1;)",R"(udp-fragment #true {x;};)",R"(udp-fragment (x)#true;)"}) if (parse(protocol,invalid)) { std::cerr<<invalid<<'\n';return 13; }
        if (std::string_view(protocol)!="direct") {
            for (auto field:{R"(bind-interface "lo";)",R"(inet4-bind-address "127.0.0.2";)",R"(inet6-bind-address "::1";)",
                R"(routing-mark 0;)",R"(reuse-addr #false;)",R"(bind-address-no-port #false;)",R"(udp-bind-port 0;)",R"(udp-bind-port 5353;)",R"(udp-fragment #false;)",R"(udp-fragment #true;)"}) {
                if (parse(protocol,std::string("detour \"direct\"; ")+field,R"(outbound "direct" type="direct")")) return 14;
                auto inherited=parse(protocol,"detour \"direct\";",std::string("outbound \"direct\" type=\"direct\" { ")+field+" }");
                if (!inherited || !inherited->direct_tcp_options.configured()) return 15;
            }
            if (parse(protocol,"detour \"direct\"; tcp-keepalive #false;",R"(outbound "direct" type="direct")")) return 7;
            if (!parse(protocol,"detour \"direct\";",R"(outbound "direct" type="direct" { tcp-keepalive #true; })")) return 8;
            if (!parse(protocol,"detour \"direct\";",R"(outbound "direct" type="direct" { tcp-fast-open #true; })")) return 36;
            if (parse(protocol,"detour \"entry\"; tcp-keepalive-idle-seconds 1;",
                R"(outbound "entry" type="shadowsocks" { server host="127.0.0.1" port=443; method "2022-blake3-aes-128-gcm"; key-file "/key"; })")) return 9;
        }
    }
    std::println("All five outbound types: keepalive, physical binding and UDP fragmentation configuration, limits, malformed addresses, duplicates and detour ownership passed");
}
