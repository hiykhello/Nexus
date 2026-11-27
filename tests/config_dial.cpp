import std;
import config;
import platform.socket_options;

namespace {
    auto parse(std::string_view protocol,std::string_view fields,std::string_view extra={}) {
        auto options=protocol=="direct" ? "" : protocol=="vless" ?
            R"(server host="127.0.0.1" port=443; authentication { uuid-file "/uuid"; }; tls { server-name "cover.example"; ca-file "/ca"; verify #true; };)" :
            protocol=="shadowsocks" ? R"(server host="127.0.0.1" port=443; method "2022-blake3-aes-128-gcm"; key-file "/key";)" :
            R"(server host="127.0.0.1" port=443; authentication { password-file "/password"; }; tls { server-name "cover.example"; ca-file "/ca"; verify #true; };)";
        auto direct=protocol=="direct" || extra.find("outbound \"direct\"")!=extra.npos ? "" : "outbound \"direct\" type=\"direct\"\n";
        return config::parse_kdl(std::format(R"(schema-version 1
role "client"
inbounds {{ inbound "in" type="socks5" {{ listen host="127.0.0.1" port=1080; authentication "none"; }} }}
outbounds {{
outbound "{}" type="{}" {{ {} {} }}
{}
{}
}}
routing {{ final "{}"; }}
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

    // Global routing defaults: inheritance vs explicit outbound override, resolver binding, detour skip, validation.
    {
        auto inherited = config::parse_kdl(R"(schema-version 1
role "client"
dns {
    servers {
        server "boot" type="udp" host="127.0.0.1" port=5353
        server "alt" type="udp" host="127.0.0.2" port=5353
    }
    default "boot"
    final "boot"
}
inbounds { inbound "in" type="socks5" { listen host="127.0.0.1" port=1080; authentication "none"; }; }
outbounds {
    interface "lo"
    mark 0x4242
outbound "direct" type="direct"
outbound "entry" type="shadowsocks" {
    server host="entry.example" port=443
    method "2022-blake3-aes-128-gcm"
    key-file "/key"
}
outbound "custom" type="shadowsocks" {
    server host="custom.example" port=443
    method "2022-blake3-aes-128-gcm"
    key-file "/key"
    bind-interface "eth1"
    routing-mark 99
    domain-resolver "alt"
}
outbound "ipnode" type="shadowsocks" {
    server host="127.0.0.1" port=444
    method "2022-blake3-aes-128-gcm"
    key-file "/key"
}
outbound "layered" type="vless" {
    server host="inner.example" port=443
    authentication { uuid-file "/uuid"; }
    tls { server-name "cover.example"; ca-file "/ca"; verify #true; }
    detour "entry"
}
}
routing {
    find-process #true
    rules {
        - domain "a.example" to="custom"
        - domain "b.example" to="ipnode"
        - domain "c.example" to="layered"
    }
    final "entry"
}
)");
        if (!inherited) { std::cerr << "routing defaults inherit: " << inherited.error() << '\n'; return 40; }
        if (inherited->defaults.default_interface != "lo" || inherited->defaults.default_mark != 0x4242u ||
            inherited->defaults.default_domain_resolver != "boot" || inherited->defaults.default_domain_resolver_index != 0 ||
            !inherited->defaults.find_process || inherited->defaults.auto_detect_interface) return 41;
        if (inherited->direct_tcp_options.binding.interface_name() != "lo" ||
            inherited->direct_tcp_options.binding.routing_mark != 0x4242u) return 42;
        auto const& entry_ob = inherited->shadowsocks_outbounds[0].config;
        auto const& custom_ob = inherited->shadowsocks_outbounds[1].config;
        auto const& ip_ob = inherited->shadowsocks_outbounds[2].config;
        auto const& layered_ob = inherited->vless_outbounds[0].config;
        if (entry_ob.tcp_options.binding.interface_name() != "lo" || entry_ob.tcp_options.binding.routing_mark != 0x4242u ||
            entry_ob.bootstrap_resolver != "boot" || entry_ob.bootstrap_index != 0) return 43;
        if (custom_ob.tcp_options.binding.interface_name() != "eth1" || custom_ob.tcp_options.binding.routing_mark != 99u ||
            custom_ob.bootstrap_resolver != "alt" || custom_ob.bootstrap_index != 1) return 44;
        if (ip_ob.tcp_options.binding.interface_name() != "lo" || ip_ob.bootstrap_resolver.has_value() ||
            ip_ob.bootstrap_index.has_value()) return 45;
        if (layered_ob.tcp_options.configured() || layered_ob.bootstrap_resolver != "boot" ||
            layered_ob.bootstrap_index != 0 || layered_ob.detour_index != 3) return 46;

        auto auto_hybrid = config::parse_kdl(R"(schema-version 1
role "client"
inbounds { inbound "in" type="socks5" { listen host="127.0.0.1" port=1080; authentication "none"; }; }
outbounds {
    auto-detect-interface #true
    network-strategy "hybrid"
    network-type "wifi"
outbound "direct" type="direct"
outbound "node" type="shadowsocks" {
    server host="127.0.0.1" port=443
    method "2022-blake3-aes-128-gcm"
    key-file "/key"
}
}
routing {
    final "node"
}
)");
        if (!auto_hybrid) { std::cerr << "auto/hybrid: " << auto_hybrid.error() << '\n'; return 47; }
        if (!auto_hybrid->defaults.auto_detect_interface || !auto_hybrid->defaults.default_network_strategy ||
            auto_hybrid->defaults.default_network_strategy->strategy != platform::network::Strategy::hybrid ||
            auto_hybrid->defaults.default_network_strategy->preferred != platform::network::Type::wifi) return 48;
        if (!auto_hybrid->direct_network || auto_hybrid->direct_network->strategy != platform::network::Strategy::hybrid ||
            !auto_hybrid->direct_tcp_options.binding.auto_detect_interface ||
            auto_hybrid->direct_tcp_options.binding.network_strategy != platform::network::Strategy::hybrid) return 49;
        auto const& node_b = auto_hybrid->shadowsocks_outbounds[0].config.tcp_options.binding;
        if (!node_b.auto_detect_interface || node_b.network_strategy != platform::network::Strategy::hybrid ||
            node_b.network_type != platform::network::Type::wifi) return 50;

        auto direct_hybrid = parse("direct", R"(network strategy="hybrid" type="ethernet" { interface "eth0" type="ethernet"; interface "wlan0" type="wifi"; };)");
        if (!direct_hybrid || !direct_hybrid->direct_network ||
            direct_hybrid->direct_network->strategy != platform::network::Strategy::hybrid ||
            direct_hybrid->direct_network->fallback_delay.count() != 0) return 51;

        for (auto bad_outbounds : {
            R"(interface "";)",
            R"(interface "abcdefghijklmnop";)",
            R"(interface "lo"; interface "lo";)",
            R"(mark -1;)",
            R"(mark 4294967296;)",
            R"(network-strategy "bogus";)",
            R"(network-type "satellite";)",
            R"(network-strategy "prefer" fallback="wifi"; network-type "wifi";)",
            R"(auto-detect-interface 1;)"}) {
            auto bad = config::parse_kdl(std::format(R"(schema-version 1
role "client"
inbounds {{ inbound "in" type="socks5" {{ listen host="127.0.0.1" port=1080; authentication "none"; }} }}
outbounds {{ {} outbound "direct" type="direct"; }}
routing {{ final "direct"; }}
)", bad_outbounds));
            if (bad) { std::cerr << "expected failure for outbounds: " << bad_outbounds << '\n'; return 52; }
        }
        if (config::parse_kdl(R"(schema-version 1
role "client"
inbounds { inbound "in" type="socks5" { listen host="127.0.0.1" port=1080; authentication "none"; }; }
dns { servers { udp "boot" host="127.0.0.1" port=5353; }; default "missing"; final "boot"; }
outbounds { outbound "direct" type="direct"; }
routing { final "direct"; }
)") || config::parse_kdl(R"(schema-version 1
role "client"
inbounds { inbound "in" type="socks5" { listen host="127.0.0.1" port=1080; authentication "none"; }; }
outbounds { outbound "direct" type="direct"; }
routing { find-process "yes"; final "direct"; }
)")) { std::cerr << "expected failure for invalid dns.default or routing.find-process\n"; return 52; }
    }

    // Shared Inbound ListenOptions across TCP/UDP inbound types & detour validation.
    {
        auto multi = config::parse_kdl(R"(schema-version 1
role "server"
inbounds {
    inbound "socks-in" type="socks5" {
        listen host="127.0.0.1" port=1080
        authentication "none"
        bind-interface "lo"
        routing-mark 0x101
        netns "/var/run/netns/demo"
        tcp-fast-open #true
        multipath-tcp #true
        tcp-keepalive idle-s=30 interval-s=10 count=4
        reuse-addr #true
        udp-fragment #false
        udp-timeout-ms 45000
        detour "mixed-in"
    }
    inbound "mixed-in" type="mixed" {
        listen host="127.0.0.1" port=1081
        authentication "none"
        tcp-keepalive { idle-s 60; interval-s 15; count 5; }
        reuse-addr #false
    }
    inbound "http-in" type="http" {
        listen host="127.0.0.1" port=8080
        authentication "none"
        tcp-fast-open #false
        tcp-keepalive #false
    }
    inbound "ss-in" type="shadowsocks" {
        listen host="127.0.0.1" port=8388
        method "2022-blake3-aes-128-gcm"
        key-file "/key"
        bind-interface "lo"
        udp-fragment #true
        udp-timeout-ms 90000
    }
    inbound "fudp-in" type="fixed-udp" {
        listen host="127.0.0.1" port=5353
        target host="127.0.0.1" port=5354
        reuse-addr #true
        udp-fragment #true
        udp-timeout-ms 15000
    }
    inbound "tproxy-in" type="tproxy" {
        listen host="127.0.0.1" port=12345
        udp #true
        routing-mark 0x202
        udp-fragment #false
    }
}
outbounds { outbound "direct" type="direct"; }
routing { final "direct"; }
)");
        if (!multi) { std::cerr << "listen options multi: " << multi.error() << '\n'; return 60; }
        auto const& l0 = multi->inbounds[0].listen;
        if (l0.bind_interface != "lo" || l0.routing_mark != 0x101u || l0.netns != "/var/run/netns/demo" ||
            l0.tcp_fast_open != true || l0.multipath_tcp != true || l0.tcp_keepalive != true ||
            l0.tcp_keepalive_idle_s != 30u || l0.tcp_keepalive_interval_s != 10u || l0.tcp_keepalive_count != 4u ||
            l0.reuse_addr != true || l0.udp_fragment != false || l0.udp_timeout_ms != 45000u ||
            l0.detour != "mixed-in" || multi->inbounds[0].detour_index != 1 || multi->listen != l0) return 61;
        auto const& l1 = multi->inbounds[1].listen;
        if (l1.tcp_keepalive != true || l1.tcp_keepalive_idle_s != 60u || l1.tcp_keepalive_interval_s != 15u ||
            l1.tcp_keepalive_count != 5u || l1.reuse_addr != false) return 62;
        if (multi->inbounds[2].listen.tcp_fast_open != false || multi->inbounds[2].listen.tcp_keepalive != false) return 63;
        if (!multi->inbounds[3].shadowsocks || multi->inbounds[3].shadowsocks->listen.bind_interface != "lo" ||
            multi->inbounds[3].shadowsocks->listen.udp_fragment != true) return 64;
        if (!multi->inbounds[4].fixed_udp || multi->inbounds[4].fixed_udp->idle_timeout_ms != 15000u ||
            multi->inbounds[4].fixed_udp->listen.udp_fragment != true) return 65;
        if (multi->inbounds[5].listen.routing_mark != 0x202u || multi->inbounds[5].listen.udp_fragment != false) return 66;

        for (auto bad_in : {
            R"(inbounds { inbound "a" type="socks5" { listen host="127.0.0.1" port=1080; authentication "none"; detour "missing"; }; })",
            R"(inbounds { inbound "a" type="socks5" { listen host="127.0.0.1" port=1080; authentication "none"; detour "a"; }; })",
            R"(inbounds { inbound "a" type="socks5" { listen host="127.0.0.1" port=1080; authentication "none"; detour "b"; }; inbound "b" type="mixed" { listen host="127.0.0.1" port=1081; authentication "none"; detour "a"; }; })",
            R"(inbounds { inbound "a" type="socks5" { listen host="127.0.0.1" port=1080; authentication "none"; bind-interface "a/b"; }; })",
            R"(inbounds { inbound "a" type="socks5" { listen host="127.0.0.1" port=1080; authentication "none"; netns "relative/path"; }; })",
            R"(inbounds { inbound "a" type="socks5" { listen host="127.0.0.1" port=1080; authentication "none"; tcp-keepalive #false idle-s=10; }; })",
            R"(inbounds { inbound "a" type="socks5" { listen host="127.0.0.1" port=1080; authentication "none"; udp-timeout-ms 500; }; })",
            R"(inbounds { inbound "a" type="socks5" { listen host="127.0.0.1" port=1080; authentication "none"; reuse-addr #true; reuse-addr #false; }; })"}) {
            auto bad = config::parse_kdl(std::format(R"(schema-version 1
role "client"
{}
outbounds {{ outbound "direct" type="direct"; }}
routing {{ final "direct"; }}
)", bad_in));
            if (bad) { std::cerr << "expected failure for inbound: " << bad_in << '\n'; return 67; }
        }
        std::println("Global routing defaults inheritance and shared inbound ListenOptions/detour validation passed");
    }
}
