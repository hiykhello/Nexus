import std;
import relay;

#ifdef NEXUS_TEST_DNS_SHARED_ACCESS
extern "C" void nexus_test_dns_shared_access(void const*) noexcept {}
#endif

auto main() -> int {
    auto server = relay::Server::create();
    if (!server) return 1;

    // The public API exists in each configuration. A disabled protocol
    // reports that fact; an enabled one reaches its normal validation.
    auto invalid_exchange = static_cast<relay::TlsKeyExchange>(-1);
    auto vless = (*server)->add_vless("127.0.0.1", 443, "", "localhost", "", invalid_exchange);
    if (vless) return 2;
#if defined(NEXUS_ENABLE_VLESS) || defined(MCPP_FEATURE_VLESS)
    if (vless.error() != "invalid TLS key exchange") return 3;
    constexpr auto vless_start_error = std::errc::invalid_argument;
#else
    if (vless.error() != "VLESS outbound is not yet available in this build") return 4;
    constexpr auto vless_start_error = std::errc::operation_not_supported;
#endif
    auto vless_start = (*server)->start(0, relay::Inbound::vless);
    if (vless_start || vless_start.error() != vless_start_error) return 5;

    auto shadowsocks = (*server)->add_shadowsocks("", 0, {});
    if (shadowsocks) return 6;
#if defined(NEXUS_ENABLE_SS2022) || defined(MCPP_FEATURE_SS2022)
    if (shadowsocks.error() != "invalid Shadowsocks 2022 server or key") return 7;
    constexpr auto ss_start_error = std::errc::invalid_argument;
#else
    if (shadowsocks.error() != "Shadowsocks 2022 outbound is not available in this build") return 8;
    constexpr auto ss_start_error = std::errc::operation_not_supported;
#endif
    auto ss_start = (*server)->start(0, relay::Inbound::shadowsocks);
    if (ss_start || ss_start.error() != ss_start_error) return 9;
    auto trojan=(*server)->add_trojan("127.0.0.1",443,"","localhost","",invalid_exchange);
    if (trojan) return 45;
#if defined(NEXUS_ENABLE_TROJAN) || defined(MCPP_FEATURE_TROJAN)
    if (trojan.error()!="invalid TLS key exchange") return 46;
    constexpr auto trojan_start_error=std::errc::invalid_argument;
#else
    if (trojan.error()!="Trojan outbound is not available in this build") return 47;
    constexpr auto trojan_start_error=std::errc::operation_not_supported;
#endif
    auto trojan_start=(*server)->start(0,relay::Inbound::trojan);
    if (trojan_start || trojan_start.error()!=trojan_start_error) return 48;
    if ((*server)->prepare_trojan_inbound("","",{})) return 49;
    auto anytls=(*server)->add_anytls("127.0.0.1",443,"","localhost","",invalid_exchange);
    if (anytls) return 50;
#if defined(NEXUS_ENABLE_ANYTLS) || defined(MCPP_FEATURE_ANYTLS)
    if (anytls.error()!="invalid TLS key exchange") return 51;
    constexpr auto anytls_start_error=std::errc::invalid_argument;
#else
    if (anytls.error()!="AnyTLS outbound is not available in this build") return 52;
    constexpr auto anytls_start_error=std::errc::operation_not_supported;
#endif
    auto anytls_start=(*server)->start(0,relay::Inbound::anytls);
    if (anytls_start || anytls_start.error()!=anytls_start_error) return 53;
    if ((*server)->prepare_anytls_inbound("","",{})) return 54;

    // Several DNS nodes can share a prerequisite; a rejected replacement must
    // leave the previous routing configuration usable.
    relay::DnsRouting dns;
    relay::DnsServer first; first.host="first.test"; first.port=53; first.resolver=2;
    relay::DnsServer second; second.host="second.test"; second.port=53; second.resolver=2;
    dns.servers={first,second,{}}; dns.final=0;
    if (!(*server)->set_dns_routing(dns)) return 11;
    auto bad=dns; bad.servers[2].host="cycle.test"; bad.servers[2].port=53; bad.servers[2].resolver=0;
    if ((*server)->set_dns_routing(bad)) return 12;
    bad=dns; bad.servers[0].resolver=3;
    if ((*server)->set_dns_routing(bad)) return 13;
    bad=dns; bad.servers[2].resolver=0;
    if ((*server)->set_dns_routing(bad)) return 14;
    dns.rules={{"EXAMPLE.test",true,1,28},{"",false,2,1}};
    if (!(*server)->set_dns_routing(dns)) return 30;
    bad=dns; bad.rules[0].query_type=0;
    if ((*server)->set_dns_routing(bad)) return 31;
    bad=dns; bad.rules[1].query_type.reset();
    if ((*server)->set_dns_routing(bad)) return 32;
    bad=dns; bad.rules[0].server=3;
    if ((*server)->set_dns_routing(bad)) return 33;
    dns.rules.push_back({.action=::policy::DnsAction::reject,.match_all=true});
    if (!(*server)->set_dns_routing(dns)) return 35;
    bad=dns; bad.rules.back().server=1;
    if ((*server)->set_dns_routing(bad)) return 36;
    bad=dns; bad.rules.back().action=static_cast<::policy::DnsAction>(255);
    if ((*server)->set_dns_routing(bad)) return 37;
    bad=dns; bad.rules.back().query_type=1;
    if ((*server)->set_dns_routing(bad)) return 38;
    dns.rules.insert(dns.rules.begin(),{.action=::policy::DnsAction::route_options,.match_all=true,.disable_cache=true});
    if (!(*server)->set_dns_routing(dns)) return 39;
    bad=dns; bad.rules.front().disable_cache.reset();
    if ((*server)->set_dns_routing(bad)) return 40;
    bad=dns; bad.rules.front().server=1;
    if ((*server)->set_dns_routing(bad)) return 41;
    dns.rules.insert(dns.rules.begin(),{.domain="context.test",.server=1,
        .context={{"source-ip-cidr","192.0.2.0/24"},{"source-port-range","1000-2000"},{"network","udp"},{"inbound","edge"},{"auth-user","alice"}}});
    if (!(*server)->set_dns_routing(dns)) return 42;
    bad=dns; bad.rules.front().context[0].value="bad";
    if ((*server)->set_dns_routing(bad)) return 43;
    bad=dns; bad.rules.front().context[0].type="domain";
    if ((*server)->set_dns_routing(bad)) return 44;

    if (!(*server)->set_outbound_detours({})) return 15;
    relay::TcpSocketOptions invalid_tcp; invalid_tcp.keepalive_idle_seconds=0;
    if ((*server)->set_direct_tcp_options(invalid_tcp)) return 23;
    relay::TcpSocketOptions tcp{true,17,3,5};
    if (!(*server)->set_direct_tcp_options(tcp)) return 24;
    std::array invalid_detour{relay::OutboundDetour{2,0}};
    if ((*server)->set_outbound_detours(invalid_detour)) return 16;
#if defined(NEXUS_ENABLE_SS2022) || defined(MCPP_FEATURE_SS2022)
    std::array<std::uint8_t,16> key{};
    for (unsigned i=0;i<3;++i) if (!(*server)->add_shadowsocks("127.0.0.1",443,key)) return 17;
    std::array detours{relay::OutboundDetour{4,3},relay::OutboundDetour{3,2}};
    if (!(*server)->set_outbound_detours(detours)) return 18;
    for (auto edge:{relay::OutboundDetour{2,2},{2,1},{2,5},{1,0}}) {
        std::array edges{edge};
        if ((*server)->set_outbound_detours(edges)) return 19;
    }
    std::array cycle{detours[0],detours[1],relay::OutboundDetour{2,4}};
    if ((*server)->set_outbound_detours(cycle)) return 20;
    std::array duplicates{detours[0],detours[0]};
    if ((*server)->set_outbound_detours(duplicates)) return 21;
    if ((*server)->add_shadowsocks("127.0.0.1",443,key,{},false,10000,invalid_tcp)) return 25;
    auto physical=(*server)->add_shadowsocks("127.0.0.1",443,key,{},false,10000,tcp);
    if (!physical) return 26;
    std::array invalid_socket_detour{relay::OutboundDetour{*physical,0}};
    if ((*server)->set_outbound_detours(invalid_socket_detour)) return 27;
    std::array use_physical{relay::OutboundDetour{4,*physical}};
    if (!(*server)->set_outbound_detours(use_physical)) return 28;
#endif

    // A standalone server creates its own DNS generation. Repeated starts with
    // different worker counts must release and recreate its reader bindings.
    for (unsigned workers : {1U, 2U, 1U, 3U}) {
        auto port = (*server)->start(0, relay::Inbound::socks5, workers);
        if (!port || !*port) return 10;
        if ((*server)->set_outbound_detours({})) return 22;
        if ((*server)->set_direct_tcp_options({})) return 29;
        if ((*server)->set_dns_routing(dns)) return 34;
        (*server)->stop();
    }

    std::println("Proxy feature APIs and standalone worker-count restarts passed");
}
