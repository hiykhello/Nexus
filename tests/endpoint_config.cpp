import std;
import endpoint.config;
import wireguard;
namespace e=endpoint;
namespace {
    auto require(bool value,std::source_location source=std::source_location::current()) -> void {
        if (!value) { std::println("endpoint config failed line {}",source.line()); throw 1; }
    }
    auto replace(std::string text,std::string_view before,std::string_view after) -> std::string {
        auto position=text.find(before); require(position!=text.npos); text.replace(position,before.size(),after); return text;
    }
    std::string const complete=R"(schema-version 1
role "client"
endpoint "wg" type="wireguard" {
    private-key-file "/secret"
    listen host="::" port=0
    device name="nx-wg" mtu=1420
    local-address "10.42.0.1/24"
    local-address "fd42::1/64"
    route-include "10.42.0.2/32"
    route-include "fd42::2/128"
    peer "a" {
        public-key-file "/public-a"
        preshared-key-file "/psk-a"
        endpoint host="192.0.2.2" port=51820
        allowed-ip "10.42.0.2/32"
        allowed-ip "fd42::2/128"
    }
    peer "b" {
        public-key-file "/public-b"
        endpoint host="192.0.2.6" port=51821
        allowed-ip "10.42.0.3/32"
        allowed-ip "fd42::3/128"
    }
}
)";
    auto valid_cases() -> void {
        auto document=e::parse_kdl(complete); require(document.has_value());
        auto const& config=document->wireguard;
        require(!document->server && !config.auto_cookie && config.network.mtu==1420 && config.network.address_count==2 && config.network.addresses[0].bytes[3]==1 &&
                config.network.addresses[0].prefix==24 && config.network.route_count==2 && config.listen.port==0 && config.listen.family==6 && config.peers.size()==2);
        auto warp=e::parse_kdl(replace(complete,"private-key-file \"/secret\"",R"(private-key-file "/secret"
    provider-profile "warp"
    reserved 17 34 51)"));
        require(warp && warp->wireguard.provider_profile==wireguard::Provider::warp && warp->wireguard.reserved==std::array<std::uint8_t,3>{17,34,51});
        for(auto field:{"provider-profile \"other\"","provider-profile \"warp\"; provider-profile \"warp\"","reserved 1 2 3","provider-profile \"standard\"; reserved 1 2 3","provider-profile \"warp\"; reserved 1 2","provider-profile \"warp\"; reserved 1 2 256","provider-profile \"warp\"; reserved 1 2 -1","provider-profile \"warp\"; reserved 1 2 3; reserved 1 2 3"})
            require(!e::parse_kdl(replace(complete,"private-key-file \"/secret\"",std::string("private-key-file \"/secret\"\n")+field)));
        auto install=[&](std::string_view field){return e::parse_kdl(replace(complete,"private-key-file \"/secret\"",std::string("private-key-file \"/secret\"\n")+std::string(field)));};
        auto dns=install(R"(host-dns { backend "resolved"; server "10.42.0.2"; server "fd42::2"; })");
        require(dns && dns->wireguard.host_dns.enabled() && dns->wireguard.host_dns.server_count==2 && dns->wireguard.host_dns.servers[1].ipv6);
        for(auto field:{
            R"(host-dns {})",R"(host-dns { backend "resolved"; })",R"(host-dns { server "10.42.0.2"; })",
            R"(host-dns { backend "other"; server "10.42.0.2"; })",R"(host-dns { backend "resolved"; backend "resolved"; server "10.42.0.2"; })",
            R"(host-dns { backend "resolved"; server "10.42.0.2"; server "10.42.0.2"; })",R"(host-dns { backend "resolved"; server "dns.test"; })",
            R"(host-dns { backend "resolved"; server "127.0.0.1"; })",R"(host-dns { backend "resolved"; server "0.0.0.0"; })",
            R"(host-dns { backend "resolved"; server "224.0.0.1"; })",R"(host-dns { backend "resolved"; server "fe80::2"; })",
            R"(host-dns { backend "resolved"; server "::ffff:10.42.0.2"; })",R"(host-dns { backend "resolved"; server "10.42.0.1"; })",
            R"(host-dns { backend "resolved"; server "8.8.8.8"; })",R"(host-dns { backend "resolved"; server "10.42.0.2"; unknown #true; })",
            R"(host-dns type="resolved" { backend "resolved"; server "10.42.0.2"; })",R"(host-dns { backend "resolved"; server "10.42.0.2" port=53; })",
            R"(host-dns { backend "resolved"; server "10.42.0.2"; }; host-dns { backend "resolved"; server "fd42::3"; })",
            R"(host-dns { backend "resolved"; server "10.42.0.2"; server "10.42.0.3"; server "fd42::2"; server "fd42::3"; })"})require(!install(field));
        auto server=e::parse_kdl(replace(complete,"role \"client\"","role \"server\"")); require(server && server->server);
        auto configured=e::parse_kdl(replace(complete,"private-key-file \"/secret\"",R"(private-key-file "/secret"
    startup-timeout-ms 1
    queue { packets 1; bytes 1420; }
    require-cookie #true
    auto-cookie #true
    bind-interface "lo"
    routing-mark 0
    udp-fragment #true
    reuse-addr #false)"));
        require(configured && configured->wireguard.queue_packets==1 && configured->wireguard.queue_bytes==1420 && configured->wireguard.require_cookie && configured->wireguard.auto_cookie &&
                configured->wireguard.binding.routing_mark==0 && configured->wireguard.binding.reuse_addr==false && configured->wireguard.binding.udp_fragment==true);
        auto domain=replace(complete,"endpoint host=\"192.0.2.2\" port=51820",R"(endpoint host="Wg.Example.Test." port=51820
        bootstrap-resolver "local"
        address-strategy "ipv6-only")");
        auto hostname=e::parse_kdl(domain); require(hostname && !hostname->wireguard.peers[0].server->numeric && hostname->wireguard.peers[0].local_bootstrap &&
                                                hostname->wireguard.peers[0].strategy==e::AddressStrategy::ipv6_only);
        auto passive=e::parse_kdl(replace(complete,"endpoint host=\"192.0.2.2\" port=51820","")); require(passive && !passive->wireguard.peers[0].server);
        auto defaults=replace(complete,"allowed-ip \"10.42.0.2/32\"","allowed-ip \"0.0.0.0/0\"");
        defaults=replace(defaults,"allowed-ip \"fd42::2/128\"","allowed-ip \"0::/0\""); require(e::parse_kdl(defaults).has_value());
        auto capture=replace(defaults,"route-include \"10.42.0.2/32\"","");
        capture=replace(capture,"route-include \"fd42::2/128\"","");
        capture=replace(capture,"private-key-file \"/secret\"","private-key-file \"/secret\"\n    route-mode \"default\"");
        auto captured=e::parse_kdl(capture);
        require(captured && captured->wireguard.default_route && !captured->wireguard.network.route_count && captured->wireguard.binding.routing_mark==0x6e780001);
        require(!e::parse_kdl(replace(capture,"route-mode \"default\"","route-mode \"default\"; route-mode \"split\"")));
        require(!e::parse_kdl(replace(capture,"route-mode \"default\"","route-mode \"unknown\"")));
        require(!e::parse_kdl(replace(capture,"route-mode \"default\"","route-mode \"default\"; routing-mark 0")));
        require(!e::parse_kdl(replace(capture,"route-mode \"default\"","route-mode \"default\"; route-include \"10.42.0.2/32\"")));
        require(!e::parse_kdl(replace(capture,"allowed-ip \"0.0.0.0/0\"","allowed-ip \"0.0.0.0/1\"")));
        require(!e::parse_kdl(replace(capture,"allowed-ip \"0::/0\"","allowed-ip \"::/1\"")));
        auto explicit_mark=e::parse_kdl(replace(capture,"route-mode \"default\"","route-mode \"default\"; routing-mark 123456"));
        require(explicit_mark && explicit_mark->wireguard.binding.routing_mark==123456);
        auto halves=replace(capture,"allowed-ip \"0.0.0.0/0\"","allowed-ip \"0.0.0.0/1\"; allowed-ip \"128.0.0.0/1\"");
        halves=replace(halves,"allowed-ip \"0::/0\"","allowed-ip \"::/1\"; allowed-ip \"8000::/1\"");require(e::parse_kdl(halves).has_value());
        auto union_text=replace(complete,"route-include \"10.42.0.2/32\"","route-include \"10.43.0.0/24\"");
        union_text=replace(union_text,"allowed-ip \"10.42.0.2/32\"","allowed-ip \"10.43.0.0/25\"");
        union_text=replace(union_text,"allowed-ip \"10.42.0.3/32\"","allowed-ip \"10.43.0.128/25\""); require(e::parse_kdl(union_text).has_value());
        require(!e::parse_kdl(replace(union_text,"allowed-ip \"10.43.0.128/25\"","allowed-ip \"10.43.0.128/26\"")));
    }
    auto invalid_cases() -> void {
        std::array<std::pair<std::string_view,std::string_view>,34> const replacements{{
            {"schema-version 1","schema-version 2"},{"schema-version 1","schema-version 1; schema-version 1"},
            {"role \"client\"","role \"endpoint\""},{"role \"client\"","role \"client\"; role \"server\""},
            {"type=\"wireguard\"","type=\"warp\""},{"endpoint \"wg\"","endpoint \"\""},
            {"private-key-file \"/secret\"","private-key-file \"relative\""},{"private-key-file \"/secret\"",""},
            {"port=51820","port=0"},{"port=51820","port=65536"},{"port=0","port=-1"},{"host=\"::\"","host=\"localhost\""},
            {"host=\"192.0.2.2\"","host=\"0.0.0.0\""},{"host=\"192.0.2.2\"","host=\"ff02::1\""},
            {"host=\"192.0.2.2\"","host=\"fd42::1\""},{"host=\"192.0.2.2\"","host=\"10.42.0.2\""},
            {"name=\"nx-wg\"","name=\"abcdefghijklmnop\""},{"name=\"nx-wg\"","name=\"tun%d\""},
            {"name=\"nx-wg\"","name=\"bad/name\""},{"mtu=1420","mtu=1279"},{"mtu=1420","mtu=2017"},
            {"local-address \"10.42.0.1/24\"","local-address \"127.0.0.1/8\""},
            {"route-include \"10.42.0.2/32\"","route-include \"10.42.0.2/24\""},
            {"route-include \"10.42.0.2/32\"","route-include \"0.0.0.0/0\""},
            {"route-include \"fd42::2/128\"","route-include \"::/0\""},
            {"allowed-ip \"10.42.0.3/32\"","allowed-ip \"10.42.0.2/32\""},
            {"peer \"b\"","peer \"a\""},{"public-key-file \"/public-a\"","public-key-file \"public\""},
            {"preshared-key-file \"/psk-a\"","preshared-key-file \"relative\""},
            {"endpoint host=\"192.0.2.2\" port=51820","endpoint host=\"127.0.00.1\" port=51820; bootstrap-resolver \"local\""},
            {"endpoint host=\"192.0.2.2\" port=51820","endpoint host=\"fe80::1%lo\" port=51820; bootstrap-resolver \"local\""},
            {"endpoint host=\"192.0.2.2\" port=51820","endpoint host=\"wg.test\" port=51820"},
            {"endpoint host=\"192.0.2.2\" port=51820","endpoint host=\"192.0.2.2\" port=51820; address-strategy \"ipv4-only\""},
            {"endpoint host=\"192.0.2.2\" port=51820","endpoint host=\"192.0.2.2\" port=51820; bootstrap-resolver \"local\""}
        }};
        for (auto const& [before,after]:replacements) {
            auto parsed=e::parse_kdl(replace(complete,before,after));
            if (parsed) std::println("unexpectedly accepted replacement {}",after);
            require(!parsed);
        }
        for (auto field:{"detour \"x\"","provider-profile \"other\"","inet4-bind-address \"192.0.2.1\"","reuse-addr #true","queue { packets 0; }",
                        "queue { bytes 1419; }","queue { bytes 16777217; }","require-cookie 1","auto-cookie 1","auto-cookie #true; auto-cookie #false","startup-timeout-ms 0","startup-timeout-ms 3600001"})
            require(!e::parse_kdl(replace(complete,"private-key-file \"/secret\"",std::string("private-key-file \"/secret\"\n")+field)));
        require(!e::parse_kdl(std::string(1024*1024+1,' ')));
        require(!e::parse_kdl(complete+"inbound \"dummy\" type=\"socks5\"\n"));
    }
}
auto main() -> int {
    try { valid_cases(); invalid_cases(); } catch (int value) { return value; }
    std::println("typed endpoint KDL uses shared scalar/header/name/path rules; host bits, cryptokey/OS-route distinction, union coverage, deployment labels and rejected duplicate/unsupported/bounded fields passed");
}
