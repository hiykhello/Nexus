import std;
import config;

namespace {
    constexpr auto basic=R"KDL(schema-version 1
role "client"
inbound "local" type="socks5" {{
    listen host="127.0.0.1" port=1080
    authentication "none"
    {}
}}
outbound "direct" type="direct"
{}
routing {{ default-outbound "{}"; }}
)KDL";

    auto parse(std::string_view inbound,std::string_view outbound={},std::string_view route="direct") {
        return config::parse_kdl(std::format(basic,inbound,outbound,route));
    }

    auto require(bool pass,std::string_view message) -> void {
        if (!pass) throw std::runtime_error(std::string(message));
    }

    auto socks() -> void {
        auto v4=parse(R"(udp-advertise-ip "198.51.100.9")");
        auto v6=parse(R"(udp-advertise-ip "2001:db8::9")");
        require(v4 && v4->inbounds.front().udp_advertise_ip->size==4,"IPv4 advertisement");
        require(v6 && v6->inbounds.front().udp_advertise_ip->size==16,"IPv6 advertisement");
        for (auto invalid:{"localhost","0.0.0.0","::","ff02::1","2001:db8::9%lo","255.255.255.255"})
            require(!parse(std::format("udp-advertise-ip \"{}\"",invalid)),invalid);
        require(!parse(R"(udp-advertise-ip "127.0.0.1"; udp-advertise-ip "127.0.0.2")"),"duplicate advertisement");
    }

    auto masque() -> void {
        auto outbound=[](std::string_view fields) {
            return std::format(R"KDL(outbound "edge" type="masque" {{
  server host="127.0.0.1" port=443
  authority "localhost"
  authentication {{ bearer-file "/run/bearer"; }}
  tls {{ server-name "localhost"; ca-file "/run/cert"; verify #true; }}
  mode "connect-ip"
  {}
}})KDL",fields);
        };
        auto parsed=parse("",outbound(R"(protocol "cf-connect-ip"; path "/"; header "Cf-Connect-Proto" "cf-connect-ip"; local-address "10.0.0.2/32"; local-address "fd00::2/128"; mtu 1280;)"),"edge");
        require(parsed.has_value(),"WARP-compatible config");
        auto const& cfg=parsed->masque_outbounds.front().config;
        require(cfg.protocol=="cf-connect-ip" && cfg.path=="/" && cfg.mtu==1280 && cfg.local_v4 && cfg.local_v6 &&
            cfg.connect_headers.size()==1 && cfg.connect_headers.front().first=="cf-connect-proto","parsed CONNECT-IP settings");
        for (auto fields:{R"(path "/"; path "/duplicate";)",R"(header "Host" "localhost";)",
                          R"(header "TEST" "1"; header "test" "2";)",R"(protocol "cf-connect-ip";)",R"(mtu 1279; local-address "fd00::2";)"})
            require(!parse("",outbound(fields),"edge"),fields);
    }
}

auto main() -> int {
    socks();
    masque();
    std::println("SOCKS UDP and MASQUE deployment validation passed");
}
