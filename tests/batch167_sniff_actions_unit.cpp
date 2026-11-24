import std;
import config;
import rules;
import sniff.tcp;
import sniff.extra;

namespace {
    auto require(bool ok, std::string_view msg) -> void {
        if (!ok) { std::cerr << "FAIL: " << msg << '\n'; std::exit(1); }
    }
}

int main() {
    // 1. Extra TCP & UDP protocol sniffers.
    {
        std::array<std::uint8_t, 64> wire{}, scratch{};
        sniff::TcpSniffer bt_sniffer(wire, scratch);
        std::vector<std::uint8_t> partial{0x13, 'B', 'i', 't'};
        auto s1 = bt_sniffer.feed(partial);
        require(s1.status == sniff::TcpStatus::need_more, "bt partial");
        std::vector<std::uint8_t> rest{'T', 'o', 'r', 'r', 'e', 'n', 't', ' ', 'p', 'r', 'o', 't', 'o', 'c', 'o', 'l'};
        auto s2 = bt_sniffer.feed(rest);
        require(s2.status == sniff::TcpStatus::matched && s2.protocol == sniff::TcpProtocol::bittorrent, "bt match");

        std::array<std::uint8_t, 64> wire2{}, scratch2{};
        sniff::TcpSniffer rdp_sniffer(wire2, scratch2);
        std::vector<std::uint8_t> rdp{0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 'C', 'o', 'o', 'k', 'i', 'e', ':', ' '};
        auto sr = rdp_sniffer.feed(rdp);
        require(sr.status == sniff::TcpStatus::matched && sr.protocol == sniff::TcpProtocol::rdp, "rdp match");

        std::array<std::uint8_t, 64> wire3{}, scratch3{};
        sniff::TcpSniffer http_sniffer(wire3, scratch3);
        std::string_view req = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        auto sh = http_sniffer.feed(std::span<std::uint8_t const>(reinterpret_cast<std::uint8_t const*>(req.data()), req.size()));
        require(sh.status == sniff::TcpStatus::matched && sh.protocol == sniff::TcpProtocol::http, "http match");

        std::array<std::uint8_t, 20> dtls{0x16, 0xfe, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x05, 1, 2, 3, 4, 5};
        require(sniff::inspect_dtls_udp(dtls), "dtls udp");
        dtls[1] = 0xaa;
        require(!sniff::inspect_dtls_udp(dtls), "non-dtls udp");

        std::array<std::uint8_t, 48> ntp{};
        ntp[0] = 0x23;
        require(sniff::inspect_ntp_udp(ntp), "ntp udp");
        require(!sniff::inspect_ntp_udp(std::span(ntp).first(32)), "short ntp rejected");

        std::array<std::uint8_t, 16> utrk{0x00, 0x00, 0x04, 0x17, 0x27, 0x10, 0x19, 0x80, 0, 0, 0, 0, 1, 2, 3, 4};
        require(sniff::inspect_bittorrent_udp(utrk), "bt udp tracker");
        std::string_view dht = "d1:ad2:id20:01234567890123456789e1:q4:ping1:t2:aa1:y1:qe";
        require(sniff::inspect_bittorrent_udp(std::span<std::uint8_t const>(reinterpret_cast<std::uint8_t const*>(dht.data()), dht.size())), "bt dht");
    }

    // 2. ip-is-cgnat / source-ip-is-cgnat & new protocols.
    {
        rules::RuleSet set{.version = 2};
        set.rules.push_back({"ip-is-cgnat", "true", {}});
        set.rules.push_back({"source-ip-is-cgnat", "true", {}});
        set.rules.push_back({"protocol", "bittorrent", {}});
        set.rules.push_back({"protocol", "dtls", {}});
        set.rules.push_back({"protocol", "rdp", {}});
        set.rules.push_back({"protocol", "ntp", {}});
        auto matcher = rules::Matcher::compile(set);
        require(matcher.has_value(), "matcher compile");

        require(matcher->match({.ip = "100.64.0.1", .port = 80, .network = rules::Network::tcp}).value() == std::optional<std::size_t>{0}, "cgnat low");
        require(matcher->match({.ip = "100.127.255.254", .port = 80, .network = rules::Network::tcp}).value() == std::optional<std::size_t>{0}, "cgnat high");
        require(!matcher->match({.ip = "100.63.255.255", .port = 80, .network = rules::Network::tcp}).value().has_value(), "non-cgnat low");
        require(!matcher->match({.ip = "100.128.0.0", .port = 80, .network = rules::Network::tcp}).value().has_value(), "non-cgnat high");
        require(matcher->match({.ip = "8.8.8.8", .port = 443, .network = rules::Network::udp, .source_ip = "100.100.1.2"}).value() == std::optional<std::size_t>{1}, "src cgnat");
        require(matcher->match({.ip = "8.8.8.8", .port = 6881, .network = rules::Network::tcp, .protocol = rules::Protocol::bittorrent}).value() == std::optional<std::size_t>{2}, "proto bt");
        require(matcher->match({.ip = "8.8.8.8", .port = 4433, .network = rules::Network::udp, .protocol = rules::Protocol::dtls}).value() == std::optional<std::size_t>{3}, "proto dtls");
        require(matcher->match({.ip = "8.8.8.8", .port = 3389, .network = rules::Network::tcp, .protocol = rules::Protocol::rdp}).value() == std::optional<std::size_t>{4}, "proto rdp");
        require(matcher->match({.ip = "8.8.8.8", .port = 123, .network = rules::Network::udp, .protocol = rules::Protocol::ntp}).value() == std::optional<std::size_t>{5}, "proto ntp");
    }

    // 3. Config parsing and RouteProgram options: override-address, override-port, tls-fragment-fallback-delay-ms.
    {
        std::string kdl = R"kdl(
schema-version 1
role "client"
inbound "socks" type="socks5" {
    listen host="127.0.0.1" port=1080
    authentication "none"
}
outbound "direct" type="direct"
routing {
    tcp-program sniff-timeout-ms=500 unknown="skip" udp=#true {
        rule action="sniff"
        rule action="route-options" tls-record-fragment=#true tls-fragment-min=8 tls-fragment-max=32 tls-fragment-fallback-delay-ms=45 override-port=8443 {
            protocol "rdp"
        }
        rule action="route" outbound="direct" override-address="198.51.100.2" {
            ip-is-cgnat #true
        }
    }
    default-outbound "direct"
}
)kdl";
        auto cfg = config::parse_kdl(kdl);
        require(cfg.has_value(), cfg ? "" : cfg.error());
        require(cfg->ordered_tcp && cfg->ordered_tcp->rules.size() == 3, "ordered_tcp rules");
        require(cfg->ordered_tcp->rules[1].tls_fragment_fallback_delay_ms == 45, "fallback delay");
        require(cfg->ordered_tcp->rules[1].override_port == 8443, "override port");
        require(cfg->ordered_tcp->rules[2].override_address == std::optional<std::string>("198.51.100.2"), "override addr");
    }

    std::cout << "BATCH 167 SNIFF AND ROUTE ACTIONS UNIT TESTS PASSED\n";
    return 0;
}
