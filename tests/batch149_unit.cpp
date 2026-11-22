import std;
import config;
import hysteria2.salamander;
import net.datagram_driver;
import quic.datagram_port;
import rules;
import socks5;
import udp;
import nexus.thirdparty.corosio;

namespace {
    int failures = 0;

    auto expect(bool cond, std::string_view msg) -> void {
        if (!cond) {
            std::cerr << "FAIL: " << msg << '\n';
            ++failures;
        }
    }

    auto test_socks4_parser_and_kdl() -> void {
        // Valid SOCKS4 IPv4 CONNECT: 127.0.0.1:8080 userid="alice"
        std::vector<std::uint8_t> s4{4, 1, 0x1f, 0x90, 127, 0, 0, 1, 'a', 'l', 'i', 'c', 'e', 0};
        auto r1 = socks5::parse_socks4_request(s4);
        expect(r1.status == socks5::Status::accepted && r1.command == 1 && r1.address_type == 1 &&
               r1.address_length == 4 && r1.port == 8080 && r1.consumed == s4.size() &&
               r1.address[0] == 127 && r1.address[3] == 1, "149A: valid SOCKS4 IPv4 CONNECT");

        // Valid SOCKS4a domain CONNECT: 0.0.0.1 + example.com:443
        std::vector<std::uint8_t> s4a{4, 1, 0x01, 0xbb, 0, 0, 0, 1, 0};
        std::string_view dom = "example.com";
        s4a.insert(s4a.end(), dom.begin(), dom.end());
        s4a.push_back(0);
        auto r2 = socks5::parse_socks4_request(s4a);
        expect(r2.status == socks5::Status::accepted && r2.address_type == 3 &&
               r2.address_length == dom.size() && r2.port == 443 && r2.consumed == s4a.size(),
               "149A: valid SOCKS4a domain CONNECT");

        // Negative cases: BIND command, port 0, incomplete, bad version, oversized userid, control char domain
        std::vector<std::uint8_t> bad_cmd{4, 2, 0x00, 0x50, 127, 0, 0, 1, 0};
        expect(socks5::parse_socks4_request(bad_cmd).status == socks5::Status::unsupported_command, "149A: reject BIND");
        std::vector<std::uint8_t> bad_port{4, 1, 0x00, 0x00, 127, 0, 0, 1, 0};
        expect(socks5::parse_socks4_request(bad_port).status == socks5::Status::invalid_address, "149A: reject port 0");
        std::vector<std::uint8_t> inc{4, 1, 0x00, 0x50, 127, 0, 0, 1};
        expect(socks5::parse_socks4_request(inc).status == socks5::Status::incomplete, "149A: incomplete SOCKS4");
        std::vector<std::uint8_t> big_uid(270, 'a');
        big_uid[0] = 4; big_uid[1] = 1; big_uid[2] = 0; big_uid[3] = 80; big_uid[4] = 127; big_uid[7] = 1;
        expect(socks5::parse_socks4_request(big_uid).status == socks5::Status::too_large, "149A: reject oversized userid");
        std::vector<std::uint8_t> bad_dom{4, 1, 0x01, 0xbb, 0, 0, 0, 1, 0, 'a', ' ', 'b', 0};
        expect(socks5::parse_socks4_request(bad_dom).status == socks5::Status::invalid_address, "149A: reject space in domain");

        // KDL outbound socks4 / socks4a
        auto ok_kdl = config::parse_kdl(R"(
            schema-version 1
            role "client"
            inbound "local" type="socks5" { listen host="127.0.0.1" port=1080; authentication "none"; }
            outbound "direct" type="direct"
            outbound "s4" type="socks4" { server host="127.0.0.1" port=1081; userid "alice"; }
            outbound "s4a" type="socks4a" { server host="127.0.0.1" port=1082; userid "bob"; }
            outbound "sel" type="selector" { member "s4"; member "s4a"; selected "s4"; }
            routing { default-outbound "sel"; }
        )");
        expect(ok_kdl.has_value() && ok_kdl->tcp_proxy_outbounds.size() == 2 &&
               ok_kdl->tcp_proxy_outbounds[0].config.protocol == config::TcpProxyProtocol::socks4 &&
               ok_kdl->tcp_proxy_outbounds[0].config.username == "alice" &&
               ok_kdl->tcp_proxy_outbounds[1].config.protocol == config::TcpProxyProtocol::socks4a,
               "149A: parse socks4 & socks4a KDL outbounds");

        auto bad_kdl = config::parse_kdl(R"(
            schema-version 1
            role "client"
            inbound "local" type="socks5" { listen host="127.0.0.1" port=1080; authentication "none"; }
            outbound "direct" type="direct"
            outbound "s4" type="socks4" { server host="127.0.0.1" port=1081; authentication { username "a"; password-file "/tmp/p"; }; }
            routing { default-outbound "s4"; }
        )");
        expect(!bad_kdl.has_value(), "149A: reject password authentication on socks4");
    }

    auto test_fixed_udp_kdl() -> void {
        auto ok = config::parse_kdl(R"(
            schema-version 1
            role "client"
            inbound "fudp" type="fixed-udp" {
                listen host="127.0.0.1" port=15353
                target host="127.0.0.1" port=5353
                idle-timeout-ms 15000
            }
            outbound "direct" type="direct"
            routing { default-outbound "direct"; }
        )");
        expect(ok.has_value() && ok->inbounds.size() == 1 &&
               ok->inbounds[0].type == config::Inbound::fixed_udp &&
               ok->inbounds[0].fixed_udp && ok->inbounds[0].fixed_udp->target_port == 5353 &&
               ok->inbounds[0].fixed_udp->idle_timeout_ms == 15000,
               "149B: parse fixed-udp inbound");

        auto bad = config::parse_kdl(R"(
            schema-version 1
            role "client"
            inbound "fudp" type="fixed-udp" { listen host="127.0.0.1" port=15353; idle-timeout-ms 500; }
            outbound "direct" type="direct"
            routing { default-outbound "direct"; }
        )");
        expect(!bad.has_value(), "149B: reject missing target and low idle-timeout-ms");
    }

    struct MockPort {
        using Failure = quic::DatagramPortError;
        nex::corosio::endpoint last_rx{};
        std::uint16_t primary = 0;
        bool emit_once = true;
        auto request_stop() noexcept -> void {}
        auto stop() noexcept -> void {}
        auto drain() noexcept -> void {}
        auto next_expiry() const noexcept -> net::DatagramDeadline { return std::nullopt; }
        auto expire(net::DatagramClock::time_point) -> std::expected<void, Failure> { return {}; }
        auto transmitted(std::uint64_t, net::DatagramClock::time_point) -> std::expected<void, Failure> { return {}; }
        auto receive(nex::corosio::endpoint const& peer, std::span<std::uint8_t>, net::DatagramClock::time_point)
            -> std::expected<void, Failure> {
            last_rx = peer;
            return {};
        }
        auto output(std::span<std::uint8_t> buf, net::DatagramClock::time_point)
            -> std::expected<std::optional<net::DatagramOutput>, Failure> {
            if (!emit_once) return std::optional<net::DatagramOutput>{};
            buf[0] = 0x42;
            return std::optional<net::DatagramOutput>{net::DatagramOutput{
                nex::corosio::endpoint{nex::corosio::ipv4_address::loopback(), primary}, 1, 1}};
        }
    };

    auto test_protocol_gaps_kdl_and_hopping() -> void {
        auto ok = config::parse_kdl(R"(
            schema-version 1
            role "client"
            inbound "tr-ws" type="trojan" {
                listen host="127.0.0.1" port=14443
                authentication { user "u1" password-file="/tmp/p1"; }
                tls { certificate-file "/tmp/c.pem"; private-key-file "/tmp/k.pem"; }
                transport "websocket" { path "/ws"; host "example.com"; }
            }
            inbound "at-grpc" type="anytls" {
                listen host="127.0.0.1" port=14444
                authentication { user "u1" password-file="/tmp/p1"; }
                tls { certificate-file "/tmp/c.pem"; private-key-file "/tmp/k.pem"; }
                transport "grpc" { service-name "tun"; authority "example.com"; }
            }
            outbound "direct" type="direct"
            outbound "tr-hu" type="trojan" {
                server host="127.0.0.1" port=14443
                authentication { password-file "/tmp/p1"; }
                tls { server-name "example.com"; ca-file "/tmp/ca.pem"; verify #true; }
                transport "httpupgrade" { path "/hu"; host "example.com"; }
            }
            outbound "at-ws" type="anytls" {
                server host="127.0.0.1" port=14444
                authentication { password-file "/tmp/p1"; }
                tls { server-name "example.com"; ca-file "/tmp/ca.pem"; verify #true; }
                transport "websocket" { path "/ws"; host "example.com"; }
            }
            outbound "sn5" type="snell" {
                server host="127.0.0.1" port=16160
                version 5
                psk-file "/tmp/psk"
            }
            outbound "hy2-hop" type="hysteria2" {
                server host="127.0.0.1" port=20000
                authentication { password-file "/tmp/p1"; }
                tls { server-name "example.com"; ca-file "/tmp/ca.pem"; verify #true; }
                quic { ports "20001-20005,20010"; hop-interval-ms 1000; }
            }
            outbound "sel" type="selector" {
                member "tr-hu"; member "at-ws"; member "sn5"; member "hy2-hop";
                selected "tr-hu"
            }
            routing { default-outbound "sel"; }
        )");
        expect(ok.has_value(), ok ? "149C: kdl ok" : "149C: kdl failed: " + ok.error());
        if (ok) {
            expect(ok->inbounds[0].trojan && ok->inbounds[0].trojan->transport && ok->inbounds[0].trojan->transport->websocket, "149C: trojan ws inbound");
            expect(ok->inbounds[1].anytls && ok->inbounds[1].anytls->grpc && ok->inbounds[1].anytls->grpc->service_name == "tun", "149C: anytls grpc inbound");
            expect(ok->trojan_outbounds[0].config.transport && !ok->trojan_outbounds[0].config.transport->websocket, "149C: trojan hu outbound");
            expect(ok->anytls_outbounds[0].config.connection.transport && ok->anytls_outbounds[0].config.connection.transport->websocket, "149C: anytls ws outbound");
            expect(ok->snell_outbounds[0].config.version == 5, "149C: snell v5 outbound");
            expect(ok->hysteria2_outbounds[0].config.transport.port_ranges.size() == 2 &&
                   ok->hysteria2_outbounds[0].config.transport.hop_interval_ms == 1000, "149C: hy2 port hopping config");
        }

        // Direct SalamanderPort periodic port hopping test
        MockPort mock{};
        mock.primary = 20000;
        hysteria2::SalamanderPort<MockPort> port(mock, std::nullopt);
        auto t0 = net::DatagramClock::now();
        std::array<std::pair<std::uint16_t, std::uint16_t>, 1> ranges{{{20001, 20004}}};
        port.configure_hopping(20000, ranges, std::chrono::milliseconds(1000), t0);
        auto p1 = port.active_hop_port();
        expect(p1 >= 20001 && p1 <= 20004, "149C: initial hop port within range");
        auto exp = port.next_expiry();
        expect(exp && *exp == t0 + std::chrono::milliseconds(1000), "149C: hop expiry scheduled");
        std::array<std::uint8_t, 64> buf{};
        auto out1 = port.output(buf, t0);
        expect(out1 && *out1 && (**out1).peer.port() == p1, "149C: output rewrites peer port to active hop port");
        expect(port.expire(t0 + std::chrono::milliseconds(1000)).has_value(), "149C: expire triggers hop");
        auto p2 = port.active_hop_port();
        expect(p2 >= 20001 && p2 <= 20004 && p2 != p1, "149C: hopped to a distinct port in range");
        auto out2 = port.output(buf, t0 + std::chrono::milliseconds(1000));
        expect(out2 && *out2 && (**out2).peer.port() == p2, "149C: output uses new hopped port");
        std::array<std::uint8_t, 4> rx{1, 2, 3, 4};
        expect(port.receive(nex::corosio::endpoint{nex::corosio::ipv4_address::loopback(), p2}, rx, t0).has_value(), "149C: receive from hopped port");
        expect(mock.last_rx.port() == 20000, "149C: receive normalizes logical peer port back to primary");
    }

    auto test_adaptive_udp_timeout_and_dashboard_kdl() -> void {
        expect(rules::adaptive_udp_timeout_ms(rules::Protocol::dns, 5353, 60000) == 10000, "149D: dns proto -> 10s");
        expect(rules::adaptive_udp_timeout_ms(std::nullopt, 53, 60000) == 10000, "149D: port 53 -> 10s");
        expect(rules::adaptive_udp_timeout_ms(std::nullopt, 123, 60000) == 10000, "149D: ntp port 123 -> 10s");
        expect(rules::adaptive_udp_timeout_ms(rules::Protocol::stun, 19302, 60000) == 10000, "149D: stun -> 10s");
        expect(rules::adaptive_udp_timeout_ms(rules::Protocol::quic, 8443, 60000) == 30000, "149D: quic -> 30s");
        expect(rules::adaptive_udp_timeout_ms(std::nullopt, 443, 60000) == 30000, "149D: port 443 -> 30s");
        expect(rules::adaptive_udp_timeout_ms(std::nullopt, 9999, 60000) == 60000, "149D: unknown -> fallback 60s");

        // Per-flow idle timeout override on udp::FlowTable
        udp::FlowTable table(udp::Mapping::endpoint_independent, udp::Filtering::endpoint_independent, {16, 8, 60000});
        auto f_dns = table.open_send({{10, 0, 0, 2}, 40001}, {{1, 1, 1, 1}, 53}, 1000);
        auto f_gen = table.open_send({{10, 0, 0, 2}, 40002}, {{1, 1, 1, 1}, 9999}, 1000);
        expect(f_dns && f_gen, "149D: open two UDP NAT flows");
        expect(table.finish_send(f_dns->first, f_dns->second, true, 1000).has_value(), "149D: finish dns send");
        expect(table.finish_send(f_gen->first, f_gen->second, true, 1000).has_value(), "149D: finish gen send");
        expect(table.set_flow_idle_ms(f_dns->first, 10000), "149D: set 10s idle override on dns flow");
        auto exp1 = table.expire(12000);
        expect(exp1 && *exp1 == 1 && table.size() == 1, "149D: dns flow expired at 10s while generic flow stays alive");
        auto exp2 = table.expire(62000);
        expect(exp2 && *exp2 == 1 && table.size() == 0, "149D: generic flow expired at 60s");

        // route-options udp-timeout-ms / udp-adaptive-timeout + control dashboard-root KDL
        auto ok = config::parse_kdl(R"(
            schema-version 1
            role "client"
            control http-listen="127.0.0.1:19090" dashboard-root="/tmp" metrics=#true
            inbound "local" type="socks5" { listen host="127.0.0.1" port=1080; authentication "none"; }
            outbound "direct" type="direct"
            routing {
                tcp-program sniff-timeout-ms=500 unknown="skip" udp=#true {
                    rule action="route-options" udp-adaptive-timeout=#true { network "udp"; }
                    rule action="route" outbound="direct" udp-timeout-ms=12000 { network "udp"; port 5353; }
                }
                default-outbound "direct"
            }
        )");
        expect(ok.has_value(), ok ? "149D: kdl ok" : "149D: kdl failed: " + ok.error());
        if (ok) {
            expect(ok->control_http && ok->control_http->dashboard_root == "/tmp", "149D: control dashboard-root parsed");
            expect(ok->ordered_tcp && ok->ordered_tcp->rules.size() == 2 &&
                   ok->ordered_tcp->rules[0].udp_adaptive_timeout &&
                   ok->ordered_tcp->rules[1].udp_timeout_ms == 12000, "149D: udp timeout options parsed");
        }
    }
}

auto main() -> int {
    test_socks4_parser_and_kdl();
    test_fixed_udp_kdl();
    test_protocol_gaps_kdl_and_hopping();
    test_adaptive_udp_timeout_and_dashboard_kdl();
    if (failures) {
        std::cerr << "batch149-unit FAILED (" << failures << " failures)\n";
        return 1;
    }
    std::cout << "batch149-unit PASSED\n";
    return 0;
}
