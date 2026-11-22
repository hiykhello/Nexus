#include <cassert>

import std;
import proxy.tor_outbound;

int main() {
    proxy::tor::Config safe_cfg;
    assert(proxy::tor::validate_config(safe_cfg).has_value());

    proxy::tor::Config remote_cfg{.socks_host = "192.0.2.10"};
    assert(!proxy::tor::validate_config(remote_cfg).has_value());

    auto greet = proxy::tor::build_socks5_greeting(true);
    assert(greet == std::vector<std::uint8_t>({0x05, 0x02, 0x00, 0x02}));

    auto iso = *proxy::tor::build_socks5_isolation_auth("stream-1", "tok");
    assert(iso[0] == 0x01 && iso[1] == 8);

    constexpr std::string_view kOnion = "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion";
    auto req = *proxy::tor::build_socks5_connect_domain(kOnion, 443);
    assert(req[0] == 0x05 && req[1] == 0x01 && req[3] == 0x03 && req[4] == kOnion.size());

    auto auth_cmd = *proxy::tor::build_control_authenticate({.cookie_hex = "deadbeef0102"});
    assert(auth_cmd == "AUTHENTICATE deadbeef0102\r\n");
    assert(proxy::tor::build_control_newnym() == "SIGNAL NEWNYM\r\n");
    assert(*proxy::tor::build_control_getinfo("status/bootstrap-phase") == "GETINFO status/bootstrap-phase\r\n");
    assert(!proxy::tor::build_control_getinfo("bad\r\nSIGNAL SHUTDOWN").has_value());

    auto rep = *proxy::tor::parse_control_reply(
        "250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=100 TAG=done SUMMARY=\"Done\"\r\n250 OK\r\n");
    assert(rep.ok && rep.code == 250 && rep.bootstrap_progress == 100);

    std::println("batch158 unit tests (tor outbound bridge) passed");
    return 0;
}
