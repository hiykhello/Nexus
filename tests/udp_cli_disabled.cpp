import std;
import config;
import cli.udp;

auto main() -> int {
#ifndef MCPP_FEATURE_SS2022
    cli::UdpRuntime udp;
    config::Config config;
    if (udp.configure(config,{},{})) return 1;
    config.inbounds.push_back({.name="local",.port=1080,.type=config::Inbound::socks5});
    if (udp.configure(config,{},{})) return 2;
    config.inbounds.push_back({.name="ss",.port=8388,.type=config::Inbound::shadowsocks,
        .shadowsocks=config::ShadowsocksInbound{}});
    if (!udp.configure(config,{},{})) return 3;
    config.inbounds.back().type=config::Inbound::socks5;
    if (!udp.configure(config,{},{})) return 4;
    config.inbounds.back().type=config::Inbound::shadowsocks;
    config.inbounds.back().shadowsocks.reset();
    if (!udp.configure(config,{},{})) return 5;
#endif
    return 0;
}
