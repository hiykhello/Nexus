export module cli.outbounds;
import std;
import config;
import cli.dns_transports;
import relay;

export namespace cli {
    auto configure_outbounds(relay::Server&,config::Config const&,std::span<DnsProtection const>) -> std::expected<void,std::string>;
}
