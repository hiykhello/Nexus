#include <csignal>
#include <string.h>
#ifdef NEXUS_ENABLE_SS2022
#include <boost/capy/buffers.hpp>
#include <boost/capy/cond.hpp>
#include <boost/capy/ex/run_async.hpp>
#include <boost/capy/task.hpp>
#include <boost/corosio/backend.hpp>
#include <boost/corosio/io_context.hpp>
#include <boost/corosio/tcp_acceptor.hpp>
#include <boost/corosio/tcp_socket.hpp>
#include <boost/corosio/udp_socket.hpp>
#include <boost/corosio/resolver.hpp>
#include <boost/corosio/timeout.hpp>
#include <boost/corosio/delay.hpp>
#include <boost/corosio/ipv4_address.hpp>
#include <boost/corosio/ipv6_address.hpp>
#endif

import std;
import nexus.proxy;
import nexus.rulefile;
import nexus.config;
#ifdef NEXUS_ENABLE_SS2022
import nexus.crypto;
import nexus.rules;
import nexus.dns.message;
import nexus.dns.cache;
import nexus.shadowsocks.udp_dispatch;
#include "udp_inbound.hpp"
#endif

namespace {
    struct SecretKey {
        std::array<std::uint8_t,32> bytes{};
        ~SecretKey() { explicit_bzero(bytes.data(),bytes.size()); }
    };
    auto decode_key(std::span<char const> input, std::span<std::uint8_t> output) -> bool {
        if (!input.empty() && input.back()=='\n') input=input.first(input.size()-1);
        if (input.size()!=((output.size()+2)/3)*4) return false;
        auto digit=[](char c) -> int {
            if (c>='A' && c<='Z') return c-'A';
            if (c>='a' && c<='z') return c-'a'+26;
            if (c>='0' && c<='9') return c-'0'+52;
            if (c=='+') return 62;
            if (c=='/') return 63;
            return -1;
        };
        std::size_t out=0;
        for (std::size_t i=0;i<input.size();i+=4) {
            int a=digit(input[i]), b=digit(input[i+1]);
            int c=input[i+2]=='=' ? -1 : digit(input[i+2]);
            int d=input[i+3]=='=' ? -1 : digit(input[i+3]);
            auto remaining=output.size()-out;
            if (a<0 || b<0 || (remaining>1 && c<0) || (remaining>2 && d<0) ||
                (remaining==1 && (input[i+2]!='=' || input[i+3]!='=' || (b&15))) ||
                (remaining==2 && (input[i+3]!='=' || (c&3)))) return false;
            output[out++]=static_cast<std::uint8_t>((a<<2)|(b>>4));
            if (remaining>1) output[out++]=static_cast<std::uint8_t>((b<<4)|(c>>2));
            if (remaining>2) output[out++]=static_cast<std::uint8_t>((c<<6)|d);
        }
        return true;
    }
    volatile std::sig_atomic_t stopped = 0;
    extern "C" auto handle_signal(int) -> void { stopped = 1; }
}

auto nexus_run(int argc, char** argv) -> int {
    if (argc == 2 && std::string_view(argv[1]) == "--help") {
        std::cout << "usage: nexus run <loopback-port> [kdl|beve <block-rules>]\n"
                     "       nexus run --config <config.kdl>\n";
        return 0;
    }
    if (argc != 2 && argc != 3 && argc != 4) {
        std::cerr << "usage: nexus run <loopback-port> [kdl|beve <block-rules>]\n"
                     "       nexus run --config <config.kdl>\n";
        return 2;
    }
    unsigned port = 0, workers = 1;
    auto inbound = nexus::proxy::Inbound::socks5;
    if ((argc == 3 && std::string_view(argv[1]) != "--config") ||
        (argc != 3 && std::string_view(argv[1]) == "--config")) {
        std::cerr << "--config accepts exactly one path\n";
        return 2;
    } else if (argc == 2 || std::string_view(argv[1]) != "--config") {
        auto text = std::string_view(argv[1]);
        auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), port);
        if (error != std::errc{} || end != text.data() + text.size() || port == 0 || port > 65535) {
            std::cerr << "port must be an integer from 1 to 65535\n";
            return 2;
        }
    }
    if (argc == 4 && std::string_view(argv[2]) != "kdl" && std::string_view(argv[2]) != "beve") {
        std::cerr << "rule format must be kdl or beve\n";
        return 2;
    }
    auto created = nexus::proxy::Server::create();
    if (!created) { std::cerr << "cannot initialize proxy: " << created.error().message() << '\n'; return 1; }
    struct Listener { std::unique_ptr<nexus::proxy::Server> server; std::uint16_t port; nexus::proxy::Inbound inbound; bool ipv6=false; };
    std::vector<Listener> listeners;
#ifdef NEXUS_ENABLE_SS2022
    std::unique_ptr<UdpInbounds> udp_inbounds;
    std::optional<nexus::proxy::DnsRouting> udp_dns;
#endif
    listeners.push_back({std::move(*created),static_cast<std::uint16_t>(port),inbound});
    auto& server=*listeners.front().server;
    if (argc == 4) {
        auto format = std::string_view(argv[2]);
        auto input = nexus::rulefile::read_regular_file(argv[3]);
        if (!input) { std::cerr << input.error() << '\n'; return 1; }
        auto result = server.set_block_rules(*input, format == "kdl" ? nexus::proxy::RuleFormat::kdl : nexus::proxy::RuleFormat::beve);
        if (!result) { std::cerr << "invalid block rules: " << result.error() << '\n'; return 1; }
    } else if (argc == 3 && std::string_view(argv[1]) == "--config") {
        auto input = nexus::rulefile::read_regular_file(argv[2]);
        if (!input) { std::cerr << "configuration: " << input.error() << '\n'; return 1; }
        auto config = nexus::config::parse_kdl(*input);
        if (!config) { std::cerr << "configuration: " << config.error() << '\n'; return 1; }
        workers=config->workers;
        listeners.front().port=config->inbounds.front().port;
        listeners.front().ipv6=config->inbounds.front().listen_ipv6;
        auto convert_inbound=[](nexus::config::Inbound type) {
            return type==nexus::config::Inbound::mixed ? nexus::proxy::Inbound::mixed :
                type==nexus::config::Inbound::vless ? nexus::proxy::Inbound::vless :
                type==nexus::config::Inbound::shadowsocks ? nexus::proxy::Inbound::shadowsocks : nexus::proxy::Inbound::socks5;
        };
        listeners.front().inbound=convert_inbound(config->inbounds.front().type);
        for (std::size_t i=1; i<config->inbounds.size(); ++i) {
            auto next=nexus::proxy::Server::create();
            if (!next) { std::cerr << "cannot initialize proxy: " << next.error().message() << '\n'; return 1; }
            auto const& entry=config->inbounds[i];
            listeners.push_back({std::move(*next),entry.port,convert_inbound(entry.type),entry.listen_ipv6});
        }
        std::vector<std::string> rules_data;
        std::vector<std::size_t> rule_data_index;
        if (!config->routes.empty()) {
            std::error_code path_error;
            auto config_path=std::filesystem::absolute(argv[2],path_error);
            if (path_error) { std::cerr << "configuration path: " << path_error.message() << '\n'; return 1; }
            std::vector<std::string> paths;
            std::size_t total=0;
            for (auto const& route : config->routes) {
                auto previous=std::ranges::find(paths,route.file.path);
                if (previous!=paths.end()) {
                    rule_data_index.push_back(static_cast<std::size_t>(previous-paths.begin()));
                    continue;
                }
                auto rules=nexus::rulefile::read_regular_file((config_path.parent_path()/route.file.path).string());
                if (!rules) { std::cerr << "routing rules: " << rules.error() << '\n'; return 1; }
                total+=rules->size();
                if (total>8*1024*1024) { std::cerr << "routing rules exceed 8 MiB total\n"; return 1; }
                rule_data_index.push_back(rules_data.size());
                paths.push_back(route.file.path);
                rules_data.push_back(std::move(*rules));
            }
        }
#ifdef NEXUS_ENABLE_SS2022
        std::vector<std::unique_ptr<SecretKey>> udp_keys(listeners.size());
#endif
        auto configure=[&](nexus::proxy::Server& server, std::size_t index) -> int {
            if (config->dns_upstream) {
                auto const& dns=*config->dns_upstream;
                std::array<std::uint8_t,4> v4{};
                std::copy_n(dns.address.begin(),4,v4.begin());
                auto result=dns.ipv6 ? server.set_dns_upstream(dns.address,dns.port) : server.set_dns_upstream(v4,dns.port);
                if (!result) { std::cerr << "DNS configuration: " << result.error().message() << '\n'; return 1; }
            }
            if (config->dns) {
                nexus::proxy::DnsRouting routing;
                routing.final=config->dns->final;
                routing.disable_cache=config->dns->disable_cache;
                routing.edns=config->dns->edns;
                switch (config->dns->strategy) {
                    case nexus::config::DnsStrategy::automatic: break;
                    case nexus::config::DnsStrategy::prefer_ipv4: routing.strategy=nexus::proxy::DnsStrategy::prefer_ipv4; break;
                    case nexus::config::DnsStrategy::prefer_ipv6: routing.strategy=nexus::proxy::DnsStrategy::prefer_ipv6; break;
                    case nexus::config::DnsStrategy::ipv4_only: routing.strategy=nexus::proxy::DnsStrategy::ipv4_only; break;
                    case nexus::config::DnsStrategy::ipv6_only: routing.strategy=nexus::proxy::DnsStrategy::ipv6_only; break;
                }
                for (auto const& server : config->dns->servers) {
                    nexus::proxy::DnsServer entry;
                    if (server.upstream) entry={server.upstream->address,server.upstream->ipv6,server.upstream->port,
                                                server.upstream->tcp,server.upstream->host,server.upstream->resolver};
                    routing.servers.push_back(entry);
                }
                for (auto const& rule : config->dns->rules) routing.rules.push_back({rule.domain,rule.suffix,rule.server});
                auto result=server.set_dns_routing(std::move(routing));
                if (!result) { std::cerr << "DNS configuration: " << result.error().message() << '\n'; return 1; }
            }
            for (auto const& named : config->vless_outbounds) {
                auto const& outbound=named.config;
                auto exchange=outbound.key_exchange==nexus::config::TlsKeyExchange::x25519 ? nexus::proxy::TlsKeyExchange::x25519 :
                    outbound.key_exchange==nexus::config::TlsKeyExchange::x25519_mlkem768 ?
                    nexus::proxy::TlsKeyExchange::x25519_mlkem768 : nexus::proxy::TlsKeyExchange::x25519_mlkem768_only;
                auto prepared=server.add_vless(outbound.host,outbound.port,outbound.uuid_file,outbound.server_name,outbound.ca_file,exchange,outbound.bootstrap_index);
                if (!prepared) { std::cerr << "configuration: " << prepared.error() << '\n'; return 1; }
            }
            for (auto const& named : config->shadowsocks_outbounds) {
                auto const& outbound=named.config;
                auto file=nexus::rulefile::read_private_file(outbound.key_file);
                if (!file) { std::cerr << "shadowsocks key: " << file.error() << '\n'; return 1; }
                SecretKey key;
                auto size=outbound.method=="2022-blake3-aes-128-gcm" ? 16U : 32U;
                auto bytes=std::span(key.bytes).first(size);
                if (!decode_key(file->bytes(),bytes)) { std::cerr << "shadowsocks key: invalid base64 or key length\n"; return 1; }
                auto prepared=server.add_shadowsocks(outbound.host,outbound.port,bytes,outbound.bootstrap_index);
                if (!prepared) { std::cerr << "configuration: " << prepared.error() << '\n'; return 1; }
            }
            auto const& entry=config->inbounds[index];
            if (entry.shadowsocks) {
                auto const& inbound=*entry.shadowsocks;
                auto file=nexus::rulefile::read_private_file(inbound.key_file);
                if (!file) { std::cerr << "shadowsocks inbound key: " << file.error() << '\n'; return 1; }
                SecretKey key;
                auto size=inbound.method=="2022-blake3-aes-128-gcm" ? 16U : 32U;
                auto bytes=std::span(key.bytes).first(size);
                if (!decode_key(file->bytes(),bytes)) { std::cerr << "shadowsocks inbound key: invalid base64 or key length\n"; return 1; }
                auto result=server.prepare_shadowsocks_inbound(bytes);
                if (!result) { std::cerr << "shadowsocks inbound: " << result.error() << '\n'; return 1; }
#ifdef NEXUS_ENABLE_SS2022
                udp_keys[index]=std::make_unique<SecretKey>();
                std::ranges::copy(bytes,udp_keys[index]->bytes.begin());
#endif
            }
            if (entry.vless) {
                std::vector<std::string> users;
                for (auto const& user:entry.vless->users) users.push_back(user.uuid_file);
                auto result=server.prepare_vless_inbound(entry.vless->certificate_file,entry.vless->private_key_file,users);
                if (!result) { std::cerr << "VLESS inbound: " << result.error() << '\n'; return 1; }
            }
            if (entry.password_auth) {
                auto password = nexus::rulefile::read_password_file(entry.password_auth->password_file);
                if (!password) { std::cerr << "authentication: " << password.error() << '\n'; return 1; }
                auto result = server.set_socks5_credentials(entry.password_auth->username, *password);
                if (!result) { std::cerr << "authentication: " << result.error() << '\n'; return 1; }
            }
            std::vector<nexus::proxy::IndexedRouteRule> routes;
            for (std::size_t i=0;i<config->routes.size();++i) {
                auto const& rule=config->routes[i];
                auto format=rule.file.format==nexus::config::RuleFormat::beve ? nexus::proxy::RuleFormat::beve : nexus::proxy::RuleFormat::kdl;
                routes.push_back({rules_data[rule_data_index[i]],format,rule.outbound});
            }
            auto result=server.set_indexed_routes(routes,config->default_outbound);
            if (!result) { std::cerr << "invalid routing: " << result.error() << '\n'; return 1; }
            return 0;
        };
        for (std::size_t i=0; i<listeners.size(); ++i) if (configure(*listeners[i].server,i)) return 1;
#ifdef NEXUS_ENABLE_SS2022
        if (std::ranges::any_of(config->inbounds,[](auto const& item) { return item.shadowsocks.has_value(); })) {
            std::vector<nexus::rules::RouteRule> routes;
            for (std::size_t i=0;i<config->routes.size();++i) {
                auto const& route=config->routes[i];
                auto const& bytes=rules_data[rule_data_index[i]];
                auto parsed=route.file.format==nexus::config::RuleFormat::beve ? nexus::rules::parse_beve(bytes) : nexus::rules::parse_kdl(bytes);
                if (!parsed) { std::cerr << "UDP routing: " << parsed.error().message << '\n'; return 1; }
                routes.push_back({std::move(*parsed),route.outbound});
            }
            auto policy=nexus::rules::RouteMatcher::compile(routes,config->default_outbound,
                2+config->vless_outbounds.size()+config->shadowsocks_outbounds.size());
            if (!policy) { std::cerr << "UDP routing: " << policy.error().message << '\n'; return 1; }
            udp_inbounds=std::make_unique<UdpInbounds>();
            udp_dns=udp_dns_config(*config);
            for (std::size_t i=0;i<config->inbounds.size();++i) {
                auto const& entry=config->inbounds[i];
                if (!entry.shadowsocks) continue;
                auto size=entry.shadowsocks->method=="2022-blake3-aes-128-gcm" ? 16U : 32U;
                auto bytes=std::span(udp_keys[i]->bytes).first(size);
                auto added=udp_inbounds->add(bytes,entry.port,*policy);
                if (!added) { std::cerr << "shadowsocks UDP: " << added.error() << '\n'; return 1; }
            }
        }
#endif
    }
    for (auto& listener : listeners) {
        auto bound=listener.server->start(listener.port,listener.inbound,workers,listener.ipv6);
        if (!bound) {
            std::cerr << "cannot listen: " << bound.error().message() << '\n';
            return 1;
        }
        listener.port=*bound;
    }
#ifdef NEXUS_ENABLE_SS2022
    if (udp_inbounds) {
        if (auto error=udp_inbounds->start(*udp_dns)) { std::cerr << "cannot listen for SS-2022 UDP: " << error.message() << '\n'; return 1; }
    }
#endif
    std::signal(SIGINT, handle_signal);
    std::signal(SIGTERM, handle_signal);
    for (auto const& listener : listeners)
        std::cout << (listener.inbound == nexus::proxy::Inbound::mixed ? "Mixed" : listener.inbound == nexus::proxy::Inbound::vless ? "VLESS/TLS" : listener.inbound == nexus::proxy::Inbound::shadowsocks ? "SS-2022" : "SOCKS5")
                  << " listening on " << (listener.ipv6 ? "[::1]:" : "127.0.0.1:") << listener.port << '\n';
    auto healthy=[&] {
#ifdef NEXUS_ENABLE_SS2022
        if (udp_inbounds && !udp_inbounds->healthy()) return false;
#endif
        return std::ranges::all_of(listeners,[](auto const& item) { return item.server->healthy(); });
    };
    while (!stopped && healthy()) {
        auto wait=std::chrono::milliseconds(std::max<std::size_t>(1,100/listeners.size()));
#ifdef NEXUS_ENABLE_SS2022
        if (udp_inbounds) wait=std::min(wait,std::chrono::milliseconds(5));
#endif
        for (auto& listener : listeners) listener.server->poll(wait);
#ifdef NEXUS_ENABLE_SS2022
        if (udp_inbounds) udp_inbounds->poll(std::chrono::milliseconds(1));
#endif
    }
    auto failed=!healthy();
#ifdef NEXUS_ENABLE_SS2022
    auto udp_failed=udp_inbounds && !udp_inbounds->healthy();
    if (udp_inbounds) udp_inbounds->stop();
#endif
    for (auto& listener : listeners) listener.server->stop();
    if (failed) {
#ifdef NEXUS_ENABLE_SS2022
        if (udp_failed) {
            std::cerr << "shadowsocks UDP listener failed\n";
            return 1;
        }
#endif
        for (auto const& listener : listeners) if (auto failure=listener.server->failure()) {
            std::cerr << "proxy: " << nexus::proxy::describe(failure->kind);
            if (failure->system_error) std::cerr << ": " << failure->system_error.message();
            std::cerr << '\n';
            return 1;
        }
        std::cerr << "proxy worker failed\n";
        return 1;
    }
    return 0;
}
