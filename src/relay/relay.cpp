module;
#include <proxy/proxy_macros.h>
#include <boost/capy/buffers.hpp>
#include <boost/capy/cond.hpp>
#include <boost/capy/ex/run_async.hpp>
#include <boost/capy/task.hpp>
#include <boost/corosio/io_context.hpp>
#include <boost/corosio/delay.hpp>
#include <boost/corosio/backend.hpp>
#include <boost/corosio/tcp_acceptor.hpp>
#include <boost/corosio/tcp_socket.hpp>
#include <boost/corosio/endpoint.hpp>
#include <boost/corosio/ipv4_address.hpp>
#include <boost/corosio/ipv6_address.hpp>
#include <boost/corosio/timeout.hpp>
#include <boost/corosio/udp_socket.hpp>
#include <netinet/in.h>
#include <sys/socket.h>
#include <cerrno>

module relay;
import proxy.v4;
import std;
import socks5;
import rules;
import rules.rule_input;
import http.connect;
import dns.message;
import relay.dns_backend;
import dns.local_config;
import corosio;
import relay.dns_state;

namespace relay {
    using namespace std::chrono_literals;

    auto Server::set_fixed_tcp_target(std::string_view host,std::uint16_t port) -> bool {
        if (running || (listener && listener->is_open()) || !sessions.empty() || !workers.empty() ||
            host.empty() || host.size()>253 || !port) return false;
        auto authority=host.contains(':') ? "["+std::string(host)+"]:"+std::to_string(port) :
            std::string(host)+":"+std::to_string(port);
        auto parsed=http::parse_destination_authority(authority);
        if (parsed.status!=http::ConnectStatus::accepted) return false;
        socks5::Request target;
        target.status=socks5::Status::accepted;
        target.port=port;
        if (parsed.kind==http::HostKind::domain) {
            target.address_type=3;
            target.address_length=static_cast<std::uint8_t>(parsed.host.size());
            std::ranges::copy(parsed.host,target.address.begin());
        } else {
            target.address_type=parsed.kind==http::HostKind::ipv4 ? 1 : 4;
            target.address_length=parsed.kind==http::HostKind::ipv4 ? 4 : 16;
            std::ranges::copy_n(parsed.address.begin(),target.address_length,target.address.begin());
        }
        fixed_tcp_target=std::move(target);
        return true;
    }

    auto Server::serve_session(std::unique_ptr<Session> session) -> capy::task<> {
        auto const& policy=session->route_snapshot ? session->route_snapshot->matcher : this->policy;
#ifdef NEXUS_ENABLE_SNELL
        if(inbound_type==Inbound::snell) {
            co_await (borrowed_snell_inbound ? *borrowed_snell_inbound : snell_inbound)(*session,context,policy);co_return;
        }
#endif
#ifdef NEXUS_ENABLE_ANYTLS
        if (inbound_type==Inbound::anytls) {
            co_await (borrowed_anytls_inbound ? *borrowed_anytls_inbound : anytls_inbound)(*session,context,policy);
            co_return;
        }
#endif
#ifdef NEXUS_ENABLE_SHADOWTLS
        if (inbound_type==Inbound::shadowtls) {
            co_await (borrowed_shadowtls_inbound ? *borrowed_shadowtls_inbound : shadowtls_inbound)(*session,context,policy);
            co_return;
        }
#endif
#ifdef NEXUS_ENABLE_TROJAN
        if (inbound_type==Inbound::trojan) {
            co_await (borrowed_trojan_inbound ? *borrowed_trojan_inbound : trojan_inbound)(*session,context,policy);
            co_return;
        }
#endif
#ifdef NEXUS_ENABLE_VLESS
        if (inbound_type==Inbound::vless) {
            co_await (borrowed_vless_inbound ? *borrowed_vless_inbound : vless_inbound)(*session,context,policy);
            co_return;
        }
#endif
#ifdef NEXUS_ENABLE_SS2022
        if (inbound_type==Inbound::shadowsocks) {
            co_await (borrowed_shadowsocks_inbound ? *borrowed_shadowsocks_inbound : shadowsocks_inbound)(*session,context,policy);
            co_return;
        }
#endif
#ifdef NEXUS_ENABLE_NAIVE
        if (inbound_type==Inbound::naive) {
            co_await (borrowed_naive_inbound ? *borrowed_naive_inbound : naive_inbound)(*session,context,policy);
            co_return;
        }
        if (inbound_type==Inbound::http && (http_modern_tcp_enabled || borrowed_http_modern_inbound)) {
            co_await (borrowed_http_modern_inbound ? *borrowed_http_modern_inbound : http_modern_inbound)(*session,context,policy);
            co_return;
        }
#endif
        if (inbound_type==Inbound::fixed_tcp) {
            if (!fixed_unix_target.empty()) co_await serve_fixed_unix(*session,context,fixed_unix_target);
            else co_await serve_fixed_tcp(*session,context,policy,*fixed_tcp_target);
            co_return;
        }
        if (inbound_type==Inbound::redirect || inbound_type==Inbound::tproxy) {
            co_await serve_transparent_tcp(*session,context,policy,bound_listener,inbound_type==Inbound::tproxy,redirect_tcp_dns);
            co_return;
        }
        session->inspect_source_owner(policy);
        auto mode=inbound_type==Inbound::mixed ? ProxyHandshake::mixed :
            inbound_type==Inbound::http ? ProxyHandshake::http : ProxyHandshake::socks5;
        co_await handshake(*session,context,policy,mode,credentials);
    }

#ifdef NEXUS_DNS_SHARED
    auto Server::bind_shared_dns(SharedDnsGeneration& generation,std::size_t group,std::size_t reader_base)
        -> std::expected<void,std::error_code> {
        if (running || (listener && listener->is_open()) || !sessions.empty() || !workers.empty())
            return std::unexpected(std::make_error_code(std::errc::operation_in_progress));
        if (!generation.cache().supports_binding(group,reader_base,1) || generation.registry().sealed())
            return std::unexpected(std::make_error_code(std::errc::invalid_argument));
        std::vector<dns_hp_experiment::ViewRegistry::Profile> profiles;
        DnsRouting local{{DnsServer{}},{},0};
        auto const& routing=dns_routing ? *dns_routing : local;
        try {
            profiles.reserve(routing.servers.size());
            for (std::size_t index=0;index<routing.servers.size();++index) {
                auto profile=generation.registry().register_profile(routing,index);
                if (!profile) return std::unexpected(std::make_error_code(std::errc::invalid_argument));
                profiles.push_back(*profile);
            }
        } catch (std::bad_alloc const&) { return std::unexpected(std::make_error_code(std::errc::not_enough_memory)); }
#ifdef NEXUS_DNS_RESPONSE
        auto has_response_program=policy::dns_has_response_program(routing.rules);
        auto* response_cache=has_response_program ? generation.ensure_response_cache() : nullptr;
        if (has_response_program && !response_cache)
            return std::unexpected(std::make_error_code(std::errc::not_enough_memory));
#endif
        dns.reset();
        if (owned_dns_generation.get()!=&generation) owned_dns_generation.reset();
        dns_group=&generation.cache(); dns_group_index=group; dns_reader_base=reader_base;
        dns_coordinator=&generation.coordinator(); dns_view_registry=&generation.registry();
#ifdef NEXUS_DNS_RESPONSE
        dns_response_cache=response_cache;
#endif
        dns_local_registry=&generation.local_registry();
        dns_profiles=std::move(profiles); dns_optimistic=routing.optimistic_cache_seconds!=0;
        return {};
    }
#endif

#ifdef NEXUS_TEST_DNS_GROUP
    auto Server::set_dns_group_for_test(dns_hp_experiment::GroupSnapshot& owner,std::size_t group,std::size_t reader_base
#ifdef NEXUS_TEST_DNS_GROUP_REFRESH
        ,dns::detail::RefreshBudget* refresh_budget
#endif
        )
        -> std::expected<void,std::error_code> {
        if (running || (listener && listener->is_open()) || !sessions.empty() || !workers.empty())
            return std::unexpected(std::make_error_code(std::errc::operation_in_progress));
        if (!owner.supports_binding(group,reader_base,1))
            return std::unexpected(std::make_error_code(std::errc::invalid_argument));
        dns.reset(); dns_group=&owner; dns_group_index=group; dns_reader_base=reader_base;
#ifdef NEXUS_TEST_DNS_GROUP_REFRESH
        dns_refresh_budget=refresh_budget;
#endif
        return {};
    }
#ifdef NEXUS_TEST_DNS_COORDINATOR
    auto Server::set_dns_coordinator_for_test(dns_hp_experiment::Coordinator& coordinator,
        dns_hp_experiment::ViewRegistry& registry,bool optimistic) -> std::expected<void,std::error_code> {
        if (running || (listener && listener->is_open()) || !sessions.empty() || !workers.empty())
            return std::unexpected(std::make_error_code(std::errc::operation_in_progress));
        if (!dns_routing) return std::unexpected(std::make_error_code(std::errc::invalid_argument));
        std::vector<dns_hp_experiment::ViewRegistry::Profile> profiles;
        try {
            profiles.reserve(dns_routing->servers.size());
            for (std::size_t index=0;index<dns_routing->servers.size();++index) {
                auto profile=registry.register_profile(*dns_routing,index);
                if (!profile) return std::unexpected(std::make_error_code(std::errc::invalid_argument));
                profiles.push_back(*profile);
            }
        } catch (std::bad_alloc const&) { return std::unexpected(std::make_error_code(std::errc::not_enough_memory)); }
        dns.reset(); dns_coordinator=&coordinator; dns_view_registry=&registry;
        dns_profiles=std::move(profiles); dns_optimistic=optimistic;
        return {};
    }
#endif
#endif
#ifdef NEXUS_ENABLE_FAKEIP
    auto Server::protects_fakeip(std::span<std::uint8_t const> address) const -> bool {
        if (!fakeip) return false;
        auto protected_address=fakeip->contains(address);
        return !protected_address || *protected_address;
    }

    auto Server::set_fakeip(std::shared_ptr<dns::FakeIpShared> owner,std::uint64_t view)
        -> std::expected<void,std::error_code> {
        if (running || (listener && listener->is_open()) || !sessions.empty() || !workers.empty())
            return std::unexpected(std::make_error_code(std::errc::operation_in_progress));
        if (!owner || !owner->sealed()) return std::unexpected(std::make_error_code(std::errc::invalid_argument));
        fakeip=std::move(owner); fakeip_view=view;
        return {};
    }
#endif
    auto Server::set_reverse_cache(std::shared_ptr<dns::ReverseCache> owner)
        -> std::expected<void,std::error_code> {
        if (running || (listener && listener->is_open()) || !sessions.empty() || !workers.empty())
            return std::unexpected(std::make_error_code(std::errc::operation_in_progress));
        reverse_cache=std::move(owner);
        return {};
    }

    auto Server::set_block_rules(std::string_view data, RuleFormat format) -> std::expected<void, std::string> {
        return set_route(data,format,RouteAction::block,!this->outbounds.empty() ? RouteAction::vless : RouteAction::direct);
    }
    auto Server::set_route(std::optional<std::string_view> data, RuleFormat format,
                           RouteAction action, RouteAction fallback) -> std::expected<void, std::string> {
        if (data) {
            RouteRule rule{*data,format,action};
            return set_routes(std::span(&rule,1),fallback);
        }
        return set_routes({},fallback);
    }
    auto Server::set_routes(std::span<RouteRule const> input, RouteAction fallback) -> std::expected<void, std::string> {
        auto valid=[](RouteAction action) { return action==RouteAction::direct || action==RouteAction::block || action==RouteAction::vless; };
        if (!valid(fallback) || std::ranges::any_of(input,[&](auto const& rule) { return !valid(rule.action); }))
            return std::unexpected("invalid route action");
        std::vector<IndexedRouteRule> indexed;
        indexed.reserve(input.size());
        for (auto const& rule : input) indexed.push_back({rule.data,rule.format,static_cast<std::size_t>(rule.action)});
        return set_indexed_routes(indexed,static_cast<std::size_t>(fallback));
    }

#ifdef NEXUS_TEST_SOURCE_ROUTE
    auto Server::set_source_policy_for_test(rules::RouteMatcher replacement) -> bool {
        if (running || (listener && listener->is_open()) || !sessions.empty() || !workers.empty()) return false;
        policy=std::move(replacement);
        return true;
    }
#endif

    auto Server::set_socks5_credentials(std::string_view username, std::string_view password)
        -> std::expected<void, std::string> {
        if (this->running || (this->listener && this->listener->is_open()) || !this->sessions.empty() || !this->workers.empty())
            return std::unexpected("stop the server before changing authentication");
        auto valid = [](std::string_view value) {
            return !value.empty() && value.size() <= 255 && std::all_of(value.begin(), value.end(),
                [](unsigned char c) { return c >= 32 && c <= 126; });
        };
        if (!valid(username) || !valid(password)) return std::unexpected("credentials must be 1..255 printable ASCII bytes");
        Credentials result;
        std::copy(username.begin(), username.end(), result.username.begin());
        std::copy(password.begin(), password.end(), result.password.begin());
        result.username_size = static_cast<std::uint8_t>(username.size());
        result.password_size = static_cast<std::uint8_t>(password.size());
        this->credentials = result;
        return {};
    }

    auto Server::clear_socks5_credentials() -> std::expected<void, std::string> {
        if (this->running || (this->listener && this->listener->is_open()) || !this->sessions.empty() || !this->workers.empty())
            return std::unexpected("stop the server before changing authentication");
        this->credentials.reset();
        return {};
    }

    auto Server::set_dns_upstream(std::array<std::uint8_t,4> address, std::uint16_t port)
        -> std::expected<void,std::error_code> {
        if (this->running || (this->listener && this->listener->is_open()) || !this->sessions.empty() || !this->workers.empty())
            return std::unexpected(std::make_error_code(std::errc::operation_in_progress));
        if (!port) return std::unexpected(std::make_error_code(std::errc::invalid_argument));
        DnsServer server; std::copy(address.begin(),address.end(),server.address.begin()); server.port=port;
        return set_dns_routing({{server},{},0});
    }
    auto Server::set_dns_upstream(std::array<std::uint8_t,16> address, std::uint16_t port)
        -> std::expected<void,std::error_code> {
        if (this->running || (this->listener && this->listener->is_open()) || !this->sessions.empty() || !this->workers.empty())
            return std::unexpected(std::make_error_code(std::errc::operation_in_progress));
        if (!port) return std::unexpected(std::make_error_code(std::errc::invalid_argument));
        DnsServer server{address,true,port};
        return set_dns_routing({{server},{},0});
    }
    auto Server::set_dns_routing(DnsRouting routing) -> std::expected<void,std::error_code> {
        if (this->running || (this->listener && this->listener->is_open()) || !this->sessions.empty() || !this->workers.empty())
            return std::unexpected(std::make_error_code(std::errc::operation_in_progress));
        if (this->max_bootstrap_index && *this->max_bootstrap_index>=routing.resolver_count())
            return std::unexpected(std::make_error_code(std::errc::invalid_argument));
        if (routing.servers.empty() || routing.servers.size()>4096 || routing.final>=routing.servers.size() || routing.rules.size()>max_tunnel_outbounds)
            return std::unexpected(std::make_error_code(std::errc::invalid_argument));
        if (routing.view_finals.size()>4096 || std::ranges::any_of(routing.view_finals,[&](auto index) {
            return index>=routing.servers.size();
        })) return std::unexpected(std::make_error_code(std::errc::invalid_argument));
        if (routing.strategy!=DnsStrategy::automatic && routing.strategy!=DnsStrategy::prefer_ipv4 &&
            routing.strategy!=DnsStrategy::prefer_ipv6 && routing.strategy!=DnsStrategy::ipv4_only && routing.strategy!=DnsStrategy::ipv6_only)
            return std::unexpected(std::make_error_code(std::errc::invalid_argument));
        for (auto& rule : routing.rules) {
            if (!policy::normalize_dns_rule(rule,routing.servers.size()))
                return std::unexpected(std::make_error_code(std::errc::invalid_argument));
        }
        if (!policy::validate_dns_response_tags(routing.rules) || !policy::validate_dns_concurrency(routing.rules))
            return std::unexpected(std::make_error_code(std::errc::invalid_argument));
        std::vector<policy::DependencyEdge> dependencies;
        dependencies.reserve(routing.servers.size());
        for (std::size_t i=0;i<routing.servers.size();++i) {
            auto const& server=routing.servers[i];
            if (server.host.empty()) {
                if (server.resolver) return std::unexpected(std::make_error_code(std::errc::invalid_argument));
                continue;
            }
            auto hostname=server.host;
            if (hostname.ends_with('.')) hostname.pop_back();
            if (!server.port || !server.resolver || *server.resolver>=routing.servers.size() ||
                !rules::normalize_rule({"domain-suffix",hostname}))
                return std::unexpected(std::make_error_code(std::errc::invalid_argument));
            dependencies.push_back({i,*server.resolver});
        }
        if (!policy::dependency_order(routing.servers.size(),dependencies))
            return std::unexpected(std::make_error_code(std::errc::invalid_argument));
        this->dns_routing=std::move(routing);
        this->dns.reset();
#if defined(NEXUS_DNS_SHARED) || defined(NEXUS_TEST_DNS_COORDINATOR)
        dns_coordinator=nullptr; dns_view_registry=nullptr; dns_profiles.clear();
#endif
#ifdef NEXUS_DNS_SHARED
        dns_group=nullptr; dns_local_registry=nullptr; owned_dns_generation.reset();
#endif
        return {};
    }

    auto Server::set_direct_connect_timeout(std::uint32_t timeout_ms) -> std::expected<void,std::string> {
        if (running || (listener && listener->is_open()) || !sessions.empty() || !workers.empty())
            return std::unexpected("stop the server before changing the outbound");
        if (!timeout_ms || timeout_ms>3600000) return std::unexpected("invalid connect timeout");
        direct_connect_timeout_ms=timeout_ms;
        return {};
    }

    auto Server::add_vless(std::string_view host, std::uint16_t port, std::string_view uuid_file,
                           std::string_view server_name, std::string_view ca_file, TlsKeyExchange key_exchange, std::optional<std::size_t> bootstrap, std::optional<Reality> reality, bool vision, std::uint32_t timeout_ms,TcpSocketOptions tcp_options,std::optional<HttpUpgradeTransport> transport,std::optional<GrpcTransport> grpc,bool fast_open,TlsFingerprint fingerprint,std::optional<std::uint16_t> record_size_limit,bool packetaddr,bool fixed_udp,std::optional<xhttp::Profile> xhttp,std::span<std::array<std::uint8_t,32> const> pins,QuicEchOptions const& ech,config::OutboundTlsFragment const& tls_fragment,std::span<std::string const> alpn) -> std::expected<std::size_t, std::string> {
        if (this->running || (this->listener && this->listener->is_open()) || !this->sessions.empty() || !this->workers.empty())
            return std::unexpected("stop the server before changing the outbound");
#ifdef NEXUS_ENABLE_VLESS
        if (this->outbounds.size()>=max_tunnel_outbounds) return std::unexpected("too many VLESS outbounds");
        if (bootstrap && (!this->dns_routing || *bootstrap>=this->dns_routing->resolver_count())) return std::unexpected("invalid bootstrap resolver");
        if (xhttp && (vision || transport || grpc || fast_open || packetaddr || fixed_udp))
            return std::unexpected("invalid VLESS XHTTP outbound options");
#ifndef NEXUS_ENABLE_XHTTP_VLESS
        if (xhttp) return std::unexpected("VLESS XHTTP outbound is unavailable in this build");
#endif
        auto factory=
#ifdef NEXUS_ENABLE_XHTTP_VLESS
            xhttp ? make_vless_xhttp_factory(host,port,uuid_file,server_name,ca_file,key_exchange,bootstrap,timeout_ms,tcp_options,
                std::move(*xhttp),fingerprint,record_size_limit,reality,pins,ech,this->dns_routing.has_value()) :
#endif
            make_vless_factory(host,port,uuid_file,server_name,ca_file,key_exchange,bootstrap,reality,vision,timeout_ms,tcp_options,
                std::move(transport),std::move(grpc),fast_open,fingerprint,record_size_limit,packetaddr,fixed_udp,pins,ech,this->dns_routing.has_value(),tls_fragment,alpn);
        if (!factory) return std::unexpected(factory.error());
        auto index=this->outbounds.size()+2;
        this->outbounds.push_back(std::move(*factory));
        if (bootstrap && (!this->max_bootstrap_index || *bootstrap>*this->max_bootstrap_index)) this->max_bootstrap_index=bootstrap;
        return index;
#else
        (void)host; (void)port; (void)uuid_file; (void)server_name; (void)ca_file; (void)key_exchange; (void)bootstrap; (void)reality; (void)vision; (void)timeout_ms; (void)tcp_options; (void)transport; (void)grpc; (void)fast_open; (void)fingerprint; (void)record_size_limit; (void)packetaddr; (void)fixed_udp; (void)xhttp; (void)pins; (void)ech; (void)tls_fragment; (void)alpn;
        return std::unexpected("VLESS outbound is not yet available in this build");
#endif
    }
    auto Server::prepare_vless(std::string_view host, std::uint16_t port, std::string_view uuid_file,
                               std::string_view server_name, std::string_view ca_file, TlsKeyExchange key_exchange, std::optional<std::size_t> bootstrap, std::optional<Reality> reality, bool vision, std::uint32_t timeout_ms,TcpSocketOptions tcp_options,std::optional<HttpUpgradeTransport> transport,std::optional<GrpcTransport> grpc,bool fast_open,TlsFingerprint fingerprint,std::optional<std::uint16_t> record_size_limit,bool packetaddr,bool fixed_udp) -> std::expected<void, std::string> {
        if (this->running || (this->listener && this->listener->is_open()) || !this->sessions.empty() || !this->workers.empty())
            return std::unexpected("stop the server before changing the outbound");
#ifdef NEXUS_ENABLE_VLESS
        if (bootstrap && (!this->dns_routing || *bootstrap>=this->dns_routing->resolver_count())) return std::unexpected("invalid bootstrap resolver");
        auto factory=make_vless_factory(host,port,uuid_file,server_name,ca_file,key_exchange,bootstrap,reality,vision,timeout_ms,tcp_options,std::move(transport),std::move(grpc),fast_open,fingerprint,record_size_limit,packetaddr,fixed_udp);
        if (!factory) return std::unexpected(factory.error());
        std::vector<TunnelFactory> factories;
        factories.push_back(std::move(*factory));
        this->outbounds=std::move(factories);
        this->max_bootstrap_index=bootstrap;
        return set_route({},RuleFormat::kdl,RouteAction::block,RouteAction::vless);
#else
        (void)host; (void)port; (void)uuid_file; (void)server_name; (void)ca_file; (void)key_exchange; (void)bootstrap; (void)reality; (void)vision; (void)timeout_ms; (void)tcp_options; (void)transport; (void)grpc; (void)fast_open; (void)fingerprint; (void)record_size_limit; (void)packetaddr; (void)fixed_udp;
        return std::unexpected("VLESS outbound is not yet available in this build");
#endif
    }

    auto Server::add_shadowsocks(std::string_view host,std::uint16_t port,std::span<std::uint8_t const> key,std::optional<std::size_t> bootstrap,bool udp_over_tcp,std::uint32_t timeout_ms,TcpSocketOptions tcp_options,bool fast_open,
        std::span<std::array<std::uint8_t,32> const> identity_keys,ShadowsocksCipher cipher,bool udp_native)
        -> std::expected<std::size_t,std::string> {
        if (running || (listener && listener->is_open()) || !sessions.empty() || !workers.empty())
            return std::unexpected("stop the server before changing the outbound");
#ifdef NEXUS_ENABLE_SS2022
        if (outbounds.size()>=max_tunnel_outbounds) return std::unexpected("too many tunnel outbounds");
        if (bootstrap && (!dns_routing || *bootstrap>=dns_routing->resolver_count())) return std::unexpected("invalid bootstrap resolver");
        auto factory=make_shadowsocks_factory(host,port,key,bootstrap,udp_over_tcp,timeout_ms,tcp_options,fast_open,identity_keys,cipher,udp_native);
        if (!factory) return std::unexpected(factory.error());
        auto index=outbounds.size()+2; outbounds.push_back(std::move(*factory));
        if (bootstrap && (!max_bootstrap_index || *bootstrap>*max_bootstrap_index)) max_bootstrap_index=bootstrap;
        return index;
#else
        (void)host; (void)port; (void)key; (void)bootstrap; (void)udp_over_tcp; (void)timeout_ms; (void)tcp_options; (void)fast_open; (void)identity_keys; (void)cipher; (void)udp_native;
        return std::unexpected("Shadowsocks 2022 outbound is not available in this build");
#endif
    }

    auto Server::prepare_vless_inbound(std::string_view certificate,std::string_view key,
            std::span<std::string const> users, bool vision, std::optional<RealityInbound> reality,
            std::span<std::string const> names,std::optional<HttpUpgradeTransport> transport,std::optional<GrpcTransport> grpc,std::optional<xhttp::Profile> xhttp,std::optional<config::InboundMultiplexConfig> multiplex) -> std::expected<void,std::string> {
        if (running || (listener && listener->is_open()) || !sessions.empty() || !workers.empty()) return std::unexpected("server is running");
#ifdef NEXUS_ENABLE_VLESS
        auto fallback_resolver=reality ? reality->fallback_resolver : std::nullopt;
        if (fallback_resolver && (!dns_routing || *fallback_resolver>=dns_routing->servers.size())) return std::unexpected("invalid Reality fallback resolver");
        if (xhttp && (vision || transport || grpc || (multiplex && multiplex->enabled)))
            return std::unexpected("invalid VLESS XHTTP inbound options");
#ifndef NEXUS_ENABLE_XHTTP_VLESS
        if (xhttp) return std::unexpected("VLESS XHTTP inbound is unavailable in this build");
#else
        if (xhttp && xhttp->endpoint.version==xhttp::HttpVersion::http3) {
            if (reality) return std::unexpected("VLESS XHTTP HTTP/3 requires ordinary TLS");
            auto prepared=prepare_xhttp3(certificate,key,users,names,std::move(*xhttp));
            if (prepared) vless_inbound={};
            return prepared;
        }
#endif
        auto prepared=
#ifdef NEXUS_ENABLE_XHTTP_VLESS
            xhttp ? make_vless_xhttp_inbound_factory(certificate,key,users,names,std::move(*xhttp),std::move(reality),inbound_tls_runtime) :
#endif
            make_vless_inbound_factory(certificate,key,users,vision,std::move(reality),names,std::move(transport),std::move(grpc),std::move(multiplex),inbound_tls_runtime);
        if (!prepared) return std::unexpected(prepared.error());
#ifdef NEXUS_ENABLE_XHTTP_VLESS
        xhttp3_inbound.reset();
#endif
        vless_inbound=std::move(*prepared);
        vless_xhttp_inbound=xhttp.has_value();
        if (fallback_resolver && (!max_bootstrap_index || *fallback_resolver>*max_bootstrap_index)) max_bootstrap_index=fallback_resolver;
        return {};
#else
        (void)vision; (void)reality; (void)names; (void)transport; (void)grpc; (void)xhttp; (void)multiplex;
        return std::unexpected("VLESS inbound is not available in this build");
#endif
    }

    auto Server::prepare_shadowsocks_inbound(std::span<std::uint8_t const> key,std::span<ShadowsocksUserKey const> users,ShadowsocksCipher cipher,std::optional<config::InboundMultiplexConfig> multiplex)
        -> std::expected<void,std::string> {
        if (running || (listener && listener->is_open()) || !sessions.empty() || !workers.empty()) return std::unexpected("server is running");
#ifdef NEXUS_ENABLE_SS2022
        if (shadowsocks_inbound) return std::unexpected("Shadowsocks 2022 inbound is already configured");
        auto prepared=make_shadowsocks_inbound_factory(key,users,cipher,std::move(multiplex));
        if (!prepared) return std::unexpected(prepared.error());
        shadowsocks_inbound=std::move(*prepared); return {};
#else
        (void)key; (void)users; (void)cipher; (void)multiplex; return std::unexpected("Shadowsocks 2022 inbound is not available in this build");
#endif
    }

}
