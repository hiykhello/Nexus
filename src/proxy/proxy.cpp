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
#include <boost/corosio/socket_option.hpp>
#include <boost/corosio/endpoint.hpp>
#include <boost/corosio/ipv4_address.hpp>
#include <boost/corosio/ipv6_address.hpp>
#include <boost/corosio/resolver.hpp>
#include <boost/corosio/timeout.hpp>
#include <boost/corosio/udp_socket.hpp>
#include <sys/random.h>

module nexus.proxy;
import proxy.v4;
import std;
import nexus.socks5;
import nexus.rules;
import nexus.http.connect;
import nexus.dns.message;
import nexus.dns.cache;
#include "dns_state.hpp"

#ifdef NEXUS_TEST_START_THROW
extern "C" void nexus_test_start_throw();
#endif

namespace nexus::proxy {
    using namespace std::chrono_literals;

    namespace {
        // Linux may surface a pending connection's network error from accept.
        auto transient_accept_error(std::error_code error) noexcept -> bool {
            return error == std::errc::connection_aborted || error == std::errc::interrupted ||
                error == std::errc::network_down || error == std::errc::protocol_error ||
                error == std::errc::no_protocol_option || error == std::errc::host_unreachable ||
                error == std::errc::operation_not_supported || error == std::errc::network_unreachable ||
                error.default_error_condition() == std::error_condition(EHOSTDOWN, std::generic_category()) ||
                error.default_error_condition() == std::error_condition(ENONET, std::generic_category());
        }
    }

    auto Server::record_failure(RuntimeFailure value) -> void {
        std::lock_guard lock(failure_mutex);
        if (!failure_state) failure_state=value;
    }

    auto Server::get_failure() const -> std::optional<RuntimeFailure> {
        std::lock_guard lock(failure_mutex);
        return failure_state;
    }


    auto Server::serve_session(std::unique_ptr<Session> session) -> capy::task<> {
#ifdef NEXUS_ENABLE_VLESS
        if (inbound_type==Inbound::vless) {
            co_await vless_inbound(*session,context,policy);
            co_return;
        }
#endif
#ifdef NEXUS_ENABLE_SS2022
        if (inbound_type==Inbound::shadowsocks) {
            co_await shadowsocks_inbound(*session,context,policy);
            co_return;
        }
#endif
        co_await handshake(*session,context,policy,mixed,credentials);
    }

    auto Server::accept_loop() -> capy::task<> {
        while (running) {
            auto [error, peer] = co_await listener.accept();
            if (running && transient_accept_error(error)) {
                // Bound retry rate if the kernel repeatedly reports a connection error.
                auto [delay_error] = co_await io::delay(10ms);
                if (delay_error && running) record_failure({FailureKind::accept, delay_error});
                if (delay_error || !running) break;
                continue;
            }
            if (error) {
                if (running) record_failure({FailureKind::accept,error});
                break;
            }
            auto session = std::make_unique<Session>(context);
            session->client = std::move(peer);
            session->dns=dns;
#ifdef NEXUS_TEST_FAKEIP
            session->fakeip=fakeip;
            session->fakeip_view=fakeip_view;
#endif
            auto lease=quota.try_acquire();
            if (!lease) { session->close(); continue; }
            session->quota=std::move(lease);
            session->started = session->touched = Clock::now();
#ifdef NEXUS_ENABLE_VLESS
            session->tunnel_factories=vless;
#endif
            sessions.push_back(session.get());
            session->registry=&sessions;
#ifdef NEXUS_ENABLE_VLESS
            if (inbound_type==Inbound::vless) {
                capy::run_async(context.get_executor(), [] {}, session_error(*session))(serve_session(std::move(session)));
                continue;
            }
#endif
#ifdef NEXUS_ENABLE_SS2022
            if (inbound_type==Inbound::shadowsocks) {
                capy::run_async(context.get_executor(), [] {}, session_error(*session))(serve_session(std::move(session)));
                continue;
            }
#endif
            capy::run_async(context.get_executor(), session->stop.get_token(), [] {}, session_error(*session))(serve_session(std::move(session)));
        }
        running = false;
    }

    Server::Server() = default;
    Server::~Server() { stop(); }
#ifdef NEXUS_TEST_FAKEIP
    auto Server::set_fakeip(std::shared_ptr<dns::FakeIpShared> owner,std::uint64_t view)
        -> std::expected<void,std::error_code> {
        if (running || listener.is_open() || !sessions.empty() || !workers.empty())
            return std::unexpected(std::make_error_code(std::errc::operation_in_progress));
        if (!owner || !owner->sealed()) return std::unexpected(std::make_error_code(std::errc::invalid_argument));
        fakeip=std::move(owner); fakeip_view=view;
        return {};
    }
#endif

    auto Server::create() -> std::expected<std::unique_ptr<Server>, std::error_code> {
        try { return std::make_unique<Server>(); }
        catch (std::system_error const& error) { return std::unexpected(error.code()); }
    }

    auto describe(FailureKind kind) noexcept -> std::string_view {
        switch (kind) {
        case FailureKind::accept: return "accept failed";
        case FailureKind::accept_task: return "accept task failed";
        case FailureKind::worker: return "worker failed";
        }
        return "unknown proxy failure";
    }

    auto Server::set_block_rules(std::string_view data, RuleFormat format) -> std::expected<void, std::string> {
#ifdef NEXUS_ENABLE_VLESS
        return set_route(data,format,RouteAction::block,this->vless && !this->vless->empty() ? RouteAction::vless : RouteAction::direct);
#else
        return set_route(data,format,RouteAction::block,RouteAction::direct);
#endif
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
    auto Server::set_indexed_routes(std::span<IndexedRouteRule const> input, std::size_t fallback) -> std::expected<void, std::string> {
        if (this->running || this->listener.is_open() || !this->sessions.empty() || !this->workers.empty())
            return std::unexpected("stop the server before changing rules");
        std::size_t outbound_count=2;
#ifdef NEXUS_ENABLE_VLESS
        if (this->vless) outbound_count+=this->vless->size();
#endif
        if (fallback>=outbound_count || input.size()>256) return std::unexpected("invalid route action or count");
        std::vector<rules::RouteRule> route_rules;
        std::size_t predicate_count=0;
        for (auto const& rule : input) {
            if (rule.outbound>=outbound_count || (rule.format!=RuleFormat::kdl && rule.format!=RuleFormat::beve))
                return std::unexpected("invalid route action or format");
            auto parsed=rule.format==RuleFormat::kdl ? rules::parse_kdl(rule.data) : rules::parse_beve(rule.data);
            if (!parsed) return std::unexpected(parsed.error().message);
            if (parsed->rules.size()>rules::max_rules-predicate_count) return std::unexpected("too many route predicates");
            predicate_count+=parsed->rules.size();
            if (!parsed->rules.empty()) route_rules.push_back({std::move(*parsed),rule.outbound});
        }
        auto matcher=rules::RouteMatcher::compile(route_rules,fallback,outbound_count);
        if (!matcher) return std::unexpected(matcher.error().message);
        this->policy=std::move(*matcher);
        return {};
    }

    auto Server::set_socks5_credentials(std::string_view username, std::string_view password)
        -> std::expected<void, std::string> {
        if (this->running || this->listener.is_open() || !this->sessions.empty())
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
        if (this->running || this->listener.is_open() || !this->sessions.empty())
            return std::unexpected("stop the server before changing authentication");
        this->credentials.reset();
        return {};
    }

    auto Server::set_dns_upstream(std::array<std::uint8_t,4> address, std::uint16_t port)
        -> std::expected<void,std::error_code> {
        if (this->running || this->listener.is_open() || !this->sessions.empty() || !this->workers.empty())
            return std::unexpected(std::make_error_code(std::errc::operation_in_progress));
        if (!port) return std::unexpected(std::make_error_code(std::errc::invalid_argument));
        DnsServer server; std::copy(address.begin(),address.end(),server.address.begin()); server.port=port;
        return set_dns_routing({{server},{},0});
    }
    auto Server::set_dns_upstream(std::array<std::uint8_t,16> address, std::uint16_t port)
        -> std::expected<void,std::error_code> {
        if (this->running || this->listener.is_open() || !this->sessions.empty() || !this->workers.empty())
            return std::unexpected(std::make_error_code(std::errc::operation_in_progress));
        if (!port) return std::unexpected(std::make_error_code(std::errc::invalid_argument));
        DnsServer server{address,true,port};
        return set_dns_routing({{server},{},0});
    }
    auto Server::set_dns_routing(DnsRouting routing) -> std::expected<void,std::error_code> {
        if (this->running || this->listener.is_open() || !this->sessions.empty() || !this->workers.empty())
            return std::unexpected(std::make_error_code(std::errc::operation_in_progress));
        if (this->max_bootstrap_index && *this->max_bootstrap_index>=routing.servers.size())
            return std::unexpected(std::make_error_code(std::errc::invalid_argument));
        if (routing.servers.empty() || routing.servers.size()>64 || routing.final>=routing.servers.size() || routing.rules.size()>256)
            return std::unexpected(std::make_error_code(std::errc::invalid_argument));
        if (routing.strategy!=DnsStrategy::automatic && routing.strategy!=DnsStrategy::prefer_ipv4 &&
            routing.strategy!=DnsStrategy::prefer_ipv6 && routing.strategy!=DnsStrategy::ipv4_only && routing.strategy!=DnsStrategy::ipv6_only)
            return std::unexpected(std::make_error_code(std::errc::invalid_argument));
        for (auto& rule : routing.rules) {
            auto normalized=rules::normalize_rule({"domain-suffix",rule.domain});
            if (rule.server>=routing.servers.size() || !normalized)
                return std::unexpected(std::make_error_code(std::errc::invalid_argument));
            rule.domain=std::move(normalized->value);
        }
        for (std::size_t start=0;start<routing.servers.size();++start) {
            std::vector<bool> visited(routing.servers.size());
            auto current=start;
            for (;;) {
                auto const& server=routing.servers[current];
                if (server.host.empty()) {
                    if (server.resolver) return std::unexpected(std::make_error_code(std::errc::invalid_argument));
                    break;
                }
                if (!server.port || !server.resolver || *server.resolver>=routing.servers.size() || visited[current] ||
                    !rules::normalize_rule({"domain-suffix",server.host}))
                    return std::unexpected(std::make_error_code(std::errc::invalid_argument));
                visited[current]=true;
                current=*server.resolver;
            }
        }
        this->dns_routing=std::move(routing);
        this->dns.reset();
        return {};
    }

    auto Server::add_vless(std::string_view host, std::uint16_t port, std::string_view uuid_file,
                           std::string_view server_name, std::string_view ca_file, TlsKeyExchange key_exchange, std::optional<std::size_t> bootstrap) -> std::expected<std::size_t, std::string> {
        if (this->running || this->listener.is_open() || !this->sessions.empty() || !this->workers.empty())
            return std::unexpected("stop the server before changing the outbound");
#ifdef NEXUS_ENABLE_VLESS
        if (this->vless && this->vless->size()>=16) return std::unexpected("too many VLESS outbounds");
        if (bootstrap && (!this->dns_routing || *bootstrap>=this->dns_routing->servers.size())) return std::unexpected("invalid bootstrap resolver");
        auto factory=make_vless_factory(host,port,uuid_file,server_name,ca_file,key_exchange,bootstrap);
        if (!factory) return std::unexpected(factory.error());
        auto factories=this->vless ? std::make_shared<std::vector<TunnelFactory>>(*this->vless) :
                                      std::make_shared<std::vector<TunnelFactory>>();
        auto index=factories->size()+2;
        factories->push_back(std::move(*factory));
        this->vless=std::move(factories);
        if (bootstrap && (!this->max_bootstrap_index || *bootstrap>*this->max_bootstrap_index)) this->max_bootstrap_index=bootstrap;
        return index;
#else
        (void)host; (void)port; (void)uuid_file; (void)server_name; (void)ca_file; (void)key_exchange; (void)bootstrap;
        return std::unexpected("VLESS outbound is not yet available in this build");
#endif
    }
    auto Server::prepare_vless(std::string_view host, std::uint16_t port, std::string_view uuid_file,
                               std::string_view server_name, std::string_view ca_file, TlsKeyExchange key_exchange, std::optional<std::size_t> bootstrap) -> std::expected<void, std::string> {
        if (this->running || this->listener.is_open() || !this->sessions.empty() || !this->workers.empty())
            return std::unexpected("stop the server before changing the outbound");
#ifdef NEXUS_ENABLE_VLESS
        if (bootstrap && (!this->dns_routing || *bootstrap>=this->dns_routing->servers.size())) return std::unexpected("invalid bootstrap resolver");
        auto factory=make_vless_factory(host,port,uuid_file,server_name,ca_file,key_exchange,bootstrap);
        if (!factory) return std::unexpected(factory.error());
        auto factories=std::make_shared<std::vector<TunnelFactory>>();
        factories->push_back(std::move(*factory));
        this->vless=std::move(factories);
        this->max_bootstrap_index=bootstrap;
        return set_route({},RuleFormat::kdl,RouteAction::block,RouteAction::vless);
#else
        (void)host; (void)port; (void)uuid_file; (void)server_name; (void)ca_file; (void)key_exchange; (void)bootstrap;
        return std::unexpected("VLESS outbound is not yet available in this build");
#endif
    }

    auto Server::add_shadowsocks(std::string_view host,std::uint16_t port,std::span<std::uint8_t const> key,std::optional<std::size_t> bootstrap)
        -> std::expected<std::size_t,std::string> {
        if (running || listener.is_open() || !sessions.empty() || !workers.empty())
            return std::unexpected("stop the server before changing the outbound");
#ifdef NEXUS_ENABLE_SS2022
        if (vless && vless->size()>=16) return std::unexpected("too many tunnel outbounds");
        if (bootstrap && (!dns_routing || *bootstrap>=dns_routing->servers.size())) return std::unexpected("invalid bootstrap resolver");
        auto factory=make_shadowsocks_factory(host,port,key,bootstrap);
        if (!factory) return std::unexpected(factory.error());
        auto factories=vless ? std::make_shared<std::vector<TunnelFactory>>(*vless) : std::make_shared<std::vector<TunnelFactory>>();
        auto index=factories->size()+2; factories->push_back(std::move(*factory)); vless=std::move(factories);
        if (bootstrap && (!max_bootstrap_index || *bootstrap>*max_bootstrap_index)) max_bootstrap_index=bootstrap;
        return index;
#else
        (void)host; (void)port; (void)key; (void)bootstrap;
        return std::unexpected("Shadowsocks 2022 outbound is not available in this build");
#endif
    }

    auto Server::prepare_vless_inbound(std::string_view certificate,std::string_view key,
            std::span<std::string const> users) -> std::expected<void,std::string> {
        if (running || !workers.empty()) return std::unexpected("server is running");
#ifdef NEXUS_ENABLE_VLESS
        auto prepared=make_vless_inbound_factory(certificate,key,users);
        if (!prepared) return std::unexpected(prepared.error());
        vless_inbound=std::move(*prepared); return {};
#else
        return std::unexpected("VLESS inbound is not available in this build");
#endif
    }

    auto Server::prepare_shadowsocks_inbound(std::span<std::uint8_t const> key) -> std::expected<void,std::string> {
        if (running || listener.is_open() || !sessions.empty() || !workers.empty()) return std::unexpected("server is running");
#ifdef NEXUS_ENABLE_SS2022
        if (shadowsocks_inbound) return std::unexpected("Shadowsocks 2022 inbound is already configured");
        auto prepared=make_shadowsocks_inbound_factory(key);
        if (!prepared) return std::unexpected(prepared.error());
        shadowsocks_inbound=std::move(*prepared); return {};
#else
        (void)key; return std::unexpected("Shadowsocks 2022 inbound is not available in this build");
#endif
    }

    auto Server::start_one(std::uint16_t port, Inbound inbound, bool reuse) -> std::expected<std::uint16_t, std::error_code> {
        if (this->running || this->listener.is_open() || !this->sessions.empty())
            return std::unexpected(std::make_error_code(std::errc::operation_in_progress));
#ifdef NEXUS_ENABLE_VLESS
        if (inbound==Inbound::vless && !vless_inbound) return std::unexpected(std::make_error_code(std::errc::invalid_argument));
#else
        if (inbound==Inbound::vless) return std::unexpected(std::make_error_code(std::errc::operation_not_supported));
#endif
#ifdef NEXUS_ENABLE_SS2022
        if (inbound==Inbound::shadowsocks && !shadowsocks_inbound) return std::unexpected(std::make_error_code(std::errc::invalid_argument));
#else
        if (inbound==Inbound::shadowsocks) return std::unexpected(std::make_error_code(std::errc::operation_not_supported));
#endif
        if (this->credentials && inbound != Inbound::socks5)
            return std::unexpected(std::make_error_code(std::errc::invalid_argument));
        if (this->dns_routing && !this->dns) this->dns=std::make_shared<DnsState>(*this->dns_routing);
        if (auto error = this->listener.open()) return std::unexpected(error);
        if (reuse) {
            if (auto error = this->listener.set_option(io::socket_option::reuse_port(true))) {
                this->listener.close(); return std::unexpected(error);
            }
        }
        if (auto error = this->listener.bind(io::endpoint(io::ipv4_address::loopback(), port))) {
            this->listener.close(); return std::unexpected(error);
        }
        if (auto error = this->listener.listen()) {
            this->listener.close(); return std::unexpected(error);
        }
        this->mixed = inbound == Inbound::mixed;
        this->inbound_type = inbound;
        auto const bound_port = this->listener.local_endpoint().port();
        this->running = true;
        try {
#ifdef NEXUS_TEST_START_THROW
            nexus_test_start_throw();
#endif
            capy::run_async(this->context.get_executor(), [] {}, [state=this](std::exception_ptr) noexcept {
                try { state->record_failure({FailureKind::accept_task,{}}); } catch (...) {}
                state->running=false;
                state->listener.close();
            })(this->accept_loop());
        } catch (...) {
            // Launch can throw before the task and its error handler are installed.
            this->running=false;
            this->listener.close();
            throw;
        }
        return bound_port;
    }

    auto Server::start(std::uint16_t port, Inbound inbound, unsigned count) -> std::expected<std::uint16_t,std::error_code> {
        auto& state=*this;
        if (state.running || state.listener.is_open() || !state.sessions.empty() || !state.workers.empty())
            return std::unexpected(std::make_error_code(std::errc::operation_in_progress));
        if (!count || count>16 || (state.credentials && inbound==Inbound::mixed))
            return std::unexpected(std::make_error_code(std::errc::invalid_argument));
        { std::lock_guard lock(state.failure_mutex); state.failure_state.reset(); }
        if (count==1) return start_one(port,inbound,false);
        state.stopping=false; state.failed=false;
        auto bound=port;
        try {
            for (unsigned i=0;i<count;++i) {
                auto worker=std::make_unique<Server>();
                worker->policy=state.policy;
                worker->credentials=state.credentials;
                worker->dns_routing=state.dns_routing;
#ifdef NEXUS_TEST_FAKEIP
                worker->fakeip=state.fakeip;
                worker->fakeip_view=state.fakeip_view;
#endif
#ifdef NEXUS_ENABLE_VLESS
                worker->vless=state.vless;
                worker->vless_inbound=state.vless_inbound;
#endif
#ifdef NEXUS_ENABLE_SS2022
                worker->shadowsocks_inbound=state.shadowsocks_inbound;
#endif
                worker->quota=state.quota;
                auto result=worker->start_one(bound,inbound,true);
                if (!result) { state.workers.clear(); return std::unexpected(result.error()); }
                bound=*result;
                state.workers.push_back(std::move(worker));
            }
            state.running=true;
            for (auto& worker : state.workers) {
                auto* ptr=worker.get();
                state.threads.emplace_back([&state,ptr] {
                    try {
                        while (!state.stopping.load(std::memory_order_relaxed)) {
                            ptr->poll(20ms);
                            if (!ptr->running) {
                                state.record_failure(ptr->get_failure().value_or(RuntimeFailure{FailureKind::worker,{}}));
                                state.failed=true; state.stopping=true;
                            }
                        }
                        ptr->stop();
                    } catch (...) {
                        try { state.record_failure({FailureKind::worker,{}}); } catch (...) {}
                        state.failed=true; state.stopping=true;
                        ptr->stop();
                    }
                });
            }
        } catch (std::system_error const& error) {
            stop(); return std::unexpected(error.code());
        } catch (...) {
            stop(); throw;
        }
        return bound;
    }

    auto Server::healthy() const noexcept -> bool {
        return this->running && !this->failed.load(std::memory_order_relaxed);
    }

    auto Server::failure() const -> std::optional<RuntimeFailure> { return this->get_failure(); }

    auto Server::poll(std::chrono::milliseconds maximum_wait) -> void {
        auto& state = *this;
        if (!state.workers.empty()) { std::this_thread::sleep_for(std::clamp(maximum_wait,0ms,100ms)); return; }
        state.context.restart();
        (void)state.context.run_for(std::clamp(maximum_wait, 0ms, 100ms));
        auto const now = Clock::now();
        for (auto const& session : state.sessions) {
            auto const expired = session->http_draining ? now - session->http_drain_started >= 5s :
                                 session->relaying ? now - session->touched >= 300s : now - session->started >= 10s;
            if (!session->done && expired) session->close();
        }
    }

    auto Server::stop() noexcept -> void {
        auto& state = *this;
        if (!state.workers.empty()) {
            state.stopping=true;
            for (auto& thread : state.threads) if (thread.joinable()) thread.join();
            state.threads.clear();
            // Workers without threads arise only on a partial thread-start failure.
            for (auto& worker : state.workers) worker->stop();
            state.workers.clear();
            state.running=false;
            return;
        }
        state.running = false;
        state.listener.close();
        for (auto const& session : state.sessions) session->close();
        state.context.restart();
        (void)state.context.run();
    }
}
