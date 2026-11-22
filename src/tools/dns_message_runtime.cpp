module;
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

module cli.dns_message_runtime;
import std;
import logging;
import logging.cli;
import config;
import cli.dns_transports;
import cli.outbounds;
import proxy;
import dns.local_config;
import dns.corosio_query;
import cli.dns_fakeip_backend;
import dns.message_program;
import dns.reverse;
import dns.message_cache;
import dns.message_tcp_listener;
import dns.message_udp_listener;
import dns.tls_query;
import dns.https_query;
import nexus.thirdparty.corosio;
import state.fakeip;
import rulefile;
import state.dns_cache;
import state.serde;

#include "dns_cache_state.hpp"
#include "dns_cache_unified.hpp"

namespace cli {
#ifdef NEXUS_ENABLE_FAKEIP
#include "fakeip_state.hpp"
#endif
    struct DnsMessageRuntime::Impl {
        logging::Runtime const& logs_;

        explicit Impl(logging::Runtime const& logs) : logs_(logs) {}

        struct Program {
            config::DnsRouting routing;
            dns::MessageLocalSource local{dns::system_local_snapshots()};
#ifdef NEXUS_ENABLE_FAKEIP
            std::shared_ptr<dns::FakeIpShared> fakeip;
            std::optional<dns::FakeIpPublisher> publisher;
#endif
            std::vector<dns::MessageUpstream> upstreams;
            std::shared_ptr<dns::MessageCache> cache;
            std::shared_ptr<dns::ReverseCache> reverse_cache;
            std::shared_ptr<DnsCacheState> cache_state;
            std::optional<DnsCacheState::Scope> cache_scope;
            std::optional<UnifiedDnsCache> unified_cache;
            bool restored=false;
            std::optional<std::uint64_t> observed_view;
            dns::MessageRuleSource rules;
            dns::MessageUpstreamSnapshot resolver{};
            bool proxy_routes=false;

            Program(config::DnsRouting const& config,dns::MessageRuleSource source)
                :routing(config),cache(std::make_shared<dns::MessageCache>(std::chrono::seconds(config.optimistic_cache_seconds))),
                 rules(std::move(source)) {}

#ifdef NEXUS_ENABLE_FAKEIP
            auto initialize_fakeip(config::DnsFakeIp const& spec) -> std::expected<void,std::string> {
                auto mode=spec.initialize ? dns::FakeIpHistoryStoreMode::create_new :
                    dns::FakeIpHistoryStoreMode::open_existing;
                std::optional<dns::FakeIpIpv6Range> ipv6;
                if (spec.ipv6) ipv6.emplace(spec.ipv6->first,spec.ipv6->second);
                if (spec.unified) {
                    auto owner=unified_fakeip(spec,ipv6);
                    if (!owner) return std::unexpected(std::move(owner.error()));
                    fakeip=std::move(*owner);
                    return {};
                }
                auto store=dns::FakeIpHistoryStore::open_with_credentials(spec.state_directory,mode,ipv6);
                if (!store) return std::unexpected("cannot open FakeIP history ("+
                    std::to_string(static_cast<int>(store.error()))+")");
                auto first=spec.first, last=spec.last;
                if (last-first>=3) {++first;--last;}
                auto ttl=std::chrono::seconds(spec.ttl_seconds);
                auto grace=std::chrono::seconds(5);
                auto owner=dns::start_fakeip(std::move(*store),{spec.first,spec.last,first,last,ttl,grace,ipv6},grace);
                if (!owner) return std::unexpected("cannot prepare FakeIP history");
                fakeip=std::move(*owner);
                return {};
            }

            auto configure_fakeip(config::DnsFakeIp const& spec,Impl const* previous)
                -> std::expected<void,std::string> {
                if (previous) {
                    auto const& running=previous->program_;
                    if (!running || !running->routing.fakeip) return std::unexpected("adding FakeIP requires restart");
                    auto const& active=*running->routing.fakeip;
                    if (active.first!=spec.first || active.last!=spec.last || active.ipv6!=spec.ipv6 ||
                        active.ttl_seconds!=spec.ttl_seconds || active.state_directory!=spec.state_directory ||
                        active.unified!=spec.unified || active.per_mapping!=spec.per_mapping)
                        return std::unexpected("changing the FakeIP pool or history requires restart");
                    fakeip=running->fakeip;
                } else {
                    auto initialized=initialize_fakeip(spec);
                    if (!initialized) return initialized;
                }
                publisher.emplace(*fakeip,spec.first,spec.ttl_seconds,0,spec.ipv6.has_value());
                upstreams[spec.upstream].fakeip=&*publisher;
                return {};
            }
#endif
        };

        struct ResolverView {
            std::shared_ptr<Program> program;
            std::shared_ptr<dns::detail::TransportSnapshot const> transports;
            std::vector<dns::MessageUpstream> upstreams;
            dns::MessageUpstreamSnapshot state;

            ResolverView(std::shared_ptr<Program> owner,std::shared_ptr<dns::detail::TransportSnapshot const> selection)
                :program(std::move(owner)),transports(std::move(selection)),upstreams(program->upstreams),
                 state(program->resolver) {
                for (std::size_t i=0;i<upstreams.size();++i) upstreams[i].protection=transports->queries[i];
                state.upstreams=upstreams;
            }
        };
        mutable std::shared_ptr<ResolverView const> resolver_view_;
        std::optional<nex::corosio::io_context> context_;
        std::unique_ptr<proxy::Server> routes_;
        dns::TlsQueryMaintenance dns_tls_maintenance_;
        std::shared_ptr<Program> program_;
        bool admitted_=false;
        std::unique_ptr<dns::MessageTcpListener> tcp_;
        std::unique_ptr<dns::MessageUdpListener> udp_;
        std::thread worker_;
        std::mutex worker_mutex_;
        std::condition_variable worker_changed_;
        bool polling_=false, paused_=false, stopping_=false, draining_=false;
        std::atomic<bool> healthy_{true},drained_{false};

        auto executor() noexcept -> nex::corosio::io_context& {
            return routes_ ? routes_->executor_context() : *context_;
        }

        auto drive() noexcept -> void {
            auto& io=executor();
            auto ex=io.get_executor();
            ex.on_work_started();
            std::unique_lock lock(worker_mutex_);
            auto next_maintenance=std::chrono::steady_clock::now()+std::chrono::seconds(1);
            auto next_flush=std::chrono::steady_clock::now()+std::chrono::milliseconds(
                program_ ? program_->routing.cache_flush_interval_ms : 60000u);
            while (!stopping_) {
                worker_changed_.wait(lock,[this] {return stopping_ || (admitted_ && !paused_);});
                if (stopping_) break;
                io.restart();
                polling_=true;
                lock.unlock();
                try {
                    (void)io.run_one_until(next_maintenance);
                    auto now=std::chrono::steady_clock::now();
                    if (now>=next_maintenance) {
                        dns_tls_maintenance_.poll(io,now);
                        next_maintenance=now+std::chrono::seconds(1);
                    }
                    if (now>=next_flush) {
                        save_checkpoint();
                        next_flush=now+std::chrono::milliseconds(
                            program_ ? program_->routing.cache_flush_interval_ms : 60000u);
                    }
                    healthy_.store(tcp_->healthy() && (!udp_ || udp_->healthy()),std::memory_order_release);
                    if (draining_) {
                        if (udp_ && udp_->drained()) udp_.reset();
                        drained_.store(!udp_ && tcp_->drained(),std::memory_order_release);
                    }
                } catch (...) {
                    healthy_.store(false,std::memory_order_release);
                    lock.lock();
                    break;
                }
                lock.lock();
                polling_=false;
                worker_changed_.notify_all();
            }
            polling_=false;
            worker_changed_.notify_all();
            ex.on_work_finished();
        }

        // Transfer exclusive use of the context to the control thread for a
        // lifecycle mutation. stop() interrupts the backend's blocking wait.
        auto synchronize(std::function_ref<void()> action) -> void {
            std::unique_lock lock(worker_mutex_);
            paused_=true;
            if (polling_) {
                executor().stop();
                worker_changed_.wait(lock,[this] {return !polling_;});
            }
            action();
            paused_=false;
            worker_changed_.notify_all();
        }

        static auto endpoint(config::DnsListen const& listen) -> nex::corosio::endpoint {
            if (listen.ipv6) return {nex::corosio::ipv6_address(listen.address),listen.port};
            nex::corosio::ipv4_address::bytes_type bytes{};
            std::copy_n(listen.address.begin(),bytes.size(),bytes.begin());
            return {nex::corosio::ipv4_address(bytes),listen.port};
        }

        auto snapshot() const -> dns::MessageRuleSnapshot {
            auto program=program_;
            auto snapshot=program->rules && !program->cache_scope ? program->rules() : dns::MessageRuleSnapshot{};
            if (!snapshot.rules) snapshot.rules={program,&program->routing.rules};
            if (snapshot.transports) {
                if (!resolver_view_ || resolver_view_->program!=program || resolver_view_->transports!=snapshot.transports)
                    resolver_view_=std::make_shared<ResolverView>(program,snapshot.transports);
                snapshot.resolver={resolver_view_,&resolver_view_->state};
            } else {
                resolver_view_.reset();
                snapshot.resolver={program,&program->resolver};
            }
            if (program->cache_state) snapshot.view=0;
            if (program->unified_cache) {
                auto view=snapshot.view.value_or(0);
                program->observed_view=view;
                if (!std::exchange(program->restored,true)) {
                    auto restored=program->unified_cache->restore(*program->cache,view);
                    if (!restored) logs_.emit(logging::Level::warn,logging::Domain::dns,120,{},
                        "DNS message cache restore failed: {}",logs_.private_text(restored.error()));
                }
            }
            return snapshot;
        }

    public:
        ~Impl() {stop();}

        auto prepare(config::Config const& config,std::span<DnsProtection const> protection,
            dns::MessageRuleSource source,Impl const* previous,std::shared_ptr<dns::ReverseCache> reverse) -> std::expected<void,std::string> {
            if (!config.dns || !config.dns->listen) return {};
            auto const& routing=*config.dns;
#ifndef NEXUS_ENABLE_FAKEIP
            (void)previous;
            if (routing.fakeip) return std::unexpected("FakeIP requires the dns-fakeip build feature");
#endif
            if (program_ || routing.servers.empty() || routing.final>=routing.servers.size() ||
                protection.size()!=routing.servers.size()) return std::unexpected("invalid DNS message configuration");

            auto program=std::make_shared<Program>(routing,std::move(source));
            program->proxy_routes=uses_proxy_dns(config.dns);
            if (previous && previous->tcp_ && previous->program_ &&
                endpoint(*previous->program_->routing.listen)==endpoint(*routing.listen)) {
                auto const& running=*previous->program_;
                if (program->proxy_routes!=running.proxy_routes)
                    return std::unexpected("changing the listener's DNS transport owner requires restart");
                auto equivalent=[](config::DnsServer const& a,config::DnsServer const& b) {
                    if (a.upstream && b.upstream && a.upstream->detour_group && b.upstream->detour_group) {
                        auto same_group=a;
                        same_group.upstream->detour_index=b.upstream->detour_index;
                        return same_group==b;
                    }
                    return a==b;
                };
                if (program->proxy_routes && (!std::ranges::equal(routing.servers,running.routing.servers,equivalent) ||
                    routing.edns!=running.routing.edns || routing.strategy!=running.routing.strategy ||
                    routing.disable_cache!=running.routing.disable_cache ||
                    routing.optimistic_cache_seconds!=running.routing.optimistic_cache_seconds))
                    return std::unexpected("changing upstreams of a layered DNS listener requires restart");
            } else if (program->proxy_routes) {
                auto created=proxy::Server::create();
                if (!created) return std::unexpected(created.error().message());
                if (auto outbounds=configure_outbounds(**created,config,protection); !outbounds)
                    return std::unexpected("cannot prepare DNS listener outbounds: "+outbounds.error());
                routes_=std::move(*created);
            }
            program->upstreams.reserve(routing.servers.size());
            for (auto const& entry : routing.servers) {
                dns::MessageUpstream upstream{};
                if (!entry.upstream) upstream.local=&program->local;
                else {
                    auto const& value=*entry.upstream;
                    upstream.tcp=value.tcp;
                    upstream.host=value.host;
                    upstream.port=value.port;
                    upstream.resolver=value.resolver;
                    if (value.host.empty()) upstream.endpoint=endpoint({value.address,value.ipv6,value.port});
                }
                upstream.protection=protection[program->upstreams.size()];
                program->upstreams.push_back(std::move(upstream));
            }
#ifdef NEXUS_ENABLE_FAKEIP
            if (routing.fakeip) {
                auto configured=program->configure_fakeip(*routing.fakeip,previous);
                if (!configured) return configured;
            }
#endif
            if (!routing.unified_cache_root.empty()) {
                try {program->unified_cache.emplace(routing,program->upstreams);}
                catch (std::runtime_error const& error) {return std::unexpected(error.what());}
            } else if (!routing.message_cache_directory.empty()) {
                auto const& path=routing.message_cache_directory;
                program->cache_scope.emplace(routing,program->upstreams);
                if (previous && previous->program_ && previous->program_->routing.message_cache_directory==path) {
                    auto const& running=*previous->program_;
                    program->cache_state=running.cache_state;
                    if (endpoint(*running.routing.listen)==endpoint(*routing.listen) &&
                        program->cache_scope->identity==running.cache_scope->identity)
                        program->cache=running.cache;
                } else {
                    auto opened=DnsCacheState::open(path);
                    if (!opened) return std::unexpected(std::move(opened.error()));
                    program->cache_state=std::move(*opened);
                    auto restored=program->cache_state->restore(*program->cache,*program->cache_scope);
                    if (!restored) logs_.emit(logging::Level::warn,logging::Domain::dns,120,{},
                        "DNS message cache restore failed: {}",logs_.private_text(restored.error()));
                }
            }
            program->reverse_cache=std::move(reverse);
            program->resolver={program->upstreams,routing.final,program->cache.get(),routing.disable_cache,program->reverse_cache.get()};
            program_=std::move(program);
            return {};
        }

#ifdef NEXUS_ENABLE_FAKEIP
        auto fakeip() const -> std::shared_ptr<dns::FakeIpShared> {
            return program_ ? program_->fakeip : nullptr;
        }
#endif
        auto start(bool admit) -> std::expected<void,std::string> {
            if (!program_) return {};
            if (tcp_ || udp_) return std::unexpected("DNS listeners already started");
            admitted_=admit;
            auto address=endpoint(*program_->routing.listen);
            auto source=[this] {return snapshot();};
            if (program_->proxy_routes) {
                if (!routes_) return std::unexpected("DNS listener has no routing executor");
                auto prepared=routes_->prepare_routing(1);
                if (!prepared) return std::unexpected(prepared.error().message());
                auto activated=routes_->activate_context();
                if (!activated) return std::unexpected(activated.error().message());
            } else {
#if BOOST_COROSIO_HAVE_LIBURING
                context_.emplace(nex::corosio::uring);
#else
                context_.emplace();
#endif
            }
            auto& io=routes_ ? routes_->executor_context() : *context_;
            auto timeout=std::chrono::seconds(10);
            std::span<config::DnsRule const> rules;
            std::span<dns::MessageUpstream const> upstreams;
            tcp_=std::make_unique<dns::MessageTcpListener>(
                io,rules,upstreams,0,256,timeout,128,nullptr,false,nullptr,nullptr,source);
            udp_=std::make_unique<dns::MessageUdpListener>(
                io,rules,upstreams,0,256,timeout,nullptr,false,nullptr,nullptr,source);
            if (auto error=tcp_->start(address,&admitted_)) {stop();return std::unexpected("DNS TCP listen: "+error.message());}
            if (auto error=udp_->start(address,&admitted_)) {stop();return std::unexpected("DNS UDP listen: "+error.message());}
            try {
                worker_=std::thread([this] {drive();});
            } catch (std::system_error const& error) {
                stop();
                return std::unexpected("DNS executor: "+error.code().message());
            }
            return {};
        }

        auto admit() noexcept -> void {
            std::lock_guard lock(worker_mutex_);
            if (admitted_) return;
            admitted_=true;
            worker_changed_.notify_all();
        }

        auto same_binding(Impl const& other) const noexcept -> bool {
            return tcp_ && program_ && other.program_ &&
                endpoint(*program_->routing.listen)==endpoint(*other.program_->routing.listen);
        }

        auto replace_program(Impl& candidate) noexcept -> void {
            synchronize([&] {
                if (program_ && candidate.program_ && program_->cache!=candidate.program_->cache) {
                    if (program_->unified_cache) save_checkpoint();
                    program_->cache->stop_refreshes();
                }
                resolver_view_.reset();
                program_=std::move(candidate.program_);
            });
        }

        auto has_listeners() const noexcept -> bool {return bool(tcp_);}

        auto save_checkpoint() noexcept -> void {
            if (!program_ || (!program_->cache_state && !program_->observed_view)) return;
            try {
                auto saved=program_->unified_cache ?
                    program_->unified_cache->save(*program_->cache,*program_->observed_view) :
                    program_->cache_state->save(*program_->cache,*program_->cache_scope);
                if (!saved) logs_.emit(logging::Level::warn,logging::Domain::dns,121,{},
                    "DNS message cache checkpoint failed: {}",logs_.private_text(saved.error()));
            } catch (std::bad_alloc const&) {
                logs_.emit(logging::Level::error,logging::Domain::dns,121,{},
                    "DNS message cache checkpoint: out of memory");
            }
        }

        auto checkpoint() noexcept -> void {synchronize([this] {save_checkpoint();});}

        auto healthy() const noexcept -> bool {
            return healthy_.load(std::memory_order_acquire);
        }

        auto begin_drain() noexcept -> void {
            if (!tcp_) return;
            synchronize([this] {
                draining_=true;
                tcp_->begin_drain();
                if (udp_) udp_->begin_drain();
            });
        }

        auto drained() const noexcept -> bool {
            return !tcp_ || drained_.load(std::memory_order_acquire);
        }

        auto stop() noexcept -> void {
            if (worker_.joinable()) {
                {
                    std::lock_guard lock(worker_mutex_);
                    stopping_=true;
                    if (polling_) executor().stop();
                    worker_changed_.notify_all();
                }
                worker_.join();
            }
            if (program_ && (tcp_ || udp_)) program_->cache->stop_refreshes();
            if (tcp_) tcp_->stop();
            if (udp_) udp_->stop();
            if (routes_) {
                routes_->stop();
            } else if (tcp_ || udp_) {
                dns::stop_https_queries(*context_);
                context_->restart();
                (void)context_->run();
            }
            tcp_.reset();
            udp_.reset();
            routes_.reset();
            context_.reset();
            resolver_view_.reset();
            program_.reset();
            stopping_=false;
            draining_=false;
            drained_.store(false,std::memory_order_relaxed);
            healthy_.store(true,std::memory_order_relaxed);
        }
    };

    DnsMessageRuntime::DnsMessageRuntime(logging::Runtime const& logs)
        :impl_(std::make_unique<Impl>(logs)) {}
    DnsMessageRuntime::~DnsMessageRuntime()=default;
    auto DnsMessageRuntime::checkpoint() noexcept -> void {impl_->checkpoint();}

    auto DnsMessageRuntime::prepare(config::Config const& value,std::span<DnsProtection const> protection,
        dns::MessageRuleSource source,DnsMessageRuntime const* previous,std::shared_ptr<dns::ReverseCache> reverse) -> std::expected<void,std::string> {
        return impl_->prepare(value,protection,std::move(source),previous ? previous->impl_.get() : nullptr,std::move(reverse));
    }
#ifdef NEXUS_ENABLE_FAKEIP
    auto DnsMessageRuntime::fakeip() const -> std::shared_ptr<dns::FakeIpShared> {return impl_->fakeip();}
#endif
    auto DnsMessageRuntime::start(bool admit) -> std::expected<void,std::string> {return impl_->start(admit);}
    auto DnsMessageRuntime::admit() noexcept -> void {impl_->admit();}
    auto DnsMessageRuntime::same_binding(DnsMessageRuntime const& other) const noexcept -> bool {
        return impl_->same_binding(*other.impl_);
    }
    auto DnsMessageRuntime::replace_program(DnsMessageRuntime& candidate) noexcept -> void {
        impl_->replace_program(*candidate.impl_);
    }
    auto DnsMessageRuntime::swap(DnsMessageRuntime& other) noexcept -> void {impl_.swap(other.impl_);}
    auto DnsMessageRuntime::has_listeners() const noexcept -> bool {return impl_->has_listeners();}
    auto DnsMessageRuntime::healthy() const noexcept -> bool {return impl_->healthy();}
    auto DnsMessageRuntime::begin_drain() noexcept -> void {impl_->begin_drain();}
    auto DnsMessageRuntime::drained() noexcept -> bool {return impl_->drained();}
    auto DnsMessageRuntime::stop() noexcept -> void {impl_->stop();}
}
