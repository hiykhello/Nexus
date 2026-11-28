module cli.dns_message_runtime;
import std;
import functional;
import logging;
import logging.cli;
import config;
import cli.dns_transports;
import cli.outbounds;
import relay;
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
import dns.quic_query;
import corosio;
import state.fakeip;
import rulefile;
import state.dns_cache;
import state.serde;
import cli.dns_cache_unified;
import cli.dns_live_query;

namespace cli {
#ifdef NEXUS_ENABLE_FAKEIP
    auto unified_fakeip(config::DnsFakeIp const&, std::optional<dns::FakeIpIpv6Range>)
        -> std::expected<std::shared_ptr<dns::FakeIpShared>, std::string>;
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
                std::optional<dns::FakeIpIpv6Range> ipv6;
                if (spec.ipv6) ipv6.emplace(spec.ipv6->first,spec.ipv6->second);
                auto owner=unified_fakeip(spec,ipv6);
                if (!owner) return std::unexpected(std::move(owner.error()));
                fakeip=std::move(*owner); return {};
            }

            auto configure_fakeip(config::DnsFakeIp const& spec,Impl const* previous) -> std::expected<void,std::string> {
                if (previous) {
                    auto const& running=previous->program_;
                    if (!running || !running->routing.fakeip) return std::unexpected("adding FakeIP requires restart");
                    auto const& active=*running->routing.fakeip;
                    if (active.first!=spec.first || active.last!=spec.last || active.ipv6!=spec.ipv6 ||
                        active.ttl_seconds!=spec.ttl_seconds || active.state_directory!=spec.state_directory ||
                        active.per_mapping!=spec.per_mapping)
                        return std::unexpected("changing the FakeIP pool or history requires restart");
                    fakeip=running->fakeip;
                } else if (auto initialized=initialize_fakeip(spec); !initialized) return initialized;
                publisher.emplace(*fakeip,spec.first,spec.ttl_seconds,0,spec.ipv6.has_value());
                upstreams[spec.upstream].fakeip=&*publisher; return {};
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
        std::optional<corosio::io_context> context_;
        std::unique_ptr<relay::Server> routes_;
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
        std::atomic<std::uint8_t> reclaim_requested_{0};
        struct PendingLiveQuery {
            std::string name; std::uint16_t qtype = 1; std::string server; std::uint32_t timeout_ms = 5000;
            LiveDnsCompletion finish;
        };
        std::shared_ptr<LiveDnsHookGate> live_hook_gate_;
        std::mutex live_query_mu_;
        std::deque<PendingLiveQuery> live_queries_;
        AsyncDnsCheckpointer checkpointer_;

        auto executor() noexcept -> corosio::io_context& {
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
                    if (auto rl = reclaim_requested_.exchange(0, std::memory_order_acq_rel)) {
                        dns::reap_idle_tls_queries(io, std::chrono::steady_clock::time_point::max());
                        dns::reap_idle_https_queries(io, std::chrono::steady_clock::time_point::max());
                        if (rl >= 2 && program_ && program_->cache) program_->cache->clear_entries();
                    }
                    drain_live_queries(io);
                    if (now>=next_maintenance) { dns_tls_maintenance_.poll(io,now); next_maintenance=now+std::chrono::seconds(1); }
                    if (now>=next_flush) {
                        save_checkpoint();
                        next_flush=now+std::chrono::milliseconds(program_ ? program_->routing.cache_flush_interval_ms : 60000u);
                    }
                    healthy_.store(tcp_->healthy() && (!udp_ || udp_->healthy()),std::memory_order_release);
                    if (draining_) {
                        if (udp_ && udp_->drained()) udp_.reset();
                        drained_.store(!udp_ && tcp_->drained(),std::memory_order_release);
                    }
                } catch (...) { healthy_.store(false,std::memory_order_release); lock.lock(); break; }
                lock.lock(); polling_=false; worker_changed_.notify_all();
            }
            polling_=false; worker_changed_.notify_all(); ex.on_work_finished();
        }

        // Transfer exclusive use of the context to the control thread for a lifecycle mutation.
        auto synchronize(functional::function_ref<void()> action) -> void {
            std::unique_lock lock(worker_mutex_);
            paused_=true;
            if (polling_) { executor().stop(); worker_changed_.wait(lock,[this] {return !polling_;}); }
            action();
            paused_=false; worker_changed_.notify_all();
        }

        static auto endpoint(config::DnsListen const& listen) -> corosio::endpoint {
            if (listen.ipv6) return {corosio::ipv6_address(listen.address),listen.port};
            corosio::ipv4_address::bytes_type bytes{};
            std::copy_n(listen.address.begin(),bytes.size(),bytes.begin());
            return {corosio::ipv4_address(bytes),listen.port};
        }

        auto snapshot() const -> dns::MessageRuleSnapshot {
            auto program=program_;
            auto snapshot=program->rules ? program->rules() : dns::MessageRuleSnapshot{};
            if (!snapshot.rules) snapshot.rules={program,&program->routing.rules};
            if (snapshot.transports) {
                if (!resolver_view_ || resolver_view_->program!=program || resolver_view_->transports!=snapshot.transports)
                    resolver_view_=std::make_shared<ResolverView>(program,snapshot.transports);
                snapshot.resolver={resolver_view_,&resolver_view_->state};
            } else {
                resolver_view_.reset();
                snapshot.resolver={program,&program->resolver};
            }
            if (program->unified_cache) {
                auto view=snapshot.view.value_or(0); program->observed_view=view;
                if (!std::exchange(program->restored,true)) {
                    auto restored=program->unified_cache->restore(*program->cache,view);
                    if (!restored) logs_.emit(logging::Level::warn,logging::Domain::dns,120,{},"DNS message cache restore failed: {}",logs_.private_text(restored.error()));
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
                auto created=relay::Server::create();
                if (!created) return std::unexpected(created.error().message());
                if (auto outbounds=configure_outbounds(**created,config,protection); !outbounds)
                    return std::unexpected("cannot prepare DNS listener outbounds: "+outbounds.error());
                routes_=std::move(*created);
            }
            program->upstreams.reserve(routing.servers.size());
            for (auto const& entry : routing.servers) {
                dns::MessageUpstream upstream{};
                if (entry.kind!=config::DnsServerKind::standard) { upstream.port=53; upstream.endpoint=endpoint({{127,0,0,1},false,53}); }
                else if (!entry.upstream) upstream.local=&program->local;
                else {
                    auto const& v=*entry.upstream;
                    upstream.tcp=v.tcp; upstream.host=v.host; upstream.port=v.port; upstream.resolver=v.resolver;
                    if (v.host.empty()) upstream.endpoint=endpoint({v.address,v.ipv6,v.port});
                }
                upstream.protection=protection[program->upstreams.size()];
                program->upstreams.push_back(std::move(upstream));
            }
#ifdef NEXUS_ENABLE_FAKEIP
            if (routing.fakeip) { if (auto configured=program->configure_fakeip(*routing.fakeip,previous); !configured) return configured; }
#endif
            if (!routing.unified_cache_root.empty()) {
                try {program->unified_cache.emplace(routing,program->upstreams);}
                catch (std::runtime_error const& error) {return std::unexpected(error.what());}
            }
            program->reverse_cache=std::move(reverse);
            program->resolver={program->upstreams,routing.final,program->cache.get(),routing.disable_cache,program->reverse_cache.get(),routing.independent_cache};
            program_=std::move(program);
            return {};
        }

#ifdef NEXUS_ENABLE_FAKEIP
        auto fakeip() const -> std::shared_ptr<dns::FakeIpShared> { return program_ ? program_->fakeip : nullptr; }
#endif
        auto start(bool admit) -> std::expected<void,std::string> {
            if (!program_) return {};
            if (tcp_ || udp_) return std::unexpected("DNS listeners already started");
            admitted_=admit;
            auto address=endpoint(*program_->routing.listen);
            auto source=[this] {return snapshot();};
            if (program_->proxy_routes) {
                if (!routes_) return std::unexpected("DNS listener has no routing executor");
                if (auto p=routes_->prepare_routing(1); !p) return std::unexpected(p.error().message());
                if (auto a=routes_->activate_context(); !a) return std::unexpected(a.error().message());
            } else {
#if BOOST_COROSIO_HAVE_LIBURING
                context_.emplace(corosio::uring);
#else
                context_.emplace();
#endif
            }
            auto& io=routes_ ? routes_->executor_context() : *context_;
            auto timeout=std::chrono::seconds(10);
            std::span<config::DnsRule const> rules; std::span<dns::MessageUpstream const> upstreams;
            tcp_=std::make_unique<dns::MessageTcpListener>(io,rules,upstreams,0,256,timeout,128,nullptr,false,nullptr,nullptr,source);
            udp_=std::make_unique<dns::MessageUdpListener>(io,rules,upstreams,0,256,timeout,nullptr,false,nullptr,nullptr,source);
            if (auto error=tcp_->start(address,&admitted_)) {stop();return std::unexpected("DNS TCP listen: "+error.message());}
            if (auto error=udp_->start(address,&admitted_)) {stop();return std::unexpected("DNS UDP listen: "+error.message());}
            try { worker_=std::thread([this] {drive();}); }
            catch (std::system_error const& error) { stop(); return std::unexpected("DNS executor: "+error.code().message()); }
            register_live_hooks();
            return {};
        }

        auto admit() noexcept -> void { std::lock_guard lock(worker_mutex_); if (!std::exchange(admitted_, true)) worker_changed_.notify_all(); }
        auto same_binding(Impl const& other) const noexcept -> bool {
            return tcp_ && program_ && other.program_ && endpoint(*program_->routing.listen)==endpoint(*other.program_->routing.listen);
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
            if (!program_ || !program_->observed_view) return;
            try {
                auto log_err = [this](std::string const& e) {
                    logs_.emit(logging::Level::warn, logging::Domain::dns, 121, {}, "DNS message cache checkpoint failed: {}", logs_.private_text(e));
                };
                if (program_->unified_cache) {
                    if (auto p = program_->unified_cache->prepare_save(*program_->cache, *program_->observed_view))
                        checkpointer_.submit([pr = program_, item = std::move(*p), log_err] { if (auto s = pr->unified_cache->commit_save(item); !s) log_err(s.error()); });
                }
            } catch (std::bad_alloc const&) {
                logs_.emit(logging::Level::error, logging::Domain::dns, 121, {}, "DNS message cache checkpoint: out of memory");
            }
        }
        auto checkpoint() noexcept -> void {
            synchronize([this] { save_checkpoint(); });
            checkpointer_.flush();
#ifdef NEXUS_ENABLE_FAKEIP
            if (program_ && program_->fakeip) program_->fakeip->flush_store();
#endif
        }
        auto healthy() const noexcept -> bool { return healthy_.load(std::memory_order_acquire); }
        auto begin_drain() noexcept -> void {
            if (tcp_) synchronize([this] { draining_=true; tcp_->begin_drain(); if (udp_) udp_->begin_drain(); });
        }
        auto drained() const noexcept -> bool { return !tcp_ || drained_.load(std::memory_order_acquire); }
        auto reclaim_memory(bool hard) noexcept -> void {
            std::uint8_t want = hard ? 2 : 1, cur = reclaim_requested_.load(std::memory_order_relaxed);
            while (cur < want && !reclaim_requested_.compare_exchange_weak(cur, want, std::memory_order_release)) {}
            std::lock_guard lock(worker_mutex_);
            if (polling_) executor().stop();
        }

        auto drain_live_queries(corosio::io_context& io) -> void {
            std::deque<PendingLiveQuery> batch;
            { std::lock_guard qlk(live_query_mu_); batch.swap(live_queries_); }
            for (auto& q : batch) {
                auto snap = snapshot();
                if (!program_ || !snap.resolver) { q.finish(std::unexpected("dns-unavailable")); continue; }
                std::size_t fb = snap.resolver->fallback;
                bool forced = false;
                if (!q.server.empty()) {
                    auto it = std::ranges::find(program_->routing.servers, q.server, &config::DnsServer::name);
                    if (it == program_->routing.servers.end()) { q.finish(std::unexpected("unknown-server")); continue; }
                    fb = static_cast<std::size_t>(it - program_->routing.servers.begin());
                    forced = true;
                }
                live_dns_detail::dispatch_runtime_live_query(io, std::move(snap), fb, forced,
                    std::move(q.name), q.qtype, q.timeout_ms, std::move(q.finish));
            }
        }
        auto clear_live_cache() noexcept -> void {
            auto run_clear = [this]() noexcept {
                try {
                    if (tcp_ || udp_) {
                        auto& io = executor();
                        dns::reap_idle_tls_queries(io, std::chrono::steady_clock::time_point::max());
                        dns::reap_idle_https_queries(io, std::chrono::steady_clock::time_point::max());
                    }
                    if (program_ && program_->cache) program_->cache->clear();
                    if (program_ && program_->unified_cache) {
                        if (auto r = program_->unified_cache->refresh_epoch(); !r)
                            logs_.emit(logging::Level::warn, logging::Domain::dns, 121, {}, "DNS message cache epoch refresh failed: {}", logs_.private_text(r.error()));
                    }
                } catch (...) {}
            };
            if (worker_.joinable() && std::this_thread::get_id() != worker_.get_id()) synchronize(run_clear);
            else run_clear();
        }
#ifdef NEXUS_ENABLE_FAKEIP
        auto flush_fakeip_unpinned() noexcept -> std::optional<std::size_t> {
            return (program_ && program_->fakeip) ? std::optional(program_->fakeip->flush_unpinned()) : std::nullopt;
        }
#endif
        auto register_live_hooks() -> void {
            live_hook_gate_ = std::make_shared<LiveDnsHookGate>();
            LiveDnsHooks h{.owner = this, .gate = live_hook_gate_, .clear_cache = [this] { clear_live_cache(); }};
#ifdef NEXUS_ENABLE_FAKEIP
            h.flush_fakeip = [this] { return flush_fakeip_unpinned(); };
#endif
            h.submit_query = [this](std::uint64_t, std::string name, std::uint16_t qtype, std::string server,
                std::uint32_t timeout_ms, LiveDnsCompletion finish) -> bool {
                if (!tcp_) return false;
                { std::lock_guard qlk(live_query_mu_); live_queries_.push_back({std::move(name), qtype, std::move(server), timeout_ms, std::move(finish)}); }
                std::lock_guard wlk(worker_mutex_);
                if (polling_) executor().stop();
                return true;
            };
            LiveDnsQueryHub::instance().register_hooks(std::move(h));
        }

        auto stop() noexcept -> void {
            LiveDnsQueryHub::instance().unregister_hooks(this);
            if (live_hook_gate_) { live_hook_gate_->deactivate_and_drain(); live_hook_gate_.reset(); }
            if (worker_.joinable()) {
                { std::lock_guard lock(worker_mutex_); stopping_=true; if (polling_) executor().stop(); worker_changed_.notify_all(); }
                worker_.join();
            }
            { std::lock_guard qlk(live_query_mu_); live_queries_.clear(); }
            if (program_ && (tcp_ || udp_)) program_->cache->stop_refreshes();
            if (tcp_) tcp_->stop(); if (udp_) udp_->stop();
            checkpointer_.stop();
            if (routes_) routes_->stop();
            else if (tcp_ || udp_) {
                dns::stop_tls_queries(*context_); dns::stop_https_queries(*context_); dns::stop_quic_queries(*context_);
                context_->restart(); (void)context_->run();
            }
#ifdef NEXUS_ENABLE_FAKEIP
            if (program_ && program_->fakeip) program_->fakeip->stop_store();
#endif
            tcp_.reset(); udp_.reset(); routes_.reset(); context_.reset(); resolver_view_.reset(); program_.reset();
            stopping_=false; draining_=false; drained_.store(false,std::memory_order_relaxed); healthy_.store(true,std::memory_order_relaxed);
        }
    };

    DnsMessageRuntime::DnsMessageRuntime(logging::Runtime const& logs) : impl_(std::make_unique<Impl>(logs)) {}
    DnsMessageRuntime::~DnsMessageRuntime() = default;
    auto DnsMessageRuntime::checkpoint() noexcept -> void { impl_->checkpoint(); }
    auto DnsMessageRuntime::clear_live_cache() noexcept -> void { impl_->clear_live_cache(); }
#ifdef NEXUS_ENABLE_FAKEIP
    auto DnsMessageRuntime::fakeip() const -> std::shared_ptr<dns::FakeIpShared> { return impl_->fakeip(); }
    auto DnsMessageRuntime::flush_fakeip_unpinned() noexcept -> std::optional<std::size_t> { return impl_->flush_fakeip_unpinned(); }
#endif
    auto DnsMessageRuntime::reclaim_memory(bool hard) noexcept -> void { impl_->reclaim_memory(hard); }
    auto DnsMessageRuntime::prepare(config::Config const& value, std::span<DnsProtection const> protection,
        dns::MessageRuleSource source, DnsMessageRuntime const* previous, std::shared_ptr<dns::ReverseCache> reverse)
        -> std::expected<void, std::string> {
        return impl_->prepare(value, protection, std::move(source), previous ? previous->impl_.get() : nullptr, std::move(reverse));
    }
    auto DnsMessageRuntime::start(bool admit) -> std::expected<void, std::string> { return impl_->start(admit); }
    auto DnsMessageRuntime::admit() noexcept -> void { impl_->admit(); }
    auto DnsMessageRuntime::same_binding(DnsMessageRuntime const& other) const noexcept -> bool { return impl_->same_binding(*other.impl_); }
    auto DnsMessageRuntime::replace_program(DnsMessageRuntime& candidate) noexcept -> void { impl_->replace_program(*candidate.impl_); }
    auto DnsMessageRuntime::swap(DnsMessageRuntime& other) noexcept -> void { impl_.swap(other.impl_); }
    auto DnsMessageRuntime::has_listeners() const noexcept -> bool { return impl_->has_listeners(); }
    auto DnsMessageRuntime::healthy() const noexcept -> bool { return impl_->healthy(); }
    auto DnsMessageRuntime::begin_drain() noexcept -> void { impl_->begin_drain(); }
    auto DnsMessageRuntime::drained() noexcept -> bool { return impl_->drained(); }
    auto DnsMessageRuntime::stop() noexcept -> void { impl_->stop(); }
}
