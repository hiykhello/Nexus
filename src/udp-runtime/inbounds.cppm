export module ss_udp.inbounds;
import std;
import containers.inplace_vector;
import platform.socket_options;
import config;
import dns.tls_query;
import dns.https_query;
import dns.quic_query;
import relay;
import rules;
import shadowsocks.key;
export import ss_udp.listener;

export namespace relay::detail {
    struct UdpDnsConfig {
        shadowsocks::detail::UdpDnsRouting routing;
        shadowsocks::detail::UdpResolveOptions options;
    };
    // The listener validates the copied routing before opening any socket.
    inline auto udp_dns_config(DnsRouting const& source) -> std::expected<UdpDnsConfig,std::error_code> {
        UdpDnsConfig result;
        using dns::detail::AddressStrategy;
        switch (source.strategy) {
        case DnsStrategy::automatic:
        case DnsStrategy::prefer_ipv4: result.options.strategy=AddressStrategy::prefer_ipv4; break;
        case DnsStrategy::prefer_ipv6: result.options.strategy=AddressStrategy::prefer_ipv6; break;
        case DnsStrategy::ipv4_only: result.options.strategy=AddressStrategy::ipv4_only; break;
        case DnsStrategy::ipv6_only: result.options.strategy=AddressStrategy::ipv6_only; break;
        default: return std::unexpected(std::make_error_code(std::errc::invalid_argument));
        }
        result.options.disable_cache=source.disable_cache; result.options.edns=source.edns;
        result.routing.fallback=source.final;
        for (auto const& server:source.servers) {
            shadowsocks::detail::udp_io::endpoint endpoint;
            if (server.ipv6) endpoint={shadowsocks::detail::udp_io::ipv6_address(server.address),server.port};
            else {
                shadowsocks::detail::udp_io::ipv4_address::bytes_type bytes{};
                std::copy_n(server.address.begin(),4,bytes.begin());
                endpoint={shadowsocks::detail::udp_io::ipv4_address(bytes),server.port};
            }
            // System resolution ignores transport settings in the TCP path too.
            result.routing.servers.push_back({endpoint,server.port!=0 && server.tcp,server.host,server.resolver,server.protection});
        }
        for (auto const& rule:source.rules) result.routing.rules.push_back(rule);
        return result;
    }
}

export namespace relay::udp_runtime {
    namespace udp_io=shadowsocks::detail::udp_io;
    auto udp_dns_config(config::Config const& config) -> relay::DnsRouting {
        relay::DnsRouting result;
        if (config.dns) {
            auto const& dns=*config.dns; result.final=dns.final; result.disable_cache=dns.disable_cache; result.edns=dns.edns;
            result.optimistic_cache_seconds=dns.optimistic_cache_seconds;
            switch (dns.strategy) {
            case config::DnsStrategy::automatic: break;
            case config::DnsStrategy::prefer_ipv4: result.strategy=relay::DnsStrategy::prefer_ipv4; break;
            case config::DnsStrategy::prefer_ipv6: result.strategy=relay::DnsStrategy::prefer_ipv6; break;
            case config::DnsStrategy::ipv4_only: result.strategy=relay::DnsStrategy::ipv4_only; break;
            case config::DnsStrategy::ipv6_only: result.strategy=relay::DnsStrategy::ipv6_only; break;
            }
            for (auto const& server:dns.servers) {
                relay::DnsServer entry;
                if (server.upstream) { auto const& up=*server.upstream;
                    entry={up.address,up.ipv6,up.port,up.tcp,up.host,up.resolver}; }
                result.servers.push_back(std::move(entry));
            }
            for (auto const& rule:dns.rules) result.rules.push_back(rule);
        } else result.servers.push_back({});
        return result;
    }

    // A fresh cache for each start prevents DNS views crossing reloads.
    class DefaultCacheSetup {
        std::optional<dns::AddressCache> cache_;
    public:
        using Lookup=shadowsocks::detail::UdpDefaultLookup;
        [[nodiscard]] auto active() const noexcept -> bool { return cache_.has_value(); }
        [[nodiscard]] auto start(udp_io::io_context&,DnsRouting const&) -> std::error_code {
            cache_.emplace(256); return {};
        }
        [[nodiscard]] auto cache() noexcept -> Lookup::Cache& { return *cache_; }
        [[nodiscard]] auto reader() noexcept -> Lookup::Reader* { return nullptr; }
        [[nodiscard]] auto extra() noexcept -> Lookup::Extra { return {}; }
        auto stop_begin() noexcept -> void {}
        [[nodiscard]] auto drained() const noexcept -> bool {return true;}
        auto stop_end() noexcept -> void { cache_.reset(); }
    };

    // Setup selects the cache and query owner at compile time. It must retain
    // all borrowed objects until stop_end(), after listeners and tasks drain.
    template<class Setup>
    class BasicUdpInbounds {
        using Lookup=typename Setup::Lookup;
        using State=shadowsocks::detail::UdpListenerState;
        using Listener=shadowsocks::detail::BasicUdpListener<Lookup>;
        struct Group {
            State* state;
            containers::inplace_vector<udp_io::endpoint,16> endpoints;
            std::vector<rules::RouteMatcher> policies;
            containers::inplace_vector<Server*,16> traffic_listeners;
            std::vector<std::optional<shadowsocks::detail::UdpIdentityRoute>> identities;
        };
        struct DynamicBase {
            std::shared_ptr<shadowsocks::detail::UdpIdentitySecret const> secret;
            std::uint8_t key_len = 0;
            std::uint16_t port = 0;
            rules::RouteMatcher policy;
            Server* traffic = nullptr;
            std::shared_ptr<relay::ShadowsocksUserDirectory> users;
        };
        struct DynamicActive {
            std::shared_ptr<relay::ShadowsocksDynamicUser> entry;
            std::unique_ptr<Group> group;
            std::unique_ptr<Listener> listener;
        };
        std::unique_ptr<udp_io::io_context> owned_context_;
        udp_io::io_context& context_;
        platform::SocketBinding binding_;
        std::optional<shadowsocks::detail::UdpListenerIngress> owned_ingress_;
        shadowsocks::detail::UdpListenerIngress* ingress_=nullptr;
        std::uint64_t generation_=0;
        shadowsocks::detail::UdpListenerRegistry registry_{1024};
        std::deque<Group> groups_;
        Setup setup_;
        std::optional<shadowsocks::detail::UdpOrderedRouting> ordered_;
        std::vector<std::unique_ptr<Listener>> listeners_;
        std::vector<DynamicBase> dynamic_bases_;
        std::vector<DynamicActive> dynamic_active_;
        std::vector<std::pair<std::unique_ptr<Listener>,std::unique_ptr<Group>>> retired_dynamic_;
        std::optional<detail::UdpDnsConfig> started_dns_config_;
        dns::TlsQueryMaintenance dns_tls_maintenance_;

        auto sync_dynamic_users() -> void {
            std::erase_if(retired_dynamic_, [](auto& item) { return item.first->drained(); });
            if (!started_dns_config_ || dynamic_bases_.empty()) return;
            auto alive_in = [](DynamicBase const& base, std::vector<std::shared_ptr<relay::ShadowsocksDynamicUser>> const& snap,
                               relay::ShadowsocksDynamicUser const* ptr) {
                return ptr->key_len == base.key_len && ptr->admits() &&
                    std::ranges::any_of(snap, [ptr](auto const& u) { return u.get() == ptr; });
            };
            std::vector<std::shared_ptr<std::vector<std::shared_ptr<relay::ShadowsocksDynamicUser>> const>> snaps;
            snaps.reserve(dynamic_bases_.size());
            for (auto const& b : dynamic_bases_)
                snaps.push_back(b.users ? b.users->snapshot() : std::make_shared<std::vector<std::shared_ptr<relay::ShadowsocksDynamicUser>> const>());
            for (auto it = dynamic_active_.begin(); it != dynamic_active_.end(); ) {
                bool keep = false;
                for (std::size_t i = 0; i < dynamic_bases_.size() && !keep; ++i)
                    if (it->group->endpoints[0].port() == dynamic_bases_[i].port && alive_in(dynamic_bases_[i], *snaps[i], it->entry.get()))
                        keep = true;
                if (keep) { ++it; continue; }
                it->listener->stop();
                retired_dynamic_.emplace_back(std::move(it->listener), std::move(it->group));
                it = dynamic_active_.erase(it);
            }
            for (std::size_t i = 0; i < dynamic_bases_.size(); ++i) {
                auto const& base = dynamic_bases_[i];
                auto const* principals = base.traffic ? base.traffic->principal_policy() : nullptr;
                for (auto const& entry : *snaps[i]) {
                    if (entry->key_len != base.key_len || !entry->admits()) continue;
                    bool exists = std::ranges::any_of(dynamic_active_, [&](auto const& a) {
                        return a.entry.get() == entry.get() && a.group->endpoints[0].port() == base.port;
                    });
                    if (exists) continue;
                    auto* st = registry_.find(entry->key_span(), shadowsocks::CipherMethod::aes);
                    if (!st) {
                        shadowsocks::UdpListenerReplay rep;
                        if (ingress_) {
                            rep = {ingress_->replay(entry->key_span(), 64, shadowsocks::CipherMethod::aes), generation_};
                            if (!rep.sessions) continue;
                        }
                        auto created = registry_.add(entry->key_span(), base.policy, 64, 64, 64, &binding_, std::move(rep));
                        if (!created) continue;
                        st = *created;
                    }
                    if (st->attached()) continue;
                    auto grp = std::make_unique<Group>();
                    grp->state = st;
                    grp->endpoints.emplace_back(udp_io::ipv4_address::loopback(), base.port);
                    grp->policies.push_back(base.policy);
                    grp->traffic_listeners.push_back(base.traffic);
                    grp->identities.push_back(shadowsocks::detail::UdpIdentityRoute{
                        base.secret, entry->identity_hash, entry->username,
                        principals ? principals->find(entry->username) : nullptr, entry, false});
                    auto unused = udp_io::endpoint(udp_io::ipv4_address::loopback(), 0);
                    auto lst = std::make_unique<Listener>(context_, *st, unused, 64, std::chrono::milliseconds(5),
                        started_dns_config_->options, started_dns_config_->routing, &setup_.cache(), setup_.reader(),
                        setup_.extra(), ordered_, ingress_, generation_);
                    lst->set_stop_ordered(false);
                    if (lst->start(grp->endpoints, grp->policies, grp->traffic_listeners, grp->identities)) continue;
                    dynamic_active_.push_back({entry, std::move(grp), std::move(lst)});
                }
            }
        }
    public:
        BasicUdpInbounds() : owned_context_(new udp_io::io_context(udp_io::make_io_context(udp_io::has_uring))),context_(*owned_context_) {}
        // The borrowed context and its owners must outlive stop() and this
        // object; poll() and stop() must not race another context runner.
        explicit BasicUdpInbounds(udp_io::io_context& context) : context_(context) {}
        BasicUdpInbounds(BasicUdpInbounds const&)=delete;
        auto operator=(BasicUdpInbounds const&) -> BasicUdpInbounds& = delete;
        ~BasicUdpInbounds() { stop(); }
        [[nodiscard]] auto setup() noexcept -> Setup& { return setup_; }
        auto set_ingress(shadowsocks::detail::UdpListenerIngress& owner,std::uint64_t generation) noexcept -> void {
            ingress_=&owner;
            generation_=generation;
        }
        // The callbacks and their transferred work must remain valid until
        // stop() has drained the listeners and the external sender owner.
        [[nodiscard]] auto set_ordered(shadowsocks::detail::UdpOrderedRouting routing) -> bool {
            if (setup_.active() || !routing.allows || !routing.send || !routing.stop || !routing.drained || !routing.finish) return false;
            ordered_=std::move(routing); return true;
        }
        [[nodiscard]] auto set_socket_binding(platform::SocketBinding binding) noexcept -> bool {
            if (!groups_.empty() || setup_.active() || !binding.valid()) return false;
            binding_=std::move(binding); return true;
        }
        [[nodiscard]] auto add(std::span<std::uint8_t const> key,std::uint16_t port,rules::RouteMatcher const& policy,
            Server* traffic=nullptr,shadowsocks::CipherMethod method=shadowsocks::CipherMethod::aes,
            std::optional<shadowsocks::detail::UdpIdentityRoute> identity={})
            -> std::expected<void,std::string> {
            if (setup_.active() || !port) return std::unexpected("invalid UDP listener state");
            if (identity && (!ingress_ || !identity->secret || method!=shadowsocks::CipherMethod::aes))
                return std::unexpected("invalid UDP identity route");
            auto* state=registry_.find(key,method);
            if (!state) {
                shadowsocks::UdpListenerReplay replay;
                if (ingress_) {
                    replay={ingress_->replay(key,64,method),generation_};
                    if (!replay.sessions) return std::unexpected("native UDP replay owner capacity exhausted");
                } else if (method!=shadowsocks::CipherMethod::aes)
                    replay.sessions=std::make_shared<shadowsocks::UdpServerSessions>(64,false,method);
                auto created=registry_.add(key,policy,64,64,64,&binding_,std::move(replay));
                if (!created) return std::unexpected("cannot create UDP key owner");
                state=*created;
                groups_.push_back({state,{},{}});
            }
            auto group=std::ranges::find(groups_,state,&Group::state);
            if (group==groups_.end() || group->endpoints.size()>=16) return std::unexpected("too many UDP listeners for one key");
            group->policies.push_back(policy);
            group->endpoints.emplace_back(udp_io::ipv4_address::loopback(),port);
            group->traffic_listeners.push_back(traffic);
            group->identities.push_back(std::move(identity));
            return {};
        }
        [[nodiscard]] auto add_dynamic_base(std::span<std::uint8_t const> primary, std::uint16_t port,
            rules::RouteMatcher const& policy, Server* traffic, std::shared_ptr<relay::ShadowsocksUserDirectory> users)
            -> std::expected<void, std::string> {
            if (setup_.active() || !port || (primary.size() != 16 && primary.size() != 32) || !users)
                return std::unexpected("invalid dynamic UDP listener state");
            if (!ingress_) { owned_ingress_.emplace(); ingress_ = &*owned_ingress_; }
            auto ep = udp_io::endpoint(udp_io::ipv4_address::loopback(), port);
            bool port_bound = std::ranges::any_of(groups_, [&](Group const& g) {
                return std::ranges::any_of(g.endpoints, [&](auto const& e) { return e == ep; });
            });
            auto secret = std::make_shared<shadowsocks::detail::UdpIdentitySecret const>(primary);
            if (!port_bound) {
                auto added = add(primary, port, policy, traffic, shadowsocks::CipherMethod::aes,
                    shadowsocks::detail::UdpIdentityRoute{secret, {}, {}, nullptr, {}, true});
                if (!added) return added;
            }
            dynamic_bases_.push_back({std::move(secret), static_cast<std::uint8_t>(primary.size()),
                port, policy, traffic, std::move(users)});
            return {};
        }
        [[nodiscard]] auto start(DnsRouting const& routing) -> std::error_code {
            if (setup_.active()) return std::make_error_code(std::errc::operation_in_progress);
            auto config=detail::udp_dns_config(routing);
            if (!config) return config.error();
            auto unused=udp_io::endpoint(udp_io::ipv4_address::loopback(),0);
            try {
                if (owned_context_) {
                    dns::resume_tls_queries(context_);
                    dns::resume_https_queries(context_);
                    dns::resume_quic_queries(context_);
                }
                if (auto error=setup_.start(context_,routing)) { stop(); return error; }
                for (auto const& group:groups_) {
                    listeners_.push_back(std::make_unique<Listener>(context_,*group.state,unused,64,
                        std::chrono::milliseconds(5),config->options,config->routing,&setup_.cache(),setup_.reader(),setup_.extra(),ordered_,ingress_,generation_));
                    if (auto error=listeners_.back()->start(group.endpoints,group.policies,group.traffic_listeners,group.identities)) {
                        stop(); return error;
                    }
                }
                started_dns_config_.emplace(detail::UdpDnsConfig{config->routing, config->options});
                sync_dynamic_users();
            } catch (...) { stop(); throw; }
            return {};
        }
        auto poll(std::chrono::milliseconds wait) -> void {
            if (listeners_.empty() && dynamic_active_.empty() && dynamic_bases_.empty()) return;
            context_.restart();
            if (wait <= std::chrono::milliseconds::zero()) (void)context_.poll();
            else (void)context_.run_for(wait);
            sync_dynamic_users();
            dns_tls_maintenance_.poll(context_);
        }
        [[nodiscard]] auto healthy() const noexcept -> bool {
            return std::ranges::all_of(listeners_,[](auto const& listener) { return listener->running(); });
        }
        [[nodiscard]] auto idle() const noexcept -> bool {
            return std::ranges::all_of(listeners_,[](auto const& listener) {return listener->idle();}) &&
                std::ranges::all_of(dynamic_active_,[](auto const& item) {return item.listener->idle();});
        }
        [[nodiscard]] auto empty() const noexcept -> bool { return groups_.empty() && dynamic_bases_.empty(); }
        auto stop() noexcept -> void {
            started_dns_config_.reset();
            for (auto& listener:listeners_) listener->stop();
            for (auto& item:dynamic_active_) item.listener->stop();
            for (auto& item:retired_dynamic_) item.first->stop();
            setup_.stop_begin();
            if (owned_context_) {
                dns::stop_tls_queries(context_);
                dns::stop_https_queries(context_);
                dns::stop_quic_queries(context_);
            }
            auto all_drained = [&] {
                return setup_.drained() &&
                    std::ranges::all_of(listeners_,[](auto const& l){return l->drained();}) &&
                    std::ranges::all_of(dynamic_active_,[](auto const& a){return a.listener->drained();}) &&
                    std::ranges::all_of(retired_dynamic_,[](auto const& r){return r.first->drained();});
            };
            if (!listeners_.empty() || !dynamic_active_.empty() || !retired_dynamic_.empty() || !setup_.drained()) {
                while (!all_drained()) {
                    context_.restart(); (void)context_.run_for(std::chrono::milliseconds(20));
                }
            }
            dynamic_active_.clear();
            retired_dynamic_.clear();
            listeners_.clear();
            setup_.stop_end();
            if (owned_context_) {context_.restart(); (void)context_.run();}
        }
    };
    using UdpInbounds=BasicUdpInbounds<DefaultCacheSetup>;
}
