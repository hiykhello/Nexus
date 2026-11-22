export module ss_udp.inbounds;
import std;
import nexus.compat;
import platform.socket_options;
import config;
import dns.tls_query;
import dns.https_query;
import proxy;
import rules;
import shadowsocks.key;
export import ss_udp.listener;

export namespace proxy::detail {
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

export namespace proxy::udp_runtime {
    namespace udp_io=shadowsocks::detail::udp_io;
    auto udp_dns_config(config::Config const& config) -> proxy::DnsRouting {
        proxy::DnsRouting result;
        if (config.dns) {
            auto const& dns=*config.dns; result.final=dns.final; result.disable_cache=dns.disable_cache; result.edns=dns.edns;
            result.optimistic_cache_seconds=dns.optimistic_cache_seconds;
            switch (dns.strategy) {
            case config::DnsStrategy::automatic: break;
            case config::DnsStrategy::prefer_ipv4: result.strategy=proxy::DnsStrategy::prefer_ipv4; break;
            case config::DnsStrategy::prefer_ipv6: result.strategy=proxy::DnsStrategy::prefer_ipv6; break;
            case config::DnsStrategy::ipv4_only: result.strategy=proxy::DnsStrategy::ipv4_only; break;
            case config::DnsStrategy::ipv6_only: result.strategy=proxy::DnsStrategy::ipv6_only; break;
            }
            for (auto const& server:dns.servers) {
                proxy::DnsServer entry;
                if (server.upstream) { auto const& up=*server.upstream;
                    entry={up.address,up.ipv6,up.port,up.tcp,up.host,up.resolver}; }
                result.servers.push_back(std::move(entry));
            }
            for (auto const& rule:dns.rules) result.rules.push_back(rule);
        } else if (config.dns_upstream) {
            auto const& up=*config.dns_upstream;
            result.servers.push_back({up.address,up.ipv6,up.port,up.tcp,up.host,up.resolver});
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
            nexus::inplace_vector<udp_io::endpoint,16> endpoints;
            std::vector<rules::RouteMatcher> policies;
            nexus::inplace_vector<Server*,16> traffic_listeners;
            std::vector<std::optional<shadowsocks::detail::UdpIdentityRoute>> identities;
        };
        std::unique_ptr<udp_io::io_context> owned_context_;
        udp_io::io_context& context_;
        platform::SocketBinding binding_;
        shadowsocks::detail::UdpListenerIngress* ingress_=nullptr;
        std::uint64_t generation_=0;
        shadowsocks::detail::UdpListenerRegistry registry_{64};
        std::vector<Group> groups_;
        Setup setup_;
        std::vector<std::unique_ptr<Listener>> listeners_;
        dns::TlsQueryMaintenance dns_tls_maintenance_;
        std::optional<shadowsocks::detail::UdpOrderedRouting> ordered_;
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
        [[nodiscard]] auto start(DnsRouting const& routing) -> std::error_code {
            if (setup_.active()) return std::make_error_code(std::errc::operation_in_progress);
            auto config=detail::udp_dns_config(routing);
            if (!config) return config.error();
            auto unused=udp_io::endpoint(udp_io::ipv4_address::loopback(),0);
            try {
                if (owned_context_) dns::resume_https_queries(context_);
                if (auto error=setup_.start(context_,routing)) { stop(); return error; }
                for (auto const& group:groups_) {
                    listeners_.push_back(std::make_unique<Listener>(context_,*group.state,unused,64,
                        std::chrono::milliseconds(5),config->options,config->routing,&setup_.cache(),setup_.reader(),setup_.extra(),ordered_,ingress_,generation_));
                    if (auto error=listeners_.back()->start(group.endpoints,group.policies,group.traffic_listeners,group.identities)) {
                        stop(); return error;
                    }
                }
            } catch (...) { stop(); throw; }
            return {};
        }
        auto poll(std::chrono::milliseconds wait) -> void {
            if (listeners_.empty()) return;
            context_.restart();
            if (wait <= std::chrono::milliseconds::zero()) (void)context_.poll();
            else (void)context_.run_for(wait);
            dns_tls_maintenance_.poll(context_);
        }
        [[nodiscard]] auto healthy() const noexcept -> bool {
            return std::ranges::all_of(listeners_,[](auto const& listener) { return listener->running(); });
        }
        [[nodiscard]] auto idle() const noexcept -> bool {
            return std::ranges::all_of(listeners_,[](auto const& listener) {return listener->idle();});
        }
        [[nodiscard]] auto empty() const noexcept -> bool { return groups_.empty(); }
        auto stop() noexcept -> void {
            for (auto& listener:listeners_) listener->stop();
            setup_.stop_begin();
            if (owned_context_) dns::stop_https_queries(context_);
            if (!listeners_.empty() || !setup_.drained()) {
                while (!setup_.drained() || std::ranges::any_of(listeners_,[](auto const& listener){return !listener->drained();})) {
                    context_.restart(); (void)context_.run_for(std::chrono::milliseconds(20));
                }
            }
            listeners_.clear();
            setup_.stop_end();
            if (owned_context_) {context_.restart(); (void)context_.run();}
        }
    };
    using UdpInbounds=BasicUdpInbounds<DefaultCacheSetup>;
}
