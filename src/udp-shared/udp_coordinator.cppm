export module ss_udp.shared_coordinator;
import std;
import relay;
import dns.response_cache;
export import ss_udp.shared_cache;
export import dns.shared_coordinator;

export namespace shadowsocks::detail {
    // The coordinator owns each query and its flight registrations; this
    // adapter returns its task directly without adding a coroutine frame.
    class UdpCoordinatedLookup {
    public:
        using Cache=dns_hp_experiment::GroupBinding;
        using Reader=Cache::Reader;
        struct Extra {
            dns_hp_experiment::CoordinatorOwner* owner=nullptr;
            dns_hp_experiment::ViewBinding* views=nullptr;
            bool optimistic=false;
            dns_hp_experiment::LocalViewBinding* local_views=nullptr;
#ifdef NEXUS_DNS_RESPONSE
            dns_hp_experiment::ResponseCoordinatorOwner* response_owner=nullptr;
#endif
        };
    private:
        Cache& cache_;
        Reader* reader_;
        Extra extra_;
        std::optional<dns_hp_experiment::CoordinatorQuery> resolver_;
#ifdef NEXUS_DNS_RESPONSE
        std::optional<dns_hp_experiment::ResponseCoordinatorQuery> response_resolver_;
        std::shared_ptr<dns::detail::ProtectedQuery const> response_protection_;
#endif
        std::unique_ptr<dns::detail::LocalAddressResolver> legacy_local_;
        std::unique_ptr<dns_hp_experiment::LocalCoordinatedResolver> local_resolver_;
        static auto strategy(dns::detail::AddressStrategy value) -> dns_hp_experiment::CoordinatedStrategy {
            using Source=dns::detail::AddressStrategy;
            using Target=dns_hp_experiment::CoordinatedStrategy;
            switch (value) {
            case Source::prefer_ipv4: return Target::prefer_ipv4;
            case Source::prefer_ipv6: return Target::prefer_ipv6;
            case Source::ipv4_only: return Target::ipv4_only;
            case Source::ipv6_only: return Target::ipv6_only;
            }
            std::terminate();
        }
    public:
        UdpCoordinatedLookup(Cache& cache,Reader* reader,Extra extra) : cache_(cache),reader_(reader),extra_(extra) {}
        // Forks share executor-local bindings and the synchronous reader;
        // resolver and cancellation state remain independent. Do not run the
        // executor recursively or access these forks from another thread.
        [[nodiscard]] auto fork() const -> UdpCoordinatedLookup {
            return UdpCoordinatedLookup(cache_,reader_,extra_);
        }
        auto cancel() noexcept -> void {
            if (resolver_) resolver_->cancel();
#ifdef NEXUS_DNS_RESPONSE
            if (response_resolver_) response_resolver_->cancel();
#endif
            if (legacy_local_) legacy_local_->cancel();
            if (local_resolver_) local_resolver_->cancel();
        }
        template<bool Full>
        auto resolve_local_impl(udp_io::io_context& context,std::shared_ptr<dns::LocalSnapshot const> snapshot,
            dns::detail::AddressStrategy family,std::size_t rotation,bool disable_cache,std::string const& name,
            std::chrono::steady_clock::time_point deadline,
            std::optional<dns::detail::FamilyCachePolicy> cache_policy={},std::optional<dns::ClientSubnet> subnet={})
            -> udp_capy::task<std::expected<dns::detail::AddressResult<Full>,dns::detail::ResolveError>> {
            if (!extra_.local_views) {
                legacy_local_=std::make_unique<dns::detail::LocalAddressResolver>(context,snapshot->config,snapshot->hosts,family,rotation,subnet);
                if constexpr (Full) return legacy_local_->resolve_answer(name,deadline);
                else return legacy_local_->resolve(name,deadline);
            }
            local_resolver_=std::make_unique<dns_hp_experiment::LocalCoordinatedResolver>(
                *extra_.owner,*reader_,*extra_.local_views,snapshot,family,rotation,disable_cache,cache_policy,subnet);
            if constexpr (Full) return local_resolver_->resolve_answer(name,deadline);
            else return local_resolver_->resolve(name,deadline);
        }
        auto resolve_local(udp_io::io_context& context,std::shared_ptr<dns::LocalSnapshot const> snapshot,
            dns::detail::AddressStrategy family,std::size_t rotation,bool disable_cache,std::string const& name,
            std::chrono::steady_clock::time_point deadline,
            std::optional<dns::detail::FamilyCachePolicy> cache_policy={},std::optional<dns::ClientSubnet> subnet={})
            -> udp_capy::task<std::expected<std::vector<dns::Address>,dns::detail::ResolveError>> {
            return resolve_local_impl<false>(context,std::move(snapshot),family,rotation,disable_cache,name,deadline,cache_policy,subnet);
        }
        auto resolve_local_answer(udp_io::io_context& context,std::shared_ptr<dns::LocalSnapshot const> snapshot,
            dns::detail::AddressStrategy family,std::size_t rotation,bool disable_cache,std::string const& name,
            std::chrono::steady_clock::time_point deadline,
            std::optional<dns::detail::FamilyCachePolicy> cache_policy={},std::optional<dns::ClientSubnet> subnet={})
            -> udp_capy::task<std::expected<dns::AddressAnswer,dns::detail::ResolveError>> {
            return resolve_local_impl<true>(context,std::move(snapshot),family,rotation,disable_cache,name,deadline,cache_policy,subnet);
        }
        auto finish_local() noexcept -> void { local_resolver_.reset(); legacy_local_.reset(); }
        auto prepare(udp_io::io_context&,udp_io::endpoint upstream,std::uint64_t view,bool tcp,
                     dns::detail::AddressStrategy family,bool disable_cache,bool edns,
                     std::optional<dns::detail::FamilyCachePolicy> cache_policy={},std::optional<dns::ClientSubnet> subnet={})
            -> std::expected<std::uint64_t,dns::detail::ResolveError> {
            if (!extra_.owner || !extra_.views || !reader_ || !view)
                return std::unexpected(dns::detail::ResolveError::state);
            auto bound=extra_.views->view(static_cast<std::size_t>(view-1),upstream,subnet);
            if (!bound) return std::unexpected(bound.error()==dns_hp_experiment::ViewRegistry::Error::limit ||
                bound.error()==dns_hp_experiment::ViewRegistry::Error::allocation ?
                dns::detail::ResolveError::limit : dns::detail::ResolveError::state);
            resolver_.emplace(*extra_.owner,reader_,strategy(family),tcp,disable_cache,edns,extra_.optimistic,cache_policy,subnet,extra_.views->protection(static_cast<std::size_t>(view-1)));
            return *bound;
        }
        auto run(udp_io::endpoint upstream,std::uint64_t view,std::string const& name,
                 std::chrono::steady_clock::time_point deadline) -> udp_capy::task<dns_hp_experiment::CoordinatedResult> {
            return resolver_->resolve(upstream,view,name,deadline);
        }
        auto run_answer(udp_io::endpoint upstream,std::uint64_t view,std::string const& name,
            std::chrono::steady_clock::time_point deadline)
            -> udp_capy::task<std::expected<dns::AddressAnswer,dns::detail::ResolveError>> {
            return resolver_->resolve_answer(upstream,view,name,deadline);
        }
        static auto map_answer(std::expected<dns::AddressAnswer,dns::detail::ResolveError> result)
            -> std::expected<dns::AddressAnswer,dns::detail::ResolveError> { return result; }
        auto finish() noexcept -> void { resolver_.reset(); }
#ifdef NEXUS_DNS_RESPONSE
        auto raw_prepare(udp_io::endpoint upstream,std::uint64_t view,std::optional<dns::ClientSubnet> subnet={}) -> std::expected<std::uint64_t,dns::detail::ResolveError> {
            if (!extra_.response_owner || !extra_.views || !view) return std::unexpected(dns::detail::ResolveError::state);
            auto bound=extra_.views->view(static_cast<std::size_t>(view-1),upstream,subnet);
            if (!bound) return std::unexpected(dns::detail::ResolveError::limit);
            response_resolver_.emplace(*extra_.response_owner);
            response_protection_=extra_.views->protection(static_cast<std::size_t>(view-1));
            return *bound;
        }
        auto raw_local_prepare(std::shared_ptr<dns::LocalSnapshot const> const& snapshot,udp_io::endpoint upstream,std::optional<dns::ClientSubnet> subnet={})
            -> std::expected<std::uint64_t,dns::detail::ResolveError> {
            if (!extra_.response_owner || !extra_.local_views) return std::unexpected(dns::detail::ResolveError::state);
            auto bound=extra_.local_views->view(snapshot,upstream,subnet);if (!bound) return std::unexpected(bound.error());
            response_resolver_.emplace(*extra_.response_owner);return *bound;
        }
        auto raw_run(udp_io::endpoint upstream,std::uint64_t view,std::string const& name,std::uint16_t type,
            std::chrono::steady_clock::time_point deadline,bool tcp,bool edns,bool disabled,std::optional<dns::ClientSubnet> subnet={})
            -> udp_capy::task<std::expected<dns::Response,dns::detail::ResolveError>> {
            return response_resolver_->resolve(upstream,view,{name,type},deadline,tcp,edns,disabled,subnet,response_protection_);
        }
        auto raw_finish() noexcept -> void {response_resolver_.reset();response_protection_.reset();}
#endif
        static auto map(dns_hp_experiment::CoordinatedResult result)
            -> std::expected<std::vector<dns::Address>,dns::detail::ResolveError> {
            if (result) return std::move(*result);
            if(result.error()==dns_hp_experiment::CoordinatedError::budget_exhausted)
                return std::unexpected(dns::detail::ResolveError::budget_exhausted);
            return std::unexpected(result.error()==dns_hp_experiment::CoordinatedError::transport ?
                dns::detail::ResolveError::transport : dns::detail::ResolveError::state);
        }
    };
}

export namespace relay::udp_runtime {
    class CoordinatorCacheSetup {
        GroupCacheSetup group_;
        dns_hp_experiment::Coordinator* coordinator_=nullptr;
        dns_hp_experiment::ViewRegistry* view_registry_=nullptr;
        dns_hp_experiment::LocalViewRegistry* local_registry_=nullptr;
        std::vector<dns_hp_experiment::ViewRegistry::Profile> profiles_;
        std::optional<dns_hp_experiment::ViewBinding> views_;
        std::optional<dns_hp_experiment::LocalViewBinding> local_views_;
        std::optional<dns_hp_experiment::CoordinatorOwner> owner_;
#ifdef NEXUS_DNS_RESPONSE
        dns::ResponseCache* response_cache_=nullptr;
        std::optional<dns_hp_experiment::ResponseCoordinatorOwner> response_owner_;
#endif
        bool optimistic_=false;
        std::chrono::milliseconds network_timeout_{std::chrono::seconds(5)};
    public:
        using Lookup=shadowsocks::detail::UdpCoordinatedLookup;
        [[nodiscard]] auto active() const noexcept -> bool { return group_.active(); }
        [[nodiscard]] auto bind(dns_hp_experiment::GroupSnapshot& owner,std::size_t group,std::size_t reader) -> bool {
            return group_.bind(owner,group,reader);
        }
        [[nodiscard]] auto bind_coordinator(dns_hp_experiment::Coordinator& coordinator,
            dns_hp_experiment::ViewRegistry& registry,DnsRouting const& routing,bool optimistic=false,
            std::chrono::milliseconds network_timeout=std::chrono::seconds(5)) -> bool {
            if (active() || !group_.configured()) return false;
            try {
                std::vector<dns_hp_experiment::ViewRegistry::Profile> profiles;
                profiles.reserve(routing.servers.size());
                for (std::size_t index=0;index<routing.servers.size();++index) {
                    auto profile=registry.register_profile(routing,index); if (!profile) return false;
                    profiles.push_back(*profile);
                }
                coordinator_=&coordinator; view_registry_=&registry; profiles_=std::move(profiles); optimistic_=optimistic; network_timeout_=network_timeout;
                return true;
            } catch (std::bad_alloc const&) { return false; }
        }
        [[nodiscard]] auto bind_local(dns_hp_experiment::LocalViewRegistry& registry) -> bool {
            if (active()) return false;
            local_registry_=&registry; return true;
        }
#ifdef NEXUS_DNS_RESPONSE
        [[nodiscard]] auto bind_response_cache(dns::ResponseCache& cache) noexcept -> bool {
            if (active()) return false;response_cache_=&cache;return true;
        }
#endif
        [[nodiscard]] auto start(udp_io::io_context& context,DnsRouting const& routing) -> std::error_code {
            if (!coordinator_ || !view_registry_ || !view_registry_->sealed() || profiles_.size()!=routing.servers.size())
                return std::make_error_code(std::errc::invalid_argument);
            for (std::size_t index=0;index<profiles_.size();++index) {
                auto valid=view_registry_->matches(profiles_[index],routing,index);
                if (!valid || !*valid) return std::make_error_code(std::errc::invalid_argument);
            }
            if (auto error=group_.start(context,routing)) return error;
            views_.emplace(*view_registry_,profiles_);
            if (local_registry_) local_views_.emplace(*local_registry_);
            owner_.emplace(context,group_.cache(),*coordinator_,network_timeout_);
#ifdef NEXUS_DNS_RESPONSE
            if (response_cache_) response_owner_.emplace(context,*response_cache_,*coordinator_,network_timeout_);
#endif
            return {};
        }
        [[nodiscard]] auto cache() noexcept -> Lookup::Cache& { return group_.cache(); }
        [[nodiscard]] auto reader() noexcept -> Lookup::Reader* { return group_.reader(); }
        [[nodiscard]] auto extra() noexcept -> Lookup::Extra { return {&*owner_,&*views_,optimistic_,local_views_ ? &*local_views_ : nullptr
#ifdef NEXUS_DNS_RESPONSE
            ,response_owner_ ? &*response_owner_ : nullptr
#endif
        }; }
        auto stop_begin() noexcept -> void { if (owner_) owner_->stop();
#ifdef NEXUS_DNS_RESPONSE
            if (response_owner_) response_owner_->stop();
#endif
            group_.stop_begin(); }
        [[nodiscard]] auto drained() const noexcept -> bool {
            if (owner_ && !owner_->drained()) return false;
#ifdef NEXUS_DNS_RESPONSE
            if (response_owner_ && !response_owner_->drained()) return false;
#endif
            return group_.drained();
        }
        auto stop_end() noexcept -> void {
            if (owner_ && !owner_->drained()) std::terminate();
#ifdef NEXUS_DNS_RESPONSE
            if (response_owner_ && !response_owner_->drained()) std::terminate();
            response_owner_.reset();
#endif
            owner_.reset(); local_views_.reset(); views_.reset(); group_.stop_end();
        }
    };
    using CoordinatorUdpInbounds=BasicUdpInbounds<CoordinatorCacheSetup>;
}
