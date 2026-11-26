export module ss_udp.resolve;
import std;
export import dns.corosio_local;
export import shadowsocks.udp_dispatch;
import dns.policy;
import rules;
import dns.response_program;
import dns.address_race_program;
import dns.response_race_walk;
import dns.response_query;
import dns.local_response;
import dns.predefined;
export import ss_udp.response_resolve;

export namespace shadowsocks::detail {
    // Lookup owns the in-flight resolver. Cache and reader are borrowed until
    // the enclosing operation returns, including after cancel().
    template<class CacheType,bool EnableRefresh=false>
    class UdpCachedLookup {
    public:
        using Cache=CacheType;
        using Reader=typename Cache::Reader;
        using Refresh=dns::detail::BasicRefreshOwner<Cache>;
        struct NoRefresh {};
        struct WithRefresh { Refresh* refresh=nullptr; };
        using Extra=std::conditional_t<EnableRefresh,WithRefresh,NoRefresh>;
    private:
        Cache& cache_;
        Reader* reader_;
        [[no_unique_address]] Extra extra_;
        std::unique_ptr<dns::detail::BasicDualAddressResolver<Cache>> resolver_;
    public:
        UdpCachedLookup(Cache& cache,Reader* reader,Extra extra)
            : cache_(cache),reader_(reader),extra_(extra) {}
        [[nodiscard]] auto fork() const -> UdpCachedLookup {
            return UdpCachedLookup(cache_,reader_,extra_);
        }
        auto cancel() noexcept -> void { if (resolver_) resolver_->cancel(); }
        auto prepare(udp_io::io_context& context,udp_io::endpoint,std::uint64_t view,bool tcp,
                     dns::detail::AddressStrategy strategy,bool disable_cache,bool edns,
                     std::optional<dns::detail::FamilyCachePolicy> cache_policy={},std::optional<dns::ClientSubnet> subnet={})
            -> std::expected<std::uint64_t,dns::detail::ResolveError> {
            Refresh* refresh=nullptr;
            if constexpr (EnableRefresh) refresh=extra_.refresh;
            resolver_=std::make_unique<dns::detail::BasicDualAddressResolver<Cache>>(
                context,cache_,tcp,strategy,disable_cache,edns,refresh,reader_,cache_policy,subnet);
            return view;
        }
        auto run(udp_io::endpoint upstream,std::uint64_t view,std::string const& name,
                 std::chrono::steady_clock::time_point deadline)
            -> udp_capy::task<std::expected<std::vector<dns::Address>,dns::detail::ResolveError>> {
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
        static auto map(std::expected<std::vector<dns::Address>,dns::detail::ResolveError> result)
            -> std::expected<std::vector<dns::Address>,dns::detail::ResolveError> { return result; }
    };
    template<class Lookup>
    class BasicUdpResolveOperation {
    public:
        using LookupType = Lookup;
    private:
        UdpDispatcher& dispatcher_;
        udp_io::io_context& context_;
        Lookup lookup_;
        std::unique_ptr<dns::detail::LocalAddressResolver> local_resolver_;
#ifdef NEXUS_DNS_RESPONSE
        std::optional<dns::detail::AddressResolver> response_address_resolver_;
        void* response_operation_=nullptr;
        void (*cancel_response_operation_)(void*) noexcept=nullptr;
#endif
        std::shared_ptr<dns::LocalSnapshot const> local_snapshot_;
        std::size_t* local_rotation_;
        std::size_t response_rotation_=0;
        UdpPending pending_;
        UdpResolvedHandler resolved_handler_;
        std::vector<UdpResolveHop> hops_;
        std::optional<UdpResolvePlan> alternate_;
        std::optional<dns::detail::FamilyCachePolicy> cache_policy_;
#ifdef NEXUS_DNS_RESPONSE
        UdpResponseRouting const* response_routing_=nullptr;
        UdpResponseContext response_context_{};
        std::span<dns::ResponseRaceMode const> response_modes_{};
        std::optional<std::pair<std::size_t,std::string>> local_candidate_;
#endif
        dns::detail::AddressStrategy strategy_;
        bool tcp_only_,disable_cache_,edns_;
        bool started_=false, canceled_=false, finished_=false;
    public:
#ifdef NEXUS_DNS_RESPONSE
        using ResponseOperation = ResponseResolveOps::ResponseOperation<BasicUdpResolveOperation, Lookup>;
#endif
        BasicUdpResolveOperation(UdpDispatcher& dispatcher, udp_io::io_context& context,
            typename Lookup::Cache& cache,UdpPending pending,bool tcp_only=false,
            dns::detail::AddressStrategy strategy=dns::detail::AddressStrategy::prefer_ipv4,
            bool disable_cache=false,bool edns=false,std::vector<UdpResolveHop> hops={},
            std::shared_ptr<dns::LocalSnapshot const> local_snapshot={},std::size_t* local_rotation=nullptr,
            typename Lookup::Reader* reader=nullptr,typename Lookup::Extra extra={},std::optional<UdpResolvePlan> alternate={},
            std::optional<dns::detail::FamilyCachePolicy> cache_policy={}
#ifdef NEXUS_DNS_RESPONSE
            ,UdpResponseRouting const* response_routing=nullptr,UdpResponseContext response_context={}
#endif
            ,UdpResolvedHandler resolved_handler={},std::span<dns::ResponseRaceMode const> response_modes={}
            )
            : dispatcher_(dispatcher),context_(context),lookup_(cache,reader,extra),
              local_snapshot_(std::move(local_snapshot)),local_rotation_(local_rotation),
              pending_(std::move(pending)),resolved_handler_(std::move(resolved_handler)),hops_(std::move(hops)),alternate_(std::move(alternate)),cache_policy_(cache_policy),
#ifdef NEXUS_DNS_RESPONSE
              response_routing_(response_routing),response_context_(response_context),response_modes_(response_modes),
#endif
              strategy_(strategy),tcp_only_(tcp_only),disable_cache_(disable_cache),edns_(edns) {}
        BasicUdpResolveOperation(BasicUdpResolveOperation const&)=delete;
        auto operator=(BasicUdpResolveOperation const&) -> BasicUdpResolveOperation& = delete;
        ~BasicUdpResolveOperation() { if (!finished_) cancel(); }
        // Serialized on the same executor as run(); cancellation removes the
        // token immediately but the object remains alive until completion.
        auto cancel() noexcept -> void {
            canceled_=true; lookup_.cancel(); if (local_resolver_) local_resolver_->cancel();
#ifdef NEXUS_DNS_RESPONSE
            if (response_address_resolver_) response_address_resolver_->cancel();
            if (cancel_response_operation_)cancel_response_operation_(response_operation_);
#endif
             (void)dispatcher_.cancel(pending_.token);
        }
        template<bool Full>
        auto query_owned(Lookup& lookup,std::unique_ptr<dns::detail::LocalAddressResolver>& local_resolver,
                   bool const& canceled,std::size_t& response_rotation,std::vector<udp_io::endpoint> const& upstreams,std::uint64_t view,bool tcp,
                   std::string const& name,dns::detail::AddressStrategy family,std::chrono::steady_clock::time_point deadline,
                   std::optional<dns::detail::FamilyCachePolicy> cache_policy={},std::optional<dns::ClientSubnet> subnet={},
                   std::shared_ptr<dns::LocalSnapshot const> const* retained=nullptr)
            -> udp_capy::task<std::expected<dns::detail::AddressResult<Full>,dns::detail::ResolveError>> {
            if (upstreams.size()==1 && upstreams.front().port()==0) {
                if (canceled) co_return std::unexpected(dns::detail::ResolveError::canceled);
                if (std::chrono::steady_clock::now()>=deadline) co_return std::unexpected(dns::detail::ResolveError::timeout);
                auto const& snapshot=retained ? *retained : local_snapshot_;
                if (!snapshot) co_return std::unexpected(dns::detail::ResolveError::state);
#ifdef NEXUS_DNS_RESPONSE
                auto rotation=response_routing_ ? response_rotation : (snapshot->config.rotate && local_rotation_ ? (*local_rotation_)++ : 0);
#else
                auto rotation=snapshot->config.rotate && local_rotation_ ? (*local_rotation_)++ : 0;
#endif
                if constexpr (requires { lookup.resolve_local(context_,snapshot,family,rotation,disable_cache_,name,deadline); }) {
                    auto task=[&] {
                        if constexpr (Full) return lookup.resolve_local_answer(context_,snapshot,family,rotation,disable_cache_,name,deadline,cache_policy,subnet);
                        else return lookup.resolve_local(context_,snapshot,family,rotation,disable_cache_,name,deadline,cache_policy,subnet);
                    }();
                    auto addresses=co_await std::move(task);
                    lookup.finish_local();
                    if (canceled) co_return std::unexpected(dns::detail::ResolveError::canceled);
                    co_return addresses;
                } else {
                    local_resolver=std::make_unique<dns::detail::LocalAddressResolver>(context_,snapshot->config,snapshot->hosts,family,rotation,subnet);
                    auto task=[&] {
                        if constexpr (Full) return local_resolver->resolve_answer(name,deadline);
                        else return local_resolver->resolve(name,deadline);
                    }();
                    auto addresses=co_await std::move(task);
                    local_resolver.reset();
                    if (canceled) co_return std::unexpected(dns::detail::ResolveError::canceled);
                    co_return addresses;
                }
            }
            for (auto const& upstream:upstreams) {
                if (canceled) co_return std::unexpected(dns::detail::ResolveError::canceled);
                auto prepared=lookup.prepare(context_,upstream,view,tcp,family,disable_cache_,edns_,cache_policy,subnet);
                if (!prepared) co_return std::unexpected(prepared.error());
                auto task=[&] {
                    if constexpr (Full) return lookup.run_answer(upstream,*prepared,name,deadline);
                    else return lookup.run(upstream,*prepared,name,deadline);
                }();
                auto raw=co_await std::move(task);
                auto result=[&] {
                    if constexpr (Full) return Lookup::map_answer(std::move(raw));
                    else return Lookup::map(std::move(raw));
                }();
                lookup.finish();
                if (canceled) co_return std::unexpected(dns::detail::ResolveError::canceled);
                if (result || result.error()!=dns::detail::ResolveError::transport) co_return result;
            }
            co_return std::unexpected(dns::detail::ResolveError::transport);
        }
        template<bool Full>
        auto query(std::vector<udp_io::endpoint> const& upstreams,std::uint64_t view,bool tcp,
                   std::string const& name,dns::detail::AddressStrategy family,std::chrono::steady_clock::time_point deadline,
                   std::optional<dns::detail::FamilyCachePolicy> cache_policy={},std::optional<dns::ClientSubnet> subnet={})
            -> udp_capy::task<std::expected<dns::detail::AddressResult<Full>,dns::detail::ResolveError>> {
            return query_owned<Full>(lookup_,local_resolver_,canceled_,response_rotation_,upstreams,view,tcp,name,family,deadline,cache_policy,subnet);
        }
#ifdef NEXUS_DNS_RESPONSE
        friend struct ResponseResolveOps;
        auto response_address(std::string const& name, std::uint16_t type,
            std::chrono::steady_clock::time_point deadline, std::optional<std::string_view> candidate, bool& local)
            -> udp_capy::task<std::expected<dns::AddressAnswer, dns::detail::ResolveError>> {
            return ResponseResolveOps::response_address(*this, name, type, deadline, candidate, local);
        }
#endif
        auto run(udp_io::endpoint upstream,std::uint64_t view,std::chrono::steady_clock::time_point deadline)
            -> udp_capy::task<std::expected<void,UdpResolveError>> {
            if (started_) co_return std::unexpected(UdpResolveError::state);
            started_=true;
            if (canceled_) { finished_=true; co_return std::unexpected(UdpResolveError::canceled); }
            auto const& a=pending_.address;
            if (a.size()<5 || a[0]!=3 || !a[1] || a.size()!=static_cast<std::size_t>(a[1])+4) {
                (void)dispatcher_.cancel(pending_.token); finished_=true;
                co_return std::unexpected(UdpResolveError::invalid_target);
            }
            std::string name(a.begin()+2,a.end()-2);
            auto port=static_cast<std::uint16_t>((static_cast<unsigned>(a[a.size()-2])<<8)|a.back());
            for (;;) {
            std::expected<std::vector<dns::Address>,dns::detail::ResolveError> result;
            dns::detail::AddressAnswers<false> answers;
            auto types=dns::detail::address_types(strategy_);
#ifdef NEXUS_DNS_RESPONSE
            if (response_routing_) {
                response_rotation_=local_snapshot_ && local_snapshot_->config.rotate && local_rotation_ ? (*local_rotation_)++ : 0;
                auto count=dns::detail::address_type_count(strategy_);
                std::vector<std::string> candidates;
                if (local_snapshot_ && count==2 && std::ranges::any_of(response_routing_->servers,[](auto const& server){return !server.endpoint.port();})) {
                    auto host=dns::detail::local_hosts_response(*local_snapshot_,name,types[0]);
                    if (!host) { (void)dispatcher_.cancel(pending_.token);finished_=true;co_return std::unexpected(UdpResolveError::dns); }
                    if (host->response) candidates.push_back(host->question);
                    else {
                        auto generated=dns::detail::local_response_candidates(local_snapshot_->config,name,host->question);
                        if (!generated) { (void)dispatcher_.cancel(pending_.token);finished_=true;co_return std::unexpected(UdpResolveError::dns); }
                        candidates=std::move(*generated);
                    }
                } else candidates.emplace_back();
                result=std::unexpected(dns::detail::ResolveError::no_data);
                for (auto const& candidate:candidates) {
                    dns::detail::AddressAnswers<false> candidate_answers;
                    bool local_used=false,next=false;local_candidate_.reset();
                    for (unsigned i=0;i<count;++i) {
                        bool local=false;
                        auto fixed=candidate.empty() ? std::optional<std::string_view>{} : std::optional<std::string_view>{candidate};
                        auto answer=co_await response_address(name,types[i],deadline,fixed,local);
                        local_used|=local;
                        auto added=candidate_answers.add(std::move(answer));
                        if (!added) {
                            if (local && added.error()==dns::detail::ResolveError::name_not_found) { next=true;break; }
                            (void)dispatcher_.cancel(pending_.token);finished_=true;co_return std::unexpected(UdpResolveError::dns);
                        }
                    }
                    if (next) continue;
                    result=candidate_answers.finish();
                    if (!result && local_used && result.error()==dns::detail::ResolveError::no_data) continue;
                    break;
                }
            } else {
#endif
            auto legs=alternate_ ? 2u : 1u;
            for (unsigned leg=0;leg<legs;++leg) {
                std::vector<udp_io::endpoint> upstreams{leg ? alternate_->upstream : upstream};
                auto selected_view=leg ? alternate_->view : view;
                auto tcp=leg ? alternate_->tcp : tcp_only_;
                auto const& hops=leg ? alternate_->hops : hops_;
                for (auto const& hop:hops) {
                    auto resolved=co_await query<false>(upstreams,selected_view,tcp,hop.host,strategy_,deadline);
                    if (canceled_) { finished_=true; co_return std::unexpected(UdpResolveError::canceled); }
                    if (!resolved) { (void)dispatcher_.cancel(pending_.token); finished_=true; co_return std::unexpected(UdpResolveError::dns); }
                    upstreams.clear();
                    for (auto const& address:*resolved) {
                        if (address.size==4) {
                            udp_io::ipv4_address::bytes_type bytes{}; std::copy_n(address.bytes.begin(),4,bytes.begin());
                            upstreams.emplace_back(udp_io::ipv4_address(bytes),hop.port);
                        } else if (address.size==16) {
                            udp_io::ipv6_address::bytes_type bytes{}; std::ranges::copy(address.bytes,bytes.begin());
                            upstreams.emplace_back(udp_io::ipv6_address(bytes),hop.port);
                        } else { (void)dispatcher_.cancel(pending_.token); finished_=true; co_return std::unexpected(UdpResolveError::dns); }
                    }
                    selected_view=hop.view; tcp=hop.tcp_only;
                }
                if (alternate_) {
                    auto family=types[leg]==1 ? dns::detail::AddressStrategy::ipv4_only : dns::detail::AddressStrategy::ipv6_only;
                    auto answer=co_await query<true>(upstreams,selected_view,tcp,name,family,deadline,cache_policy_);
                    auto added=answers.add(std::move(answer));
                    if (!added) { result=std::unexpected(added.error()); break; }
                    if (leg+1==legs) result=answers.finish();
                } else result=co_await query<false>(upstreams,selected_view,tcp,name,strategy_,deadline,cache_policy_);
            }
#ifdef NEXUS_DNS_RESPONSE
            }
#endif
            if (canceled_) { finished_=true; co_return std::unexpected(UdpResolveError::canceled); }
            if (!result) {
                (void)dispatcher_.cancel(pending_.token); finished_=true;
                co_return std::unexpected(UdpResolveError::dns);
            }
            std::vector<UdpPeer> candidates; candidates.reserve(result->size());
            for (auto const& address:*result) {
                if (address.size!=4 && address.size!=16) {
                    (void)dispatcher_.cancel(pending_.token); finished_=true;
                    co_return std::unexpected(UdpResolveError::dns);
                }
                candidates.push_back({address.size==4 ? std::uint8_t{4} : std::uint8_t{6},address.bytes,port});
            }
            if (std::chrono::steady_clock::now()>=deadline) {
                (void)dispatcher_.cancel(pending_.token); finished_=true;
                co_return std::unexpected(UdpResolveError::dns);
            }
            if (resolved_handler_) {
                auto handled=resolved_handler_(pending_.token,candidates,deadline);
                if (handled && *handled==UdpResolvedAction::resolve_again) continue;
                if (!handled) (void)dispatcher_.cancel(pending_.token);
                finished_=true;
                if (!handled) co_return std::unexpected(handled.error());
                co_return std::expected<void,UdpResolveError>{};
            }
            auto sent=dispatcher_.complete(pending_.token,candidates,std::chrono::steady_clock::now());
            finished_=true;
            if (!sent) co_return std::unexpected(UdpResolveError::dispatch);
            co_return std::expected<void,UdpResolveError>{};
            }
        }
    };
    struct UdpResolveOptions {
        bool tcp_only=false;
        dns::detail::AddressStrategy strategy=dns::detail::AddressStrategy::prefer_ipv4;
        bool disable_cache=false;
        bool edns=false;
    };
    enum class UdpResolveStartError { stopped, full, expired, duplicate };
    template<class Lookup>
    class BasicUdpResolveOwner {
        using Clock=std::chrono::steady_clock;
        struct Entry { std::unique_ptr<BasicUdpResolveOperation<Lookup>> operation; Clock::time_point deadline; };
        UdpDispatcher& dispatcher_;
        udp_io::io_context& context_;
        typename Lookup::Cache& cache_;
        typename Lookup::Reader* reader_;
        [[no_unique_address]] typename Lookup::Extra extra_;
        dns::LocalSnapshotSource* local_source_;
        std::size_t* local_rotation_;
        std::vector<std::pair<std::uint64_t,Entry>> active_;
        std::size_t limit_;
        bool stopped_=false;
        std::size_t succeeded_=0,failed_=0;
        auto find_active(std::uint64_t token) noexcept {
            auto it=std::ranges::lower_bound(active_,token,{},[](auto const& item){return item.first;});
            return (it!=active_.end() && it->first==token) ? it : active_.end();
        }
        auto find_active(std::uint64_t token) const noexcept {
            auto it=std::ranges::lower_bound(active_,token,{},[](auto const& item){return item.first;});
            return (it!=active_.end() && it->first==token) ? it : active_.end();
        }
        // The active entry owns the operation until run finishes. Completion
        // erases it only after the awaited operation has returned or unwound.
        auto run(BasicUdpResolveOperation<Lookup>& operation,udp_io::endpoint upstream,
                 std::uint64_t view,Clock::time_point deadline) -> udp_capy::task<> {
            auto result=co_await operation.run(upstream,view,deadline);
            if (result) ++succeeded_; else ++failed_;
        }
        auto done(std::uint64_t token,bool exception) noexcept -> void {
            auto it=find_active(token);
            if (it==active_.end()) return;
            if (exception) { ++failed_; it->second.operation->cancel(); }
            active_.erase(it);
        }
    public:
        BasicUdpResolveOwner(UdpDispatcher& dispatcher,udp_io::io_context& context,typename Lookup::Cache& cache,std::size_t limit,
                        dns::LocalSnapshotSource* local_source=nullptr,std::size_t* local_rotation=nullptr,
                        typename Lookup::Reader* reader=nullptr,typename Lookup::Extra extra={})
            : dispatcher_(dispatcher),context_(context),cache_(cache),reader_(reader),extra_(extra),
              local_source_(local_source),local_rotation_(local_rotation),limit_(limit) {}
        BasicUdpResolveOwner(BasicUdpResolveOwner const&)=delete;
        auto operator=(BasicUdpResolveOwner const&) -> BasicUdpResolveOwner& = delete;
        // Every method and completion must run on the same executor. On failure
        // to start, the supplied pending token is canceled before return.
        [[nodiscard]] auto start(UdpPending pending,udp_io::endpoint upstream,std::uint64_t view,
            Clock::time_point now,Clock::time_point deadline,
            dns::detail::AddressStrategy strategy=dns::detail::AddressStrategy::prefer_ipv4,
            bool tcp_only=false,bool disable_cache=false,bool edns=false,std::vector<UdpResolveHop> hops={},
            std::optional<UdpResolvePlan> alternate={},std::optional<dns::detail::FamilyCachePolicy> cache_policy={}
#ifdef NEXUS_DNS_RESPONSE
            ,UdpResponseRouting const* response_routing=nullptr,UdpResponseContext response_context={}
#endif
            ,UdpResolvedHandler resolved_handler={}
            )
            -> std::expected<void,UdpResolveStartError> {
            auto token=pending.token;
            auto reject=[&](UdpResolveStartError error) -> std::expected<void,UdpResolveStartError> {
                (void)dispatcher_.cancel(token); return std::unexpected(error);
            };
            if (find_active(token)!=active_.end()) return std::unexpected(UdpResolveStartError::duplicate);
            if (stopped_) return reject(UdpResolveStartError::stopped);
            if (active_.size()>=limit_) return reject(UdpResolveStartError::full);
            if (deadline<=now) return reject(UdpResolveStartError::expired);
            std::unique_ptr<BasicUdpResolveOperation<Lookup>> operation;
            try { operation=std::make_unique<BasicUdpResolveOperation<Lookup>>(dispatcher_,context_,cache_,std::move(pending),tcp_only,strategy,disable_cache,edns,std::move(hops),local_source_ ? local_source_->acquire() : nullptr,local_rotation_,reader_,extra_,std::move(alternate),cache_policy
#ifdef NEXUS_DNS_RESPONSE
                ,response_routing,response_context
#endif
                ,std::move(resolved_handler)
                ); }
            catch (...) { (void)dispatcher_.cancel(token); throw; }
            auto* raw=operation.get();
            if (active_.empty() || active_.back().first<token) active_.emplace_back(token,Entry{std::move(operation),deadline});
            else {
                auto pos=std::ranges::lower_bound(active_,token,{},[](auto const& item){return item.first;});
                if (pos!=active_.end() && pos->first==token) return reject(UdpResolveStartError::full);
                active_.emplace(pos,token,Entry{std::move(operation),deadline});
            }
            try {
                udp_capy::run_async(context_.get_executor(),[this,token] { done(token,false); },
                    [this,token](std::exception_ptr) noexcept { done(token,true); })(run(*raw,upstream,view,deadline));
            } catch (...) {
                if (auto it=find_active(token); it!=active_.end()) {
                    it->second.operation->cancel();
                    active_.erase(it);
                }
                throw;
            }
            return {};
        }
        auto cancel_expired(Clock::time_point now) noexcept -> void {
            for (auto& [token,entry]:active_) if (entry.deadline<=now) entry.operation->cancel();
        }
        auto stop() noexcept -> void {
            stopped_=true;
            for (auto& [token,entry]:active_) entry.operation->cancel();
        }
        [[nodiscard]] auto drained() const noexcept -> bool { return active_.empty(); }
        [[nodiscard]] auto busy(std::uint64_t token) const noexcept -> bool { return find_active(token)!=active_.end(); }
        [[nodiscard]] auto active() const noexcept -> std::size_t { return active_.size(); }
        [[nodiscard]] auto succeeded() const noexcept -> std::size_t { return succeeded_; }
        [[nodiscard]] auto failed() const noexcept -> std::size_t { return failed_; }
    };
    using UdpDefaultLookup=UdpCachedLookup<dns::AddressCache>;
    using UdpDnsCache=dns::AddressCache;
    using UdpResolveOperation=BasicUdpResolveOperation<UdpDefaultLookup>;
    using UdpResolveOwner=BasicUdpResolveOwner<UdpDefaultLookup>;
}
