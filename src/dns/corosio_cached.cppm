export module dns.corosio_cached;
import std;
export import dns.address_sequence;
export import dns.cache;

export namespace dns::detail {
    template<class Cache,class=void> struct CacheTokenType { using type=CacheToken; };
    template<class Cache> struct CacheTokenType<Cache,std::void_t<typename Cache::Token>> { using type=typename Cache::Token; };
    template<class Cache> using CacheTokenFor=typename CacheTokenType<Cache>::type;
    // The cache interface can be adapted to an executor's membership in a
    // shared owner; the default alias below retains the existing cache API.
    template<class Cache>
    class BasicRefreshOwner {
        using Clock=std::chrono::steady_clock;
        using Token=CacheTokenFor<Cache>;
        struct Entry {
            CacheKey key;
            Token token;
            std::optional<RefreshBudget::Lease> lease;
            AddressResolver resolver;
            bool canceled=false;
            Entry(CacheKey key_,Token token_,std::optional<RefreshBudget::Lease> lease_,
                  dns_io::io_context& context,bool tcp,bool edns)
                : key(std::move(key_)),token(token_),lease(std::move(lease_)),resolver(context,tcp,edns) {}
        };
        struct Backoff { CacheKey key; Clock::time_point until; };
        dns_io::io_context& context_;
        Cache& cache_;
        RefreshBudget* budget_;
        std::map<std::uint64_t,std::unique_ptr<Entry>> active_;
        std::vector<Backoff> backoff_;
        std::size_t limit_;
        std::chrono::milliseconds timeout_,retry_delay_;
        std::uint64_t next_id_=0;
        bool stopped_=false;
        static auto now_ms() noexcept -> std::uint64_t {
            auto value=std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now().time_since_epoch()).count();
            return value<0 ? 0 : static_cast<std::uint64_t>(value);
        }
        static auto normalized(CacheKey key) -> std::optional<CacheKey> {
            if (key.type!=1 && key.type!=28) return {};
            if (!canonicalize_name(key.name)) return {};
            return key;
        }
        static auto same(CacheKey const& a,CacheKey const& b) noexcept -> bool {
            return a.view==b.view && a.type==b.type && a.name==b.name;
        }
        auto run(Entry& entry,dns_io::endpoint upstream,Clock::time_point deadline) -> dns_capy::task<> {
            struct Registration {
                Cache& cache; Token token;
                ~Registration() { (void)cache.cancel_query(token); }
            } registration{cache_,entry.token};
            auto result=co_await entry.resolver.resolve_random(upstream,{entry.key.name,entry.key.type},deadline);
            if (entry.canceled || stopped_) co_return;
            if (result) {
                (void)cache_.publish(entry.key,std::move(*result),now_ms(),entry.token);
                co_return;
            }
            if (result.error()==ResolveError::name_not_found || result.error()==ResolveError::no_data) {
                auto ttl=entry.resolver.negative_cache_ttl();
                if (ttl) (void)cache_.publish_negative(entry.key,result.error()==ResolveError::name_not_found ? NegativeKind::name_not_found : NegativeKind::no_data,*ttl,now_ms(),entry.token);
                else (void)cache_.invalidate(entry.key,now_ms(),entry.token);
                co_return;
            }
            // Backoff is bounded separately from active work and is best effort.
            try {
                auto now=Clock::now();
                if (entry.lease) { entry.lease->delay_until(now+retry_delay_); co_return; }
                std::erase_if(backoff_,[now](auto const& item) { return item.until<=now; });
                if (backoff_.size()<limit_) backoff_.push_back({entry.key,now+retry_delay_});
            } catch (...) {}
        }
        auto done(std::uint64_t id,bool failed) noexcept -> void {
            auto it=active_.find(id); if (it==active_.end()) return;
            if (failed) (void)cache_.cancel_query(it->second->token);
            active_.erase(it);
        }
    public:
        BasicRefreshOwner(dns_io::io_context& context,Cache& cache,std::size_t limit,
                     std::chrono::milliseconds timeout=std::chrono::seconds(5),std::chrono::milliseconds retry_delay=std::chrono::seconds(1),
                     RefreshBudget* budget=nullptr)
            : context_(context),cache_(cache),budget_(budget),limit_(std::min<std::size_t>(limit,256)),
              timeout_(std::clamp(timeout,std::chrono::milliseconds(1),std::chrono::milliseconds(30000))),
              retry_delay_(std::clamp(retry_delay,std::chrono::milliseconds(1),std::chrono::milliseconds(30000))) {}
        BasicRefreshOwner(BasicRefreshOwner const&)=delete;
        auto operator=(BasicRefreshOwner const&) -> BasicRefreshOwner& = delete;
        // False includes ineligible, already running, throttled, stopped or full.
        // Start failure cancels its cache token before propagating an exception.
        [[nodiscard]] auto start(CacheKey key,dns_io::endpoint upstream,bool tcp=false,bool edns=false) -> bool {
            if (stopped_ || active_.size()>=limit_ || next_id_==std::numeric_limits<std::uint64_t>::max()) return false;
            auto canonical=normalized(std::move(key)); if (!canonical) return false;
            auto now=Clock::now();
            std::erase_if(backoff_,[now](auto const& item) { return item.until<=now; });
            if (std::ranges::any_of(active_,[&](auto const& item) { return same(item.second->key,*canonical); }) ||
                std::ranges::any_of(backoff_,[&](auto const& item) { return same(item.key,*canonical); })) return false;
            std::optional<RefreshBudget::Lease> lease;
            if (budget_) {
                lease=budget_->acquire(*canonical);
                if (!lease) return false;
            }
            auto token=cache_.begin_refresh(*canonical,now_ms(),budget_ ? budget_->limit() : limit_);
            if (!token || !*token) return false;
            auto id=++next_id_;
            try {
                auto entry=std::make_unique<Entry>(std::move(*canonical),**token,std::move(lease),context_,tcp,edns);
                auto [it,inserted]=active_.emplace(id,std::move(entry));
                if (!inserted) { (void)cache_.cancel_query(**token); return false; }
                try {
                    dns_capy::run_async(context_.get_executor(),[this,id] { done(id,false); },
                        [this,id](std::exception_ptr) noexcept { done(id,true); })(run(*it->second,upstream,now+timeout_));
                } catch (...) { active_.erase(it); throw; }
            } catch (...) { (void)cache_.cancel_query(**token); throw; }
            return true;
        }
        auto stop() noexcept -> void {
            stopped_=true;
            for (auto& [id,entry]:active_) { entry->canceled=true; entry->resolver.cancel(); }
        }
        [[nodiscard]] auto active() const noexcept -> std::size_t { return active_.size(); }
        [[nodiscard]] auto drained() const noexcept -> bool { return active_.empty(); }
    };
    using RefreshOwner=BasicRefreshOwner<AddressCache>;
}

export namespace dns::detail {
    // One operation per object; cache and object live until the task completes.
    // All cache access and cancellation occur on the same owner/executor.
    template<class Cache>
    class BasicCachedAddressResolver {
        Cache& cache_;
        typename Cache::Reader* reader_;
        AddressResolver resolver_;
        BasicRefreshOwner<Cache>* refresh_;
        bool started_=false, canceled_=false, disable_cache_=false, tcp_only_=false, edns_=false;
        static auto now_ms() -> std::uint64_t {
            auto value=std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count();
            return value<0 ? 0 : static_cast<std::uint64_t>(value);
        }
    public:
        BasicCachedAddressResolver(dns_io::io_context& context, Cache& cache, bool tcp_only=false, bool disable_cache=false, bool edns=false,
                                   BasicRefreshOwner<Cache>* refresh=nullptr,typename Cache::Reader* reader=nullptr,std::optional<ClientSubnet> subnet={},
                                   ProtectedQuery const* protection=nullptr)
            : cache_(cache), reader_(reader), resolver_(context,tcp_only,edns,subnet,protection), refresh_(protection ? nullptr : refresh), disable_cache_(disable_cache || subnet.has_value()),tcp_only_(tcp_only),edns_(edns) {}
        auto cancel() noexcept -> void { canceled_=true; resolver_.cancel(); }
        auto resolve(dns_io::endpoint upstream, std::uint64_t view, Question question,
                     std::chrono::steady_clock::time_point deadline)
            -> dns_capy::task<std::expected<AddressAnswer,ResolveError>> {
            if (started_) co_return std::unexpected(ResolveError::state);
            started_=true;
            if (canceled_) co_return std::unexpected(ResolveError::canceled);
            if (std::chrono::steady_clock::now()>=deadline) co_return std::unexpected(ResolveError::timeout);
            if (disable_cache_) {
                auto answer=co_await resolver_.resolve_random(upstream,std::move(question),deadline);
                if (canceled_) co_return std::unexpected(ResolveError::canceled);
                co_return answer;
            }
            CacheKey key{view,question.name,question.type};
            auto cached=reader_ ? cache_.lookup(key,now_ms(),*reader_) : cache_.lookup(key,now_ms());
            if (!cached && cached.error()==CacheError::reader_required) co_return std::unexpected(ResolveError::state);
            if (cached && *cached) co_return std::move(**cached);
            auto negative=reader_ ? cache_.lookup_negative(key,now_ms(),*reader_) : cache_.lookup_negative(key,now_ms());
            if (negative && *negative) co_return std::unexpected(**negative==NegativeKind::name_not_found ?
                ResolveError::name_not_found : ResolveError::no_data);
            if (refresh_) {
                auto stale=reader_ ? cache_.lookup_stale(key,now_ms(),*reader_) : cache_.lookup_stale(key,now_ms());
                if (stale && *stale) {
                    try { (void)refresh_->start(key,upstream,tcp_only_,edns_); } catch (...) {}
                    co_return std::move((**stale).answer);
                }
            }
            auto token=cache_.begin_query(key);
            struct Registration {
                Cache& cache;
                std::optional<CacheTokenFor<Cache>> token;
                ~Registration() { if (token) (void)cache.cancel_query(*token); }
            } registration{cache_,token ? std::optional<CacheTokenFor<Cache>>(*token) : std::nullopt};
            auto answer=co_await resolver_.resolve_random(upstream,std::move(question),deadline);
            // Registration is best effort; cache errors do not turn a successful
            // network resolution into a failure. A clear may invalidate the token.
            if (token && !canceled_) {
                if (answer) (void)cache_.publish(key,*answer,now_ms(),*token);
                else if (answer.error()==ResolveError::name_not_found || answer.error()==ResolveError::no_data) {
                    auto ttl=resolver_.negative_cache_ttl();
                    if (ttl) (void)cache_.publish_negative(key,answer.error()==ResolveError::name_not_found ?
                        NegativeKind::name_not_found : NegativeKind::no_data,*ttl,now_ms(),*token);
                    else (void)cache_.invalidate(key,now_ms(),*token);
                }
            }
            if (canceled_) co_return std::unexpected(ResolveError::canceled);
            co_return answer;
        }
    };
    using CachedAddressResolver=BasicCachedAddressResolver<AddressCache>;
}

export namespace dns::detail {
    // A single owner/executor retains this object and its cache until completion.
    // Selected address families share one deadline; a transport or protocol
    // failure fails the operation instead of returning incomplete addresses.
    template<class Cache>
    class BasicDualAddressResolver {
        dns_io::io_context& context_;
        Cache& cache_;
        typename Cache::Reader* reader_;
        BasicRefreshOwner<Cache>* refresh_;
        std::unique_ptr<BasicCachedAddressResolver<Cache>> active_;
        bool started_=false, canceled_=false, tcp_only_=false, edns_=false;
        FamilyCachePolicy disable_cache_;
        AddressStrategy strategy_;
        std::optional<ClientSubnet> subnet_;
        ProtectedQuery const* protection_;
    public:
        BasicDualAddressResolver(dns_io::io_context& context, Cache& cache, bool tcp_only=false,
                                 AddressStrategy strategy=AddressStrategy::prefer_ipv4, bool disable_cache=false, bool edns=false,
                                 BasicRefreshOwner<Cache>* refresh=nullptr,typename Cache::Reader* reader=nullptr,
                                 std::optional<FamilyCachePolicy> cache_policy={},std::optional<ClientSubnet> subnet={},
                                 ProtectedQuery const* protection=nullptr)
            : context_(context), cache_(cache), reader_(reader), refresh_(refresh), tcp_only_(tcp_only), edns_(edns),
              disable_cache_(cache_policy.value_or(FamilyCachePolicy{disable_cache,disable_cache})),strategy_(strategy),subnet_(subnet),protection_(protection) {}
        auto cancel() noexcept -> void { canceled_=true; if (active_) active_->cancel(); }
        template<bool Full>
        auto resolve_impl(dns_io::endpoint upstream, std::uint64_t view, std::string name,
                     std::chrono::steady_clock::time_point deadline)
            -> dns_capy::task<std::expected<AddressResult<Full>,ResolveError>> {
            if (started_) co_return std::unexpected(ResolveError::state);
            started_=true;
            if (canceled_) co_return std::unexpected(ResolveError::canceled);
            AddressAnswers<Full> answers;
            auto types=address_types(strategy_);
            auto count=address_type_count(strategy_);
            for (unsigned i=0;i<count;++i) {
                auto type=types[i];
                active_=std::make_unique<BasicCachedAddressResolver<Cache>>(context_,cache_,tcp_only_,disable_cache_[type==1 ? 0 : 1],edns_,refresh_,reader_,subnet_,protection_);
                auto result=co_await active_->resolve(upstream,view,{name,type},deadline);
                active_.reset();
                if (canceled_) co_return std::unexpected(ResolveError::canceled);
                auto added=answers.add(std::move(result));
                if (!added) co_return std::unexpected(added.error());
            }
            co_return answers.finish();
        }
        auto resolve(dns_io::endpoint upstream,std::uint64_t view,std::string name,
                     std::chrono::steady_clock::time_point deadline)
            -> dns_capy::task<std::expected<std::vector<Address>,ResolveError>> {
            return resolve_impl<false>(upstream,view,std::move(name),deadline);
        }
        auto resolve_answer(dns_io::endpoint upstream,std::uint64_t view,std::string name,
                            std::chrono::steady_clock::time_point deadline)
            -> dns_capy::task<std::expected<AddressAnswer,ResolveError>> {
            return resolve_impl<true>(upstream,view,std::move(name),deadline);
        }
    };
    using DualAddressResolver=BasicDualAddressResolver<AddressCache>;
}
