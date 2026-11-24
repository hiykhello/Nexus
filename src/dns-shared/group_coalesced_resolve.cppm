// Coordinated DNS coalesced resolver composition module.
export module dns.group_coalesced_resolve;
import std;
import capy;
import corosio;
import dns.cache;
import dns.corosio_cached;
import dns.message;
import dns.reverse;
export import dns.group_flight_operation;

export namespace dns_hp_experiment {
    template<class Cache>
    class CoalescedCachedResolver {
        using Clock = std::chrono::steady_clock;
        Cache& cache_;
        typename Cache::Reader* reader_;
        FlightGroup& group_;
        FlightOwner<Cache>& owner_;
        FlightOperation<Cache> flight_;
        io::io_context& context_;
        d::detail::BasicRefreshOwner<Cache>* refresh_;
        std::optional<d::detail::AddressResolver> direct_;
        bool coordinated_refresh_ = false, started_ = false, canceled_ = false;
#ifdef NEXUS_TEST_DNS_REVERSE_OBSERVATION
        bool fresh_for_reverse_ = true;
#endif
        static auto now_ms() noexcept -> std::uint64_t {
            auto value = std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now().time_since_epoch()).count();
            return value < 0 ? 0 : static_cast<std::uint64_t>(value);
        }
        static auto from_ms(std::uint64_t value) noexcept -> Clock::time_point {
            auto maximum = std::chrono::duration_cast<std::chrono::milliseconds>(Clock::duration::max()).count();
            if (value > static_cast<std::uint64_t>(maximum)) return Clock::time_point::max();
            return Clock::time_point(std::chrono::duration_cast<Clock::duration>(std::chrono::milliseconds(value)));
        }
    public:
        CoalescedCachedResolver(io::io_context& context, Cache& cache, typename Cache::Reader* reader,
                                FlightGroup& group, FlightOwner<Cache>& owner,
                                d::detail::BasicRefreshOwner<Cache>* refresh = nullptr, bool coordinated_refresh = false)
            : cache_(cache), reader_(reader), group_(group), owner_(owner), flight_(group, owner),
              context_(context), refresh_(refresh), coordinated_refresh_(coordinated_refresh) {
            if (refresh_ && coordinated_refresh_) throw std::invalid_argument("conflicting refresh owners");
        }
        CoalescedCachedResolver(CoalescedCachedResolver const&) = delete;
#ifdef NEXUS_TEST_DNS_REVERSE_OBSERVATION
        [[nodiscard]] auto fresh_for_reverse() const noexcept -> bool { return fresh_for_reverse_; }
#endif
        auto cancel() noexcept -> void {
            canceled_ = true;
            flight_.cancel();
            if (direct_) direct_->cancel();
        }
        [[nodiscard]] auto try_resolve_cached(FlightGroup::Key const& key, Clock::time_point deadline)
            -> std::optional<FlightGroup::Result> {
            using Error = d::detail::ResolveError;
            if (key.subnet && !d::valid_client_subnet(*key.subnet)) return std::unexpected(Error::state);
            if (canceled_) return std::unexpected(Error::canceled);
            auto const tp = Clock::now();
            if (tp >= deadline) return std::unexpected(Error::timeout);
            if (!key.use_cache) return std::nullopt;
            auto const ms_val = std::chrono::duration_cast<std::chrono::milliseconds>(tp.time_since_epoch()).count();
            auto const now = ms_val < 0 ? std::uint64_t{0} : static_cast<std::uint64_t>(ms_val);
            auto cached = reader_ ? cache_.lookup_fresh(key.cache, now, *reader_) : cache_.lookup_fresh(key.cache, now);
            if (!cached && cached.error() == d::CacheError::reader_required) return std::unexpected(Error::state);
            if (cached && *cached) {
                auto& entry = **cached;
                if (entry.answer) return std::move(*entry.answer);
                if (entry.negative) return std::unexpected(*entry.negative == d::NegativeKind::name_not_found ?
                    Error::name_not_found : Error::no_data);
            }
            if ((refresh_ && !key.subnet && !key.protection) || coordinated_refresh_) {
                auto stale = reader_ ? cache_.lookup_stale(key.cache, now, *reader_) : cache_.lookup_stale(key.cache, now);
                if (stale && *stale) {
                    try {
                        if (refresh_) (void)refresh_->start(key.cache, key.upstream, key.tcp, key.edns);
                        else (void)owner_.start_refresh(key);
                    } catch (...) {}
#ifdef NEXUS_TEST_DNS_REVERSE_OBSERVATION
                    fresh_for_reverse_ = false;
#endif
                    return std::move((**stale).answer);
                }
            }
            return std::nullopt;
        }
        auto resolve(FlightGroup::Key key, Clock::time_point deadline) -> capy::task<FlightGroup::Result> {
            using Error = d::detail::ResolveError;
            if (started_) co_return std::unexpected(Error::state);
            started_ = true;
            if (auto hit = try_resolve_cached(key, deadline)) co_return std::move(*hit);
            if (!key.use_cache) {
                if (!owner_.available()) co_return std::unexpected(Error::canceled);
                auto lease = group_.try_direct();
                if (!lease) co_return std::unexpected(Error::limit);
                direct_.emplace(context_, key.tcp, key.edns, key.subnet, key.protection.get());
                auto answer = co_await direct_->resolve_random(key.upstream, {key.cache.name, key.cache.type}, deadline);
                if (canceled_) co_return std::unexpected(Error::canceled);
                co_return answer;
            }
            auto recheck = [this](FlightGroup::Key const& joined) -> std::optional<FlightGroup::Rechecked> {
                auto cached = reader_ ? cache_.lookup_fresh(joined.cache, now_ms(), *reader_) : cache_.lookup_fresh(joined.cache, now_ms());
                if (!cached && cached.error() == d::CacheError::reader_required)
                    return FlightGroup::Rechecked{std::unexpected(Error::state), {}};
                if (cached && *cached) {
                    auto& entry = **cached;
                    auto expires = from_ms(entry.expires);
                    if (entry.answer) return FlightGroup::Rechecked{std::move(*entry.answer), expires};
                    if (entry.negative) return FlightGroup::Rechecked{std::unexpected(*entry.negative == d::NegativeKind::name_not_found ?
                        Error::name_not_found : Error::no_data), expires};
                    return FlightGroup::Rechecked{std::unexpected(Error::state), {}};
                }
                return {};
            };
            co_return co_await flight_.resolve(std::move(key), deadline, recheck);
        }
    };

    template<class Cache>
    class CoalescedDualResolver {
        using Clock = std::chrono::steady_clock;
        io::io_context& context_;
        Cache& cache_;
        typename Cache::Reader* reader_;
        FlightGroup& group_;
        FlightOwner<Cache>& owner_;
        d::detail::BasicRefreshOwner<Cache>* refresh_;
        std::optional<CoalescedCachedResolver<Cache>> active_;
        d::detail::AddressStrategy strategy_;
        bool tcp_, edns_, coordinated_refresh_, started_ = false, canceled_ = false;
        std::optional<d::ClientSubnet> subnet_;
        d::detail::FamilyCachePolicy disable_cache_;
        std::shared_ptr<d::detail::ProtectedQuery const> protection_;
#ifdef NEXUS_TEST_DNS_REVERSE_OBSERVATION
        d::ReverseCache* reverse_for_test_ = nullptr;
        static auto reverse_now() noexcept -> std::uint64_t {
            auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now().time_since_epoch()).count();
            return ms < 0 ? 0 : static_cast<std::uint64_t>(ms);
        }
#endif
    public:
        CoalescedDualResolver(io::io_context& context, Cache& cache, typename Cache::Reader* reader,
                              FlightGroup& group, FlightOwner<Cache>& owner, d::detail::AddressStrategy strategy,
                              bool tcp = false, bool disable_cache = false, bool edns = false,
                              d::detail::BasicRefreshOwner<Cache>* refresh = nullptr, bool coordinated_refresh = false,
                              std::optional<d::detail::FamilyCachePolicy> cache_policy = {}, std::optional<d::ClientSubnet> subnet = {},
                              std::shared_ptr<d::detail::ProtectedQuery const> protection = {})
            : context_(context), cache_(cache), reader_(reader), group_(group), owner_(owner), refresh_(refresh),
              strategy_(strategy), tcp_(tcp), edns_(edns), coordinated_refresh_(coordinated_refresh), subnet_(subnet),
              disable_cache_(cache_policy.value_or(d::detail::FamilyCachePolicy{disable_cache, disable_cache})),
              protection_(std::move(protection)) {
            if (refresh_ && coordinated_refresh_) throw std::invalid_argument("conflicting refresh owners");
        }
        CoalescedDualResolver(CoalescedDualResolver const&) = delete;
#ifdef NEXUS_TEST_DNS_REVERSE_OBSERVATION
        auto observe_reverse_for_test(d::ReverseCache& cache) noexcept -> void { reverse_for_test_ = &cache; }
#endif
        auto cancel() noexcept -> void { canceled_ = true; if (active_) active_->cancel(); }
    private:
        auto try_lookup_one(io::endpoint upstream, std::uint64_t view, std::string_view name, std::uint16_t type,
            std::uint64_t now, bool& fresh_hit) -> std::optional<FlightGroup::Result> {
            using Error = d::detail::ResolveError;
            fresh_hit = true;
            if (subnet_ && !d::valid_client_subnet(*subnet_)) return std::unexpected(Error::state);
            if (disable_cache_[type == 1 ? 0 : 1]) return std::nullopt;
            d::CacheKey ck{view, std::string(name), type};
            auto cached = reader_ ? cache_.lookup_fresh(ck, now, *reader_) : cache_.lookup_fresh(ck, now);
            if (!cached && cached.error() == d::CacheError::reader_required) return std::unexpected(Error::state);
            if (cached && *cached) {
                auto& entry = **cached;
                if (entry.answer) return std::move(*entry.answer);
                if (entry.negative) return std::unexpected(*entry.negative == d::NegativeKind::name_not_found ?
                    Error::name_not_found : Error::no_data);
            }
            if ((refresh_ && !subnet_ && !protection_) || coordinated_refresh_) {
                auto stale = reader_ ? cache_.lookup_stale(ck, now, *reader_) : cache_.lookup_stale(ck, now);
                if (stale && *stale) {
                    try {
                        if (refresh_) (void)refresh_->start(ck, upstream, tcp_, edns_);
                        else {
                            FlightGroup::Key key{std::move(ck), upstream, tcp_, edns_, true};
                            key.subnet = subnet_;
                            key.protection = protection_;
                            (void)owner_.start_refresh(std::move(key));
                        }
                    } catch (...) {}
                    fresh_hit = false;
                    return std::move((**stale).answer);
                }
            }
            return std::nullopt;
        }
    public:
        template<bool Full>
        [[nodiscard]] auto try_resolve_cached_impl(io::endpoint upstream, std::uint64_t view, std::string_view name,
            Clock::time_point deadline) -> std::optional<std::expected<d::detail::AddressResult<Full>, d::detail::ResolveError>> {
            using Error = d::detail::ResolveError;
            if (started_ || canceled_) return std::nullopt;
            if (subnet_ && !d::valid_client_subnet(*subnet_)) return std::unexpected(Error::state);
            auto const tp = Clock::now();
            if (tp >= deadline) return std::unexpected(Error::timeout);
            auto const ms_val = std::chrono::duration_cast<std::chrono::milliseconds>(tp.time_since_epoch()).count();
            auto const now = ms_val < 0 ? std::uint64_t{0} : static_cast<std::uint64_t>(ms_val);
            d::detail::AddressAnswers<Full> answers;
            auto types = d::detail::address_types(strategy_);
            auto count = d::detail::address_type_count(strategy_);
            for (unsigned i = 0; i < count; ++i) {
                bool fresh = true;
                auto hit = try_lookup_one(upstream, view, name, types[i], now, fresh);
                if (!hit) return std::nullopt;
                auto added = answers.add(std::move(*hit));
                if (!added) return std::unexpected(added.error());
            }
            return answers.finish();
        }
        template<bool Full>
        auto resolve_impl(io::endpoint upstream, std::uint64_t view, std::string name, Clock::time_point deadline)
            -> capy::task<std::expected<d::detail::AddressResult<Full>, d::detail::ResolveError>> {
            using Error = d::detail::ResolveError;
            if (started_) co_return std::unexpected(Error::state);
            started_ = true;
            if (canceled_) co_return std::unexpected(Error::canceled);
            if (subnet_ && !d::valid_client_subnet(*subnet_)) co_return std::unexpected(Error::state);
            auto const tp = Clock::now();
            if (tp >= deadline) co_return std::unexpected(Error::timeout);
            auto const ms_val = std::chrono::duration_cast<std::chrono::milliseconds>(tp.time_since_epoch()).count();
            auto const now = ms_val < 0 ? std::uint64_t{0} : static_cast<std::uint64_t>(ms_val);
            d::detail::AddressAnswers<Full> answers;
#ifdef NEXUS_TEST_DNS_REVERSE_OBSERVATION
            auto started = now;
            std::optional<d::ReverseTransaction> reverse;
            if (reverse_for_test_) reverse.emplace(*reverse_for_test_, view, name);
#endif
            auto types = d::detail::address_types(strategy_);
            auto count = d::detail::address_type_count(strategy_);
            for (unsigned i = 0; i < count; ++i) {
                auto const iter_tp = i == 0 ? tp : Clock::now();
                if (iter_tp >= deadline) co_return std::unexpected(Error::timeout);
                auto const iter_ms = std::chrono::duration_cast<std::chrono::milliseconds>(iter_tp.time_since_epoch()).count();
                auto const iter_now = iter_ms < 0 ? std::uint64_t{0} : static_cast<std::uint64_t>(iter_ms);
                bool fresh = true;
                FlightGroup::Result result = std::unexpected(Error::state);
                if (auto hit = try_lookup_one(upstream, view, name, types[i], iter_now, fresh)) {
                    result = std::move(*hit);
                } else {
                    active_.emplace(context_, cache_, reader_, group_, owner_, refresh_, coordinated_refresh_);
                    FlightGroup::Key key{{view, name, types[i]}, upstream, tcp_, edns_, !disable_cache_[types[i] == 1 ? 0 : 1]};
                    key.subnet = subnet_;
                    key.protection = protection_;
                    result = co_await active_->resolve(std::move(key), deadline);
#ifdef NEXUS_TEST_DNS_REVERSE_OBSERVATION
                    fresh = active_->fresh_for_reverse();
#endif
                    active_.reset();
                }
                if (canceled_) co_return std::unexpected(Error::canceled);
#ifdef NEXUS_TEST_DNS_REVERSE_OBSERVATION
                if (reverse && result) (void)reverse->stage(*result, fresh, started);
#endif
                auto added = answers.add(std::move(result));
                if (!added) co_return std::unexpected(added.error());
            }
            auto result = answers.finish();
            if (!result) co_return std::unexpected(result.error());
#ifdef NEXUS_TEST_DNS_REVERSE_OBSERVATION
            if (reverse) (void)reverse->finish(true, reverse_now());
#endif
            co_return result;
        }
        [[nodiscard]] auto try_resolve_cached(io::endpoint upstream, std::uint64_t view, std::string_view name, Clock::time_point deadline)
            -> std::optional<std::expected<std::vector<d::Address>, d::detail::ResolveError>> {
            return try_resolve_cached_impl<false>(upstream, view, name, deadline);
        }
        [[nodiscard]] auto try_resolve_cached_answer(io::endpoint upstream, std::uint64_t view, std::string_view name, Clock::time_point deadline)
            -> std::optional<std::expected<d::AddressAnswer, d::detail::ResolveError>> {
            return try_resolve_cached_impl<true>(upstream, view, name, deadline);
        }
        auto resolve(io::endpoint upstream, std::uint64_t view, std::string name, Clock::time_point deadline)
            -> capy::task<std::expected<std::vector<d::Address>, d::detail::ResolveError>> {
            return resolve_impl<false>(upstream, view, std::move(name), deadline);
        }
        auto resolve_answer(io::endpoint upstream, std::uint64_t view, std::string name, Clock::time_point deadline)
            -> capy::task<std::expected<d::AddressAnswer, d::detail::ResolveError>> {
            return resolve_impl<true>(upstream, view, std::move(name), deadline);
        }
    };
}
