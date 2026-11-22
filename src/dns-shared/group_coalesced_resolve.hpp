// Coordinated resolver composition. One object is used for
// one query; all methods run on its executor. The cache, reader, flight group,
// owner and optional refresh owner outlive the complete coroutine and drain.
#pragma once
#include "group_singleflight.hpp"

namespace dns_hp_experiment {
template<class Cache>
class CoalescedCachedResolver {
    using Clock=std::chrono::steady_clock;
    Cache& cache_;
    typename Cache::Reader* reader_;
    FlightGroup& group_;
    FlightOwner<Cache>& owner_;
    FlightOperation<Cache> flight_;
    io::io_context& context_;
    d::detail::BasicRefreshOwner<Cache>* refresh_;
    std::optional<d::detail::AddressResolver> direct_;
    bool coordinated_refresh_=false,started_=false,canceled_=false;
#ifdef NEXUS_TEST_DNS_REVERSE_OBSERVATION
    bool fresh_for_reverse_=true;
#endif
    static auto now_ms() noexcept -> std::uint64_t {
        auto value=std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now().time_since_epoch()).count();
        return value<0 ? 0 : static_cast<std::uint64_t>(value);
    }
    static auto from_ms(std::uint64_t value) noexcept -> Clock::time_point {
        auto maximum=std::chrono::duration_cast<std::chrono::milliseconds>(Clock::duration::max()).count();
        if (value>static_cast<std::uint64_t>(maximum)) return Clock::time_point::max();
        return Clock::time_point(std::chrono::duration_cast<Clock::duration>(std::chrono::milliseconds(value)));
    }
public:
    CoalescedCachedResolver(io::io_context& context,Cache& cache,typename Cache::Reader* reader,
                            FlightGroup& group,FlightOwner<Cache>& owner,
                            d::detail::BasicRefreshOwner<Cache>* refresh=nullptr,bool coordinated_refresh=false)
        : cache_(cache),reader_(reader),group_(group),owner_(owner),flight_(group,owner),context_(context),refresh_(refresh),
          coordinated_refresh_(coordinated_refresh) {
        if (refresh_ && coordinated_refresh_) throw std::invalid_argument("conflicting refresh owners");
    }
    CoalescedCachedResolver(CoalescedCachedResolver const&)=delete;
#ifdef NEXUS_TEST_DNS_REVERSE_OBSERVATION
    [[nodiscard]] auto fresh_for_reverse() const noexcept -> bool { return fresh_for_reverse_; }
#endif
    auto cancel() noexcept -> void {
        canceled_=true; flight_.cancel(); if (direct_) direct_->cancel();
    }
    auto resolve(FlightGroup::Key key,Clock::time_point deadline) -> capy::task<FlightGroup::Result> {
        using Error=d::detail::ResolveError;
        if (started_) co_return std::unexpected(Error::state);
        started_=true;
        if (key.subnet && !d::valid_client_subnet(*key.subnet)) co_return std::unexpected(Error::state);
        if (canceled_) co_return std::unexpected(Error::canceled);
        if (Clock::now()>=deadline) co_return std::unexpected(Error::timeout);
        // An explicit no-cache policy performs its own query, preserving the
        // existing resolver's behavior; internal cache failure still uses the
        // bounded flight group instead of launching an unbounded bypass.
        if (!key.use_cache) {
            if (!owner_.available()) co_return std::unexpected(Error::canceled);
            auto lease=group_.try_direct();
            if (!lease) co_return std::unexpected(Error::limit);
            direct_.emplace(context_,key.tcp,key.edns,key.subnet,key.protection.get());
            auto answer=co_await direct_->resolve_random(key.upstream,{key.cache.name,key.cache.type},deadline);
            if (canceled_) co_return std::unexpected(Error::canceled);
            co_return answer;
        }
        // One snapshot lookup supplies both positive and negative answers.
        // A miss still goes through registration and the existing recheck.
        auto cached=reader_ ? cache_.lookup_fresh(key.cache,now_ms(),*reader_) : cache_.lookup_fresh(key.cache,now_ms());
        if (!cached && cached.error()==d::CacheError::reader_required) co_return std::unexpected(Error::state);
        if (cached && *cached) {
            auto& entry=**cached;
            if (entry.answer) co_return std::move(*entry.answer);
            if (entry.negative) co_return std::unexpected(*entry.negative==d::NegativeKind::name_not_found ?
                Error::name_not_found : Error::no_data);
        }
        if ((refresh_ && !key.subnet && !key.protection) || coordinated_refresh_) {
            auto stale=reader_ ? cache_.lookup_stale(key.cache,now_ms(),*reader_) : cache_.lookup_stale(key.cache,now_ms());
            if (stale && *stale) {
                try {
                    if (refresh_) (void)refresh_->start(key.cache,key.upstream,key.tcp,key.edns);
                    else (void)owner_.start_refresh(key);
                } catch (...) {}
#ifdef NEXUS_TEST_DNS_REVERSE_OBSERVATION
                fresh_for_reverse_=false;
#endif
                co_return std::move((**stale).answer);
            }
        }
        auto recheck=[this](FlightGroup::Key const& joined) -> std::optional<FlightGroup::Rechecked> {
            auto cached=reader_ ? cache_.lookup_fresh(joined.cache,now_ms(),*reader_) : cache_.lookup_fresh(joined.cache,now_ms());
            if (!cached && cached.error()==d::CacheError::reader_required)
                return FlightGroup::Rechecked{std::unexpected(Error::state),{}};
            if (cached && *cached) {
                auto& entry=**cached; auto expires=from_ms(entry.expires);
                if (entry.answer) return FlightGroup::Rechecked{std::move(*entry.answer),expires};
                if (entry.negative) return FlightGroup::Rechecked{std::unexpected(*entry.negative==d::NegativeKind::name_not_found ?
                    Error::name_not_found : Error::no_data),expires};
                return FlightGroup::Rechecked{std::unexpected(Error::state),{}};
            }
            return {};
        };
        co_return co_await flight_.resolve(std::move(key),deadline,recheck);
    }
};

// Same sequential A/AAAA policy as the existing dual resolver, with the
// foreground coalescer substituted for each address query.
template<class Cache>
class CoalescedDualResolver {
    using Clock=std::chrono::steady_clock;
    io::io_context& context_;
    Cache& cache_;
    typename Cache::Reader* reader_;
    FlightGroup& group_;
    FlightOwner<Cache>& owner_;
    d::detail::BasicRefreshOwner<Cache>* refresh_;
    std::optional<CoalescedCachedResolver<Cache>> active_;
    d::detail::AddressStrategy strategy_;
    bool tcp_,edns_,coordinated_refresh_,started_=false,canceled_=false;
    std::optional<d::ClientSubnet> subnet_;
    d::detail::FamilyCachePolicy disable_cache_;
    std::shared_ptr<d::detail::ProtectedQuery const> protection_;
#ifdef NEXUS_TEST_DNS_REVERSE_OBSERVATION
    d::ReverseCache* reverse_for_test_=nullptr;
    static auto reverse_now() noexcept -> std::uint64_t {
        auto ms=std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now().time_since_epoch()).count();
        return ms<0 ? 0 : static_cast<std::uint64_t>(ms);
    }
#endif
public:
    CoalescedDualResolver(io::io_context& context,Cache& cache,typename Cache::Reader* reader,
                          FlightGroup& group,FlightOwner<Cache>& owner,d::detail::AddressStrategy strategy,
                          bool tcp=false,bool disable_cache=false,bool edns=false,
                          d::detail::BasicRefreshOwner<Cache>* refresh=nullptr,bool coordinated_refresh=false,
                          std::optional<d::detail::FamilyCachePolicy> cache_policy={},std::optional<d::ClientSubnet> subnet={},
                          std::shared_ptr<d::detail::ProtectedQuery const> protection={})
        : context_(context),cache_(cache),reader_(reader),group_(group),owner_(owner),refresh_(refresh),
          strategy_(strategy),tcp_(tcp),edns_(edns),coordinated_refresh_(coordinated_refresh),subnet_(subnet),
          disable_cache_(cache_policy.value_or(d::detail::FamilyCachePolicy{disable_cache,disable_cache})),protection_(std::move(protection)) {
        if (refresh_ && coordinated_refresh_) throw std::invalid_argument("conflicting refresh owners");
    }
    CoalescedDualResolver(CoalescedDualResolver const&)=delete;
#ifdef NEXUS_TEST_DNS_REVERSE_OBSERVATION
    auto observe_reverse_for_test(d::ReverseCache& cache) noexcept -> void { reverse_for_test_=&cache; }
#endif
    auto cancel() noexcept -> void { canceled_=true; if (active_) active_->cancel(); }
    template<bool Full>
    auto resolve_impl(io::endpoint upstream,std::uint64_t view,std::string name,Clock::time_point deadline)
        -> capy::task<std::expected<d::detail::AddressResult<Full>,d::detail::ResolveError>> {
        using Error=d::detail::ResolveError;
        if (started_) co_return std::unexpected(Error::state);
        started_=true;
        if (canceled_) co_return std::unexpected(Error::canceled);
        d::detail::AddressAnswers<Full> answers;
#ifdef NEXUS_TEST_DNS_REVERSE_OBSERVATION
        // Capture the epoch before the first suspension; the start bound is
        // no later than every cache lookup or network question in this query.
        auto started=reverse_now();
        std::optional<d::ReverseTransaction> reverse;
        if (reverse_for_test_) reverse.emplace(*reverse_for_test_,view,name);
#endif
        auto types=d::detail::address_types(strategy_);
        auto count=d::detail::address_type_count(strategy_);
        for (unsigned i=0;i<count;++i) {
            active_.emplace(context_,cache_,reader_,group_,owner_,refresh_,coordinated_refresh_);
            FlightGroup::Key key{{view,name,types[i]},upstream,tcp_,edns_,!disable_cache_[types[i]==1 ? 0 : 1]};
            key.subnet=subnet_;
            key.protection=protection_;
            auto result=co_await active_->resolve(std::move(key),deadline);
#ifdef NEXUS_TEST_DNS_REVERSE_OBSERVATION
            auto fresh=active_->fresh_for_reverse();
#endif
            active_.reset();
            if (canceled_) co_return std::unexpected(Error::canceled);
#ifdef NEXUS_TEST_DNS_REVERSE_OBSERVATION
            if (reverse && result) (void)reverse->stage(*result,fresh,started);
#endif
            auto added=answers.add(std::move(result));
            if (!added) co_return std::unexpected(added.error());
        }
        auto result=answers.finish();
        if (!result) co_return std::unexpected(result.error());
#ifdef NEXUS_TEST_DNS_REVERSE_OBSERVATION
        if (reverse) (void)reverse->finish(true,reverse_now());
#endif
        co_return result;
    }
    auto resolve(io::endpoint upstream,std::uint64_t view,std::string name,Clock::time_point deadline)
        -> capy::task<std::expected<std::vector<d::Address>,d::detail::ResolveError>> {
        return resolve_impl<false>(upstream,view,std::move(name),deadline);
    }
    auto resolve_answer(io::endpoint upstream,std::uint64_t view,std::string name,Clock::time_point deadline)
        -> capy::task<std::expected<d::AddressAnswer,d::detail::ResolveError>> {
        return resolve_impl<true>(upstream,view,std::move(name),deadline);
    }
};
}
