// Bounded foreground DNS coalescing.
// Import std, nexus.dns.message and nexus.dns.cache before including this file.
// A FlightGroup belongs to one immutable DNS configuration; all waiters and
// per-executor owners must drain before that group, its cache and contexts die.
#pragma once
#ifndef NEXUS_DNS_USE_MODULES
#include <boost/capy/ex/async_waker.hpp>
#include <boost/capy/ex/run_async.hpp>
#include <boost/capy/when_all.hpp>
#include <boost/corosio/timeout.hpp>
#endif

namespace dns_hp_experiment {
namespace d=dns;
#ifdef NEXUS_DNS_USE_MODULES
namespace io=nex::corosio;
namespace capy=nex::capy;
#else
namespace io=boost::corosio;
namespace capy=boost::capy;
#endif

class FlightGroup {
public:
    using Result=std::expected<d::AddressAnswer,d::detail::ResolveError>;
#ifdef NEXUS_DNS_RESPONSE
    using RawResult=std::expected<d::Response,d::detail::ResolveError>;
#endif
    using Clock=std::chrono::steady_clock;
    struct Key {
        d::CacheKey cache;
        io::endpoint upstream;
        bool tcp=false,edns=false,use_cache=true;
#ifdef NEXUS_DNS_RESPONSE
        bool raw_response=false;
#endif
        std::optional<d::ClientSubnet> subnet;
        std::shared_ptr<d::detail::ProtectedQuery const> protection{};
    };
private:
    struct Flight;
public:
    // Owned by one operation on its executor. The group borrows its address
    // only between join() and leave(); neither the operation nor its executor
    // may be destroyed before the suspended resolve has unwound. A registered
    // waiter is one-shot because its waker can retain a completion token.
    struct Waiter {
        capy::async_waker wake;
        ~Waiter() { if (flight) std::terminate(); }
    private:
        friend class FlightGroup;
        Flight* flight=nullptr;
        Waiter* prev=nullptr;
        Waiter* next=nullptr;
        bool used=false;
    };
private:
    struct Flight {
        Key key;
        capy::async_waker control;
        Waiter* waiters=nullptr;
#ifdef NEXUS_DNS_RESPONSE
        std::optional<std::variant<Result,RawResult>> result;
#else
        std::optional<Result> result;
#endif
        std::optional<std::uint32_t> negative_ttl;
        std::optional<Clock::time_point> expires;
        Clock::time_point completed_at{};
        bool retiring=false,task_done=false,retry=false,background=false;
        // Immutable after registration; a foreground flight can later gain a
        // background interest without changing its original registration kind.
        bool started_background=false;
        explicit Flight(Key value,bool refresh=false)
            : key(std::move(value)),background(refresh),started_background(refresh) {}
    };
    // Fixed-size keys avoid allocating or throwing during network completion.
    // The array is bounded by the group's configured work limit and does not
    // consume a network permit while a failed refresh is in backoff.
    struct Backoff {
        std::array<char,254> name{};
        std::size_t length=0;
        std::uint64_t view=0;
        std::uint16_t type=0;
        io::endpoint upstream;
        Clock::time_point until{};
        bool tcp=false,edns=false,used=false;
        std::optional<d::ClientSubnet> subnet;
        [[nodiscard]] auto matches(Key const& key) const noexcept -> bool {
            return used && view==key.cache.view && type==key.cache.type &&
                   std::string_view(name.data(),length)==key.cache.name && upstream==key.upstream &&
                   tcp==key.tcp && edns==key.edns && subnet==key.subnet && key.use_cache;
        }
        auto set(Key const& key,Clock::time_point end) noexcept -> void {
            if (key.cache.name.size()>name.size()) std::terminate();
            length=key.cache.name.size(); std::copy(key.cache.name.begin(),key.cache.name.end(),name.begin());
            view=key.cache.view; type=key.cache.type; upstream=key.upstream;
            tcp=key.tcp; edns=key.edns; subnet=key.subnet; until=end; used=true;
        }
    };
    template<class> friend class FlightOwner;
    template<class> friend class BasicFlightOperation;
    friend class ResponseFlightOwner;
    friend struct ResponseOperationTraits;
public:
    struct Joined {
        Flight* flight;
        bool leader;
    };
    struct Delivery { Result answer; bool expired=false; };
    struct Rechecked { Result answer; std::optional<Clock::time_point> expires; };
private:
    mutable std::mutex mutex_;
    // Includes completed flights while either their task or a waiter still
    // borrows them. Such retained flights continue to consume capacity.
    std::vector<std::unique_ptr<Flight>> active_;
    std::size_t max_flights_,max_waiters_,waiters_=0,direct_=0;
    std::unique_ptr<Backoff[]> backoff_;
    std::chrono::milliseconds retry_delay_;
    static auto same(Key const& a,Key const& b) noexcept -> bool {
        return a.cache.view==b.cache.view && a.cache.type==b.cache.type && a.cache.name==b.cache.name &&
               a.upstream==b.upstream && a.tcp==b.tcp && a.edns==b.edns && a.use_cache==b.use_cache && a.subnet==b.subnet && a.protection==b.protection
#ifdef NEXUS_DNS_RESPONSE
               && a.raw_response==b.raw_response
#endif
               ;
    }
    auto in_backoff(Key const& key,Clock::time_point now) noexcept -> bool {
        for (std::size_t i=0;i<max_flights_;++i) {
            auto& slot=backoff_[i];
            if (slot.used && slot.until<=now) slot.used=false;
            if (slot.matches(key)) return true;
        }
        return false;
    }
    auto clear_backoff(Key const& key) noexcept -> void {
        for (std::size_t i=0;i<max_flights_;++i) if (backoff_[i].matches(key)) backoff_[i].used=false;
    }
    auto delay_background(Key const& key,Clock::time_point now) noexcept -> void {
        if (!max_flights_) return;
        std::size_t candidate=max_flights_;
        for (std::size_t i=0;i<max_flights_;++i) {
            auto& slot=backoff_[i];
            if (slot.used && slot.until<=now) slot.used=false;
            if (slot.matches(key)) { candidate=i; break; }
            if (!slot.used) { if (candidate==max_flights_ || backoff_[candidate].used) candidate=i; }
            else if (candidate==max_flights_ || (backoff_[candidate].used && slot.until<backoff_[candidate].until)) candidate=i;
        }
        auto delay=std::chrono::duration_cast<Clock::duration>(retry_delay_);
        auto end=now>Clock::time_point::max()-delay ? Clock::time_point::max() : now+delay;
        backoff_[candidate].set(key,end);
    }
    auto release_if_drained(Flight& flight) noexcept -> void {
        if (!flight.task_done || flight.waiters) return;
        auto it=std::ranges::find_if(active_,[&](auto const& item) { return item.get()==&flight; });
        if (it==active_.end()) std::terminate();
        active_.erase(it);
    }
    auto release_direct() noexcept -> void {
        std::lock_guard lock(mutex_);
        if (!direct_) std::terminate();
        --direct_;
    }
public:
    // A non-coalesced query still occupies the same total-work budget until
    // its own network coroutine has completed, including cancellation drain.
    class DirectLease {
        friend class FlightGroup;
        FlightGroup* owner_;
        explicit DirectLease(FlightGroup& owner) noexcept : owner_(&owner) {}
    public:
        DirectLease(DirectLease const&)=delete;
        auto operator=(DirectLease const&) -> DirectLease& = delete;
        DirectLease(DirectLease&& other) noexcept : owner_(std::exchange(other.owner_,nullptr)) {}
        auto operator=(DirectLease&&) -> DirectLease& = delete;
        ~DirectLease() { if (owner_) owner_->release_direct(); }
    };
    FlightGroup(std::size_t flights,std::size_t waiters,std::chrono::milliseconds retry_delay=std::chrono::seconds(1))
        : max_flights_(std::min<std::size_t>(flights,256)),max_waiters_(std::min<std::size_t>(waiters,4096)),
          backoff_(std::make_unique<Backoff[]>(max_flights_)),
          retry_delay_(std::clamp(retry_delay,std::chrono::milliseconds(1),std::chrono::milliseconds(30000))) {
        active_.reserve(max_flights_);
    }
    FlightGroup(FlightGroup const&)=delete;
    ~FlightGroup() { if (!active_.empty() || waiters_ || direct_) std::terminate(); }
    [[nodiscard]] auto try_direct() -> std::optional<DirectLease> {
        std::lock_guard lock(mutex_);
        if (active_.size()+direct_>=max_flights_) return {};
        ++direct_; return DirectLease(*this);
    }
    // Capacity rejection is explicit; no unbounded bypass queries are launched.
    // An OOM before registration changes no counters or visible flight.
    [[nodiscard]] auto join(Key key,Waiter& waiter) -> std::expected<Joined,d::detail::ResolveError> {
        if (!key.upstream.port() || (key.cache.type!=1 && key.cache.type!=28) ||
            !d::canonicalize_name(key.cache.name) || !d::detail::compact_key_storage(key.cache))
            return std::unexpected(d::detail::ResolveError::state);
        std::lock_guard lock(mutex_);
        if (waiter.used) return std::unexpected(d::detail::ResolveError::state);
        if (waiters_>=max_waiters_) return std::unexpected(d::detail::ResolveError::limit);
        auto found=std::ranges::find_if(active_,[&](auto const& flight) { return !flight->result && same(flight->key,key); });
        Flight* flight;
        bool leader=false;
        if (found!=active_.end()) {
            if ((*found)->retiring) return std::unexpected(d::detail::ResolveError::limit);
            flight=found->get();
        } else {
            if (active_.size()+direct_>=max_flights_) return std::unexpected(d::detail::ResolveError::limit);
            auto created=std::make_unique<Flight>(std::move(key));
            flight=created.get();
            active_.push_back(std::move(created));
            leader=true;
        }
        waiter.used=true;
        waiter.flight=flight;
        waiter.next=flight->waiters;
        if (waiter.next) waiter.next->prev=&waiter;
        flight->waiters=&waiter;
        ++waiters_;
        return Joined{flight,leader};
    }
    // A stale caller does not wait. If a foreground transaction already
    // exists, keep that actual task alive even if its last waiter departs.
    // Only the creator launches a network owner.
    [[nodiscard]] auto join_background(Key key) -> std::expected<Joined,d::detail::ResolveError> {
        if (!key.use_cache || !key.upstream.port() || (key.cache.type!=1 && key.cache.type!=28) ||
            !d::canonicalize_name(key.cache.name) || !d::detail::compact_key_storage(key.cache))
            return std::unexpected(d::detail::ResolveError::state);
        std::lock_guard lock(mutex_);
        auto found=std::ranges::find_if(active_,[&](auto const& flight) { return !flight->result && same(flight->key,key); });
        if (found!=active_.end()) {
            if ((*found)->retiring) return std::unexpected(d::detail::ResolveError::limit);
            (*found)->background=true; return Joined{found->get(),false};
        }
        if (in_backoff(key,Clock::now())) return std::unexpected(d::detail::ResolveError::limit);
        if (active_.size()+direct_>=max_flights_) return std::unexpected(d::detail::ResolveError::limit);
        auto created=std::make_unique<Flight>(std::move(key),true); auto* flight=created.get();
        active_.push_back(std::move(created)); return Joined{flight,true};
    }
    // Last-waiter departure keeps the retiring flight in the global limit and
    // rejects a new same-key query until the original network task drains.
    auto leave(Waiter& waiter) noexcept -> void {
        std::lock_guard lock(mutex_);
        auto* flight=waiter.flight;
        if (!flight) std::terminate();
        if (waiter.prev) waiter.prev->next=waiter.next;
        else flight->waiters=waiter.next;
        if (waiter.next) waiter.next->prev=waiter.prev;
        waiter.flight=nullptr; waiter.prev=nullptr; waiter.next=nullptr;
        --waiters_;
        if (!flight->waiters && !flight->background && !flight->result && !flight->retiring) {
            flight->retiring=true;
            // Publish the wake while holding the same lock used by completion:
            // a late wake must not reach a destroyed leader executor.
            flight->control.wake();
        }
        release_if_drained(*flight);
    }
    auto retire(Flight* flight) noexcept -> void {
        std::lock_guard lock(mutex_);
        if (!flight->result && !flight->retiring) {
            flight->retiring=true; flight->control.wake();
        }
    }
    [[nodiscard]] auto retiring(Flight* flight) const noexcept -> bool {
        std::lock_guard lock(mutex_); return flight->retiring;
    }
    // Serialize publication against the last waiter leaving or the owning
    // executor stopping. Cache code never acquires the group lock in reverse.
    template<class F> auto while_live(Flight* flight,F&& publish) -> void {
        std::lock_guard lock(mutex_);
        if (!flight->retiring && !flight->result) std::forward<F>(publish)();
    }
    // Completion has no allocating operations. Each waiter retains its own
    // slot until leave(), including after completion while its executor stalls.
    auto complete(Flight* flight,Result result,Clock::time_point now=Clock::now(),
                  std::optional<std::uint32_t> negative_ttl={},std::optional<Clock::time_point> expires={}) noexcept -> void {
        static_assert(std::is_nothrow_move_constructible_v<Result>);
        std::lock_guard lock(mutex_);
        if (flight->result) return;
        if (result || result.error()==d::detail::ResolveError::name_not_found || result.error()==d::detail::ResolveError::no_data)
            clear_backoff(flight->key);
        else if (flight->background && !flight->retiring && result.error()!=d::detail::ResolveError::canceled)
            delay_background(flight->key,now);
#ifdef NEXUS_DNS_RESPONSE
        flight->result.emplace(std::in_place_type<Result>,std::move(result));
#else
        flight->result.emplace(std::move(result));
#endif
        flight->completed_at=now;
        flight->negative_ttl=negative_ttl;
        flight->expires=expires;
        for (auto* waiter=flight->waiters;waiter;waiter=waiter->next) waiter->wake.wake();
    }
#ifdef NEXUS_DNS_RESPONSE
    struct RawDelivery { RawResult answer;Clock::time_point completed;std::optional<Clock::time_point> expires; };
    auto complete_raw(Flight* flight,RawResult result,Clock::time_point now=Clock::now(),
                      std::optional<Clock::time_point> expires={}) noexcept -> void {
        static_assert(std::is_nothrow_move_constructible_v<RawResult>);
        std::lock_guard lock(mutex_);
        if (flight->result) return;
        flight->result.emplace(std::in_place_type<RawResult>,std::move(result));
        flight->completed_at=now;flight->expires=expires;
        for (auto* waiter=flight->waiters;waiter;waiter=waiter->next) waiter->wake.wake();
    }
    // Like result(), the caller retains this group's registered waiter until
    // the synchronous copy returns or throws; leave runs on its same executor.
    [[nodiscard]] auto result_raw(Waiter const& waiter) const -> std::optional<RawDelivery> {
        std::unique_lock lock(mutex_);
        auto const* flight=waiter.flight;
        if (!flight || !flight->result) return {};
        auto const* value=std::get_if<RawResult>(&*flight->result);
        if (!value) return {};
        auto completed=flight->completed_at;auto expires=flight->expires;
        lock.unlock();
        return RawDelivery{*value,completed,expires};
    }
#endif
    // A background transaction whose stale token became ineligible before
    // launch does not do network work. Any foreground waiters recheck and
    // retry under their own original deadlines.
    auto complete_retry(Flight* flight) noexcept -> void {
        std::lock_guard lock(mutex_);
        if (flight->result) return;
        flight->retry=true;
#ifdef NEXUS_DNS_RESPONSE
        flight->result.emplace(std::in_place_type<Result>,std::unexpected(d::detail::ResolveError::state));
#else
        flight->result.emplace(std::unexpected(d::detail::ResolveError::state));
#endif
        for (auto* waiter=flight->waiters;waiter;waiter=waiter->next) waiter->wake.wake();
    }
    // Called only after the owner's task, including its monitor, has exited.
    auto finish(Flight* flight) noexcept -> void {
        std::lock_guard lock(mutex_);
        if (!flight->result || flight->task_done) std::terminate();
        flight->task_done=true;
        release_if_drained(*flight);
    }
    // Same-executor caller must keep this group's waiter registered until
    // return/unwind. Completion publishes result and timing fields once; the
    // waiter then pins the Flight even if its task finishes or peers leave.
    // No borrowed result escapes this synchronous call, including on OOM.
    [[nodiscard]] auto result(Waiter const& waiter,Clock::time_point now=Clock::now()) const -> std::optional<Delivery> {
        std::unique_lock lock(mutex_);
        auto const* flight=waiter.flight;
        if (!flight || !flight->result) return {};
        if (flight->retry) return Delivery{std::unexpected(d::detail::ResolveError::state),true};
#ifdef NEXUS_DNS_RESPONSE
        auto const* stored=std::get_if<Result>(&*flight->result);
#else
        auto const* stored=&*flight->result;
#endif
        if (!stored) return {};
        auto ttl=*stored ? (**stored).ttl : flight->negative_ttl;
        auto completed=flight->completed_at;auto expires=flight->expires;
        auto expired=[&](Clock::time_point at) {
            if (expires) return at>=*expires;
            // A zero or absent network TTL is usable only by the waiters
            // already in this transaction. join() never attaches later
            // callers to a completed flight, and the cache does not store it.
            return ttl && *ttl && at>completed && at-completed>=std::chrono::seconds(*ttl);
        };
        if (expired(now)) return Delivery{std::unexpected(d::detail::ResolveError::state),true};
        lock.unlock();
        auto answer=*stored;
        now=std::max(now,Clock::now());
        if (expired(now)) return Delivery{std::unexpected(d::detail::ResolveError::state),true};
        if (answer && answer->ttl) {
            auto& remaining=*answer->ttl;
            if (expires) {
                auto seconds=std::chrono::duration_cast<std::chrono::seconds>(*expires-now).count();
                if (seconds<remaining) remaining=static_cast<std::uint32_t>(seconds);
            } else if (now>completed) {
                auto elapsed=std::chrono::ceil<std::chrono::seconds>(now-completed).count();
                remaining=elapsed>=remaining ? 0 : remaining-static_cast<std::uint32_t>(elapsed);
            }
        }
        return Delivery{std::move(answer),false};
    }
    [[nodiscard]] auto counts() const noexcept -> std::pair<std::size_t,std::size_t> {
        std::lock_guard lock(mutex_); return {active_.size(),waiters_};
    }
    [[nodiscard]] auto direct_active() const noexcept -> std::size_t { std::lock_guard lock(mutex_); return direct_; }
    [[nodiscard]] auto backoff_reserved_bytes() const noexcept -> std::size_t { return max_flights_*sizeof(Backoff); }
};


} // namespace dns_hp_experiment

#include "group_flight_operation.hpp"
