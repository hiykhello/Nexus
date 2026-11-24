// Flight owner and waiter operation module.
export module dns.group_flight_operation;
import std;
import capy;
import corosio;
import dns.cache;
import dns.corosio_cached;
import dns.message;
export import dns.group_singleflight;

export namespace dns_hp_experiment {
    template<class Cache>
    class FlightOwner {
        using Clock = std::chrono::steady_clock;
        using Token = d::detail::CacheTokenFor<Cache>;
        struct Entry {
            FlightGroup::Flight* flight;
            d::detail::AddressResolver resolver;
            bool finished = false;
            Entry(FlightGroup::Flight* value, io::io_context& context)
                : flight(value), resolver(context, flight->key.tcp, flight->key.edns, flight->key.subnet, flight->key.protection.get()) {}
        };
        io::io_context& context_;
        Cache& cache_;
        FlightGroup& group_;
        std::map<std::uint64_t, std::unique_ptr<Entry>> active_;
        std::uint64_t next_ = 0;
        std::chrono::milliseconds network_timeout_;
        bool stopped_ = false;
        static auto time_ms(Clock::time_point time) noexcept -> std::uint64_t {
            auto value = std::chrono::duration_cast<std::chrono::milliseconds>(time.time_since_epoch()).count();
            return value < 0 ? 0 : static_cast<std::uint64_t>(value);
        }
        auto monitor(Entry& entry) -> capy::task<capy::results<>> {
            while (!entry.finished) {
                if (group_.retiring(entry.flight)) entry.resolver.cancel();
                auto [error] = co_await entry.flight->control.wait();
                if (error) { entry.resolver.cancel(); break; }
            }
            co_return capy::results<>{};
        }
        auto work(Entry& entry) -> capy::task<capy::results<>> {
            using Error = d::detail::ResolveError;
            FlightGroup::Result answer = std::unexpected(Error::state);
            auto available = Clock::now();
            try {
                auto const& key = entry.flight->key;
                std::optional<Token> token;
                if (key.use_cache) try {
                    if (entry.flight->started_background) {
                        auto registered = cache_.begin_refresh(key.cache, time_ms(Clock::now()), 256);
                        if (registered && *registered) token = **registered;
                    } else {
                        auto registered = cache_.begin_query(key.cache);
                        if (registered) token = *registered;
                    }
                } catch (std::bad_alloc const&) {}
                struct Registration {
                    Cache& cache;
                    std::optional<Token>& token;
                    ~Registration() { if (token) (void)cache.cancel_query(*token); }
                } registration{cache_, token};
                if (entry.flight->started_background && !token) {
                    entry.finished = true;
                    group_.complete_retry(entry.flight);
                    entry.flight->control.wake();
                    co_return capy::results<>{};
                }
                answer = co_await entry.resolver.resolve_random(key.upstream, {key.cache.name, key.cache.type}, Clock::now() + network_timeout_);
                available = Clock::now();
                if (token) {
                    try {
                        group_.while_live(entry.flight, [&] {
                            if (answer) {
                                if constexpr (requires { cache_.publish_from(key.cache, *answer, time_ms(available), time_ms(Clock::now()), *token); })
                                    (void)cache_.publish_from(key.cache, *answer, time_ms(available), time_ms(Clock::now()), *token);
                                else (void)cache_.publish(key.cache, *answer, time_ms(Clock::now()), *token);
                            } else if (answer.error() == Error::name_not_found || answer.error() == Error::no_data) {
                                auto ttl = entry.resolver.negative_cache_ttl();
                                auto kind = answer.error() == Error::name_not_found ? d::NegativeKind::name_not_found : d::NegativeKind::no_data;
                                if (ttl) {
                                    if constexpr (requires { cache_.publish_negative_from(key.cache, kind, *ttl, time_ms(available), time_ms(Clock::now()), *token); })
                                        (void)cache_.publish_negative_from(key.cache, kind, *ttl, time_ms(available), time_ms(Clock::now()), *token);
                                    else (void)cache_.publish_negative(key.cache, kind, *ttl, time_ms(Clock::now()), *token);
                                } else (void)cache_.invalidate(key.cache, time_ms(Clock::now()), *token);
                            }
                        });
                    } catch (std::bad_alloc const&) {}
                }
            } catch (...) { answer = std::unexpected(Error::state); }
            auto negative_ttl = !answer && (answer.error() == Error::name_not_found || answer.error() == Error::no_data) ?
                entry.resolver.negative_cache_ttl() : std::optional<std::uint32_t>{};
            entry.finished = true;
            group_.complete(entry.flight, std::move(answer), available, negative_ttl);
            entry.flight->control.wake();
            co_return capy::results<>{};
        }
        auto run(Entry& entry) -> capy::task<capy::results<>> {
            (void)co_await capy::when_all(work(entry), monitor(entry));
            co_return capy::results<>{};
        }
        auto done(std::uint64_t id) noexcept -> void {
            auto it = active_.find(id);
            if (it == active_.end()) return;
            auto* flight = it->second->flight;
            group_.complete(flight, std::unexpected(d::detail::ResolveError::state));
            active_.erase(it);
            group_.finish(flight);
        }
    public:
        FlightOwner(io::io_context& context, Cache& cache, FlightGroup& group, std::chrono::milliseconds timeout = std::chrono::seconds(5))
            : context_(context), cache_(cache), group_(group),
              network_timeout_(std::clamp(timeout, std::chrono::milliseconds(1), std::chrono::milliseconds(30000))) {}
        FlightOwner(FlightOwner const&) = delete;
        ~FlightOwner() { if (!active_.empty()) std::terminate(); }
        [[nodiscard]] auto start_refresh(FlightGroup::Key key) -> bool {
            if (stopped_) return false;
            auto joined = group_.join_background(std::move(key));
            if (!joined) return false;
            if (joined->leader) start(joined->flight);
            return true;
        }
        auto start(FlightGroup::Flight* flight) noexcept -> void {
            using Error = d::detail::ResolveError;
            if (stopped_ || next_ == std::numeric_limits<std::uint64_t>::max()) {
                group_.complete(flight, std::unexpected(stopped_ ? Error::canceled : Error::limit));
                group_.finish(flight);
                return;
            }
            if (group_.retiring(flight)) {
                group_.complete(flight, std::unexpected(Error::canceled));
                group_.finish(flight);
                return;
            }
            auto id = ++next_;
            try {
                auto entry = std::make_unique<Entry>(flight, context_);
                auto [it, inserted] = active_.emplace(id, std::move(entry));
                if (!inserted) {
                    group_.complete(flight, std::unexpected(Error::state));
                    group_.finish(flight);
                    return;
                }
                try {
                    capy::run_async(context_.get_executor(), [this, id](capy::results<>) { done(id); },
                        [this, id](std::exception_ptr) noexcept { done(id); })(run(*it->second));
                } catch (...) { active_.erase(it); throw; }
            } catch (...) {
                group_.complete(flight, std::unexpected(Error::state));
                group_.finish(flight);
            }
        }
        auto stop() noexcept -> void {
            stopped_ = true;
            for (auto& [id, entry] : active_) { group_.retire(entry->flight); entry->resolver.cancel(); }
        }
        [[nodiscard]] auto drained() const noexcept -> bool { return active_.empty(); }
        [[nodiscard]] auto active() const noexcept -> std::size_t { return active_.size(); }
        [[nodiscard]] auto available() const noexcept -> bool { return !stopped_; }
    };

    template<class Cache>
    struct AddressOperationTraits {
        using Owner = FlightOwner<Cache>;
        using Result = FlightGroup::Result;
        using Rechecked = FlightGroup::Rechecked;
        static auto delivered(FlightGroup& group, FlightGroup::Waiter const& waiter) -> std::optional<FlightGroup::Delivery> {
            return group.result(waiter);
        }
        static auto age_cached(Rechecked& cached, std::chrono::steady_clock::time_point now) -> void {
            if (cached.answer && cached.expires && cached.answer->ttl) {
                auto remaining = std::chrono::duration_cast<std::chrono::seconds>(*cached.expires - now).count();
                if (remaining < *cached.answer->ttl) cached.answer->ttl = static_cast<std::uint32_t>(remaining);
            }
        }
        template<class Flight> static auto complete_cached(FlightGroup& group, Flight* flight, Rechecked& cached) -> void {
            group.complete(flight, std::move(cached.answer), std::chrono::steady_clock::now(), {}, cached.expires);
        }
    };

    template<class Traits>
    class BasicFlightOperation {
        using Owner = typename Traits::Owner;
        using Result = typename Traits::Result;
        using Rechecked = typename Traits::Rechecked;
        using Clock = std::chrono::steady_clock;
        FlightGroup& group_;
        Owner& owner_;
        std::optional<FlightGroup::Waiter> waiter_;
        bool started_ = false, canceled_ = false, waiting_ = false;
    public:
        BasicFlightOperation(FlightGroup& group, Owner& owner) : group_(group), owner_(owner) {}
        BasicFlightOperation(BasicFlightOperation const&) = delete;
        auto cancel() noexcept -> void { canceled_ = true; if (waiting_) waiter_->wake.wake(); }
        auto resolve(FlightGroup::Key key, Clock::time_point deadline) -> capy::task<Result> {
            return resolve(std::move(key), deadline, [](FlightGroup::Key const&) -> std::optional<Rechecked> { return {}; });
        }
        template<class Recheck>
        auto resolve(FlightGroup::Key key, Clock::time_point deadline, Recheck recheck) -> capy::task<Result> {
            using Error = d::detail::ResolveError;
            if (started_) co_return std::unexpected(Error::state);
            started_ = true;
            bool retrying = false;
            for (;;) {
                if (canceled_) co_return std::unexpected(Error::canceled);
                if (Clock::now() >= deadline) co_return std::unexpected(Error::timeout);
                if (!owner_.available()) co_return std::unexpected(Error::canceled);
                if (retrying) {
                    std::optional<Rechecked> cached;
                    try { cached = recheck(key); }
                    catch (std::bad_alloc const&) {}
                    catch (...) { cached.emplace(Rechecked{std::unexpected(Error::state), {}}); }
                    auto now = Clock::now();
                    if (now >= deadline) co_return std::unexpected(Error::timeout);
                    if (cached && (!cached->expires || now < *cached->expires)) {
                        Traits::age_cached(*cached, now);
                        co_return std::move(cached->answer);
                    }
                }
                waiter_.emplace();
                std::expected<FlightGroup::Joined, Error> joined = std::unexpected(Error::state);
                try { joined = group_.join(std::move(key), *waiter_); }
                catch (std::bad_alloc const&) { co_return std::unexpected(Error::limit); }
                if (!joined) co_return std::unexpected(joined.error());
                waiting_ = true;
                {
                    struct Registration {
                        FlightGroup& group;
                        FlightGroup::Waiter& waiter;
                        bool& waiting;
                        ~Registration() { waiting = false; group.leave(waiter); }
                    } registration{group_, *waiter_, waiting_};
                    if (joined->leader) {
                        std::optional<Rechecked> cached;
                        try { cached = recheck(joined->flight->key); }
                        catch (std::bad_alloc const&) {}
                        catch (...) { cached.emplace(Rechecked{std::unexpected(Error::state), {}}); }
                        if (cached) {
                            Traits::complete_cached(group_, joined->flight, *cached);
                            group_.finish(joined->flight);
                        } else owner_.start(joined->flight);
                    }
                    auto [error] = co_await io::timeout(waiter_->wake.wait(), deadline);
                    if (canceled_) co_return std::unexpected(Error::canceled);
                    if (error == capy::cond::timeout || Clock::now() >= deadline) co_return std::unexpected(Error::timeout);
                    if (error) co_return std::unexpected(Error::canceled);
                    try {
                        auto result = Traits::delivered(group_, *waiter_);
                        if (!result) co_return std::unexpected(Error::state);
                        if (Clock::now() >= deadline) co_return std::unexpected(Error::timeout);
                        auto retry_timeout = !result->answer && result->answer.error() == Error::timeout;
                        if (!result->expired && !retry_timeout) co_return std::move(result->answer);
                        key = joined->flight->key;
                    } catch (std::bad_alloc const&) { co_return std::unexpected(Error::limit); }
                }
                waiter_.reset();
                retrying = true;
            }
        }
    };

    template<class Cache>
    using FlightOperation = BasicFlightOperation<AddressOperationTraits<Cache>>;
}
