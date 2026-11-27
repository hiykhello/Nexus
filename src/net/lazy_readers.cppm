export module net.lazy_readers;
import std;
import capy;
import containers.lru_slab;

export namespace net {
    struct SlotSelection {
        std::size_t index = 0;
        bool evicted = false;
    };

    namespace detail {
        struct RouteSlotHash {
            auto operator()(std::uint64_t k) const noexcept -> std::size_t {
                k ^= k >> 33;
                k *= 0xff51afd7ed558ccdull;
                k ^= k >> 33;
                k *= 0xc4ceb9fe1a85ec53ull;
                return static_cast<std::size_t>(k ^ (k >> 33));
            }
        };

        template<class Peer>
        struct FixedPeerKey {
            std::size_t route = 0;
            Peer peer{};
            auto operator==(FixedPeerKey const&) const noexcept -> bool = default;
        };

        template<class Peer>
        struct FixedPeerKeyHash {
            auto operator()(FixedPeerKey<Peer> const& k) const noexcept -> std::size_t {
                std::uint64_t h = 14695981039346656037ull;
                auto mix = [&](std::uint64_t v) noexcept { h = (h ^ v) * 1099511628211ull; };
                mix(static_cast<std::uint64_t>(k.route));
                std::uint8_t fam = 0;
                bool is_v6 = false;
                if constexpr (requires { k.peer.family; }) {
                    fam = k.peer.family;
                    is_v6 = fam == 6;
                } else {
                    fam = k.peer.address_type;
                    is_v6 = fam == 4;
                }
                mix((static_cast<std::uint64_t>(fam) << 16) | k.peer.port);
                std::uint64_t a = 0, b = 0;
                std::memcpy(&a, k.peer.address.data(), 8);
                mix(a);
                if (is_v6) {
                    std::memcpy(&b, k.peer.address.data() + 8, 8);
                    mix(b);
                }
                return static_cast<std::size_t>(h ^ (h >> 32));
            }
        };

        struct AwaitContextProbe {
            capy::await_context const* ctx = nullptr;
            auto await_ready() const noexcept -> bool { return false; }
            auto await_suspend(std::coroutine_handle<> h, capy::await_context const* env) noexcept
                -> std::coroutine_handle<> {
                ctx = env;
                return h;
            }
            auto await_resume() const noexcept -> capy::await_context const* { return ctx; }
        };

        struct LazyRunState {
            std::stop_source child_stop;
            capy::async_event done_ev;
            capy::async_event* owner_changed = nullptr;
            decltype(capy::await_context::owner) parent_owner = nullptr;
            std::size_t active = 0;
            std::error_code first_error{};
            std::exception_ptr first_exception{};
            bool failed = false;
            bool abandoned = false;
            bool launching = false;

            auto on_result(std::error_code ec, std::exception_ptr ep) noexcept -> void {
                if (!failed && (ec || ep)) {
                    failed = true;
                    first_error = ec;
                    first_exception = std::move(ep);
                    auto keep = child_stop;
                    keep.request_stop();
                    if (!abandoned && owner_changed) owner_changed->set();
                }
                if (active > 0) --active;
                if (active == 0) {
                    if (abandoned) {
                        if (auto* owner = std::exchange(parent_owner, nullptr)) owner->abandon();
                    } else {
                        done_ev.set();
                    }
                }
            }

            auto on_abandon() noexcept -> void {
                if (launching) {
                    if (active > 0) --active;
                    return;
                }
                abandoned = true;
                auto keep = child_stop;
                keep.request_stop();
                if (active > 0) --active;
                if (active == 0) {
                    if (auto* owner = std::exchange(parent_owner, nullptr)) owner->abandon();
                    else done_ev.set();
                }
            }
        };

        struct LazyChildHandler {
            std::shared_ptr<LazyRunState> state;

            LazyChildHandler() = default;
            explicit LazyChildHandler(std::shared_ptr<LazyRunState> s) noexcept : state(std::move(s)) {}
            LazyChildHandler(LazyChildHandler&&) noexcept = default;
            auto operator=(LazyChildHandler&&) noexcept -> LazyChildHandler& = default;
            LazyChildHandler(LazyChildHandler const&) = delete;
            auto operator=(LazyChildHandler const&) -> LazyChildHandler& = delete;

            ~LazyChildHandler() noexcept {
                if (auto s = std::move(state)) s->on_abandon();
            }

            auto operator()(capy::results<> value) noexcept -> void {
                if (auto s = std::move(state)) s->on_result(std::get<0>(value), {});
            }
            auto operator()(std::exception_ptr ep) noexcept -> void {
                if (auto s = std::move(state)) s->on_result({}, std::move(ep));
            }
        };
    }

    // Dynamic pointer-stable O(1) routed datagram slot pool keyed by (outbound, family_bit).
    template<class Slot, std::size_t DefaultSoftCap = 4096>
    class RoutedDatagramSlots {
        containers::LruSlab<std::uint64_t, Slot, detail::RouteSlotHash> slab_;
    public:
        explicit RoutedDatagramSlots(std::size_t soft_cap = DefaultSoftCap) noexcept : slab_(soft_cap) {}

        [[nodiscard]] auto size() const noexcept -> std::size_t { return slab_.size(); }
        [[nodiscard]] auto soft_cap() const noexcept -> std::size_t { return slab_.soft_cap(); }
        auto set_soft_cap(std::size_t cap) noexcept -> void { slab_.set_soft_cap(cap); }

        [[nodiscard]] auto select(std::uint64_t route_key) -> std::optional<std::size_t> {
            auto idx = slab_.emplace(route_key);
            return idx ? std::optional<std::size_t>{*idx} : std::nullopt;
        }

        template<class OnEvict>
        [[nodiscard]] auto select_or_evict(std::uint64_t route_key, OnEvict&& on_evict) -> std::optional<SlotSelection> {
            if (auto hit = slab_.find_index_and_touch(route_key)) return SlotSelection{*hit, false};
            if (auto fresh = slab_.emplace(route_key)) return SlotSelection{*fresh, false};
            auto recycled = slab_.rekey_lru(route_key, [&](std::uint32_t, std::uint64_t const&, Slot& s) noexcept {
                on_evict(s);
            });
            return recycled ? std::optional<SlotSelection>{SlotSelection{*recycled, true}} : std::nullopt;
        }

        [[nodiscard]] auto slot(std::size_t index) noexcept -> Slot& {
            return slab_.slot_value(static_cast<std::uint32_t>(index));
        }
        [[nodiscard]] auto occupied(std::size_t index) const noexcept -> bool {
            return slab_.occupied(static_cast<std::uint32_t>(index));
        }

        template<class Visit>
        auto for_each(Visit&& visit) noexcept -> void {
            slab_.for_each([&](std::uint32_t, std::uint64_t const&, Slot& s) noexcept { visit(s); });
        }
    };

    // Fixed-target stream slots backed by a pointer-stable O(1) LRU slab.
    // Slot indices remain stable for readers; grows lazily up to configurable soft_cap.
    template<class Slot, class Peer, std::size_t DefaultSoftCap = 512>
    class FixedDatagramSlots {
        using Key = detail::FixedPeerKey<Peer>;
        using KeyHash = detail::FixedPeerKeyHash<Peer>;
        containers::LruSlab<Key, Slot, KeyHash> slab_;
    public:
        explicit FixedDatagramSlots(std::size_t soft_cap = DefaultSoftCap) noexcept : slab_(soft_cap) {}

        [[nodiscard]] auto size() const noexcept -> std::size_t { return slab_.size(); }
        [[nodiscard]] auto soft_cap() const noexcept -> std::size_t { return slab_.soft_cap(); }
        auto set_soft_cap(std::size_t cap) noexcept -> void { slab_.set_soft_cap(cap); }

        [[nodiscard]] auto select(std::size_t route, Peer const& peer) -> std::optional<std::size_t> {
            auto idx = slab_.emplace(Key{route, peer});
            return idx ? std::optional<std::size_t>{*idx} : std::nullopt;
        }

        template<class OnEvict>
        [[nodiscard]] auto select_or_evict(std::size_t route, Peer const& peer, OnEvict&& on_evict)
            -> std::optional<SlotSelection> {
            Key key{route, peer};
            if (auto hit = slab_.find_index_and_touch(key)) return SlotSelection{*hit, false};
            if (auto fresh = slab_.emplace(key)) return SlotSelection{*fresh, false};
            auto recycled = slab_.rekey_lru(key, [&](std::uint32_t, Key const&, Slot& s) noexcept {
                on_evict(s);
            });
            return recycled ? std::optional<SlotSelection>{SlotSelection{*recycled, true}} : std::nullopt;
        }

        [[nodiscard]] auto slot(std::size_t index) noexcept -> Slot& {
            return slab_.slot_value(static_cast<std::uint32_t>(index));
        }
        [[nodiscard]] auto peer(std::size_t index) const noexcept -> Peer const& {
            return slab_.slot_key(static_cast<std::uint32_t>(index)).peer;
        }
        [[nodiscard]] auto occupied(std::size_t index) const noexcept -> bool {
            return slab_.occupied(static_cast<std::uint32_t>(index));
        }

        template<class Visit>
        auto for_each(Visit&& visit) noexcept -> void {
            slab_.for_each([&](std::uint32_t, Key const&, Slot& s) noexcept { visit(s); });
        }
    };

    // One association/executor, at most one reader per physical slot.
    // Flat O(1)-stack dispatch loop launches each slot reader once via run_async
    // and drains all active readers on stop/error/cancel without coroutine recursion.
    template<std::size_t Capacity = 0>
    class LazyReaders {
        static constexpr std::uint8_t kIdle = 0, kRequested = 1, kStarted = 2;
        std::size_t max_capacity_ = Capacity ? Capacity : 65536;
        std::vector<std::uint8_t> states_;
        std::deque<std::size_t> queue_;
        capy::async_event changed_;
        bool stopped_ = false;
    public:
        LazyReaders() = default;
        explicit LazyReaders(std::size_t capacity) noexcept
            : max_capacity_(Capacity ? Capacity : std::max<std::size_t>(capacity, 1)) {}
        LazyReaders(LazyReaders const&) = delete;
        auto operator=(LazyReaders const&) -> LazyReaders& = delete;

        [[nodiscard]] auto capacity() const noexcept -> std::size_t { return max_capacity_; }
        auto set_capacity(std::size_t capacity) noexcept -> void {
            if constexpr (Capacity == 0) max_capacity_ = std::max<std::size_t>(capacity, 1);
        }

        // A request can precede run(), and repeated publication after a slot
        // rotation reuses the already-started slot reader rather than spawning.
        [[nodiscard]] auto request(this LazyReaders& self, std::size_t index) noexcept -> bool {
            if (self.stopped_ || index >= self.max_capacity_) return false;
            try {
                if (index >= self.states_.size()) self.states_.resize(index + 1, kIdle);
                if (self.states_[index] != kIdle) return true;
                self.queue_.push_back(index);
                self.states_[index] = kRequested;
                self.changed_.set();
                return true;
            } catch (...) {
                return false;
            }
        }
        auto stop(this LazyReaders& self) noexcept -> void {
            self.stopped_ = true;
            self.changed_.set();
        }
        [[nodiscard]] auto stopped(this LazyReaders const& self) noexcept -> bool { return self.stopped_; }

        template<class Factory>
        auto run(this LazyReaders& self, Factory factory) -> capy::task<capy::results<>> {
            auto const* env = co_await detail::AwaitContextProbe{};
            auto ex = env->executor;
            auto token = env->stop_token;

            auto st = std::make_shared<detail::LazyRunState>();
            st->owner_changed = &self.changed_;
            st->parent_owner = env->owner;

            struct RunGuard {
                std::shared_ptr<detail::LazyRunState> st;
                ~RunGuard() noexcept {
                    st->owner_changed = nullptr;
                    st->parent_owner = nullptr;
                    if (st->active > 0) {
                        auto keep = st->child_stop;
                        keep.request_stop();
                    }
                }
            } guard{st};

            std::stop_callback parent_cb(token, [st]() noexcept {
                auto keep = st->child_stop;
                keep.request_stop();
            });

            std::error_code wait_error{};
            for (;;) {
                if (self.stopped_ || st->failed || token.stop_requested()) break;
                while (!self.queue_.empty()) {
                    if (self.stopped_ || st->failed || token.stop_requested()) break;
                    auto index = self.queue_.front();
                    self.queue_.pop_front();
                    if (index >= self.states_.size() || self.states_[index] != kRequested) continue;
                    self.states_[index] = kStarted;
                    try {
                        auto reader = factory(index);
                        ++st->active;
                        st->done_ev.clear();
                        st->launching = true;
                        capy::run_async(ex, st->child_stop.get_token(), detail::LazyChildHandler{st})(std::move(reader));
                        st->launching = false;
                    } catch (...) {
                        st->launching = false;
                        if (!st->failed) {
                            st->failed = true;
                            st->first_exception = std::current_exception();
                            auto keep = st->child_stop;
                            keep.request_stop();
                        }
                        break;
                    }
                }
                if (self.stopped_ || st->failed || token.stop_requested()) break;
                self.changed_.clear();
                if (!self.queue_.empty() || self.stopped_ || st->failed || token.stop_requested()) continue;
                auto [error] = co_await self.changed_.wait();
                if (error) {
                    wait_error = error;
                    auto keep = st->child_stop;
                    keep.request_stop();
                    break;
                }
            }

            if (token.stop_requested()) {
                auto keep = st->child_stop;
                keep.request_stop();
            }

            if (st->active > 0) {
                auto drain = [](std::shared_ptr<detail::LazyRunState> s) -> capy::task<void> {
                    while (s->active > 0) {
                        s->done_ev.clear();
                        if (s->active == 0) break;
                        (void)co_await s->done_ev.wait();
                    }
                };
                co_await capy::run(std::stop_token{})(drain(st));
            }

            if (st->first_exception) std::rethrow_exception(st->first_exception);
            if (st->first_error) co_return capy::results<>{st->first_error};
            co_return capy::results<>{wait_error};
        }
    };
}
