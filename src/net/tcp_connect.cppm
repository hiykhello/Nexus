export module net.tcp_connect;
import std;
export import net.happy_eyeballs;
export import platform.socket_options;
import platform.network_state;
import platform.network_selection;
import capy;
import corosio;

export namespace net {
    [[nodiscard]] inline auto select_default_egress_interface(platform::network::Snapshot const& snapshot,
        bool ipv6) noexcept -> std::uint32_t {
        return platform::network::select_default_egress_interface(snapshot, ipv6);
    }

    namespace detail {
        template<class Endpoint>
        [[nodiscard]] inline auto is_loopback_endpoint(Endpoint const& ep) noexcept -> bool {
            if (ep.is_v6()) return ep.address().to_v6().is_loopback();
            return ep.address().to_v4().to_bytes()[0] == 127;
        }

        [[nodiscard]] inline auto cached_network_snapshot() noexcept
            -> std::shared_ptr<platform::network::Snapshot const> {
            struct SnapshotCache {
                std::mutex mu; std::condition_variable_any cv;
                std::shared_ptr<platform::network::Snapshot const> snap;
                std::atomic<std::int64_t> last_req_ms{std::chrono::duration_cast<std::chrono::milliseconds>(
                    platform::network::Clock::now().time_since_epoch()).count()};
                bool dirty = true;
                std::jthread worker; // Declared last: stops and joins before mu/cv/snap destruction.
                SnapshotCache() : worker([this](std::stop_token st) {
                    platform::network::Monitor mon(false);
                    while (!st.stop_requested()) {
                        { std::unique_lock lk(mu); cv.wait(lk, st, [this] { return dirty; }); if (st.stop_requested()) break; dirty = false; }
                        try {
                            auto const now = platform::network::Clock::now();
                            if (!mon.started()) (void)mon.start(now + std::chrono::milliseconds(20));
                            else (void)mon.poll(now + std::chrono::milliseconds(5));
                            if (auto live = mon.get()) { std::lock_guard lk(mu); snap = std::move(live); }
                        } catch (...) {}
                    }
                    mon.stop();
                }) {}
                auto get() noexcept -> std::shared_ptr<platform::network::Snapshot const> {
                    auto const now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                        platform::network::Clock::now().time_since_epoch()).count();
                    auto prev = last_req_ms.load(std::memory_order_relaxed);
                    bool const trigger = (now_ms - prev >= 2000) &&
                        last_req_ms.compare_exchange_strong(prev, now_ms, std::memory_order_relaxed);
                    std::shared_ptr<platform::network::Snapshot const> out;
                    { std::lock_guard lk(mu); out = snap; if (trigger) dirty = true; }
                    if (trigger) cv.notify_one();
                    return out;
                }
            };
            try { static SnapshotCache cache; return cache.get(); } catch (...) { return {}; }
        }
    }

    [[nodiscard]] inline auto auto_detect_default_interface(bool ipv6) noexcept -> std::uint32_t {
        if (auto snap = detail::cached_network_snapshot())
            return platform::network::select_default_egress_interface(*snap, ipv6);
        return 0;
    }

    // The source and deadline stay with the caller. Preparation opens only a
    // physical socket and introduces no protocol-specific connection behavior.
    template<class Socket,class Endpoint>
    [[nodiscard]] auto prepare_tcp_socket(Socket& socket,Endpoint const& endpoint,
        platform::TcpSocketOptions const& options,
        platform::SocketDeadline deadline=platform::SocketDeadline::max()) noexcept -> std::error_code {
        if (!options.configured()) return {};
        if (!options.valid()) return std::make_error_code(std::errc::invalid_argument);
        auto multipath=options.multipath_tcp.value_or(false);
        if (multipath || !options.binding.network_namespace.empty()) {
            auto fd=platform::open_physical_socket(endpoint.is_v6(),false,multipath,options.binding.network_namespace);
            if(!fd)return fd.error();
            if(auto error=socket.assign(*fd)) { platform::close_unadopted_socket(*fd);return error; }
        } else if (auto error=socket.open(endpoint.address().family())) return error;
        bool const auto_bind = options.binding.auto_detect_interface &&
            options.binding.interface_name().empty() && !options.binding.interface_index &&
            !options.binding.network && options.binding.network_namespace.empty() &&
            !detail::is_loopback_endpoint(endpoint);
        if (auto_bind) {
            if (auto idx = auto_detect_default_interface(endpoint.is_v6())) {
                auto effective = options;
                effective.binding.auto_detect_interface = false;
                effective.binding.interface_index = idx;
                auto err = platform::apply_tcp_options(socket.native_handle(), effective, deadline);
                if (err && platform::network::retry_interface_error(err)) {
                    effective.binding.interface_index = 0;
                    err = platform::apply_tcp_options(socket.native_handle(), effective, deadline);
                }
                if (err) return err;
            } else if (auto error = platform::apply_tcp_options(socket.native_handle(), options, deadline)) {
                return error;
            }
        } else if (auto error=platform::apply_tcp_options(socket.native_handle(),options,deadline)) {
            return error;
        }
        platform::tune_tcp_low_latency(socket.native_handle());
        if (endpoint.is_v4() && options.binding.inet4_bind_address)
            return socket.bind(Endpoint(corosio::ipv4_address(*options.binding.inet4_bind_address),0));
        if (endpoint.is_v6() && options.binding.inet6_bind_address)
            return socket.bind(Endpoint(corosio::ipv6_address(*options.binding.inet6_bind_address),0));
        return {};
    }

    namespace detail {
        struct PlannedInterface {
            std::uint32_t index = 0; std::uint8_t tier = 0, order = 0;
            bool supports_v4 = false, supports_v6 = false, all_degraded = false;
        };

        struct InterfacePlan {
            containers::inplace_vector<PlannedInterface, 16> entries;
            std::chrono::milliseconds fallback_delay{};
            bool parallel_fallback = false, hybrid_race = false, allow_unbound_fallback = false;
            std::shared_ptr<platform::network::FallbackMemory> fallback_memory;
        };

        [[nodiscard]] inline auto tcp_interfaces(platform::TcpSocketOptions const& options,bool ipv6)
            -> platform::network::InterfaceCandidates {
            if (options.binding.network) return (*options.binding.network)(ipv6);
            platform::network::InterfaceCandidates result;
            result.indices.push_back(0); result.tiers.push_back(0);
            return result;
        }

        inline auto merge_candidates(InterfacePlan& plan, platform::network::InterfaceCandidates cands, bool ipv6) -> void {
            if (!plan.fallback_memory && cands.fallback_memory) plan.fallback_memory = std::move(cands.fallback_memory);
            if (plan.fallback_delay.count() == 0) plan.fallback_delay = cands.fallback_delay;
            plan.parallel_fallback = plan.parallel_fallback || cands.parallel_fallback;
            plan.hybrid_race = plan.hybrid_race || cands.hybrid_race;
            for (std::size_t i = 0; i < cands.indices.size(); ++i) {
                auto const idx = cands.indices[i];
                auto const tier = i < cands.tiers.size() ? cands.tiers[i] : static_cast<std::uint8_t>(i);
                auto it = std::ranges::find(plan.entries, idx, &PlannedInterface::index);
                if (it == plan.entries.end()) {
                    if (plan.entries.size() < plan.entries.capacity())
                        plan.entries.push_back({idx, tier, static_cast<std::uint8_t>(plan.entries.size()), !ipv6, ipv6, false});
                } else {
                    it->tier = std::min(it->tier, tier);
                    if (ipv6) it->supports_v6 = true; else it->supports_v4 = true;
                }
            }
        }

        [[nodiscard]] inline auto plan_tcp_interfaces(platform::TcpSocketOptions const& options,
            bool has_v4,bool has_v6,std::int64_t now_ms) -> InterfacePlan {
            InterfacePlan plan{};
            auto finalize = [&]() -> InterfacePlan {
                if (plan.parallel_fallback && plan.fallback_memory && plan.entries.size() >= 2) {
                    for (auto& entry : plan.entries) {
                        bool const v4_bad = !entry.supports_v4 || plan.fallback_memory->is_degraded(entry.index, now_ms, false);
                        bool const v6_bad = !entry.supports_v6 || plan.fallback_memory->is_degraded(entry.index, now_ms, true);
                        entry.all_degraded = (entry.supports_v4 || entry.supports_v6) && v4_bad && v6_bad;
                    }
                }
                std::ranges::stable_sort(plan.entries, [](PlannedInterface const& a, PlannedInterface const& b) noexcept {
                    return std::tie(a.all_degraded, a.tier, a.order) < std::tie(b.all_degraded, b.tier, b.order);
                });
                return plan;
            };
            if (options.binding.network) {
                if (has_v4) merge_candidates(plan, (*options.binding.network)(false), false);
                if (has_v6) merge_candidates(plan, (*options.binding.network)(true), true);
                plan.allow_unbound_fallback = plan.parallel_fallback;
                return finalize();
            }
            bool const implicit_iface = options.binding.interface_name().empty() && !options.binding.interface_index &&
                options.binding.network_namespace.empty();
            if (implicit_iface && options.binding.network_strategy) {
                if (auto snap = cached_network_snapshot()) {
                    platform::network::Policy pol{*options.binding.network_strategy,
                        options.binding.network_type.value_or(platform::network::Type::ethernet), std::nullopt, {},
                        *options.binding.network_strategy == platform::network::Strategy::hybrid
                            ? std::chrono::milliseconds(0) : std::chrono::milliseconds(300)};
                    if (has_v4) merge_candidates(plan, platform::network::select_interfaces(*snap, pol, false), false);
                    if (has_v6) merge_candidates(plan, platform::network::select_interfaces(*snap, pol, true), true);
                    if (!plan.entries.empty()) { plan.allow_unbound_fallback = true; return finalize(); }
                }
            }
            if (implicit_iface && options.binding.auto_detect_interface) {
                if (auto snap = cached_network_snapshot()) {
                    auto add_auto = [&](bool ipv6) {
                        if (auto idx = platform::network::select_default_egress_interface(*snap, ipv6)) {
                            platform::network::InterfaceCandidates c{};
                            c.indices.push_back(idx); c.tiers.push_back(0); c.parallel_fallback = true;
                            merge_candidates(plan, std::move(c), ipv6);
                        }
                    };
                    if (has_v4) add_auto(false); if (has_v6) add_auto(true);
                    if (!plan.entries.empty()) { plan.allow_unbound_fallback = true; return finalize(); }
                }
            }
            plan.entries.push_back({0, 0, 0, has_v4, has_v6, false});
            return plan;
        }

        [[nodiscard]] inline auto plan_tcp_interfaces(platform::TcpSocketOptions const& options,
            bool has_v4,bool has_v6) -> InterfacePlan {
            auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count();
            return plan_tcp_interfaces(options, has_v4, has_v6, now_ms);
        }

        inline auto tcp_attempt_deadline(platform::SocketDeadline deadline,
            platform::network::InterfaceCandidates const& interfaces,std::size_t candidate)
            -> platform::SocketDeadline {
            if (candidate+1==interfaces.indices.size()) return deadline;
            return std::min(deadline,std::chrono::steady_clock::now()+interfaces.fallback_delay);
        }

        [[nodiscard]] inline auto tcp_planned_deadline(platform::SocketDeadline deadline,
            InterfacePlan const& plan,bool has_later_iface,bool has_later_ep,bool dual_stack,bool has_deferred)
            -> platform::SocketDeadline {
            auto stop = deadline; auto const now = std::chrono::steady_clock::now();
            if (has_later_iface || has_deferred)
                stop = std::min(stop, now + (plan.fallback_delay.count() > 0 ? plan.fallback_delay : kHappyEyeballsFallbackDelay));
            if (dual_stack && has_later_ep) stop = std::min(stop, now + kHappyEyeballsFallbackDelay);
            return stop;
        }

        [[nodiscard]] inline auto tcp_interface_options(platform::TcpSocketOptions const& options,
            std::uint32_t index,platform::TcpSocketOptions& selected) -> platform::TcpSocketOptions const& {
            if (!options.binding.network && !options.binding.auto_detect_interface && !options.binding.network_strategy)
                return options;
            selected=options;
            selected.binding.network.reset(); selected.binding.auto_detect_interface=false;
            selected.binding.network_strategy.reset(); selected.binding.network_type.reset();
            selected.binding.interface_index=index;
            return selected;
        }

        template<class Socket, class Endpoint>
        auto race_hybrid_attempts(Socket& out_socket, std::span<std::pair<PlannedInterface, Endpoint> const> racers,
            platform::TcpSocketOptions const& options, InterfacePlan const& plan,
            platform::SocketDeadline deadline, bool& preparation_failed, bool& saw_bound_attempt,
            bool& all_bound_eperm, std::error_code& last, std::uint32_t* connected_interface)
            -> capy::task<std::optional<capy::results<Endpoint>>> {
            if constexpr (!requires { Socket(out_socket.context()); }) { co_return std::nullopt; }
            else {
                constexpr std::size_t kMaxRacers = 4;
                auto const count = std::min(racers.size(), kMaxRacers);
                std::array<std::optional<Socket>, kMaxRacers> sockets;
                std::optional<std::size_t> winner; std::optional<std::error_code> fatal_prep;
                std::error_code cancel_ec;
                auto race_one = [&](std::size_t slot) -> capy::task<capy::results<>> {
                    auto const& [iface, ep] = racers[slot];
                    if (slot > 0 && plan.fallback_delay.count() > 0) {
                        auto const now = std::chrono::steady_clock::now();
                        if (now >= deadline) co_return capy::results<>{};
                        auto const stagger = std::chrono::duration_cast<std::chrono::steady_clock::duration>(
                            plan.fallback_delay * static_cast<long long>(slot));
                        auto [de] = co_await corosio::delay(std::min(stagger, deadline - now));
                        if (de == capy::cond::canceled) { if (!winner && !cancel_ec) cancel_ec = de; co_return capy::results<>{}; }
                        if (de || winner) co_return capy::results<>{};
                    }
                    if (winner || std::chrono::steady_clock::now() >= deadline) co_return capy::results<>{};
                    sockets[slot].emplace(out_socket.context());
                    auto& sock = *sockets[slot];
                    auto const bind_idx = (options.binding.auto_detect_interface && !options.binding.network &&
                        is_loopback_endpoint(ep)) ? std::uint32_t{0} : iface.index;
                    platform::TcpSocketOptions selected;
                    auto const& settings = tcp_interface_options(options, bind_idx, selected);
                    if (bind_idx != 0) saw_bound_attempt = true;
                    if (settings.configured()) {
                        if (auto err = prepare_tcp_socket(sock, ep, settings, deadline)) {
                            sock.close();
                            if (bind_idx != 0 && err != std::errc::operation_not_permitted) all_bound_eperm = false;
                            if (bind_idx != 0 && platform::network::retry_interface_error(err)) { last = err; co_return capy::results<>{}; }
                            if (!fatal_prep) fatal_prep = err;
                            co_return capy::results<>{};
                        }
                    } else if (auto err = sock.open(ep.address().family())) {
                        if (bind_idx != 0 && err != std::errc::operation_not_permitted) all_bound_eperm = false;
                        last = err; co_return capy::results<>{};
                    }
                    auto [ec] = co_await corosio::timeout(sock.connect(ep), deadline);
                    if (!ec && !winner) {
                        winner = slot;
                        if (!settings.configured()) platform::tune_tcp_low_latency(sock.native_handle());
                        co_return capy::results<>{std::make_error_code(std::errc::operation_canceled)};
                    }
                    sock.close();
                    if (ec == capy::cond::canceled) { if (!winner && !cancel_ec) cancel_ec = ec; }
                    else if (ec) { if (bind_idx != 0 && ec != std::errc::operation_not_permitted) all_bound_eperm = false; last = ec; }
                    co_return capy::results<>{};
                };
                if (count == 2) (void)co_await capy::when_all(race_one(0), race_one(1));
                else if (count == 3) (void)co_await capy::when_all(race_one(0), race_one(1), race_one(2));
                else if (count >= 4) (void)co_await capy::when_all(race_one(0), race_one(1), race_one(2), race_one(3));
                if (winner) {
                    auto const slot = *winner;
                    for (std::size_t i = 0; i < count; ++i)
                        if (i != slot && sockets[i] && sockets[i]->is_open()) sockets[i]->close();
                    if (out_socket.is_open()) out_socket.close();
                    out_socket = std::move(*sockets[slot]);
                    auto const& [iface, ep] = racers[slot];
                    if (plan.fallback_memory && iface.index != 0) plan.fallback_memory->mark_healthy(iface.index, ep.is_v6());
                    if (connected_interface) *connected_interface = iface.index;
                    co_return capy::results<Endpoint>{std::error_code{}, ep};
                }
                for (std::size_t i = 0; i < count; ++i) if (sockets[i] && sockets[i]->is_open()) sockets[i]->close();
                if (cancel_ec) co_return capy::results<Endpoint>{cancel_ec, Endpoint{}};
                if (fatal_prep) { preparation_failed = true; co_return capy::results<Endpoint>{*fatal_prep, Endpoint{}}; }
                if (std::chrono::steady_clock::now() >= deadline)
                    co_return capy::results<Endpoint>{std::make_error_code(std::errc::timed_out), Endpoint{}};
                co_return std::nullopt;
            }
        }

        // Iterates interfaces (tier 0 before fallback tiers) and compatible endpoints with RFC 8305
        // Happy Eyeballs, lazy condition admission, per-family degradation memory, hybrid racing, and EPERM recovery.
        template<class Socket,std::ranges::input_range Range,class Condition>
        auto connect_prepared(Socket& socket,Range endpoints,Condition condition,
            platform::TcpSocketOptions const& options,bool& preparation_failed,platform::SocketDeadline deadline,
            std::uint32_t* connected_interface)
            -> capy::task<capy::results<typename Socket::endpoint_type>> {
            using Endpoint=typename Socket::endpoint_type;
            std::vector<Endpoint> ordered; bool has_v4 = false, has_v6 = false;
            for (auto&& item : endpoints) { ordered.emplace_back(item); (ordered.back().is_v6() ? has_v6 : has_v4) = true; }
            bool const dual_stack = has_v4 && has_v6;
            auto now_ms = []() noexcept {
                return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count();
            };
            auto const plan_start_ms = now_ms();
            auto plan = plan_tcp_interfaces(options, has_v4, has_v6, plan_start_ms);
            std::error_code last;
            std::vector<std::int8_t> admitted(ordered.size(), -1); std::size_t checked = 0;
            auto admit = [&](std::size_t idx) -> bool {
                while (checked <= idx) {
                    admitted[checked] = condition(std::as_const(last), std::as_const(ordered[checked])) ? 1 : 0;
                    ++checked;
                }
                return admitted[idx] == 1;
            };
            if (plan.entries.empty()) {
                for (std::size_t i = 0; i < ordered.size(); ++i)
                    if (admit(i)) last = std::make_error_code(std::errc::network_unreachable);
                if (!last) last = std::make_error_code(std::errc::no_such_device_or_address);
                co_return {last, Endpoint{}};
            }
            auto compatible = [](PlannedInterface const& iface, Endpoint const& ep) noexcept {
                return ep.is_v6() ? iface.supports_v6 : iface.supports_v4;
            };
            bool saw_bound_attempt = false, all_bound_eperm = true;
            containers::inplace_vector<std::pair<std::size_t, std::size_t>, 4> raced_pairs;
            if (plan.hybrid_race && plan.entries.size() >= 2) {
                containers::inplace_vector<std::pair<PlannedInterface, Endpoint>, 4> racers;
                for (std::size_t ii = 0; ii < plan.entries.size() && racers.size() < racers.capacity(); ++ii) {
                    for (std::size_t ep_idx = 0; ep_idx < ordered.size(); ++ep_idx) {
                        if (!compatible(plan.entries[ii], ordered[ep_idx]) || !admit(ep_idx)) continue;
                        racers.emplace_back(plan.entries[ii], ordered[ep_idx]);
                        if constexpr (requires { Socket(socket.context()); }) raced_pairs.emplace_back(ii, ep_idx);
                        break;
                    }
                }
                if (racers.size() >= 2) {
                    auto const race_span = std::span<std::pair<PlannedInterface, Endpoint> const>(racers.data(), racers.size());
                    if (auto done = co_await race_hybrid_attempts(socket, race_span, options, plan, deadline,
                            preparation_failed, saw_bound_attempt, all_bound_eperm, last, connected_interface))
                        co_return std::move(*done);
                } else { raced_pairs.clear(); }
            }
            std::vector<std::pair<std::size_t, std::size_t>> deferred;
            auto try_attempt = [&](PlannedInterface const& iface, std::size_t ep_idx,
                platform::SocketDeadline stop, bool unbound) -> capy::task<std::optional<capy::results<Endpoint>>> {
                if (std::chrono::steady_clock::now() >= deadline)
                    co_return capy::results<Endpoint>{std::make_error_code(std::errc::timed_out), Endpoint{}};
                Endpoint endpoint = ordered[ep_idx];
                if (socket.is_open()) socket.close();
                auto const bind_idx = (unbound || (!options.binding.network && options.binding.auto_detect_interface &&
                    is_loopback_endpoint(endpoint))) ? std::uint32_t{0} : iface.index;
                platform::TcpSocketOptions selected;
                auto const& settings = tcp_interface_options(options, bind_idx, selected);
                bool const dynamic_bind = !unbound && bind_idx != 0 &&
                    (options.binding.network || options.binding.auto_detect_interface || options.binding.network_strategy);
                if (dynamic_bind) saw_bound_attempt = true;
                if (settings.configured()) {
                    if (auto error = prepare_tcp_socket(socket, endpoint, settings, deadline)) {
                        socket.close();
                        if (dynamic_bind && error != std::errc::operation_not_permitted) all_bound_eperm = false;
                        if (dynamic_bind && platform::network::retry_interface_error(error)) { last = error; co_return std::nullopt; }
                        preparation_failed = true; co_return capy::results<Endpoint>{error, Endpoint{}};
                    }
                } else if (auto error = socket.open(endpoint.address().family())) {
                    if (dynamic_bind && error != std::errc::operation_not_permitted) all_bound_eperm = false;
                    last = error; co_return std::nullopt;
                }
                auto [error] = stop == deadline ? co_await socket.connect(endpoint) :
                    co_await corosio::timeout(socket.connect(endpoint), stop);
                if (!error) {
                    if (!settings.configured()) platform::tune_tcp_low_latency(socket.native_handle());
                    if (!unbound && plan.fallback_memory && bind_idx != 0) plan.fallback_memory->mark_healthy(bind_idx, endpoint.is_v6());
                    if (connected_interface) *connected_interface = settings.binding.interface_index;
                    co_return capy::results<Endpoint>{std::error_code{}, std::move(endpoint)};
                }
                if (error == capy::cond::canceled) co_return capy::results<Endpoint>{error, Endpoint{}};
                if (dynamic_bind && error != std::errc::operation_not_permitted) all_bound_eperm = false;
                last = error; co_return std::nullopt;
            };
            for (std::size_t iface_idx = 0; iface_idx < plan.entries.size(); ++iface_idx) {
                auto const& iface = plan.entries[iface_idx];
                bool const has_later_iface = iface_idx + 1 < plan.entries.size();
                bool failed_v4 = false, failed_v6 = false, non_eperm_v4 = false, non_eperm_v6 = false;
                auto is_ep_degraded = [&](Endpoint const& ep) noexcept {
                    return plan.parallel_fallback && plan.fallback_memory && iface.index != 0 &&
                        plan.fallback_memory->is_degraded(iface.index, plan_start_ms, ep.is_v6());
                };
                for (std::size_t ep_idx = 0; ep_idx < ordered.size(); ++ep_idx) {
                    if (std::ranges::contains(raced_pairs, std::pair{iface_idx, ep_idx})) continue;
                    auto const& ep = ordered[ep_idx];
                    if (!compatible(iface, ep)) continue;
                    if (is_ep_degraded(ep)) { deferred.emplace_back(iface_idx, ep_idx); continue; }
                    if (!admit(ep_idx)) continue;
                    bool has_later_ep = false, has_deferred = !deferred.empty();
                    for (std::size_t j = ep_idx + 1; j < ordered.size(); ++j) {
                        if (!compatible(iface, ordered[j])) continue;
                        if (is_ep_degraded(ordered[j])) has_deferred = true; else has_later_ep = true;
                        if (has_later_ep && has_deferred) break;
                    }
                    auto stop = tcp_planned_deadline(deadline, plan, has_later_iface, has_later_ep, dual_stack, has_deferred);
                    if (auto done = co_await try_attempt(iface, ep_idx, stop, false)) {
                        auto [done_ec, done_ep] = std::move(*done);
                        if (!done_ec && plan.parallel_fallback && plan.fallback_memory && iface.index != 0) {
                            auto const ts = now_ms();
                            if (ep.is_v6() && failed_v4 && non_eperm_v4) plan.fallback_memory->mark_failed(iface.index, ts, false);
                            if (!ep.is_v6() && failed_v6 && non_eperm_v6) plan.fallback_memory->mark_failed(iface.index, ts, true);
                        }
                        co_return {done_ec, std::move(done_ep)};
                    }
                    if (ep.is_v6()) { failed_v6 = true; if (last != std::errc::operation_not_permitted) non_eperm_v6 = true; }
                    else { failed_v4 = true; if (last != std::errc::operation_not_permitted) non_eperm_v4 = true; }
                }
                if (plan.parallel_fallback && plan.fallback_memory && iface.index != 0 && plan.entries.size() > 1) {
                    auto const ts = now_ms();
                    if (failed_v4 && non_eperm_v4) plan.fallback_memory->mark_failed(iface.index, ts, false);
                    if (failed_v6 && non_eperm_v6) plan.fallback_memory->mark_failed(iface.index, ts, true);
                }
            }
            for (std::size_t d = 0; d < deferred.size(); ++d) {
                auto [iface_idx, ep_idx] = deferred[d];
                if (!admit(ep_idx)) continue;
                auto const& iface = plan.entries[iface_idx];
                auto stop = (d + 1 < deferred.size()) ? std::min(deadline, std::chrono::steady_clock::now() +
                    (plan.fallback_delay.count() > 0 ? plan.fallback_delay : kHappyEyeballsFallbackDelay)) : deadline;
                if (auto done = co_await try_attempt(iface, ep_idx, stop, false)) co_return std::move(*done);
            }
            if (plan.allow_unbound_fallback && saw_bound_attempt && all_bound_eperm) {
                PlannedInterface unbound{};
                for (std::size_t ep_idx = 0; ep_idx < ordered.size(); ++ep_idx) {
                    if (!admit(ep_idx)) continue;
                    auto stop = (dual_stack && ep_idx + 1 < ordered.size())
                        ? std::min(deadline, std::chrono::steady_clock::now() + kHappyEyeballsFallbackDelay) : deadline;
                    if (auto done = co_await try_attempt(unbound, ep_idx, stop, true)) co_return std::move(*done);
                }
            }
            if (!last) {
                for (std::size_t i = 0; i < ordered.size(); ++i)
                    if (admit(i)) { last = std::make_error_code(std::errc::network_unreachable); break; }
            }
            if (!last) last = std::make_error_code(std::errc::no_such_device_or_address);
            co_return {last, Endpoint{}};
        }
    }

    // Returning the selected task directly retains one range-connect frame.
    template<class Socket,std::ranges::input_range Range,class Condition>
    auto connect_tcp_candidates(Socket& socket,Range endpoints,Condition condition,
        platform::TcpSocketOptions const& options,bool& preparation_failed,
        platform::SocketDeadline deadline=platform::SocketDeadline::max(),std::uint32_t* connected_interface=nullptr)
        -> capy::task<capy::results<typename Socket::endpoint_type>> {
        if (connected_interface) *connected_interface=0;
        if (!options.configured()) {
            bool dual_stack=false;
            if constexpr (std::ranges::forward_range<Range>) {
                bool v4=false,v6=false;
                for (auto const& item:endpoints) {
                    if (item.is_v6()) v6=true; else v4=true;
                    if (v4 && v6) { dual_stack=true; break; }
                }
            }
            if (!dual_stack) return corosio::connect(socket,std::move(endpoints),std::move(condition));
        }
        return detail::connect_prepared(socket,std::move(endpoints),std::move(condition),options,preparation_failed,deadline,connected_interface);
    }
}
