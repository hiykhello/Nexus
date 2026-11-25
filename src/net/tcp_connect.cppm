export module net.tcp_connect;
import std;
export import net.happy_eyeballs;
export import platform.socket_options;
import capy;
import corosio;

export namespace net {
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
        if (auto error=platform::apply_tcp_options(socket.native_handle(),options,deadline)) return error;
        platform::tune_tcp_low_latency(socket.native_handle());
        if (endpoint.is_v4() && options.binding.inet4_bind_address)
            return socket.bind(Endpoint(corosio::ipv4_address(*options.binding.inet4_bind_address),0));
        if (endpoint.is_v6() && options.binding.inet6_bind_address)
            return socket.bind(Endpoint(corosio::ipv6_address(*options.binding.inet6_bind_address),0));
        return {};
    }

    namespace detail {
        struct PlannedInterface {
            std::uint32_t index = 0;
            std::uint8_t tier = 0;
            std::uint8_t order = 0;
            bool supports_v4 = false;
            bool supports_v6 = false;
            bool all_degraded = false;
        };

        struct InterfacePlan {
            containers::inplace_vector<PlannedInterface, 16> entries;
            std::chrono::milliseconds fallback_delay{};
            bool parallel_fallback = false;
            std::shared_ptr<platform::network::FallbackMemory> fallback_memory;
        };

        [[nodiscard]] inline auto tcp_interfaces(platform::TcpSocketOptions const& options,bool ipv6)
            -> platform::network::InterfaceCandidates {
            if (options.binding.network) return (*options.binding.network)(ipv6);
            platform::network::InterfaceCandidates result;
            result.indices.push_back(0);
            result.tiers.push_back(0);
            return result;
        }

        [[nodiscard]] inline auto plan_tcp_interfaces(platform::TcpSocketOptions const& options,
            bool has_v4,bool has_v6,std::int64_t now_ms) -> InterfacePlan {
            InterfacePlan plan{};
            if (!options.binding.network) {
                plan.entries.push_back({.index = 0, .tier = 0, .order = 0, .supports_v4 = has_v4, .supports_v6 = has_v6});
                return plan;
            }
            auto merge = [&](bool ipv6) {
                auto cands = (*options.binding.network)(ipv6);
                if (!plan.fallback_memory && cands.fallback_memory) plan.fallback_memory = std::move(cands.fallback_memory);
                if (plan.fallback_delay.count() == 0) plan.fallback_delay = cands.fallback_delay;
                plan.parallel_fallback = plan.parallel_fallback || cands.parallel_fallback;
                for (std::size_t i = 0; i < cands.indices.size(); ++i) {
                    auto const idx = cands.indices[i];
                    auto const tier = i < cands.tiers.size() ? cands.tiers[i] : static_cast<std::uint8_t>(i);
                    auto it = std::ranges::find(plan.entries, idx, &PlannedInterface::index);
                    if (it == plan.entries.end()) {
                        if (plan.entries.size() < plan.entries.capacity()) {
                            plan.entries.push_back({
                                .index = idx,
                                .tier = tier,
                                .order = static_cast<std::uint8_t>(plan.entries.size()),
                                .supports_v4 = !ipv6,
                                .supports_v6 = ipv6,
                            });
                        }
                    } else {
                        it->tier = std::min(it->tier, tier);
                        if (ipv6) it->supports_v6 = true; else it->supports_v4 = true;
                    }
                }
            };
            if (has_v4) merge(false);
            if (has_v6) merge(true);
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
            auto stop = deadline;
            auto const now = std::chrono::steady_clock::now();
            if (has_later_iface || has_deferred) {
                auto const delay = plan.fallback_delay.count() > 0 ? plan.fallback_delay : kHappyEyeballsFallbackDelay;
                stop = std::min(stop, now + delay);
            }
            if (dual_stack && has_later_ep)
                stop = std::min(stop, now + kHappyEyeballsFallbackDelay);
            return stop;
        }

        [[nodiscard]] inline auto tcp_interface_options(platform::TcpSocketOptions const& options,
            std::uint32_t index,platform::TcpSocketOptions& selected) -> platform::TcpSocketOptions const& {
            if (!options.binding.network) return options;
            selected=options;
            selected.binding.network.reset();
            selected.binding.interface_index=index;
            return selected;
        }

        // Iterates interfaces in the outer loop (tier 0 before fallback tiers)
        // and compatible endpoints in the inner loop with RFC 8305 Happy Eyeballs
        // 300ms per-endpoint fallback, lazy sequential condition admission,
        // per-family degradation memory, and parallel_fallback EPERM recovery.
        template<class Socket,std::ranges::input_range Range,class Condition>
        auto connect_prepared(Socket& socket,Range endpoints,Condition condition,
            platform::TcpSocketOptions const& options,bool& preparation_failed,platform::SocketDeadline deadline,
            std::uint32_t* connected_interface)
            -> capy::task<capy::results<typename Socket::endpoint_type>> {
            using Endpoint=typename Socket::endpoint_type;
            std::vector<Endpoint> ordered;
            bool has_v4 = false, has_v6 = false;
            for (auto&& item:endpoints) {
                ordered.emplace_back(item);
                if (ordered.back().is_v6()) has_v6 = true; else has_v4 = true;
            }
            bool const dual_stack = has_v4 && has_v6;
            auto now_ms = []() noexcept {
                return std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now().time_since_epoch()).count();
            };
            auto const plan_start_ms = now_ms();
            auto plan = plan_tcp_interfaces(options, has_v4, has_v6, plan_start_ms);
            std::error_code last;
            std::vector<std::int8_t> admitted(ordered.size(), -1);
            std::size_t checked = 0;
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
            std::vector<std::pair<std::size_t, std::size_t>> deferred;
            auto try_attempt = [&](PlannedInterface const& iface, std::size_t ep_idx,
                platform::SocketDeadline stop, bool unbound) -> capy::task<std::optional<capy::results<Endpoint>>> {
                if (std::chrono::steady_clock::now() >= deadline)
                    co_return capy::results<Endpoint>{std::make_error_code(std::errc::timed_out), Endpoint{}};
                Endpoint endpoint = ordered[ep_idx];
                if (socket.is_open()) socket.close();
                platform::TcpSocketOptions selected;
                auto const& settings = tcp_interface_options(options, unbound ? std::uint32_t{0} : iface.index, selected);
                if (!unbound && options.binding.network && iface.index != 0) saw_bound_attempt = true;
                if (settings.configured()) {
                    if (auto error = prepare_tcp_socket(socket, endpoint, settings, deadline)) {
                        socket.close();
                        if (!unbound && options.binding.network && iface.index != 0 &&
                            error != std::errc::operation_not_permitted)
                            all_bound_eperm = false;
                        if (!unbound && options.binding.network && platform::network::retry_interface_error(error)) {
                            last = error;
                            co_return std::nullopt;
                        }
                        preparation_failed = true;
                        co_return capy::results<Endpoint>{error, Endpoint{}};
                    }
                } else if (auto error = socket.open(endpoint.address().family())) {
                    if (!unbound && options.binding.network && iface.index != 0 &&
                        error != std::errc::operation_not_permitted)
                        all_bound_eperm = false;
                    last = error;
                    co_return std::nullopt;
                }
                auto [error] = stop == deadline ? co_await socket.connect(endpoint) :
                    co_await corosio::timeout(socket.connect(endpoint), stop);
                if (!error) {
                    if (!settings.configured()) platform::tune_tcp_low_latency(socket.native_handle());
                    if (!unbound && plan.fallback_memory && iface.index != 0)
                        plan.fallback_memory->mark_healthy(iface.index, endpoint.is_v6());
                    if (connected_interface) *connected_interface = settings.binding.interface_index;
                    co_return capy::results<Endpoint>{std::error_code{}, std::move(endpoint)};
                }
                if (error == capy::cond::canceled) co_return capy::results<Endpoint>{error, Endpoint{}};
                if (!unbound && options.binding.network && iface.index != 0 &&
                    error != std::errc::operation_not_permitted)
                    all_bound_eperm = false;
                last = error;
                co_return std::nullopt;
            };
            for (std::size_t iface_idx = 0; iface_idx < plan.entries.size(); ++iface_idx) {
                auto const& iface = plan.entries[iface_idx];
                bool const has_later_iface = iface_idx + 1 < plan.entries.size();
                bool failed_v4 = false, failed_v6 = false;
                bool non_eperm_v4 = false, non_eperm_v6 = false;
                auto is_ep_degraded = [&](Endpoint const& ep) noexcept {
                    return plan.parallel_fallback && plan.fallback_memory && iface.index != 0 &&
                        plan.fallback_memory->is_degraded(iface.index, plan_start_ms, ep.is_v6());
                };
                for (std::size_t ep_idx = 0; ep_idx < ordered.size(); ++ep_idx) {
                    auto const& ep = ordered[ep_idx];
                    if (!compatible(iface, ep)) continue;
                    if (is_ep_degraded(ep)) {
                        deferred.emplace_back(iface_idx, ep_idx);
                        continue;
                    }
                    if (!admit(ep_idx)) continue;
                    bool has_later_ep = false;
                    bool has_deferred = !deferred.empty();
                    for (std::size_t j = ep_idx + 1; j < ordered.size(); ++j) {
                        if (!compatible(iface, ordered[j])) continue;
                        if (is_ep_degraded(ordered[j])) has_deferred = true;
                        else has_later_ep = true;
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
                bool const has_more = d + 1 < deferred.size();
                auto stop = has_more ? std::min(deadline, std::chrono::steady_clock::now() +
                    (plan.fallback_delay.count() > 0 ? plan.fallback_delay : kHappyEyeballsFallbackDelay)) : deadline;
                if (auto done = co_await try_attempt(iface, ep_idx, stop, false))
                    co_return std::move(*done);
            }
            if (options.binding.network && plan.parallel_fallback && saw_bound_attempt && all_bound_eperm) {
                PlannedInterface unbound{};
                for (std::size_t ep_idx = 0; ep_idx < ordered.size(); ++ep_idx) {
                    if (!admit(ep_idx)) continue;
                    auto stop = (dual_stack && ep_idx + 1 < ordered.size())
                        ? std::min(deadline, std::chrono::steady_clock::now() + kHappyEyeballsFallbackDelay)
                        : deadline;
                    if (auto done = co_await try_attempt(unbound, ep_idx, stop, true))
                        co_return std::move(*done);
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
