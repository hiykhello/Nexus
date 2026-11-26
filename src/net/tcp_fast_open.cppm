module;
#include <cerrno>
#include <netinet/in.h>
#include <sys/socket.h>

export module net.tcp_fast_open;
import std;
import net.tcp_connect;
import capy;
import corosio;

export namespace net {
    // The accepted byte count is meaningful even on error: once the kernel
    // accepts data, retrying it on another connection can duplicate it.
    struct FastOpenResult {std::error_code error;std::size_t accepted=0;bool unsupported=false,preparation_failed=false;};

    // Single candidate. The caller retains socket and payload until return,
    // closes the socket on error, and sends only the unaccepted suffix on
    // success. An empty first write performs an ordinary connection.
    [[nodiscard]] inline auto tcp_fast_open_first_write(corosio::tcp_socket& socket,
        corosio::endpoint endpoint,std::span<std::uint8_t const> payload,
        std::chrono::steady_clock::time_point deadline,platform::TcpSocketOptions const& options={})
        -> capy::task<FastOpenResult> {
        using Clock=std::chrono::steady_clock;
        auto stop=co_await capy::this_coro::stop_token;
        if(stop.stop_requested())co_return FastOpenResult{std::make_error_code(std::errc::operation_canceled)};
        if(Clock::now()>=deadline)co_return FastOpenResult{std::make_error_code(std::errc::timed_out)};
        if(socket.is_open())co_return FastOpenResult{std::make_error_code(std::errc::already_connected)};
        if(auto error=prepare_tcp_socket(socket,endpoint,options,deadline))co_return FastOpenResult{error,0,false,true};
        if(!socket.is_open()) {
            if(auto error=socket.open(endpoint.address().family()))co_return FastOpenResult{error,0,false,true};
            platform::tune_tcp_low_latency(socket.native_handle());
        }
        if(payload.empty()) {
            auto [error]=co_await corosio::timeout(socket.connect(endpoint),deadline);
            if(!error && Clock::now()>=deadline)error=std::make_error_code(std::errc::timed_out);
            co_return FastOpenResult{error};
        }
        sockaddr_storage address{};socklen_t length;
        if(endpoint.is_v4()) {
            auto* value=reinterpret_cast<sockaddr_in*>(&address);value->sin_family=AF_INET;value->sin_port=htons(endpoint.port());
            auto bytes=endpoint.address().to_v4().to_bytes();std::memcpy(&value->sin_addr,bytes.data(),bytes.size());length=sizeof(*value);
        } else {
            auto* value=reinterpret_cast<sockaddr_in6*>(&address);value->sin6_family=AF_INET6;value->sin6_port=htons(endpoint.port());
            auto ip=endpoint.address().to_v6();auto bytes=ip.to_bytes();std::memcpy(&value->sin6_addr,bytes.data(),bytes.size());
            value->sin6_scope_id=ip.scope_id();length=sizeof(*value);
        }
        if(stop.stop_requested())co_return FastOpenResult{std::make_error_code(std::errc::operation_canceled)};
        if(Clock::now()>=deadline)co_return FastOpenResult{std::make_error_code(std::errc::timed_out)};
#if defined(__linux__) && defined(MSG_FASTOPEN)
        auto count=::sendto(socket.native_handle(),payload.data(),payload.size(),MSG_FASTOPEN|MSG_DONTWAIT|MSG_NOSIGNAL,
                            reinterpret_cast<sockaddr const*>(&address),length);
        std::size_t accepted=0;
        if(count>=0)accepted=static_cast<std::size_t>(count);
        else if(errno!=EINPROGRESS) {
            auto error=errno;
            co_return FastOpenResult{{error,std::generic_category()},0,error==EPIPE || error==EOPNOTSUPP};
        }
        auto [wait_error]=co_await corosio::timeout(socket.wait(corosio::wait_type::write),deadline);
        if(wait_error)co_return FastOpenResult{wait_error,accepted};
        if(Clock::now()>=deadline)co_return FastOpenResult{std::make_error_code(std::errc::timed_out),accepted};
        int socket_error=0;socklen_t error_length=sizeof(socket_error);
        if(::getsockopt(socket.native_handle(),SOL_SOCKET,SO_ERROR,&socket_error,&error_length)<0)
            co_return FastOpenResult{{errno,std::generic_category()},accepted};
        if(error_length!=sizeof(socket_error))co_return FastOpenResult{std::make_error_code(std::errc::protocol_error),accepted};
        co_return FastOpenResult{{socket_error,std::generic_category()},accepted};
#else
        (void)address; (void)length;
        co_return FastOpenResult{std::make_error_code(std::errc::operation_not_supported),0,true};
#endif
    }

    struct FastOpenCandidatesResult {
        FastOpenResult result;
        corosio::endpoint endpoint;
        bool preparation_failed=false;
        std::uint32_t interface_index=0;
    };
    // Retry a new candidate only if the previous socket accepted no data.
    // Unsupported TFO may use ordinary connect on that same candidate; the
    // caller remains responsible for the complete first-write suffix.
    template<std::ranges::input_range Range,class Condition>
    [[nodiscard]] auto tcp_fast_open_candidates(corosio::tcp_socket& socket,Range endpoints,Condition condition,
        std::span<std::uint8_t const> payload,std::chrono::steady_clock::time_point deadline,
        platform::TcpSocketOptions const& options={}) -> capy::task<FastOpenCandidatesResult> {
        std::vector<corosio::endpoint> ordered;
        bool has_v4 = false, has_v6 = false;
        for (auto&& item : endpoints) {
            ordered.emplace_back(item);
            if (ordered.back().is_v6()) has_v6 = true; else has_v4 = true;
        }
        bool const dual_stack = has_v4 && has_v6;
        auto now_ms = []() noexcept {
            return std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count();
        };
        auto const plan_start_ms = now_ms();
        auto plan = detail::plan_tcp_interfaces(options, has_v4, has_v6, plan_start_ms);
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
            co_return FastOpenCandidatesResult{{last}, {}};
        }
        auto compatible = [](detail::PlannedInterface const& iface, corosio::endpoint const& ep) noexcept {
            return ep.is_v6() ? iface.supports_v6 : iface.supports_v4;
        };
        bool saw_bound_attempt = false, all_bound_eperm = true;
        std::vector<std::pair<std::size_t, std::size_t>> deferred;
        auto try_attempt = [&](detail::PlannedInterface const& iface, std::size_t ep_idx,
            std::chrono::steady_clock::time_point stop, bool unbound) -> capy::task<std::optional<FastOpenCandidatesResult>> {
            if (std::chrono::steady_clock::now() >= deadline)
                co_return FastOpenCandidatesResult{{std::make_error_code(std::errc::timed_out)}, {}};
            corosio::endpoint endpoint = ordered[ep_idx];
            if (socket.is_open()) socket.close();
            platform::TcpSocketOptions selected;
            auto const& settings = detail::tcp_interface_options(options, unbound ? std::uint32_t{0} : iface.index, selected);
            if (!unbound && options.binding.network && iface.index != 0) saw_bound_attempt = true;
            auto result = co_await tcp_fast_open_first_write(socket, endpoint, payload, stop, settings);
            if (result.unsupported) {
                socket.close();
                result = co_await tcp_fast_open_first_write(socket, endpoint, {}, stop, settings);
            }
            if (!result.error) {
                if (!unbound && plan.fallback_memory && iface.index != 0)
                    plan.fallback_memory->mark_healthy(iface.index, endpoint.is_v6());
                co_return FastOpenCandidatesResult{result, endpoint, false, settings.binding.interface_index};
            }
            socket.close();
            if (!unbound && options.binding.network && iface.index != 0 &&
                result.error != std::errc::operation_not_permitted)
                all_bound_eperm = false;
            if (result.preparation_failed && !unbound && options.binding.network &&
                platform::network::retry_interface_error(result.error)) {
                last = result.error;
                co_return std::nullopt;
            }
            if (result.preparation_failed || result.accepted || result.error == capy::cond::canceled ||
                ((capy::is_timeout(result.error) || result.error == std::errc::timed_out) && stop == deadline))
                co_return FastOpenCandidatesResult{result, endpoint, result.preparation_failed};
            last = result.error;
            co_return std::nullopt;
        };
        for (std::size_t iface_idx = 0; iface_idx < plan.entries.size(); ++iface_idx) {
            auto const& iface = plan.entries[iface_idx];
            bool const has_later_iface = iface_idx + 1 < plan.entries.size();
            bool failed_v4 = false, failed_v6 = false;
            bool non_eperm_v4 = false, non_eperm_v6 = false;
            auto is_ep_degraded = [&](corosio::endpoint const& ep) noexcept {
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
                auto stop = detail::tcp_planned_deadline(deadline, plan, has_later_iface, has_later_ep, dual_stack, has_deferred);
                if (auto done = co_await try_attempt(iface, ep_idx, stop, false)) {
                    if (!done->result.error && plan.parallel_fallback && plan.fallback_memory && iface.index != 0) {
                        auto const ts = now_ms();
                        if (ep.is_v6() && failed_v4 && non_eperm_v4) plan.fallback_memory->mark_failed(iface.index, ts, false);
                        if (!ep.is_v6() && failed_v6 && non_eperm_v6) plan.fallback_memory->mark_failed(iface.index, ts, true);
                    }
                    co_return std::move(*done);
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
            detail::PlannedInterface unbound{};
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
        co_return FastOpenCandidatesResult{{last}, {}};
    }
}
