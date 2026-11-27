module cli.dns_transports;
import std;
import capy;
import corosio;
import config;
import dns.corosio_query;
import dns.dhcp_upstream;
import dns.input_budget;
import dns.message;
import platform.ip_address;

namespace cli {
    namespace {
        struct DhcpServerCache {
            std::string interface_name;
            std::mutex mutex;
            std::condition_variable_any cv;
            std::vector<corosio::endpoint> endpoints;
            std::jthread worker;

            explicit DhcpServerCache(std::string iface) : interface_name(std::move(iface)) {
                refresh();
                worker = std::jthread([this](std::stop_token tok) {
                    std::unique_lock lk(mutex);
                    while (!tok.stop_requested()) {
                        cv.wait_for(lk, tok, std::chrono::seconds(30), [] { return false; });
                        if (tok.stop_requested()) break;
                        lk.unlock();
                        refresh();
                        lk.lock();
                    }
                });
            }
            ~DhcpServerCache() {
                worker.request_stop();
                cv.notify_all();
                if (worker.joinable()) worker.join();
            }
            auto refresh() -> void {
                auto found = dns::discover_dhcp_dns_servers({}, interface_name);
                std::vector<corosio::endpoint> next;
                next.reserve(found.size());
                for (auto const& e : found) {
                    if (auto ep = resolve_dhcp_endpoint(e.address, e.scope, interface_name, 53))
                        next.push_back(*ep);
                }
                std::lock_guard lk(mutex);
                endpoints = std::move(next);
            }
            auto snapshot() -> std::vector<corosio::endpoint> {
                std::lock_guard lk(mutex);
                return endpoints;
            }
        };
    }

    auto resolve_dhcp_endpoint(platform::IpAddress const& ip, std::string_view scope,
        std::string_view fallback_iface, std::uint16_t port) noexcept -> std::optional<corosio::endpoint> {
        if (ip.size == 4) {
            corosio::ipv4_address::bytes_type b{};
            std::copy_n(ip.bytes.begin(), 4, b.begin());
            return corosio::endpoint{corosio::ipv4_address(b), port};
        }
        if (ip.size == 16) {
            bool const link_local = dns::is_ipv6_link_local(ip);
            std::string_view zone = !scope.empty() ? scope : (link_local ? fallback_iface : std::string_view{});
            std::uint32_t scope_id = 0;
            if (!zone.empty()) {
                scope_id = dns::resolve_ipv6_scope_id(zone);
                if (scope_id == 0 && link_local) return std::nullopt;
            }
            return corosio::endpoint{corosio::ipv6_address(ip.bytes, scope_id), port};
        }
        return std::nullopt;
    }

    auto query_dhcp_endpoints(corosio::io_context& context, std::span<corosio::endpoint const> endpoints,
        dns::QueryMessage const& query, std::uint16_t id, std::chrono::steady_clock::time_point deadline,
        dns::InputBudget& budget, std::stop_token stop)
        -> capy::task<std::expected<dns::Response, dns::detail::UdpError>> {
        using Error = dns::detail::UdpError;
        using Clock = std::chrono::steady_clock;
        if (stop.stop_requested()) co_return std::unexpected(Error::canceled);
        auto now = Clock::now();
        if (now >= deadline) co_return std::unexpected(Error::timeout);
        if (endpoints.empty()) co_return std::unexpected(Error::transport);

        if (endpoints.size() == 1) {
            dns::detail::FallbackQuery transport(context, false, &budget, nullptr);
            std::stop_callback cancel(stop, [&]() noexcept { transport.cancel(); });
            auto res = co_await transport.query_borrowed(endpoints[0], query, deadline, id);
            if (!res && stop.stop_requested()) co_return std::unexpected(Error::canceled);
            co_return res;
        }

        auto const count = std::min<std::size_t>(endpoints.size(), 8);
        auto const remaining_ms = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count();
        auto const stagger = std::chrono::milliseconds(
            std::clamp<std::int64_t>(remaining_ms / static_cast<std::int64_t>(count), 1, 300));

        struct RaceState {
            std::stop_source race_stop;
            capy::async_event progress;
            std::optional<dns::Response> winner;
            Error last_error = Error::transport;
            std::size_t active = 0;
            bool fast_failed = false;
        };
        RaceState state{};
        std::stop_callback forward_stop(stop, [&]() noexcept { state.race_stop.request_stop(); });

        auto probe = [](RaceState& st, corosio::io_context& ctx, corosio::endpoint ep,
            dns::QueryMessage const& q, std::uint16_t qid, Clock::time_point dl,
            dns::InputBudget& b) -> capy::task<void> {
            dns::detail::FallbackQuery transport(ctx, false, &b, nullptr);
            std::stop_callback cancel(st.race_stop.get_token(), [&]() noexcept { transport.cancel(); });
            if (!st.race_stop.stop_requested()) {
                auto res = co_await transport.query_borrowed(ep, q, dl, qid);
                if (res && !st.winner) {
                    st.winner.emplace(std::move(*res));
                    st.race_stop.request_stop();
                } else if (!res && !st.race_stop.stop_requested()) {
                    st.last_error = res.error();
                    st.fast_failed = true;
                }
            }
            --st.active;
            st.progress.set();
        };

        auto wait_progress = [](capy::async_event& ev) -> capy::task<void> {
            (void)co_await ev.wait();
        };

        auto wait_progress_until = [](capy::async_event& ev, Clock::time_point dl) -> capy::task<void> {
            (void)co_await corosio::timeout(ev.wait(), dl);
        };

        for (std::size_t idx = 0; idx < count; ++idx) {
            if (state.winner || state.race_stop.stop_requested() || Clock::now() >= deadline) break;
            state.fast_failed = false;
            ++state.active;
            capy::run_async(context.get_executor(), state.race_stop.get_token(),
                []() noexcept {},
                [&](std::exception_ptr) noexcept {
                    --state.active;
                    state.progress.set();
                })(probe(state, context, endpoints[idx], query, id, deadline, budget));

            if (idx + 1 >= count) break;
            auto const next_launch = std::min(deadline, Clock::now() + stagger);
            while (!state.winner && !state.race_stop.stop_requested() &&
                   !state.fast_failed && state.active > 0 && Clock::now() < next_launch) {
                state.progress.clear();
                if (state.winner || state.race_stop.stop_requested() || state.fast_failed || state.active == 0) break;
                co_await capy::run(state.race_stop.get_token())(
                    wait_progress_until(state.progress, next_launch));
            }
        }

        while (!state.winner && state.active > 0) {
            state.progress.clear();
            if (state.winner || state.active == 0) break;
            if (state.race_stop.stop_requested() || Clock::now() >= deadline) {
                state.race_stop.request_stop();
                break;
            }
            co_await capy::run(state.race_stop.get_token())(
                wait_progress_until(state.progress, deadline));
        }

        state.race_stop.request_stop();
        while (state.active > 0) {
            state.progress.clear();
            if (state.active == 0) break;
            co_await capy::run(std::stop_token{})(wait_progress(state.progress));
        }

        if (state.winner) co_return std::move(*state.winner);
        if (stop.stop_requested()) co_return std::unexpected(Error::canceled);
        if (Clock::now() >= deadline) co_return std::unexpected(Error::timeout);
        co_return std::unexpected(state.last_error);
    }

    auto prepare_dhcp_dns_transport(config::DnsServer const& server)
        -> std::expected<dns::detail::ProtectedQuery, std::string> {
        auto cache = std::make_shared<DhcpServerCache>(server.interface_name);
        return dns::detail::ProtectedQuery{
            [cache](corosio::io_context& context, corosio::endpoint, dns::QueryMessage const& query, std::uint16_t id,
                std::chrono::steady_clock::time_point deadline, dns::InputBudget& budget, std::stop_token stop)
                -> capy::task<std::expected<dns::Response, dns::detail::UdpError>> {
                auto discovered = cache->snapshot();
                co_return co_await query_dhcp_endpoints(context, discovered, query, id, deadline, budget, stop);
            }
        };
    }
}
