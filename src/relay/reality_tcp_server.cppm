module;
#include <boost/corosio/socket_option.hpp>

module relay:reality_tcp_server;
import std;
import memory.budget;
import reality.server_profile;
import reality.server_probe;
import reality.fallback;
import tls.corosio_application;
import tls.corosio_server_handshake;
import platform.wall_clock;
import capy;
import corosio;
import :types;
import :session_interface;
import :internal_decls;

namespace relay {
    struct RealityTcpProfile {
        reality::ServerProfile profile;
        std::string fallback_host;
        std::uint16_t fallback_port;
        std::optional<std::size_t> fallback_resolver;

        static inline auto load(RealityInbound cfg) -> std::expected<RealityTcpProfile, std::string> {
            if (cfg.fallback_host.empty() || !cfg.fallback_port) return std::unexpected("invalid Reality fallback");
            auto ready = reality::ServerProfile::load(cfg.private_key_file, cfg.certificate_file, cfg.signing_key_file,
                cfg.server_names, cfg.short_ids, cfg.max_time_difference_seconds);
            if (!ready) return std::unexpected(ready.error());
            return RealityTcpProfile{std::move(*ready), std::move(cfg.fallback_host), cfg.fallback_port, cfg.fallback_resolver};
        }
    };

    namespace reality_tcp {
        inline auto fallback_connect(Session& session, corosio::io_context& context, RealityTcpProfile const& owned,
                              Clock::time_point limit) -> capy::task<capy::results<bool>> {
            auto connect = [&]() -> capy::task<bool> {
                if (Clock::now() >= limit) co_return false;
                std::vector<corosio::endpoint> endpoints;
                if (owned.fallback_resolver) {
                    auto resolved = co_await resolve_bootstrap(session, context, *owned.fallback_resolver, owned.fallback_host, owned.fallback_port, limit);
                    if (!resolved) co_return false;
                    endpoints = std::move(*resolved);
                } else {
                    auto resolved = co_await resolve_local(session, context, owned.fallback_host, owned.fallback_port, limit);
                    if (!resolved) co_return false;
                    endpoints = std::move(*resolved);
                }
                if (session.closed || endpoints.empty() || endpoints.size() > 64) co_return false;
                std::erase_if(endpoints, [](auto const& endpoint) { return !valid_destination(endpoint); });
                if (endpoints.empty()) co_return false;
                auto [error, connected] = co_await corosio::timeout(corosio::connect_candidates(session.target, std::move(endpoints)), limit);
                (void)connected;
                co_return !error && !session.closed;
            };
            auto connected = co_await connect();
            // Signal the join to cancel its error watcher after dialing completes.
            co_return capy::results<bool>{std::make_error_code(std::errc::operation_canceled), connected};
        }

        inline auto establish(Session& session, corosio::io_context& context, RealityTcpProfile const& owned,
            std::shared_ptr<memory::Budget> budget, std::uint64_t start, std::uint64_t deadline, std::string_view protocol = {})
            -> capy::task<std::optional<tls::detail::ServerAsyncResult>> {
            auto probe = reality::ServerProbe::create(131072, budget); if (!probe) co_return std::nullopt;
            auto limit = session.started + std::chrono::seconds(10);
            std::array<std::uint8_t, 4096> input{}; std::span<std::uint8_t const> suffix;
            bool fallback = false;
            while (probe->status() == reality::ProbeStatus::pending) {
                auto [error, n] = co_await corosio::timeout(session.client.read_some(capy::mutable_buffer(input.data(), input.size())), limit);
                if (session.closed || (error && error != capy::cond::eof) || (!error && (!n || n > input.size()))) co_return std::nullopt;
                if (error == capy::cond::eof) { fallback = true; break; }
                auto now = platform::calibrated_wall_seconds();
                if (now < 0) co_return std::nullopt;
                auto fed = probe->feed(std::span{input}.first(n), owned.profile.private_key(), owned.profile.policy(), static_cast<std::uint64_t>(now));
                if (fed.consumed > n) co_return std::nullopt;
                suffix = std::span{input}.subspan(fed.consumed, n - fed.consumed);
                if (fed.status == reality::ProbeStatus::fallback) { fallback = true; break; }
                if (!suffix.empty()) co_return std::nullopt;
            }
            if (fallback) {
                auto [signal, connected, watch_result] = co_await capy::when_all(
                    fallback_connect(session, context, owned, limit), watch_client_error(session));
                (void)signal; (void)watch_result;
                if (!connected || session.closed) co_return std::nullopt;
                session.relaying = true; session.touched = Clock::now();
                session.lifetime_deadline = session.started + std::chrono::minutes(10);
                auto abortive = [](auto& socket) noexcept {
                    (void)socket.set_option(::boost::corosio::socket_option::linger(true, 0));
                };
                (void)co_await reality::fallback(session.client, session.target, probe->bytes(), suffix,
                    [&session] { session.touched = Clock::now(); }, abortive);
                co_return std::nullopt;
            }
            auto auth = probe->take_authentication(); if (!auth) co_return std::nullopt;
            auto handshake = owned.profile.handshake(auth->key, start, deadline, budget, protocol); if (!handshake) co_return std::nullopt;
            auto result = co_await tls::detail::server_handshake(session.client, *handshake, budget, probe->bytes());
            if (!result || session.closed) co_return std::nullopt;
            co_return std::move(*result);
        }
    }
}
