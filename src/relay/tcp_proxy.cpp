// Non-TLS TCP proxy outbound implementation (SOCKS4/4a/5 and plain HTTP CONNECT).
module relay;
import :tcp_proxy_impl;
import std;
import capy;
import config;

namespace relay {
    namespace tcp_proxy_detail {
        struct NoTlsOps {
            using Profile = std::monostate;
            static constexpr bool supported = false;
            template<class TlsSocket, class Stream> struct State {};

            static auto load(config::TcpProxyTls const&, bool = false) -> std::expected<Profile, std::string> {
                return std::unexpected("HTTP CONNECT TLS is unavailable in this build");
            }
            template<class TlsSocket, class Stream>
            static auto resolve_ech(Session&, corosio::io_context&, State<TlsSocket, Stream>&,
                BasicTcpProxyProfile<Profile> const&, Clock::time_point, bool const&) -> capy::task<TunnelConnectResult> {
                co_return TunnelConnectResult::connected;
            }
            template<bool FastOpen, class Socket, class Stream, class TlsSocket>
            static auto handshake_and_connect(Session&, State<TlsSocket, Stream>&, Socket*, Stream&,
                BasicTcpProxyProfile<Profile> const&, corosio::endpoint, std::string&, Clock::time_point,
                std::string_view, bool const&) -> capy::task<bool> {
                co_return false;
            }
            template<class TlsSocket, class Stream>
            static auto active(State<TlsSocket, Stream> const&) noexcept -> bool { return false; }
            template<class TlsSocket, class Stream>
            static auto cancel(State<TlsSocket, Stream>&) noexcept -> bool { return false; }
            template<class TlsSocket, class Stream>
            static auto send(State<TlsSocket, Stream>&, std::span<std::uint8_t const>) -> capy::task<bool> {
                co_return false;
            }
            template<class TlsSocket, class Stream>
            static auto read(State<TlsSocket, Stream>&, std::span<std::uint8_t>)
                -> capy::task<std::expected<std::size_t, std::string>> {
                co_return std::unexpected("HTTP CONNECT TLS stream read failed");
            }
            template<class TlsSocket, class Stream>
            static auto close_output(State<TlsSocket, Stream>&) -> capy::task<bool> { co_return false; }
        };
    }

    auto Server::add_tcp_proxy(config::TcpProxyOutbound const& config) -> std::expected<std::size_t, std::string> {
        bool busy = running || (listener && listener->is_open()) || !sessions.empty() || !workers.empty();
        return tcp_proxy_detail::add_tcp_proxy_impl<tcp_proxy_detail::NoTlsOps>(
            config, outbounds, dns_routing, max_bootstrap_index, busy);
    }
}
