// TLS-capable TCP proxy outbound implementation (SOCKS4/4a/5 and HTTPS CONNECT).
module relay;
import :tcp_proxy_handshake;
import :tcp_proxy_impl;
import :quic_ech;
import std;
import capy;
import config;
import corosio;
import net.socket_stream;
import platform.wall_clock;
import quic.ech_config;
import tls.byte_stream;
import tls.client_handshake_io;
import tls.corosio_client;
import tls.fingerprint;
import tls.profiles;

namespace relay {
    namespace tcp_proxy_detail {
        struct HttpConnectTlsOps {
            struct Profile {
                tls::ShapedClientProfile tls;
                quic_ech::Profile ech;
            };
            static constexpr bool supported = true;

            template<class TlsSocket, class Stream>
            struct State {
                DnsSlot ech_dns;
                std::optional<quic::EchConfig> ech;
                std::optional<net::ByteStreamAdapter<Stream>> tls_fast_open;
                std::unique_ptr<tls::detail::ClientConnection<TlsSocket>> tls_client;
                std::unique_ptr<tls::detail::ByteStream<TlsSocket>> tls_stream;
            };

            static auto load(config::TcpProxyTls const& tls_cfg, bool dns_available = false) -> std::expected<Profile, std::string> {
                if ((tls_cfg.ech.dns || !tls_cfg.ech.config_file.empty()) && tls_cfg.fingerprint == config::TlsFingerprint::tls12)
                    return std::unexpected("HTTP CONNECT ECH requires TLS 1.3");
                auto ech = quic_ech::Profile::load(tls_cfg.ech, tls_cfg.server_name, dns_available);
                if (!ech) return std::unexpected(ech.error());
                constexpr std::array<std::string_view, 1> protocols{"http/1.1"};
                auto identity = tls::ClientProfile::load(tls_cfg.server_name, tls_cfg.ca_file, 0x001d, false, protocols);
                if (!identity) return std::unexpected(identity.error());
                identity->certificate_pins = tls_cfg.certificate_sha256;
                auto fp = tls::parse_fingerprint(config::tls_fingerprint_name(tls_cfg.fingerprint));
                if (!fp) return std::unexpected("invalid HTTP CONNECT TLS fingerprint");
                auto shaped = tls::ShapedClientProfile::create(std::move(*identity), *fp);
                if (!shaped) return std::unexpected(shaped.error());
                return Profile{std::move(*shaped), std::move(*ech)};
            }

            template<class TlsSocket, class Stream>
            static auto resolve_ech(Session& session, corosio::io_context& context, State<TlsSocket, Stream>& state,
                BasicTcpProxyProfile<Profile> const& profile, Clock::time_point deadline, bool const& canceled)
                -> capy::task<TunnelConnectResult> {
                if (!profile.tls_profile) co_return TunnelConnectResult::connected;
                auto resolved = co_await profile.tls_profile->ech.resolve(
                    session, context, state.ech_dns, profile.bootstrap, profile.port, deadline, quic_ech::Transport::tcp);
                if (canceled || session.closed) co_return TunnelConnectResult::failed;
                if (!resolved) co_return Clock::now() >= deadline ? TunnelConnectResult::timeout : TunnelConnectResult::failed;
                state.ech = std::move(*resolved);
                co_return TunnelConnectResult::connected;
            }

            template<bool FastOpen, class Socket, class Stream, class TlsSocket>
            static auto handshake_and_connect(Session& session, State<TlsSocket, Stream>& state,
                Socket* raw_socket, Stream& stream, BasicTcpProxyProfile<Profile> const& profile,
                corosio::endpoint target, std::string& buffered, Clock::time_point deadline,
                std::string_view domain, bool const& canceled) -> capy::task<bool> {
                using std::chrono::duration_cast;
                using std::chrono::milliseconds;
                auto start = duration_cast<milliseconds>(Clock::now().time_since_epoch()).count();
                auto end = duration_cast<milliseconds>(deadline.time_since_epoch()).count();
                auto verified = platform::calibrated_wall_seconds();
                if (start < 0 || verified < 0 || end <= start) co_return false;
                auto handshake = profile.tls_profile->tls.handshake(static_cast<std::uint64_t>(start),
                    static_cast<std::uint64_t>(end), verified, std::span<std::uint8_t const>{},
                    state.ech ? &*state.ech : nullptr);
                if (!handshake) co_return false;
                TlsSocket* socket = nullptr;
                if constexpr (FastOpen) socket = &state.tls_fast_open.emplace(stream);
                else socket = raw_socket;
                state.tls_client = std::make_unique<tls::detail::ClientConnection<TlsSocket>>(
                    *socket, std::move(*handshake));
                auto authenticated = co_await state.tls_client->start();
                if (!authenticated || canceled || session.closed) co_return false;
                auto* application = state.tls_client->application();
                if (!application) co_return false;
                state.tls_stream = std::make_unique<tls::detail::ByteStream<TlsSocket>>(*application);
                (void)state.tls_stream->try_enable_ktls();
                co_return co_await http_connect(*state.tls_stream, profile, target, buffered, deadline, domain);
            }

            template<class TlsSocket, class Stream>
            static auto active(State<TlsSocket, Stream> const& state) noexcept -> bool {
                return static_cast<bool>(state.tls_stream);
            }

            template<class TlsSocket, class Stream>
            static auto cancel(State<TlsSocket, Stream>& state) noexcept -> bool {
                state.ech_dns.cancel();
                if (state.tls_stream) {
                    state.tls_stream->cancel();
                    return true;
                }
                if (state.tls_client) {
                    state.tls_client->cancel();
                    return true;
                }
                return false;
            }

            template<class TlsSocket, class Stream>
            static auto send(State<TlsSocket, Stream>& state, std::span<std::uint8_t const> bytes) -> capy::task<bool> {
                co_return co_await state.tls_stream->send(bytes);
            }

            template<class TlsSocket, class Stream>
            static auto read(State<TlsSocket, Stream>& state, std::span<std::uint8_t> bytes)
                -> capy::task<std::expected<std::size_t, std::string>> {
                auto count = co_await state.tls_stream->read(bytes);
                if (!count) co_return std::unexpected("HTTP CONNECT TLS stream read failed");
                co_return *count;
            }

            template<class TlsSocket, class Stream>
            static auto close_output(State<TlsSocket, Stream>& state) -> capy::task<bool> {
                co_return co_await state.tls_stream->close_output();
            }
        };
    }

    auto Server::add_tcp_proxy(config::TcpProxyOutbound const& config) -> std::expected<std::size_t, std::string> {
        bool busy = running || (listener && listener->is_open()) || !sessions.empty() || !workers.empty();
        return tcp_proxy_detail::add_tcp_proxy_impl<tcp_proxy_detail::HttpConnectTlsOps>(
            config, outbounds, dns_routing, max_bootstrap_index, busy);
    }
}
