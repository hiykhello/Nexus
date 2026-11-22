module;
#include <proxy/proxy_macros.h>
#include <boost/capy/task.hpp>
#include <boost/corosio/io_context.hpp>
#include <boost/corosio/tcp_socket.hpp>
#include <boost/corosio/endpoint.hpp>
#include <boost/corosio/timeout.hpp>
module proxy;
import std;
import proxy.v4;
import config;
import rulefile;
import crypto;
import shadowtls.v3;
import shadowtls.stream;
import tls.profiles;
import tls.fingerprint;
import net.stream_relay;
import net.tcp_connect;
import net.tcp_fast_open_stream;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;

namespace proxy {
    namespace {
        struct StlsProfile {
            std::string host;
            std::uint16_t port = 0;
            std::string password;
            tls::ClientProfile tls;
            tls::Fingerprint fingerprint = tls::Fingerprint::native;
            std::optional<std::size_t> bootstrap;
            std::uint32_t timeout_ms = 10000;
            TcpSocketOptions options;
            bool strict_tls13 = true;

            ~StlsProfile() {
                crypto::cleanse(std::span(reinterpret_cast<std::uint8_t*>(password.data()), password.size()));
            }
        };

        struct LowerSocket {
            pro::proxy<TunnelFacade>& lower;
            auto read_some(nex::capy::mutable_buffer buf) -> nex::capy::task<nex::capy::results<std::size_t>> {
                auto res = co_await lower->read({static_cast<std::uint8_t*>(buf.data()), buf.size()});
                if (!res) co_return nex::capy::results<std::size_t>{std::make_error_code(std::errc::io_error), 0};
                if (!*res) co_return nex::capy::results<std::size_t>{std::error_code{}, 0};
                co_return nex::capy::results<std::size_t>{std::error_code{}, *res};
            }
            auto write_some(nex::capy::const_buffer buf) -> nex::capy::task<nex::capy::results<std::size_t>> {
                auto ok = co_await lower->send({static_cast<std::uint8_t const*>(buf.data()), buf.size()});
                if (!ok) co_return nex::capy::results<std::size_t>{std::make_error_code(std::errc::io_error), 0};
                co_return nex::capy::results<std::size_t>{std::error_code{}, buf.size()};
            }
            auto close_output_some() -> nex::capy::task<nex::capy::results<std::size_t>> {
                auto ok = co_await lower->close_output();
                co_return nex::capy::results<std::size_t>{ok ? std::error_code{} : std::make_error_code(std::errc::io_error), 0};
            }
            auto cancel() noexcept -> void { lower->cancel(); }
        };

        enum class Carrier { tcp, fast_open, detour };
        template<Carrier Mode>
        class StlsTunnel {
            using FastSocket=net::ByteStreamAdapter<net::FastOpenStream>;
            using Socket=std::conditional_t<Mode==Carrier::detour,LowerSocket,
                std::conditional_t<Mode==Carrier::fast_open,FastSocket,io::tcp_socket>>;
            Session& session_;
            io::io_context& context_;
            StlsProfile const& profile_;
            TcpSocketOptions const& physical_options_;
            bool relay_local_;
            DnsSlot dns_;
            LowerConnector lower_;
            std::unique_ptr<net::FastOpenStream> fast_stream_;
            std::optional<Socket> socket_;
            std::unique_ptr<shadowtls::VerifiedSocket<Socket>> stream_;
            bool ready_ = false;
            bool canceled_ = false;

            auto start(Clock::time_point deadline) -> capy::task<TunnelConnectResult> {
                if (canceled_ || session_.closed || Clock::now() >= deadline)
                    co_return Clock::now() >= deadline ? TunnelConnectResult::timeout : TunnelConnectResult::failed;
                if constexpr (Mode==Carrier::detour) {
                    typename LowerConnector::Candidates candidates;
                    auto connected = co_await lower_.connect(session_, deadline, candidates);
                    if (connected != TunnelConnectResult::connected || canceled_ || session_.closed)
                        co_return connected;
                    socket_.emplace(LowerSocket{lower_.tunnel});
                } else {
                    auto eps = profile_.bootstrap
                        ? co_await resolve_bootstrap_owned(session_, context_, dns_, *profile_.bootstrap, profile_.host, profile_.port, deadline)
                        : co_await resolve_local_owned(session_, context_, dns_, profile_.host, profile_.port, deadline);
                    if (canceled_ || session_.closed) co_return TunnelConnectResult::failed;
                    if (!eps || eps->empty())
                        co_return Clock::now() >= deadline ? TunnelConnectResult::timeout : TunnelConnectResult::retryable;
                    if constexpr (Mode==Carrier::fast_open) {
                        fast_stream_=std::make_unique<net::FastOpenStream>(context_,std::move(*eps),deadline,physical_options_);
                        socket_.emplace(*fast_stream_);
                    } else {
                        socket_.emplace(context_);
                        bool preparation_failed=false;
                        auto connect=net::connect_tcp_candidates(*socket_,std::span(*eps),
                            [](auto const&,auto const& endpoint) {return valid_destination(endpoint);},
                            physical_options_,preparation_failed,deadline);
                        auto [error,selected]=co_await io::timeout(std::move(connect),deadline);
                        (void)selected;
                        if (canceled_ || session_.closed) co_return TunnelConnectResult::failed;
                        if (error) {
                            if (nex::capy::is_timeout(error) || Clock::now()>=deadline)
                                co_return TunnelConnectResult::timeout;
                            co_return preparation_failed ? TunnelConnectResult::failed : TunnelConnectResult::retryable;
                        }
                    }
                }
                auto now_sec = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
                auto hs = co_await shadowtls::handshake_client(
                    *socket_, profile_.tls, profile_.fingerprint, profile_.password,
                    deadline, now_sec, profile_.strict_tls13);
                if (!hs || canceled_ || session_.closed) {
                    cancel();
                    co_return Clock::now() >= deadline ? TunnelConnectResult::timeout : TunnelConnectResult::failed;
                }
                stream_ = std::make_unique<shadowtls::VerifiedSocket<Socket>>(
                    *socket_, std::move(hs->stream), std::move(hs->unread_wire));
                ready_ = true;
                co_return TunnelConnectResult::connected;
            }

        public:
            StlsTunnel(Session& s, io::io_context& ctx, StlsProfile const& p,
                TcpSocketOptions const& options, bool relay_local) requires (Mode!=Carrier::detour)
                : session_(s), context_(ctx), profile_(p), physical_options_(options), relay_local_(relay_local) {}
            StlsTunnel(Session& s, io::io_context& ctx, TunnelFactory const& detour, StlsProfile const& p, bool relay_local) requires (Mode==Carrier::detour)
                : session_(s), context_(ctx), profile_(p), physical_options_(p.options), relay_local_(relay_local),
                  lower_{{}, &ctx, &detour, p.host, p.port, p.bootstrap} {}

            auto cancel() noexcept -> void {
                canceled_ = true;
                dns_.cancel();
                if (stream_) stream_->cancel();
                else if (socket_) socket_->cancel();
                else lower_.cancel();
            }
            auto connect(io::endpoint) -> capy::task<TunnelConnectResult> {
                co_return co_await start(session_.started + std::chrono::milliseconds(profile_.timeout_ms));
            }
            auto connect_until(io::endpoint, Clock::time_point deadline) -> capy::task<TunnelConnectResult> {
                co_return co_await start(deadline);
            }
            auto packet_transport() const noexcept -> net::PacketTransport { return {}; }
            auto connect_packets(Clock::time_point) -> capy::task<TunnelConnectResult> { co_return TunnelConnectResult::failed; }
            auto has_uot() const noexcept -> bool { return false; }
            auto connect_uot() -> capy::task<TunnelConnectResult> { co_return TunnelConnectResult::failed; }
            auto connect_uot_until(Clock::time_point) -> capy::task<TunnelConnectResult> { co_return TunnelConnectResult::failed; }
            auto has_xudp() const noexcept -> bool { return false; }
            auto connect_xudp() -> capy::task<TunnelConnectResult> { co_return TunnelConnectResult::failed; }
            auto connect_xudp_until(Clock::time_point) -> capy::task<TunnelConnectResult> { co_return TunnelConnectResult::failed; }
            auto send(std::span<std::uint8_t const> bytes) -> capy::task<bool> {
                if (!ready_ || !stream_) co_return false;
                auto ok = co_await stream_->send(bytes);
                if (ok) session_.touched = Clock::now();
                co_return ok;
            }
            auto read(std::span<std::uint8_t> bytes) -> capy::task<std::expected<std::size_t, std::string>> {
                if (!ready_ || !stream_) co_return std::unexpected("ShadowTLS closed");
                auto n = co_await stream_->read(bytes);
                if (n && *n) session_.touched = Clock::now();
                co_return n;
            }
            auto close_output() -> capy::task<bool> {
                if (!ready_ || !stream_) co_return false;
                co_return co_await stream_->close_output();
            }
            auto upload() -> capy::task<bool> {
                if (!ready_ || !stream_) co_return false;
                co_return co_await net::stream_relay::upload(net::ByteRelayAdapter{
                    session_.client, *stream_, [this] { session_.touched = Clock::now(); }, relay_local_, session_.traffic_delivery()});
            }
            auto download() -> capy::task<bool> {
                if (!ready_ || !stream_) co_return false;
                co_return co_await net::stream_relay::download(net::ByteRelayAdapter{
                    session_.client, *stream_, [this] { session_.touched = Clock::now(); }, relay_local_, session_.traffic_delivery()});
            }
        };
    }

    auto make_shadowtls_factory(std::string_view host, std::uint16_t port, std::string_view password_file,
        std::string_view server_name, std::string_view ca_file, TlsKeyExchange exchange,
        std::optional<std::size_t> bootstrap, std::uint32_t timeout_ms, TcpSocketOptions options,
        TlsFingerprint fingerprint, bool strict_tls13, std::span<std::array<std::uint8_t,32> const> pins) -> std::expected<TunnelFactory, std::string> {
        if (host.empty() || host.size() > 253 || !port || !timeout_ms || timeout_ms > 3600000 || !options.valid())
            return std::unexpected("invalid ShadowTLS outbound options");
        auto pass = rulefile::read_password_file(password_file);
        if (!pass || pass->empty()) return std::unexpected("invalid ShadowTLS password-file");
        auto tls = tls::ClientProfile::load(
            server_name, ca_file, exchange == TlsKeyExchange::x25519 ? 0x001d : 0x11ec,
            exchange == TlsKeyExchange::x25519_mlkem768_only);
        if (!tls) return std::unexpected(tls.error());
        tls->certificate_pins.assign(pins.begin(), pins.end());
        auto fp = tls::parse_fingerprint(config::tls_fingerprint_name(fingerprint));
        if (!fp) return std::unexpected("invalid ShadowTLS TLS fingerprint");
        auto profile = std::make_unique<StlsProfile>(
            std::string(host), port, std::move(*pass), std::move(*tls), *fp, bootstrap, timeout_ms, options, strict_tls13);
        auto* borrowed = profile.get();
        return TunnelFactory{
            [profile = std::move(profile)](Session& s, io::io_context& ctx, bool relay_local, TcpSocketOptions const* inherited) -> pro::proxy<TunnelFacade> {
                auto const& physical = inherited ? *inherited : profile->options;
                if (physical.tcp_fast_open.value_or(false))
                    return pro::make_proxy<TunnelFacade, StlsTunnel<Carrier::fast_open>>(s,ctx,*profile,physical,relay_local);
                return pro::make_proxy<TunnelFacade, StlsTunnel<Carrier::tcp>>(s,ctx,*profile,physical,relay_local);
            },
            timeout_ms,
            [borrowed](Session& s, io::io_context& ctx, TunnelFactory const& detour, bool relay_local) -> pro::proxy<TunnelFacade> {
                return pro::make_proxy<TunnelFacade, StlsTunnel<Carrier::detour>>(s, ctx, detour, *borrowed, relay_local);
            },
            std::nullopt, options.configured()};
    }
}
