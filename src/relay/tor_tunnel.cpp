module;
#include <proxy/proxy_macros.h>
module relay;
import std;
import proxy.v4;
import capy;
import corosio;
import config;
import net.datagram_frame;
import net.socket_stream;
import net.stream_relay;
import net.tcp_connect;
import platform.ip_address;
import platform.socket_options;
import relay.tor_outbound;

namespace relay {
    namespace {
        struct TorProfile {
            tor::Config config;
            std::uint32_t timeout_ms = 15000;
            std::atomic<std::uint64_t> stream_seq{0};
            TcpSocketOptions options{};
        };

        auto write_all(net::SocketByteStream<corosio::tcp_socket>& stream, std::span<std::uint8_t const> bytes,
            Clock::time_point deadline) -> capy::task<bool> {
            co_return co_await stream.send(bytes, deadline);
        }

        auto read_exact(net::SocketByteStream<corosio::tcp_socket>& stream, std::span<std::uint8_t> dst,
            Clock::time_point deadline) -> capy::task<bool> {
            while (!dst.empty()) {
                auto n = co_await stream.read(dst, deadline);
                if (!n || *n == 0) co_return false;
                dst = dst.subspan(*n);
            }
            co_return true;
        }

        auto build_connect_ip(corosio::endpoint const& target) -> std::vector<std::uint8_t> {
            std::vector<std::uint8_t> out{0x05, 0x01, 0x00};
            if (target.is_v4()) {
                auto b = target.address().to_v4().to_bytes();
                out.push_back(0x01);
                out.insert(out.end(), b.begin(), b.end());
            } else {
                auto b = target.address().to_v6().to_bytes();
                out.push_back(0x04);
                out.insert(out.end(), b.begin(), b.end());
            }
            out.push_back(static_cast<std::uint8_t>((target.port() >> 8) & 0xff));
            out.push_back(static_cast<std::uint8_t>(target.port() & 0xff));
            return out;
        }

        class TorTunnel {
            Session& session_;
            corosio::io_context& context_;
            TorProfile& profile_;
            bool relay_local_;
            DnsSlot dns_;
            std::optional<corosio::tcp_socket> socket_;
            std::optional<net::SocketByteStream<corosio::tcp_socket>> stream_;
            bool starting_ = false, ready_ = false, canceled_ = false;

            auto resolve_socks(Clock::time_point deadline) -> capy::task<std::optional<std::vector<corosio::endpoint>>> {
                if (auto ip = platform::parse_ip_address(profile_.config.socks_host)) {
                    std::vector<corosio::endpoint> eps;
                    if (ip->size == 4) {
                        corosio::ipv4_address::bytes_type b{};
                        std::copy_n(ip->bytes.begin(), 4, b.begin());
                        eps.emplace_back(corosio::ipv4_address(b), profile_.config.socks_port);
                    } else {
                        eps.emplace_back(corosio::ipv6_address(ip->bytes), profile_.config.socks_port);
                    }
                    co_return eps;
                }
                co_return co_await resolve_local_owned(session_, context_, dns_,
                    profile_.config.socks_host, profile_.config.socks_port, deadline);
            }

        public:
            TorTunnel(Session& session, corosio::io_context& context, TorProfile& profile, bool relay_local) noexcept
                : session_(session), context_(context), profile_(profile), relay_local_(relay_local) {}

            auto connect(corosio::endpoint target) -> capy::task<TunnelConnectResult> {
                return connect_until(target, session_.started + std::chrono::milliseconds(profile_.timeout_ms));
            }

            auto connect_domain(std::string_view domain, std::uint16_t port, Clock::time_point deadline)
                -> capy::task<TunnelConnectResult> {
                co_return co_await connect_until(corosio::endpoint(corosio::ipv4_address{}, port), deadline, domain);
            }

            auto connect_until(corosio::endpoint target, Clock::time_point deadline, std::string_view domain = {})
                -> capy::task<TunnelConnectResult> {
                if ((domain.empty() && !valid_destination(target)) || starting_ || ready_ || canceled_ || session_.closed)
                    co_return TunnelConnectResult::failed;
                if (Clock::now() >= deadline) co_return TunnelConnectResult::timeout;
                starting_ = true;
                struct Guard {
                    TorTunnel& t;
                    ~Guard() { t.starting_ = false; if (!t.ready_) t.cancel(); }
                } guard{*this};

                auto eps = co_await resolve_socks(deadline);
                if (canceled_ || session_.closed) co_return TunnelConnectResult::failed;
                if (Clock::now() >= deadline) co_return TunnelConnectResult::timeout;
                if (!eps || eps->empty()) co_return TunnelConnectResult::retryable;

                socket_.emplace(context_);
                bool prep_fail = false;
                auto op = net::connect_tcp_candidates(*socket_, std::span(*eps),
                    [](auto const&, auto const&) { return true; }, profile_.options, prep_fail, deadline);
                auto [ce, sel] = co_await corosio::timeout(std::move(op), deadline);
                (void)sel;
                if (ce) {
                    if (capy::is_timeout(ce) || Clock::now() >= deadline) co_return TunnelConnectResult::timeout;
                    co_return prep_fail ? TunnelConnectResult::failed : TunnelConnectResult::retryable;
                }
                stream_.emplace(*socket_);

                // 1. SOCKS5 greeting (request RFC 1929 auth when isolate_streams enabled).
                auto greeting = tor::build_socks5_greeting(profile_.config.isolate_streams);
                if (!co_await write_all(*stream_, greeting, deadline)) co_return TunnelConnectResult::failed;
                std::array<std::uint8_t, 2> choice{};
                if (!co_await read_exact(*stream_, choice, deadline) || choice[0] != 0x05)
                    co_return TunnelConnectResult::failed;
                if (choice[1] == 0x02) {
                    if (!profile_.config.isolate_streams) co_return TunnelConnectResult::failed;
                    auto seq = profile_.stream_seq.fetch_add(1, std::memory_order_relaxed) + 1;
                    auto user = std::format("nexus-iso-{}", seq);
                    auto pass = std::format("stream-{}", seq ^ 0x9e3779b97f4a7c15ull);
                    auto auth = tor::build_socks5_isolation_auth(user, pass);
                    if (!auth || !co_await write_all(*stream_, *auth, deadline)) co_return TunnelConnectResult::failed;
                    std::array<std::uint8_t, 2> arep{};
                    if (!co_await read_exact(*stream_, arep, deadline) || arep[0] != 0x01 || arep[1] != 0x00)
                        co_return TunnelConnectResult::failed;
                } else if (choice[1] != 0x00) {
                    co_return TunnelConnectResult::failed;
                }

                // 2. SOCKS5 CONNECT (DOMAINNAME for hostnames/.onion to prevent DNS leaks).
                std::vector<std::uint8_t> req;
                if (!domain.empty()) {
                    auto built = tor::build_socks5_connect_domain(domain, target.port());
                    if (!built) co_return TunnelConnectResult::failed;
                    req = std::move(*built);
                } else {
                    req = build_connect_ip(target);
                }
                if (!co_await write_all(*stream_, req, deadline)) co_return TunnelConnectResult::failed;

                std::array<std::uint8_t, 4> hdr{};
                if (!co_await read_exact(*stream_, hdr, deadline) || hdr[0] != 0x05 || hdr[1] != 0x00)
                    co_return TunnelConnectResult::failed;
                std::size_t skip = 0;
                if (hdr[3] == 0x01) skip = 6;
                else if (hdr[3] == 0x04) skip = 18;
                else if (hdr[3] == 0x03) {
                    std::uint8_t dlen = 0;
                    if (!co_await read_exact(*stream_, {&dlen, 1}, deadline)) co_return TunnelConnectResult::failed;
                    skip = static_cast<std::size_t>(dlen) + 2;
                } else {
                    co_return TunnelConnectResult::failed;
                }
                std::array<std::uint8_t, 260> discard{};
                if (skip > discard.size() || !co_await read_exact(*stream_, std::span(discard).first(skip), deadline))
                    co_return TunnelConnectResult::failed;
                if (canceled_ || session_.closed) co_return TunnelConnectResult::failed;
                ready_ = true;
                co_return TunnelConnectResult::connected;
            }

            auto cancel() noexcept -> void {
                canceled_ = true;
                dns_.cancel();
                if (stream_) stream_->cancel();
                else if (socket_) socket_->cancel();
            }

            auto send(std::span<std::uint8_t const> bytes) -> capy::task<bool> {
                if (!ready_ || canceled_) co_return false;
                auto ok = co_await stream_->send(bytes);
                if (ok) session_.touched = Clock::now();
                co_return ok;
            }

            auto read(std::span<std::uint8_t> bytes) -> capy::task<std::expected<std::size_t, std::string>> {
                if (!ready_ || canceled_) co_return std::unexpected("Tor stream closed");
                auto n = co_await stream_->read(bytes);
                if (!n) co_return std::unexpected("Tor stream read failed");
                if (*n) session_.touched = Clock::now();
                co_return *n;
            }

            auto close_output() -> capy::task<bool> {
                if (!ready_ || canceled_) co_return false;
                co_return co_await stream_->close_output();
            }

            auto upload() -> capy::task<bool> {
                return net::stream_relay::upload(net::ByteRelayAdapter{session_.client, *this,
                    [this] { session_.touched = Clock::now(); }, relay_local_, session_.traffic_delivery()});
            }

            auto download() -> capy::task<bool> {
                return net::stream_relay::download(net::ByteRelayAdapter{session_.client, *this,
                    [this] { session_.touched = Clock::now(); }, relay_local_, session_.traffic_delivery()});
            }

            auto packet_transport() const noexcept -> net::PacketTransport { return {}; }
            auto connect_packets(Clock::time_point) -> capy::task<TunnelConnectResult> { co_return TunnelConnectResult::failed; }
            auto has_uot() const noexcept -> bool { return false; }
            auto connect_uot() -> capy::task<TunnelConnectResult> { co_return TunnelConnectResult::failed; }
            auto connect_uot_until(Clock::time_point) -> capy::task<TunnelConnectResult> { co_return TunnelConnectResult::failed; }
            auto has_xudp() const noexcept -> bool { return false; }
            auto connect_xudp() -> capy::task<TunnelConnectResult> { co_return TunnelConnectResult::failed; }
            auto connect_xudp_until(Clock::time_point) -> capy::task<TunnelConnectResult> { co_return TunnelConnectResult::failed; }
        };
    }

    auto make_tor_factory(config::TorServiceConfig const& cfg, std::uint32_t timeout_ms)
        -> std::expected<TunnelFactory, std::string> {
        tor::Config tc{
            .socks_host = cfg.socks_host,
            .socks_port = cfg.socks_port,
            .control_host = cfg.control_host,
            .control_port = cfg.control_port,
            .control_password = cfg.control_password,
            .cookie_hex = cfg.cookie_hex,
            .isolate_streams = cfg.isolate_streams,
            .allow_remote_socks = cfg.allow_remote_socks,
        };
        if (auto ok = tor::validate_config(tc); !ok) return std::unexpected(std::move(ok.error()));
        if (!timeout_ms || timeout_ms > 3600000) return std::unexpected("invalid Tor outbound timeout");
        auto profile = std::make_shared<TorProfile>();
        profile->config = std::move(tc);
        profile->timeout_ms = timeout_ms;
        TunnelFactory factory{
            [profile = std::move(profile)](Session& session, corosio::io_context& context, bool relay_local,
                TcpSocketOptions const*) -> pro::proxy<TunnelFacade> {
                return pro::make_proxy<TunnelFacade, TorTunnel>(session, context, *profile, relay_local);
            },
            timeout_ms};
        factory.remote_domain_dial = true;
        return factory;
    }
}
