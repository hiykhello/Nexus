module relay:xhttp_http1_dial;
import std;
import config;
import net.tcp_connect;
import platform.ip_address;
import platform.socket_options;
import tls.connector;
import tls.corosio_application;
import tls.fingerprint;
import tls.profiles;
import vless;
import vless.client_profile;
import xhttp.config;
import capy;
import corosio;
import :types;
import :route_interface;
import :session_interface;
import :internal_decls;
import :xhttp_http1;

namespace relay::vless_xhttp {
    struct Peer {
        std::string host;
        std::uint16_t port;
        xhttp::Endpoint endpoint;
        std::optional<tls::ShapedClientProfile> tls;
        std::optional<vless::detail::ClientProfile> reality;
        auto secure() const noexcept -> bool { return tls.has_value() || reality.has_value(); }
        auto handshake(std::uint64_t now, std::uint64_t until, std::int64_t time,
            std::span<std::uint8_t const> target = {}) const {
            std::array<std::string_view, 1> alpn{endpoint.version == xhttp::HttpVersion::http2 ? "h2" : "http/1.1"};
            return reality ? reality->handshake(now, until, time, alpn) : tls->handshake(now, until, time, target);
        }
    };

    struct Profile {
        Peer up;
        std::optional<Peer> down;
        xhttp::Profile transport;
        vless::UserId user;
        std::optional<std::size_t> bootstrap;
        std::uint32_t timeout;
        TcpSocketOptions options;
    };

    class CarrierDns {
        std::optional<std::string> inbound_, user_, interface_;
    public:
        Session session;
        CarrierDns(Session const& original, corosio::io_context& context) : session(context) {
            session.dns = original.dns;
            session.local_dns = original.local_dns;
            session.route_snapshot = original.route_snapshot;
            session.dns_transport_override = original.dns_transport_override;
            if (original.inbound) session.inbound = inbound_.emplace(*original.inbound);
            if (original.auth_user) session.auth_user = user_.emplace(*original.auth_user);
            if (original.source_interface) session.source_interface = interface_.emplace(*original.source_interface);
        }
    };

    struct Resolver {
        Session& session;
        corosio::io_context& context;
        Peer const& peer;
        std::optional<std::size_t> bootstrap;
        DnsSlot slot;
        std::optional<corosio::endpoint>* connected_peer = nullptr;
        auto operator()(Clock::time_point deadline) -> capy::task<std::optional<std::vector<corosio::endpoint>>> {
            if (bootstrap) return resolve_bootstrap_owned(session, context, slot, *bootstrap, peer.host, peer.port, deadline);
            return resolve_local_owned(session, context, slot, peer.host, peer.port, deadline);
        }
        auto cancel() noexcept -> void { slot.cancel(); }
        auto connected(corosio::endpoint const& endpoint) noexcept -> void {
            session.record_physical_peer(endpoint);
            if (connected_peer) *connected_peer = endpoint;
        }
    };

    class Connection {
        using Tls = tls::detail::PhysicalConnector<Resolver, Peer>;
        Socket socket_;
        Resolver resolver_;
        std::optional<Tls> tls_;
        TcpSocketOptions options_;
        xhttp::HttpVersion version_;
        bool reality_;
    public:
        std::optional<corosio::endpoint> connected_peer;
        Lower stream;
        Connection(Session& session, corosio::io_context& context, Peer const& peer,
                   std::optional<std::size_t> bootstrap, TcpSocketOptions const& options)
            : socket_(context), resolver_{session, context, peer, bootstrap}, options_(options), version_(peer.endpoint.version),
              reality_(peer.reality.has_value()), stream(socket_) {
            if (peer.secure()) tls_.emplace(context, Resolver{session, context, peer, bootstrap, {}, &connected_peer}, peer, options_);
        }
        auto connect(Clock::time_point deadline) -> capy::task<bool> {
            if (tls_) {
                if (co_await tls_->start(deadline) != tls::detail::ConnectResult::connected) co_return false;
                auto negotiated = tls_->negotiated();
                if (!negotiated) co_return false;
                if (version_ == xhttp::HttpVersion::http2) {
                    // Xray's REALITY listener starts HTTP/2 without an ALPN selection.
                    if (negotiated->alpn) {
                        if (!std::ranges::equal(*negotiated->alpn, std::string_view("h2"))) co_return false;
                    } else if (!reality_) co_return false;
                } else if (negotiated->alpn && !std::ranges::equal(*negotiated->alpn, std::string_view("http/1.1")))
                    co_return false;
                stream.attach(*tls_->application());
                co_return true;
            }
            auto endpoints = co_await resolver_(deadline);
            if (!endpoints || endpoints->empty()) co_return false;
            bool preparation_failed = false;
            auto condition = [](std::error_code const&, corosio::endpoint const& endpoint) { return valid_destination(endpoint); };
            auto [error, endpoint] = co_await corosio::timeout(
                net::connect_tcp_candidates(socket_, std::move(*endpoints), condition, options_, preparation_failed, deadline), deadline);
            if (!error) {
                connected_peer = endpoint;
                resolver_.connected(endpoint);
            }
            co_return !error;
        }
        auto cancel() noexcept -> void {
            resolver_.cancel();
            if (tls_) tls_->cancel();
            stream.cancel();
        }
    };

    inline auto make_peer(std::string_view host, std::uint16_t port, xhttp::Endpoint endpoint, std::string_view server_name,
            std::string_view ca, TlsKeyExchange exchange, TlsFingerprint fingerprint, std::optional<std::uint16_t> record_size,
            std::optional<Reality> reality = {}, std::span<std::array<std::uint8_t, 32> const> pins = {})
        -> std::expected<Peer, std::string> {
        if (endpoint.authority.empty()) {
            endpoint.authority = server_name.empty() ? host : server_name;
            if (auto ip = platform::parse_ip_address(endpoint.authority); ip && ip->size == 16)
                endpoint.authority = "[" + endpoint.authority + "]";
        }
        Peer peer{std::string(host), port, std::move(endpoint), {}, {}};
        if (reality) {
            if (server_name.empty() || !ca.empty() || peer.endpoint.version == xhttp::HttpVersion::http3)
                return std::unexpected("XHTTP Reality requires a TCP endpoint, an SNI name and no CA file");
            auto& profile = peer.reality.emplace();
            profile.server_name = server_name;
            profile.key_exchange = static_cast<config::TlsKeyExchange>(exchange);
            profile.reality = config::VlessOutbound::Reality{reality->public_key, reality->short_id};
            profile.fingerprint = fingerprint;
            profile.record_size_limit = record_size;
            if (auto checked = peer.handshake(0, 1, 0); !checked) return std::unexpected(checked.error());
            return peer;
        }
        if (server_name.empty()) return peer;
        std::array<std::string_view, 1> alpn{peer.endpoint.version == xhttp::HttpVersion::http3 ? "h3" :
            peer.endpoint.version == xhttp::HttpVersion::http2 ? "h2" : "http/1.1"};
        auto certificate = tls::ClientProfile::load(server_name, ca, exchange == TlsKeyExchange::x25519 ? 0x001d : 0x11ec,
            exchange == TlsKeyExchange::x25519_mlkem768_only, alpn);
        if (!certificate) return std::unexpected(certificate.error());
        certificate->certificate_pins.assign(pins.begin(), pins.end());
        auto shape = tls::parse_fingerprint(config::tls_fingerprint_name(fingerprint));
        if (!shape) return std::unexpected("invalid XHTTP TLS fingerprint");
        auto shaped = tls::ShapedClientProfile::create(std::move(*certificate), *shape, record_size);
        if (!shaped) return std::unexpected(shaped.error());
        peer.tls.emplace(std::move(*shaped));
        return peer;
    }
}
