// TLS-capable outbound HTTPS and HTTP/2 PING probe implementation.
module relay;
import :probe_h2_wire;
import std;
import capy;
import http.connect;
import http.header;
import net.socket_stream;
import tls.byte_stream;
import tls.client_handshake_io;
import tls.corosio_client;
import tls.profiles;

namespace relay {
    namespace probe_h2_detail {
        template<class TlsSocket>
        auto exchange_tls_h2_ping(
            Session const& session,
            TlsSocket& socket,
            OutboundProbe const& probe) -> capy::task<std::optional<std::uint32_t>> {
            using std::chrono::duration_cast;
            using std::chrono::milliseconds;
            using std::chrono::seconds;
            constexpr std::array<std::string_view, 1> kAlpn{"h2"};
            auto profile = tls::ClientProfile::load(
                probe.tls_server_name, probe.tls_ca_file, 0x001d, false, kAlpn);
            if (!profile) co_return std::nullopt;
            auto start = duration_cast<milliseconds>(Clock::now().time_since_epoch()).count();
            auto end = duration_cast<milliseconds>(probe.deadline.time_since_epoch()).count();
            auto verified = duration_cast<seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
            if (start < 0 || end <= start) co_return std::nullopt;
            auto handshake = profile->handshake(
                static_cast<std::uint64_t>(start), static_cast<std::uint64_t>(end), verified);
            if (!handshake) co_return std::nullopt;
            tls::detail::ClientConnection<TlsSocket> client(socket, std::move(*handshake));
            auto authenticated = co_await client.start();
            if (!authenticated || session.closed) co_return std::nullopt;
            auto* application = client.application();
            if (!application) co_return std::nullopt;
            tls::detail::ByteStream<TlsSocket> stream(*application);
            auto write_all = [&](std::span<std::uint8_t const> bytes) -> capy::task<bool> {
                co_return co_await stream.send(bytes);
            };
            auto read_some = [&](std::span<std::uint8_t> out) -> capy::task<std::optional<std::size_t>> {
                auto r = co_await stream.read(out);
                co_return r ? std::optional<std::size_t>{*r} : std::nullopt;
            };
            co_return co_await exchange_h2_ping(session, probe.deadline, write_all, read_some);
        }

        template<class TlsSocket>
        auto exchange_tls_http_probe(
            Session& session,
            TlsSocket& socket,
            OutboundProbe& probe) -> capy::task<bool> {
            using std::chrono::duration_cast;
            using std::chrono::milliseconds;
            using std::chrono::seconds;
            constexpr std::array<std::string_view, 1> kAlpn{"http/1.1"};
            auto profile = tls::ClientProfile::load(
                probe.tls_server_name, probe.tls_ca_file, 0x001d, false, kAlpn);
            if (!profile) co_return false;
            auto start = duration_cast<milliseconds>(Clock::now().time_since_epoch()).count();
            auto end = duration_cast<milliseconds>(probe.deadline.time_since_epoch()).count();
            auto verified = duration_cast<seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
            if (start < 0 || end <= start) co_return false;
            auto handshake = profile->handshake(
                static_cast<std::uint64_t>(start), static_cast<std::uint64_t>(end), verified);
            if (!handshake) co_return false;
            tls::detail::ClientConnection<TlsSocket> client(socket, std::move(*handshake));
            auto authenticated = co_await client.start();
            if (!authenticated || session.closed) co_return false;
            auto* application = client.application();
            if (!application) co_return false;
            tls::detail::ByteStream<TlsSocket> stream(*application);
            if (!co_await stream.send({reinterpret_cast<std::uint8_t const*>(probe.request.data()), probe.request.size()}))
                co_return false;
            http::ResponseDecoder decoder(true, false);
            std::array<std::uint8_t, 1024> buffer{};
            auto status_ok = [&](std::uint16_t code) noexcept -> bool {
                if (probe.expected_status.empty()) return code >= 200 && code < 300;
                return std::ranges::any_of(probe.expected_status, [code](auto const& range) {
                    return code >= range.low && code <= range.high;
                });
            };
            while (!session.closed && Clock::now() < probe.deadline) {
                auto r = co_await stream.read(buffer);
                if (!r || *r == 0 || Clock::now() >= probe.deadline) co_return false;
                auto data = std::string_view(reinterpret_cast<char const*>(buffer.data()), *r);
                while (!data.empty()) {
                    auto step = decoder.feed(data);
                    if (step.event == http::ResponseEvent::header && !step.informational) {
                        probe.status_code.store(step.status_code, std::memory_order_relaxed);
                        co_return status_ok(step.status_code);
                    }
                    if (!step.consumed || step.event == http::ResponseEvent::malformed) co_return false;
                    data.remove_prefix(step.consumed);
                }
            }
            co_return false;
        }
    }

    auto Server::probe_https(Session& session, OutboundProbe& probe) -> capy::task<bool> {
        if (co_await dial_destination(session, context, probe.route, probe.target, probe.deadline)) {
            co_return false;
        }
        session.handshake_deadline = probe.deadline;
        if (session.tunnel) {
            probe_h2_detail::ProxyLowerStream lower{session.tunnel};
            net::ByteStreamAdapter<probe_h2_detail::ProxyLowerStream> adapter(lower);
            co_return co_await probe_h2_detail::exchange_tls_http_probe(session, adapter, probe);
        }
        co_return co_await probe_h2_detail::exchange_tls_http_probe(session, session.target, probe);
    }

    auto Server::probe_h2_ping(Session& session, OutboundProbe& probe)
        -> capy::task<std::optional<std::uint32_t>> {
        if (co_await dial_destination(session, context, probe.route, probe.target, probe.deadline)) {
            co_return std::nullopt;
        }
        session.handshake_deadline = probe.deadline;
        if (probe.use_tls) {
            if (session.tunnel) {
                probe_h2_detail::ProxyLowerStream lower{session.tunnel};
                net::ByteStreamAdapter<probe_h2_detail::ProxyLowerStream> adapter(lower);
                co_return co_await probe_h2_detail::exchange_tls_h2_ping(session, adapter, probe);
            }
            co_return co_await probe_h2_detail::exchange_tls_h2_ping(session, session.target, probe);
        }
        co_return co_await probe_h2_detail::exchange_plain_h2_ping(session, probe);
    }
}
