module;
#include <boost/corosio/socket_option.hpp>
#include <netinet/in.h>

module proxy;
import std;
import proxy.v4;
import config;
import crypto;
import naive.padding;
import naive.h2_connect;
import naive.h2_server;
import naive.h3_connect;
import http.connect;
import http.header;
import http2.headers;
import http2.client_types;
import http2.server_streams;
import http2.driver;
import tls.profiles;
import tls.server_credential;
import tls.server_handshake_io;
import tls.corosio_server_handshake;
import tls.corosio_application;
import tls.byte_stream;
import quic.cid_registry;
import quic.native_memory;
import quic.datagram_port;
import quic.datagram_session;
import quic.retry_admission;
import quic.retry_token;
import quic.tls_server;
import net.datagram_driver;
import net.datagram_frame;
import net.udp_connect;
import hysteria2.transport_options;
import masque.session;
import masque.datagram;
import masque.target;
import platform.ip_address;
import rulefile;
import rules;
import socks5;
import sniff.tcp;
import sniff.tcp_io;
import sniff.route_tcp;
import uot;
import proxy.stream_relay;
import nexus.thirdparty.nghttp3;
import nexus.thirdparty.ngtcp2;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;

#include "modern_h3_inbound.hpp"

namespace proxy::naive_in_detail {
    namespace {
        struct NaiveH2Profile {
            tls::ServerCredential credential;
            std::vector<naive::UserCredential> users;
            bool padding = true;
            std::uint16_t fallback_status = 404;
            std::uint32_t handshake_timeout_ms = 10000;
        };

        auto serve_h1_decoy(tls::detail::ByteStream<nex::corosio::tcp_socket>& stream, std::uint16_t status,
                            Clock::time_point until) -> nex::capy::task<> {
            std::array<std::uint8_t, 4096> buf{};
            std::string req;
            while (req.size() < 4096) {
                auto n = co_await stream.read(buf, until);
                if (!n || !*n) break;
                req.append(reinterpret_cast<char const*>(buf.data()), *n);
                if (req.contains("\r\n\r\n")) break;
            }
            auto body = naive::decoy_html_body(status);
            std::string resp = std::format(
                "HTTP/1.1 {} {}\r\nServer: nginx\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                status, status == 200 ? "OK" : "Not Found", body.size(), body);
            (void)co_await stream.send({reinterpret_cast<std::uint8_t const*>(resp.data()), resp.size()}, until);
            (void)co_await stream.send({}, until);
        }

        auto handle_h2_stream(Session& parent, nex::corosio::io_context& context, rules::RouteMatcher const& policy,
                              NaiveH2Profile const& profile, naive::H2ServerStream<tls::detail::ByteStream<nex::corosio::tcp_socket>>& stream)
            -> nex::capy::task<> {
            auto until = Clock::now() + std::chrono::seconds(10);
            auto info = stream.inspect();
            if (!info || info->failure) co_return;
            std::string method, authority, auth_hdr, pad_req;
            for (auto const& h : info->headers) {
                if (h.name == ":method") method = h.value;
                else if (h.name == ":authority") authority = h.value;
                else if (naive::header_ci_equal(h.name, "proxy-authorization")) auth_hdr = h.value;
                else if (naive::header_ci_equal(h.name, "padding-type-request")) pad_req = h.value;
            }
            auto matched_user = naive::verify_basic_auth(auth_hdr, profile.users);
            if (method != "CONNECT" || !matched_user) {
                (void)co_await stream.respond_decoy(profile.fallback_status, until);
                co_return;
            }
            auto dst = naive::parse_connect_authority(authority);
            if (!dst) {
                (void)co_await stream.respond_decoy(profile.fallback_status, until);
                co_return;
            }
            bool pad_on = profile.padding && naive::parse_padding_type_request(pad_req);
            auto lease = parent.quota ? parent.quota->try_acquire() : std::nullopt;
            if (parent.quota && !lease) {
                (void)co_await stream.respond_decoy(profile.fallback_status, until);
                co_return;
            }
            Session child(context);
            child.quota = std::move(lease);
            child.auth_user = *matched_user;
            init_naive_child(child, parent, until);
            if (!child.admit_principal_child(parent)) {
                (void)co_await stream.respond_decoy(profile.fallback_status, until);
                co_return;
            }
            child.begin_traffic(TrafficProtocol::naive, dst->port);
            if (!child.ordered_tcp) {
                if (co_await dial_naive_target(child, context, policy, *dst, stream) != 0 || child.closed) {
                    (void)co_await stream.respond_decoy(profile.fallback_status, until);
                    co_return;
                }
            }
            std::string pad_hdr = pad_on ? naive::generate_padding_header() : std::string{};
            if (pad_on) {
                std::array<http2::FieldView, 3> ok{
                    http2::FieldView{":status", "200"},
                    http2::FieldView{"padding", pad_hdr},
                    http2::FieldView{"padding-type-reply", "1"},
                };
                if (!stream.respond(ok, false)) co_return;
            } else {
                std::array<http2::FieldView, 1> ok{http2::FieldView{":status", "200"}};
                if (!stream.respond(ok, false)) co_return;
            }
            stream.arm_padding(pad_on);
            if (child.ordered_tcp) {
                if (co_await dial_naive_target(child, context, policy, *dst, stream) != 0 || child.closed) co_return;
            }
            child.relaying = true;
            child.touched = parent.touched = Clock::now();
            std::stop_callback sc(parent.stop.get_token(), [&]() noexcept { child.close(); stream.cancel(); });
            auto watch = [&]() -> nex::capy::task<nex::capy::results<>> {
                while (!child.closed && !stream.failure() && co_await stream.wait()) {}
                child.close();
                co_return nex::capy::results<>{};
            };
            (void)co_await nex::capy::when_all(
                watch(),
                stream_relay::direction(child, stream_relay::upload(child, stream)),
                stream_relay::direction(child, stream_relay::download(child, stream)));
        }

        auto serve_naive_h2(Session& session, nex::corosio::io_context& context, rules::RouteMatcher const& policy,
                            NaiveH2Profile const& profile) -> nex::capy::task<> {
            struct Done { Session& s; ~Done() { s.close(); s.done = true; } } done{session};
            auto ms = [](Clock::time_point t) {
                return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(t.time_since_epoch()).count());
            };
            auto deadline = session.started + std::chrono::milliseconds(profile.handshake_timeout_ms);
            session.handshake_deadline = std::max(session.handshake_deadline, deadline);
            constexpr std::array<std::string_view, 2> alpn{"h2", "http/1.1"};
            auto hs = tls::make_server_handshake(profile.credential, ms(session.started), ms(deadline), {}, alpn, true);
            if (!hs) co_return;
            auto accepted = co_await tls::detail::server_handshake(session.client, *hs, {});
            if (!accepted || session.closed) co_return;
            auto neg_bytes = hs->negotiated_alpn();
            std::string_view neg(reinterpret_cast<char const*>(neg_bytes.data()), neg_bytes.size());
            tls::detail::ApplicationConnection<nex::corosio::tcp_socket> app(session.client, std::move(accepted->records), std::move(accepted->unread));
            tls::detail::ByteStream<nex::corosio::tcp_socket> tls_stream(app);
            if (neg != "h2") {
                co_await serve_h1_decoy(tls_stream, profile.fallback_status, Clock::now() + std::chrono::seconds(10));
                co_return;
            }
            auto limits = naive::make_h2_limits();
            limits.header_bytes = http::max_header_bytes;
            auto srv = http2::ServerStreams<naive::kH2StreamCapacity>::create(limits);
            if (!srv) co_return;
            naive::H2ServerDriver<tls::detail::ByteStream<nex::corosio::tcp_socket>> driver(tls_stream, std::move(*srv));
            session.relaying = true;
            auto run_drv = [&]() -> nex::capy::task<nex::capy::results<>> {
                auto r = co_await driver.run();
                session.close();
                co_return r;
            };
            auto worker = [&]() -> nex::capy::task<nex::capy::results<>> {
                while (!session.closed) {
                    auto ticket = driver.protocol().accept();
                    if (!ticket) {
                        if (!co_await driver.wait_change()) break;
                        continue;
                    }
                    naive::H2ServerStream<tls::detail::ByteStream<nex::corosio::tcp_socket>> st(driver, *ticket);
                    try { co_await handle_h2_stream(session, context, policy, profile, st); }
                    catch (...) { st.cancel(); }
                }
                co_return nex::capy::results<>{};
            };
            std::vector<nex::capy::task<nex::capy::results<>>> tasks;
            tasks.reserve(17);
            tasks.push_back(run_drv());
            for (unsigned i = 0; i < 16; ++i) tasks.push_back(worker());
            try { (void)co_await nex::capy::when_all(std::move(tasks)); }
            catch (...) { driver.cancel(); }
        }
    }
}

namespace proxy {
    auto make_naive_h2_inbound_factory(config::NaiveInbound const& cfg) -> std::expected<InboundFactory, std::string> {
        auto cred = tls::load_server_credential(cfg.certificate_file, cfg.private_key_file);
        if (!cred) return std::unexpected("NaiveProxy TLS credential: " + cred.error());
        auto users = naive_in_detail::load_naive_users(cfg.users);
        if (!users) return std::unexpected(users.error());
        auto profile = std::make_unique<naive_in_detail::NaiveH2Profile>(
            naive_in_detail::NaiveH2Profile{std::move(*cred), std::move(*users), cfg.padding, cfg.fallback_status, cfg.handshake_timeout_ms});
        return InboundFactory{[profile = std::move(profile)](Session& s, nex::corosio::io_context& ctx, rules::RouteMatcher const& policy) {
            return naive_in_detail::serve_naive_h2(s, ctx, policy, *profile);
        }};
    }

    auto Server::prepare_modern_h3_naive(config::NaiveInbound const& cfg) -> std::expected<void, std::string> {
        auto cred = tls::load_server_credential(cfg.certificate_file, cfg.private_key_file);
        if (!cred) return std::unexpected("NaiveProxy H3 TLS credential: " + cred.error());
        auto users = naive_in_detail::load_naive_users(cfg.users);
        if (!users) return std::unexpected(users.error());
        hysteria2::TransportOptions opts{std::chrono::milliseconds(cfg.handshake_timeout_ms),
                                        std::chrono::milliseconds(cfg.idle_timeout_ms), cfg.native_bytes, true};
        if (!opts.valid()) return std::unexpected("invalid NaiveProxy H3 transport options");
        auto* raw = new ModernHttp3Inbound(*this, std::move(*cred), opts, std::move(*users), std::nullopt,
                                         true, cfg.padding, false, cfg.fallback_status);
        modern_h3_inbound = {raw, +[](ModernHttp3Inbound* p) noexcept { delete p; }};
        return {};
    }

    auto Server::prepare_modern_h3_http(config::HttpInbound const& cfg, std::optional<Credentials> const& creds)
        -> std::expected<void, std::string> {
        auto cred = tls::load_server_credential(cfg.certificate_file, cfg.private_key_file);
        if (!cred) return std::unexpected("HTTP/3 TLS credential: " + cred.error());
        hysteria2::TransportOptions opts{std::chrono::milliseconds(cfg.handshake_timeout_ms),
                                        std::chrono::milliseconds(cfg.idle_timeout_ms), cfg.native_bytes, cfg.connect_udp};
        if (!opts.valid()) return std::unexpected("invalid HTTP/3 transport options");
        auto* raw = new ModernHttp3Inbound(*this, std::move(*cred), opts, {}, creds,
                                         false, false, cfg.connect_udp, 404);
        modern_h3_inbound = {raw, +[](ModernHttp3Inbound* p) noexcept { delete p; }};
        return {};
    }

    auto Server::start_modern_h3(nex::corosio::endpoint ep) -> std::expected<std::uint16_t, std::error_code> {
        if (!modern_h3_inbound || admission) return std::unexpected(std::make_error_code(std::errc::operation_not_supported));
        if (!running) {
            if (auto active = activate_context(); !active) { stop(); return std::unexpected(active.error()); }
        }
        try {
            if (modern_h3_inbound->used_) {
                auto fresh = modern_h3_inbound->clone_fresh();
                if (!fresh) return std::unexpected(std::make_error_code(std::errc::invalid_argument));
                modern_h3_inbound = std::move(fresh);
            }
            auto bound = modern_h3_inbound->start(ep, [this]() { record_failure({FailureKind::accept_task, {}}); });
            if (!bound) { stop(); return std::unexpected(bound.error()); }
            if (!running) {
                bound_listener = *bound;
                accepting = true;
                running = true;
            }
            return bound->port();
        } catch (...) {
            stop();
            throw;
        }
    }

    auto Server::drain_modern_h3() noexcept -> void { if (modern_h3_inbound) modern_h3_inbound->drain(); }
    auto Server::stop_modern_h3() noexcept -> void { if (modern_h3_inbound) modern_h3_inbound->stop(); }
    auto Server::modern_h3_drained() const noexcept -> bool { return !modern_h3_inbound || modern_h3_inbound->drained(); }
}
