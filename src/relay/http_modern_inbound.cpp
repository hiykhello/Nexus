module;
#include <string.h>

module relay;
import std;
import proxy.v4;
import config;
import crypto;
import naive.padding;
import naive.h2_connect;
import naive.h2_server;
import http.connect;
import http.header;
import http2.headers;
import http2.client_types;
import http2.server_streams;
import http2.driver;
import tls.profiles;
import tls.server_credential;
import tls.ech_server;
import tls.server_handshake_io;
import tls.corosio_server_handshake;
import tls.corosio_application;
import tls.byte_stream;
import platform.ip_address;
import rulefile;
import rules;
import socks5;
import sniff.tcp;
import sniff.tcp_io;
import sniff.route_tcp;
import relay.stream_relay;
import capy;
import corosio;
import :naive_inbound_helpers;
import :http_modern_h1;

namespace relay::http_modern_detail {
    namespace {
        auto default_port_authority(std::string_view authority, std::string_view scheme) -> std::string {
            if (authority.empty()) return {};
            auto parsed = http::parse_destination_authority(authority);
            if (parsed.status == http::ConnectStatus::accepted) return std::string(authority);
            std::uint16_t p = (scheme == "https") ? 443 : 80;
            if (authority.starts_with('[') && authority.ends_with(']'))
                return std::string(authority) + ":" + std::to_string(p);
            if (!authority.contains(':'))
                return std::string(authority) + ":" + std::to_string(p);
            return std::string(authority);
        }

        auto handle_h2_stream(Session& parent, corosio::io_context& context, rules::RouteMatcher const& policy,
                              HttpModernProfile const& profile,
                              naive::H2ServerStream<tls::detail::ByteStream<corosio::tcp_socket>>& stream) -> capy::task<> {
            auto until = Clock::now() + std::chrono::seconds(10);
            auto info = stream.inspect();
            if (!info || info->failure) co_return;
            std::string method, authority, scheme, path, auth_hdr;
            for (auto const& h : info->headers) {
                if (h.name == ":method") method = h.value;
                else if (h.name == ":authority") authority = h.value;
                else if (h.name == ":scheme") scheme = h.value;
                else if (h.name == ":path") path = h.value;
                else if (naive::header_ci_equal(h.name, "proxy-authorization")) auth_hdr = h.value;
            }
            std::optional<std::string> authed_user;
            if (profile.creds) {
                if (!naive_in_detail::match_basic_single(auth_hdr, *profile.creds)) {
                    (void)co_await stream.respond_407(until);
                    co_return;
                }
                authed_user.emplace(reinterpret_cast<char const*>(profile.creds->username.data()), profile.creds->username_size);
            }
            auto fail_status = [&](std::string_view st) -> capy::task<> {
                std::array<http2::FieldView, 1> err{http2::FieldView{":status", st}};
                if (stream.respond(err, true)) (void)co_await stream.send_raw_chunk({}, true, until);
            };
            bool is_connect = (method == "CONNECT");
            if (!is_connect) authority = default_port_authority(authority, scheme);
            auto dst = naive::parse_connect_authority(authority);
            if (!dst) { co_await fail_status("400"); co_return; }
            auto lease = parent.quota ? parent.quota->try_acquire() : std::nullopt;
            if (parent.quota && !lease) { co_await fail_status("503"); co_return; }
            Session child(context);
            child.quota = std::move(lease);
            if (authed_user) child.auth_user = *authed_user;
            naive_in_detail::init_naive_child(child, parent, until);
            if (!child.admit_principal_child(parent)) { co_await fail_status("403"); co_return; }
            child.begin_traffic(is_connect ? TrafficProtocol::http_connect : TrafficProtocol::http_forward, dst->port);
            auto code = co_await naive_in_detail::dial_naive_target(child, context, policy, *dst, stream);
            if (code != 0 || child.closed) { co_await fail_status(code == 2 ? "403" : "502"); co_return; }
            if (!is_connect) {
                child.relaying = true;
                std::stop_callback sc(parent.stop.get_token(), [&]() noexcept { child.close(); stream.cancel(); });
                co_await forward_h2_request(child, stream, info->headers, method, authority, path, until);
                co_return;
            }
            std::array<http2::FieldView, 1> ok{http2::FieldView{":status", "200"}};
            if (!stream.respond(ok, false)) co_return;
            child.relaying = true;
            child.touched = parent.touched = Clock::now();
            std::stop_callback sc(parent.stop.get_token(), [&]() noexcept { child.close(); stream.cancel(); });
            auto watch = [&]() -> capy::task<capy::results<>> {
                while (!child.closed && !stream.failure() && co_await stream.wait()) {}
                child.close();
                co_return capy::results<>{};
            };
            (void)co_await capy::when_all(
                watch(),
                stream_relay::direction(child, stream_relay::upload(child, stream)),
                stream_relay::direction(child, stream_relay::download(child, stream)));
        }

        auto serve_http_modern(Session& session, corosio::io_context& context, rules::RouteMatcher const& policy,
                               HttpModernProfile const& profile) -> capy::task<> {
            struct Done { Session& s; ~Done() { s.close(); s.done = true; } } done{session};
            auto ms = [](Clock::time_point t) {
                return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(t.time_since_epoch()).count());
            };
            auto deadline = session.started + std::chrono::milliseconds(profile.handshake_timeout_ms);
            session.handshake_deadline = std::max(session.handshake_deadline, deadline);
            std::optional<tls::ServerCredential> dyn_cred;
            tls::ServerCredential const* active_cred = nullptr;
            if (profile.atomic_credential) {
                auto cur = profile.atomic_credential->clone_current();
                if (!cur) co_return;
                dyn_cred.emplace(std::move(*cur));
                active_cred = &*dyn_cred;
            } else if (profile.credential) {
                active_cred = &*profile.credential;
            } else {
                co_return;
            }
            std::array<std::string_view, 2> both{"h2", "http/1.1"};
            std::array<std::string_view, 1> h1only{"http/1.1"};
            std::vector<std::string_view> custom_alpn;
            auto prefs = profile.http2 ? std::span<std::string_view const>(both) : std::span<std::string_view const>(h1only);
            if (!profile.alpn.empty()) {
                custom_alpn.reserve(profile.alpn.size());
                for (auto const& p : profile.alpn) custom_alpn.push_back(p);
                prefs = custom_alpn;
            }
            auto hs = tls::make_server_handshake(*active_cred, ms(session.started), ms(deadline), {}, prefs, true, profile.ech_keys);
            if (!hs) co_return;
            auto accepted = co_await tls::detail::server_handshake(session.client, *hs, {});
            if (!accepted || session.closed) co_return;
            auto neg_bytes = hs->negotiated_alpn();
            std::string_view neg(reinterpret_cast<char const*>(neg_bytes.data()), neg_bytes.size());
            tls::detail::ApplicationConnection<corosio::tcp_socket> app(session.client, std::move(accepted->records), std::move(accepted->unread));
            tls::detail::ByteStream<corosio::tcp_socket> tls_stream(app);
            if (neg != "h2") {
                co_await serve_h1_tls(session, context, policy, profile, tls_stream);
                co_return;
            }
            auto limits = naive::make_h2_limits();
            limits.header_bytes = http::max_header_bytes;
            auto srv = http2::ServerStreams<naive::kH2StreamCapacity>::create(limits);
            if (!srv) co_return;
            naive::H2ServerDriver<tls::detail::ByteStream<corosio::tcp_socket>> driver(tls_stream, std::move(*srv));
            session.relaying = true;
            auto run_drv = [&]() -> capy::task<capy::results<>> {
                auto r = co_await driver.run();
                session.close();
                co_return r;
            };
            auto worker = [&]() -> capy::task<capy::results<>> {
                while (!session.closed) {
                    auto ticket = driver.protocol().accept();
                    if (!ticket) {
                        if (!co_await driver.wait_change()) break;
                        continue;
                    }
                    naive::H2ServerStream<tls::detail::ByteStream<corosio::tcp_socket>> st(driver, *ticket);
                    try { co_await handle_h2_stream(session, context, policy, profile, st); }
                    catch (...) { st.cancel(); }
                }
                co_return capy::results<>{};
            };
            std::vector<capy::task<capy::results<>>> tasks;
            tasks.reserve(17);
            tasks.push_back(run_drv());
            for (unsigned i = 0; i < 16; ++i) tasks.push_back(worker());
            try { (void)co_await capy::when_all(std::move(tasks)); }
            catch (...) { driver.cancel(); }
        }
    }
}

namespace relay {
    auto make_http_modern_inbound_factory(config::HttpInbound const& cfg, std::optional<Credentials> const& creds, InboundTlsRuntime const& tls_rt)
        -> std::expected<InboundFactory, std::string> {
        auto profile = std::make_unique<http_modern_detail::HttpModernProfile>();
        if (tls_rt.atomic_credential) {
            profile->atomic_credential = std::static_pointer_cast<tls::AtomicServerCredential>(tls_rt.atomic_credential);
        } else {
            auto cred = tls::load_server_credential(cfg.certificate_file, cfg.private_key_file);
            if (!cred) return std::unexpected("HTTP TLS credential: " + cred.error());
            profile->credential.emplace(std::move(*cred));
        }
        profile->alpn = !cfg.alpn.empty() ? cfg.alpn : tls_rt.alpn;
        auto const& ech_path = !cfg.ech_key_file.empty() ? cfg.ech_key_file : tls_rt.ech_key_file;
        if (!ech_path.empty()) {
            auto ech = tls::load_ech_server_keys_file(ech_path);
            if (!ech) return std::unexpected("HTTP TLS ECH key: " + ech.error());
            profile->ech_keys = std::move(*ech);
        }
        profile->creds = creds;
        profile->http2 = cfg.http2;
        profile->handshake_timeout_ms = cfg.handshake_timeout_ms;
        return InboundFactory{[profile = std::move(profile)](Session& s, corosio::io_context& ctx, rules::RouteMatcher const& policy) {
            return http_modern_detail::serve_http_modern(s, ctx, policy, *profile);
        }};
    }
}
