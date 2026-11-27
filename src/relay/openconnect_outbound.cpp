module;
#include <proxy/proxy_macros.h>
#include <boost/capy/ex/async_event.hpp>
#include <boost/capy/ex/run_async.hpp>
#include <boost/capy/task.hpp>
#include <boost/capy/when_all.hpp>
#include <boost/corosio/delay.hpp>
#include <boost/corosio/endpoint.hpp>
#include <boost/corosio/io_context.hpp>
#include <boost/corosio/timeout.hpp>

module relay;
import std;
import proxy.v4;
import config;
import crypto;
import encoding.hex;
import rulefile;
import platform.linux_random;
import platform.ip_address;
import tls.profiles;
import tls.fingerprint;
import tls.byte_stream;
import tls.connector;
import openconnect.types;
import openconnect.auth;
import openconnect.cstp;
import openconnect.dtls;
import capy;
import corosio;
import relay.l3_mux;
import :l3_tunnel;
import :openconnect_dtls;

namespace relay {
    namespace {
        using oc_detail::DtlsChannel;
        using oc_detail::oc_now_ms;
        using oc_detail::parse_content_length;
        using oc_detail::trim_crlf;
        using encoding::hex_encode;

        struct OcResolver {
            Session& session; io::io_context& context; std::string_view host; std::uint16_t port;
            std::optional<std::size_t> bootstrap; DnsSlot slot;
            auto operator()(Clock::time_point deadline) -> capy::task<std::optional<std::vector<corosio::endpoint>>> {
                if (bootstrap) return resolve_bootstrap_owned(session, context, slot, *bootstrap, std::string(host), port, deadline);
                return resolve_local_owned(session, context, slot, std::string(host), port, deadline);
            }
            auto connected(corosio::endpoint const& ep) noexcept -> void { session.record_physical_peer(ep); }
            auto cancel() noexcept -> void { slot.cancel(); }
        };

        struct OcLower {
            using Candidates = LowerConnector::Candidates;
            Session& session; LowerConnector connector;
            OcLower(Session& v, io::io_context& c, TunnelFactory const& f, std::string_view h, std::uint16_t p, std::optional<std::size_t> b)
                : session(v), connector{{}, &c, &f, h, p, b} {}
            auto connect(Clock::time_point dl, Candidates& cands) -> capy::task<tls::detail::ConnectResult> {
                switch (co_await connector.connect(session, dl, cands)) {
                case TunnelConnectResult::connected: co_return tls::detail::ConnectResult::connected;
                case TunnelConnectResult::retryable: co_return tls::detail::ConnectResult::retryable;
                case TunnelConnectResult::failed: co_return tls::detail::ConnectResult::failed;
                case TunnelConnectResult::timeout: co_return tls::detail::ConnectResult::timeout;
                }
                std::terminate();
            }
            auto retry() noexcept -> bool { return connector.retry(); }
            auto read(std::span<std::uint8_t> b) { return connector.tunnel->read(b); }
            auto send(std::span<std::uint8_t const> b) { return connector.tunnel->send(b); }
            auto close_output() { return connector.tunnel->close_output(); }
            auto cancel() noexcept -> void { connector.cancel(); }
        };

        using OcConnector = tls::detail::UnifiedConnector<OcResolver, OcLower, tls::ShapedClientProfile>;
        using OcTlsStream = tls::detail::ByteStream<typename OcConnector::Socket>;

        struct OpenConnectProfile {
            config::OpenConnectOutbound cfg;
            tls::ShapedClientProfile tls;
            std::string password;
            std::string initial_cookie;

            struct Host : std::enable_shared_from_this<Host> {
                io::io_context& context;
                OpenConnectProfile const& profile;
                platform::TcpSocketOptions options;
                TunnelFactory const* via;
                net::UdpEndpoint connected_peer{};
                std::unique_ptr<Session> conn_session;
                std::unique_ptr<OcConnector> conn;
                std::unique_ptr<OcTlsStream> tls_stream;
                DtlsChannel dtls;
                std::vector<std::uint8_t> rx_buf;
                std::size_t rx_head = 0;
                openconnect::Session oc_session;
                L3Mux mux;
                std::uint16_t dpd_s = 30, keepalive_s = 20;
                std::deque<std::vector<std::uint8_t>> tx_queue;
                capy::async_event ready_event, tx_event, timer_wake;
                std::stop_source stop_src;
                std::uint64_t last_tx_ms = 0, last_rx_ms = 0;
                bool started = false, connecting = false, stopped = false, loop_active = false;

                Host(io::io_context& ctx, OpenConnectProfile const& p, platform::TcpSocketOptions opts, TunnelFactory const* d)
                    : context(ctx), profile(p), options(std::move(opts)), via(d),
                      mux(L3Endpoint{p.cfg.has_v4, p.cfg.local_v4, p.cfg.has_v6, p.cfg.local_v6, p.cfg.mtu}, &Host::send_ip, this),
                      dpd_s(p.cfg.dpd_s), keepalive_s(p.cfg.keepalive_s) {
                    dtls.allow_fallback = !p.cfg.dtls || p.cfg.dtls_fallback;
                }

                static auto send_ip(void* ctx, std::span<std::uint8_t const> pkt) -> bool {
                    auto* h = static_cast<Host*>(ctx);
                    if (h->stopped) return false;
                    bool const strict_dtls = h->profile.cfg.dtls && !h->profile.cfg.dtls_fallback;
                    if (h->dtls.established()) {
                        if (h->dtls.send_data(pkt, h->oc_session)) {
                            h->last_tx_ms = oc_now_ms();
                            return true;
                        }
                        if (h->dtls.failed_hard) { h->stop(); return false; }
                        if (strict_dtls || !h->dtls.may_send_cstp_data()) return false;
                    } else if (strict_dtls || !h->dtls.may_send_cstp_data()) {
                        if (h->dtls.failed_hard) h->stop();
                        return false;
                    }
                    if (h->dtls.failed_hard) { h->stop(); return false; }
                    if (h->tx_queue.size() >= 256) return false;
                    auto frame = openconnect::encode_cstp_frame(openconnect::CstpType::data, pkt);
                    if (!frame) return false;
                    h->last_tx_ms = oc_now_ms();
                    h->tx_queue.push_back(std::move(*frame));
                    h->tx_event.set();
                    h->timer_wake.set();
                    return true;
                }

                auto open_tls(Session& parent, std::unique_ptr<Session>& sess, std::unique_ptr<OcConnector>& c,
                              std::unique_ptr<OcTlsStream>& stream, Clock::time_point dl) -> capy::task<bool> {
                    sess = std::make_unique<Session>(context);
                    sess->dns = parent.dns; sess->local_dns = parent.local_dns; sess->route_snapshot = parent.route_snapshot;
                    sess->tunnel_factories = parent.tunnel_factories; sess->direct_tcp_options = parent.direct_tcp_options;
                    sess->physical_peer = &connected_peer;
                    c = via
                        ? std::make_unique<OcConnector>(context, profile.tls, std::in_place, *sess, context, *via,
                              profile.cfg.host, profile.cfg.port, profile.cfg.bootstrap_index)
                        : std::make_unique<OcConnector>(tls::detail::TransportMode::physical, context,
                              OcResolver{*sess, context, profile.cfg.host, profile.cfg.port, profile.cfg.bootstrap_index},
                              profile.tls, options);
                    if (co_await c->start(dl) != tls::detail::ConnectResult::connected || !c->application()) co_return false;
                    stream = std::make_unique<OcTlsStream>(*c->application());
                    co_return true;
                }

                auto authenticate_once(Session& parent, openconnect::AuthRequest const& req, Clock::time_point dl)
                    -> capy::task<std::expected<openconnect::AuthResult, std::string>> {
                    std::unique_ptr<Session> sess;
                    std::unique_ptr<OcConnector> c;
                    std::unique_ptr<OcTlsStream> stream;
                    if (!co_await open_tls(parent, sess, c, stream, dl))
                        co_return std::unexpected("OpenConnect auth TLS connect failed");
                    auto wire_req = openconnect::build_http_auth_request(profile.cfg.server_name, req, false);
                    struct StrWipe { std::string& s; ~StrWipe() { if (!s.empty()) crypto::cleanse(std::span<std::uint8_t>(reinterpret_cast<std::uint8_t*>(s.data()), s.size())); } };
                    StrWipe req_wipe{wire_req};
                    auto req_span = std::span(reinterpret_cast<std::uint8_t const*>(wire_req.data()), wire_req.size());
                    if (!co_await stream->send(req_span, dl)) co_return std::unexpected("OpenConnect auth request send failed");
                    std::string acc; StrWipe acc_wipe{acc};
                    std::array<std::uint8_t, 4096> buf{};
                    std::optional<std::size_t> hdr_end, clen;
                    while (acc.size() < 131072) {
                        auto r = co_await stream->read(buf, dl);
                        if (!r) co_return std::unexpected("OpenConnect auth read failed");
                        if (*r == 0) break;
                        acc.append(reinterpret_cast<char const*>(buf.data()), *r);
                        if (!hdr_end) if (auto p = acc.find("\r\n\r\n"); p != acc.npos) { hdr_end = p + 4; clen = parse_content_length(std::string_view(acc).substr(0, p)); }
                        if (hdr_end && clen && acc.size() >= *hdr_end + *clen) break;
                    }
                    stream->cancel();
                    if (!hdr_end) co_return std::unexpected("malformed OpenConnect HTTP auth response");
                    auto hdrs_sv = std::string_view(acc).substr(0, *hdr_end);
                    auto first_nl = hdrs_sv.find('\n');
                    auto status_line = (first_nl == hdrs_sv.npos) ? hdrs_sv : hdrs_sv.substr(0, first_nl);
                    if (!status_line.empty() && status_line.back() == '\r') status_line.remove_suffix(1);
                    if (!((status_line.starts_with("HTTP/1.1 200") || status_line.starts_with("HTTP/1.0 200")) && (status_line.size() == 12 || status_line[12] == ' ')))
                        co_return std::unexpected("OpenConnect HTTP auth rejected");
                    auto body = clen ? std::string_view(acc).substr(*hdr_end, std::min(*clen, acc.size() - *hdr_end))
                                     : std::string_view(acc).substr(*hdr_end);
                    co_return openconnect::parse_config_auth_response(body);
                }

                static auto rx_loop(Host* h) -> capy::task<capy::results<>> {
                    std::array<std::uint8_t, 4096> buf{};
                    while (!h->stopped && !h->stop_src.stop_requested()) {
                        for (;;) {
                            auto dec = openconnect::decode_cstp_frame(std::span(h->rx_buf).subspan(h->rx_head));
                            if (!dec) {
                                if (dec.error() == "incomplete") break;
                                h->stop(); co_return capy::results<>{};
                            }
                            auto [frame, consumed] = std::move(*dec);
                            h->rx_head += consumed;
                            if (h->rx_head == h->rx_buf.size()) { h->rx_buf.clear(); h->rx_head = 0; }
                            else if (h->rx_head >= 4096 && h->rx_head * 2 >= h->rx_buf.size()) {
                                h->rx_buf.erase(h->rx_buf.begin(), h->rx_buf.begin() + static_cast<std::ptrdiff_t>(h->rx_head));
                                h->rx_head = 0;
                            }
                            auto ms = oc_now_ms();
                            h->last_rx_ms = ms;
                            if (frame.type == openconnect::CstpType::data) {
                                h->mux.on_ip_packet(frame.payload, ms);
                                h->timer_wake.set();
                            } else if (auto resp = h->oc_session.handle_frame(frame)) {
                                if (auto enc = openconnect::encode_cstp_frame(resp->type, resp->payload); enc && h->tx_queue.size() < 256) {
                                    h->tx_queue.push_back(std::move(*enc));
                                    h->tx_event.set();
                                }
                            } else if (frame.type == openconnect::CstpType::disconnect) {
                                h->stop(); co_return capy::results<>{};
                            }
                        }
                        auto r = co_await h->tls_stream->read(buf);
                        if (!r || *r == 0) break;
                        h->rx_buf.insert(h->rx_buf.end(), buf.begin(), buf.begin() + static_cast<std::ptrdiff_t>(*r));
                    }
                    h->stop();
                    co_return capy::results<>{};
                }

                static auto tx_loop(Host* h) -> capy::task<capy::results<>> {
                    while (!h->stopped && !h->stop_src.stop_requested()) {
                        h->tx_event.clear();
                        if (h->tx_queue.empty()) {
                            auto [ec] = co_await h->tx_event.wait();
                            if (ec) break;
                            continue;
                        }
                        auto frame = std::move(h->tx_queue.front());
                        h->tx_queue.pop_front();
                        if (!co_await h->tls_stream->send(frame)) break;
                    }
                    h->stop();
                    co_return capy::results<>{};
                }

                static auto timer_loop(Host* h) -> capy::task<capy::results<>> {
                    while (!h->stopped && !h->stop_src.stop_requested()) {
                        h->timer_wake.clear();
                        if (h->stopped || h->stop_src.stop_requested()) break;
                        auto ms = oc_now_ms();
                        h->mux.tick(ms);
                        if (h->dpd_s > 0 && ms - h->last_tx_ms >= static_cast<std::uint64_t>(h->dpd_s) * 1000) {
                            auto dpd = h->oc_session.make_dpd_req();
                            if (auto enc = openconnect::encode_cstp_frame(dpd.type, dpd.payload); enc && h->tx_queue.size() < 256) {
                                h->last_tx_ms = ms; h->tx_queue.push_back(std::move(*enc)); h->tx_event.set();
                            }
                        } else if (h->keepalive_s > 0 && ms - h->last_tx_ms >= static_cast<std::uint64_t>(h->keepalive_s) * 1000) {
                            auto ka = h->oc_session.make_keepalive();
                            if (auto enc = openconnect::encode_cstp_frame(ka.type, ka.payload); enc && h->tx_queue.size() < 256) {
                                h->last_tx_ms = ms; h->tx_queue.push_back(std::move(*enc)); h->tx_event.set();
                            }
                        }
                        if (h->dpd_s > 0 && h->last_rx_ms > 0 && ms - h->last_rx_ms >= static_cast<std::uint64_t>(h->dpd_s) * 3000) { h->stop(); break; }
                        std::optional<std::uint64_t> next = h->mux.next_tick_ms(ms);
                        auto clamp = [&](std::uint64_t t) { if (!next || t < *next) next = t; };
                        if (h->dpd_s > 0) {
                            clamp(h->last_tx_ms + static_cast<std::uint64_t>(h->dpd_s) * 1000);
                            if (h->last_rx_ms > 0) clamp(h->last_rx_ms + static_cast<std::uint64_t>(h->dpd_s) * 3000);
                        } else if (h->keepalive_s > 0) clamp(h->last_tx_ms + static_cast<std::uint64_t>(h->keepalive_s) * 1000);
                        if (next) {
                            auto wait_ms = *next > ms ? (*next - ms) : 1;
                            (void)co_await io::timeout(h->timer_wake.wait(), Clock::now() + std::chrono::milliseconds(wait_ms));
                        } else if (auto [ec] = co_await h->timer_wake.wait(); ec) break;
                    }
                    co_return capy::results<>{};
                }

                static auto dtls_loop(Host* h) -> capy::task<capy::results<>> {
                    while (!h->stopped && !h->stop_src.stop_requested() && h->dtls.enabled) {
                        auto ms = oc_now_ms();
                        bool moved = h->dtls.poll_once(h->oc_session, ms, [&](std::span<std::uint8_t const> ip) {
                            h->last_rx_ms = ms;
                            h->mux.on_ip_packet(ip, ms);
                            h->timer_wake.set();
                        });
                        if (h->dtls.failed_hard) { h->stop(); break; }
                        if (!h->dtls.enabled) break;
                        auto [ec] = co_await io::delay(moved ? std::chrono::milliseconds(1) : std::chrono::milliseconds(5));
                        if (ec) break;
                    }
                    co_return capy::results<>{};
                }

                static auto run(std::shared_ptr<Host> h) -> capy::task<> {
                    struct Guard { Host& host; ~Guard() { host.loop_active = false; } } guard{*h};
                    (void)co_await capy::when_all(rx_loop(h.get()), tx_loop(h.get()), timer_loop(h.get()), dtls_loop(h.get()));
                }

                auto ensure_started(Session& s, DnsSlot& dns, Clock::time_point deadline) -> capy::task<bool> {
                    (void)dns;
                    if (stopped || s.closed || Clock::now() >= deadline) co_return false;
                    if (started) co_return true;
                    while (connecting) {
                        ready_event.clear();
                        auto [ec] = co_await io::timeout(ready_event.wait(), deadline);
                        if (ec || stopped || s.closed || Clock::now() >= deadline) co_return false;
                        if (started) co_return true;
                    }
                    if (stopped) co_return false;
                    connecting = true;
                    struct Fin {
                        Host& h;
                        ~Fin() {
                            if (!h.started) {
                                h.dtls.close();
                                if (h.tls_stream) h.tls_stream->cancel();
                                if (h.conn) h.conn->cancel();
                                h.tls_stream.reset();
                                h.conn.reset();
                            }
                            h.connecting = false;
                            h.ready_event.set();
                        }
                    } fin{*this};

                    std::string cookie = profile.initial_cookie, cstp_req, dtls_secret_hex;
                    std::array<std::uint8_t, 48> dtls_secret{};
                    struct Cleanse { std::string& ck, &req, &hex; std::array<std::uint8_t, 48>& sec; ~Cleanse() {
                        if (!ck.empty()) crypto::cleanse(std::span<std::uint8_t>(reinterpret_cast<std::uint8_t*>(ck.data()), ck.size()));
                        if (!req.empty()) crypto::cleanse(std::span<std::uint8_t>(reinterpret_cast<std::uint8_t*>(req.data()), req.size()));
                        if (!hex.empty()) crypto::cleanse(std::span<std::uint8_t>(reinterpret_cast<std::uint8_t*>(hex.data()), hex.size()));
                        crypto::cleanse(std::span<std::uint8_t>(sec));
                    } } cleanse{cookie, cstp_req, dtls_secret_hex, dtls_secret};
                    if (cookie.empty()) {
                        openconnect::AuthRequest req{profile.cfg.username, profile.password, profile.cfg.group, {},
                            profile.cfg.user_agent};
                        auto a1 = co_await authenticate_once(s, req, deadline);
                        if (!a1) co_return false;
                        if (a1->needs_auth_reply) {
                            req.opaque = a1->opaque;
                            auto a2 = co_await authenticate_once(s, req, deadline);
                            if (!a2 || !a2->authenticated) co_return false;
                            cookie = std::move(a2->cookie);
                        } else if (a1->authenticated) {
                            cookie = std::move(a1->cookie);
                        } else {
                            co_return false;
                        }
                    }

                    if (!co_await open_tls(s, conn_session, conn, tls_stream, deadline)) co_return false;
                    if (!platform::secure_random(std::as_writable_bytes(std::span{dtls_secret}))) co_return false;
                    if (profile.cfg.dtls) dtls_secret_hex = hex_encode(dtls_secret);
                    cstp_req = openconnect::build_cstp_connect_headers(
                        profile.cfg.server_name, cookie, profile.cfg.mtu,
                        dtls_secret_hex, profile.cfg.user_agent, profile.cfg.dtls);
                    if (!co_await tls_stream->send(std::span(reinterpret_cast<std::uint8_t const*>(cstp_req.data()), cstp_req.size()), deadline))
                        co_return false;

                    std::string hdrs;
                    std::array<std::uint8_t, 4096> buf{};
                    std::size_t hdr_end = std::string::npos;
                    while (hdrs.size() < 16384) {
                        auto r = co_await tls_stream->read(buf, deadline);
                        if (!r || *r == 0) co_return false;
                        hdrs.append(reinterpret_cast<char const*>(buf.data()), *r);
                        if (auto p = hdrs.find("\r\n\r\n"); p != hdrs.npos) { hdr_end = p + 4; break; }
                    }
                    if (hdr_end == std::string::npos) co_return false;
                    if (hdr_end < hdrs.size()) {
                        rx_buf.assign(reinterpret_cast<std::uint8_t const*>(hdrs.data() + hdr_end),
                                      reinterpret_cast<std::uint8_t const*>(hdrs.data() + hdrs.size()));
                    }
                    auto parsed = openconnect::parse_cstp_connect_headers(std::string_view(hdrs).substr(0, hdr_end));
                    if (!parsed) co_return false;

                    auto ep_l3 = mux.endpoint();
                    if (!parsed->ipv4_address.empty())
                        if (auto ip4 = platform::parse_ip_address(parsed->ipv4_address); ip4 && ip4->size == 4) { ep_l3.has_v4 = true; std::ranges::copy(ip4->view(), ep_l3.local_v4.begin()); }
                    if (!parsed->ipv6_address.empty())
                        if (auto ip6 = platform::parse_ip_address(parsed->ipv6_address); ip6 && ip6->size == 16) { ep_l3.has_v6 = true; std::ranges::copy(ip6->view(), ep_l3.local_v6.begin()); }
                    ep_l3.mtu = parsed->mtu; mux.set_endpoint(ep_l3);
                    dpd_s = parsed->dpd_s; keepalive_s = parsed->keepalive_s;
                    bool dtls_started = false;
                    if (profile.cfg.dtls) {
                        dtls_started = !via && !parsed->dtls_session_id.empty() &&
                            dtls.start(connected_peer, *parsed, dtls_secret, options.binding, profile.cfg.dtls_fallback, oc_now_ms(), deadline);
                        if (!dtls_started && !profile.cfg.dtls_fallback) co_return false;
                        if (dtls_started && !profile.cfg.dtls_fallback) {
                            bool ok = co_await dtls.await_handshake(oc_session, deadline, [&] { return stopped || s.closed; });
                            if (!ok) co_return false;
                        }
                    }
                    oc_session.on_connected(dtls_started);
                    last_tx_ms = last_rx_ms = oc_now_ms(); loop_active = true;
                    try {
                        auto keep = shared_from_this();
                        capy::run_async(context.get_executor(), []() noexcept {}, [keep](std::exception_ptr) noexcept { keep->stop(); })(run(keep));
                    } catch (...) { loop_active = false; stop(); co_return false; }
                    started = !stopped; co_return started;
                }

                auto stop() noexcept -> void {
                    if (stopped) return;
                    stopped = true; stop_src.request_stop(); ready_event.set(); tx_event.set(); timer_wake.set();
                    mux.reset_flows(); dtls.close();
                    if (tls_stream) tls_stream->cancel();
                    if (conn) conn->cancel();
                    if (conn_session) conn_session->close();
                }
            };

            std::mutex mutex;
            std::unordered_map<io::io_context*, std::shared_ptr<Host>> hosts;
            std::vector<std::pair<io::io_context*, std::shared_ptr<Host>>> retired;
            bool shutting_down = false;

            ~OpenConnectProfile() {
                auto wipe = [](std::string& s) { if (!s.empty()) crypto::cleanse(std::span<std::uint8_t>(reinterpret_cast<std::uint8_t*>(s.data()), s.size())); };
                wipe(password); wipe(initial_cookie);
            }

            auto get_host(io::io_context& ctx, platform::TcpSocketOptions const& opts, TunnelFactory const* via) -> std::shared_ptr<Host> {
                std::lock_guard lock(mutex);
                std::erase_if(retired, [](auto const& e) { return !e.second || (!e.second->loop_active && !e.second->connecting); });
                auto it = hosts.find(&ctx);
                if (it != hosts.end() && it->second) {
                    if (!it->second->stopped) return it->second;
                    if (it->second->loop_active || it->second->connecting) retired.emplace_back(&ctx, std::move(it->second));
                }
                if (shutting_down) return nullptr;
                auto h = std::make_shared<Host>(ctx, *this, opts, via);
                hosts[&ctx] = h;
                return h;
            }
        };

        using l3_detail::L3Tunnel;
        using OpenConnectTunnel = L3Tunnel<OpenConnectProfile::Host>;
    }

    auto make_openconnect_factory(config::OpenConnectOutbound const& cfg) -> std::expected<TunnelFactory, std::string> {
        if (cfg.host.empty() || !cfg.port || !cfg.connect_timeout_ms || cfg.connect_timeout_ms > 3600000 || !cfg.tcp_options.valid())
            return std::unexpected("invalid OpenConnect outbound options");
        std::string pw, cookie;
        if (cfg.password_file) {
            auto f = rulefile::read_password_file(*cfg.password_file);
            if (!f) return std::unexpected("OpenConnect password-file: " + f.error());
            pw = std::move(*f); trim_crlf(pw);
        }
        if (cfg.cookie_file) {
            auto f = rulefile::read_private_file(*cfg.cookie_file);
            if (!f) return std::unexpected("OpenConnect cookie-file: " + f.error());
            cookie.assign(f->bytes().data(), f->bytes().size()); trim_crlf(cookie);
            if (cookie.empty()) return std::unexpected("OpenConnect cookie-file is empty");
        }
        if (cfg.client_cert_file || cfg.client_key_file)
            return std::unexpected("OpenConnect outbound TLS client-cert-file/client-key-file requires client TLS mTLS handshake support");
        auto fp = tls::parse_fingerprint(config::tls_fingerprint_name(cfg.fingerprint));
        if (!fp) return std::unexpected("invalid OpenConnect TLS fingerprint");
        std::uint16_t kx = cfg.key_exchange == config::TlsKeyExchange::x25519 ? 0x001d : 0x11ec;
        constexpr std::array<std::string_view, 1> alpn_h1{"http/1.1"};
        auto tls_id = tls::ClientProfile::load(cfg.server_name, cfg.ca_file, kx,
            cfg.key_exchange == config::TlsKeyExchange::x25519_mlkem768_only, alpn_h1);
        if (!tls_id) return std::unexpected(tls_id.error());
        tls_id->certificate_pins = cfg.certificate_sha256;
        auto shaped = tls::ShapedClientProfile::create(std::move(*tls_id), *fp);
        if (!shaped) return std::unexpected(shaped.error());

        auto profile = std::make_shared<OpenConnectProfile>(cfg, std::move(*shaped), std::move(pw), std::move(cookie));
        auto connect_auth = [profile](Session& s, io::io_context& ctx, bool rl, TcpSocketOptions const* lower) -> pro::proxy<TunnelFacade> {
            auto h = profile->get_host(ctx, lower ? *lower : profile->cfg.tcp_options, nullptr);
            return h ? pro::make_proxy<TunnelFacade, OpenConnectTunnel>(s, std::move(h), profile->cfg.connect_timeout_ms, rl) : pro::proxy<TunnelFacade>{};
        };
        auto connect_detour = [profile](Session& s, io::io_context& ctx, TunnelFactory const& lower, bool rl) -> pro::proxy<TunnelFacade> {
            auto h = profile->get_host(ctx, platform::TcpSocketOptions{}, &lower);
            return h ? pro::make_proxy<TunnelFacade, OpenConnectTunnel>(s, std::move(h), profile->cfg.connect_timeout_ms, rl) : pro::proxy<TunnelFacade>{};
        };
        TunnelFactory factory{std::move(connect_auth), cfg.connect_timeout_ms, std::move(connect_detour), std::nullopt, cfg.tcp_options.configured()};
        factory.stop_context = [profile](io::io_context& ctx) noexcept {
            std::lock_guard lock(profile->mutex); profile->shutting_down = true;
            if (auto it = profile->hosts.find(&ctx); it != profile->hosts.end()) it->second->stop();
            for (auto const& [c, h] : profile->retired) if (c == &ctx && h) h->stop();
        };
        factory.quiesced_context = [profile](io::io_context& ctx) noexcept -> bool {
            std::lock_guard lock(profile->mutex);
            auto it = profile->hosts.find(&ctx);
            bool ok = it == profile->hosts.end() || (!it->second->loop_active && !it->second->connecting);
            for (auto const& [c, h] : profile->retired) if (c == &ctx && h && (h->loop_active || h->connecting)) ok = false;
            return ok;
        };
        factory.finish_context = [profile](io::io_context& ctx) noexcept { std::lock_guard lock(profile->mutex); profile->hosts.erase(&ctx); std::erase_if(profile->retired, [&](auto const& e) { return e.first == &ctx; }); };
        return factory;
    }
}
