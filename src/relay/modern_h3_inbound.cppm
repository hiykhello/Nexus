module;
#include <boost/corosio/socket_option.hpp>

module relay:modern_h3_inbound;
import std;
import functional;
import naive.padding;
import naive.h3_connect;
import tls.profiles;
import tls.server_credential;
import tls.byte_stream;
import quic.cid_registry;
import quic.native_memory;
import quic.datagram_port;
import quic.datagram_session;
import quic.retry_admission;
import quic.retry_token;
import quic.tls_server;
import net.datagram_driver;
import hysteria2.transport_options;
import masque.session;
import rules;
import socks5;
import relay.stream_relay;
import nghttp3;
import ngtcp2;
import capy;
import corosio;
import :types;
import :session_interface;
import :internal_decls;
import :server_interface;
import :naive_inbound_helpers;
import :modern_h3_connect_udp;

namespace relay {
    struct ModernHttp3Inbound {
        using Registry = quic::CidRegistry<32, 8>;
        using Hooks = naive::H3ConnectHooks<Registry, true, naive::kH3StreamCapacity, true>;
        using Tls = quic::TlsServer;
        using Application = masque::Session<Tls, Hooks, true>;
        using Native = quic::DatagramSession<Tls, Application>;
        using Endpoint = corosio::endpoint;
        static constexpr std::size_t capacity = 32;

        struct Bundle {
            ModernHttp3Inbound& owner;
            Session parent;
            Tls tls;
            Hooks hooks;
            quic::NativeMemory<> memory;
            Application app;
            Native session;
            bool working = false;

            Bundle(ModernHttp3Inbound& listener, Registry& reg, quic::SessionHandle id, Endpoint const& peer, SessionQuota::Lease lease)
                : owner(listener), parent(owner.context_), tls(owner.credential_, "h3"),
                  hooks(reg, id, owner.driver_.changed()), memory(owner.transport_.native_bytes),
                  app(tls, hooks, true, memory.http3()), session(tls, app, owner.local_) {
                owner.server_.attach_session(parent, std::move(lease));
                parent.relaying = true;
                parent.datagram_source = traffic_endpoint(peer);
                parent.ingress = owner.server_.transparent_metadata(*parent.datagram_source);
            }
            auto stop() noexcept -> void {
                parent.close();
                app.request_stop();
            }
        };

        struct Factory {
            using Session = Native;
            using ControlFailure = quic::RetryFailure;
            ModernHttp3Inbound& listener;
            quic::RetryAdmission<> retry;
            std::optional<quic::RetryClaims> permit;
            std::optional<ControlFailure> failure;
            std::array<std::optional<Bundle>, capacity> sessions;

            auto admit(ngtcp2::ngtcp2_pkt_hd const& initial, Endpoint const& peer, Clock::time_point now, std::size_t bytes) noexcept -> bool {
                if (listener.draining_) return false;
                auto res = retry.inspect(initial, peer, now, bytes);
                if (!res) { failure = res.error(); return false; }
                permit = *res;
                return permit.has_value();
            }
            auto control_failure() const noexcept { return failure; }
            auto control_output(std::span<std::uint8_t> bytes, Clock::time_point now) noexcept -> std::expected<std::optional<net::DatagramOutput>, ControlFailure> {
                if (failure) return std::unexpected(*failure);
                return retry.output(bytes, now);
            }
            auto control_transmitted(std::uint64_t token, Clock::time_point now) noexcept { return retry.transmitted(token, now); }
            auto control_next_expiry() const noexcept { return retry.next_expiry(); }
            auto control_expire(Clock::time_point now) noexcept { return retry.expire(now); }
            auto control_request_stop() noexcept -> void { retry.request_stop(); }
            auto control_stop() noexcept -> void { permit.reset(); retry.stop(); }
            auto control_drained() const noexcept -> bool { return retry.drained(); }
            auto create(quic::SessionHandle id, Registry& reg, std::span<std::uint8_t const> source,
                        ngtcp2::ngtcp2_pkt_hd const& initial, Endpoint const& peer, Clock::time_point now) noexcept -> std::expected<Session*, int>;
            auto application_drained(quic::SessionHandle id, Session const&) const noexcept -> bool {
                return sessions[id.slot] && !sessions[id.slot]->working;
            }
            auto failed(quic::SessionHandle id, int) noexcept -> void { if (auto& s = sessions[id.slot]) s->stop(); }
            auto destroy(quic::SessionHandle id, Session&) noexcept -> void { sessions[id.slot].reset(); }
        };

        using Transport = hysteria2::TransportProfile<naive::kH3StreamCapacity, naive::kH3Window>;
        using Port = quic::DatagramPort<Factory, capacity, 8, 8, true>;
        using Driver = net::DatagramDriver<Port>;

        Server& server_;
        corosio::io_context& context_;
        tls::ServerCredential credential_;
        hysteria2::TransportOptions transport_;
        std::vector<naive::UserCredential> users_;
        std::optional<Credentials> http_creds_;
        bool is_naive_ = false, padding_ = false, connect_udp_ = false;
        std::uint16_t fallback_status_ = 404;
        corosio::udp_socket socket_;
        Endpoint local_;
        Factory factory_{*this};
        Port port_{factory_};
        Driver driver_{socket_, port_};
        bool draining_ = false, stopped_ = false, running_ = false, used_ = false;

        ModernHttp3Inbound(Server& s, tls::ServerCredential cred, hysteria2::TransportOptions opts,
                           std::vector<naive::UserCredential> users, std::optional<Credentials> http_creds,
                           bool is_naive, bool padding, bool connect_udp, std::uint16_t fallback_status)
            : server_(s), context_(s.executor_context()), credential_(std::move(cred)), transport_(opts),
              users_(std::move(users)), http_creds_(std::move(http_creds)),
              is_naive_(is_naive), padding_(padding), connect_udp_(connect_udp), fallback_status_(fallback_status),
              socket_(context_) {}

        auto clone_fresh() -> std::unique_ptr<ModernHttp3Inbound, void(*)(ModernHttp3Inbound*)> {
            auto cred = credential_.clone();
            if (!cred) return {nullptr, +[](ModernHttp3Inbound*) {}};
            auto* p = new ModernHttp3Inbound(server_, std::move(*cred), transport_, users_, http_creds_,
                                             is_naive_, padding_, connect_udp_, fallback_status_);
            return {p, +[](ModernHttp3Inbound* ptr) noexcept { delete ptr; }};
        }

        template<class H3H>
        auto send_decoy(H3H& h, std::uint16_t status, Clock::time_point until) -> capy::task<> {
            auto s = std::to_string(status);
            auto body = naive::decoy_html_body(status);
            auto len = std::to_string(body.size());
            std::array<nghttp3::nghttp3_nv, 4> hdrs{
                naive::h3_nv(":status", s),
                naive::h3_nv("content-type", "text/html; charset=utf-8"),
                naive::h3_nv("server", "nginx"),
                naive::h3_nv("content-length", len),
            };
            if (h.respond(hdrs, true))
                (void)co_await h.send_raw({reinterpret_cast<std::uint8_t const*>(body.data()), body.size()}, true, until);
        }

        template<class H3H>
        auto handle_h3_stream(Bundle& bundle, H3H& h) -> capy::task<> {
            auto until = Clock::now() + std::chrono::seconds(10);
            auto* s = h.state();
            if (!s) co_return;
            std::string method, authority, protocol, path, auth_hdr, pad_req;
            for (auto const& f : s->headers) {
                if (f.name == ":method") method = f.value;
                else if (f.name == ":authority") authority = f.value;
                else if (f.name == ":protocol") protocol = f.value;
                else if (f.name == ":path") path = f.value;
                else if (naive::header_ci_equal(f.name, "proxy-authorization")) auth_hdr = f.value;
                else if (naive::header_ci_equal(f.name, "padding-type-request")) pad_req = f.value;
            }
            if (is_naive_) {
                auto matched_user = naive::verify_basic_auth(auth_hdr, users_);
                if (method != "CONNECT" || !protocol.empty() || !matched_user) {
                    co_await send_decoy(h, fallback_status_, until);
                    co_return;
                }
                auto dst = naive::parse_connect_authority(authority);
                if (!dst) { co_await send_decoy(h, fallback_status_, until); co_return; }
                bool pad_on = padding_ && naive::parse_padding_type_request(pad_req);
                auto lease = bundle.parent.quota ? bundle.parent.quota->try_acquire() : std::nullopt;
                if (bundle.parent.quota && !lease) { co_await send_decoy(h, fallback_status_, until); co_return; }
                Session child(context_);
                child.quota = std::move(lease);
                child.auth_user = *matched_user;
                naive_in_detail::init_naive_child(child, bundle.parent, until);
                if (!child.admit_principal_child(bundle.parent)) { co_await send_decoy(h, fallback_status_, until); co_return; }
                child.begin_traffic(TrafficProtocol::naive, dst->port);
                auto const& policy = bundle.parent.route_snapshot ? bundle.parent.route_snapshot->matcher : server_.routing_policy();
                if (!child.ordered_tcp) {
                    if (co_await naive_in_detail::dial_naive_target(child, context_, policy, *dst, h) != 0 || child.closed) {
                        co_await send_decoy(h, fallback_status_, until);
                        co_return;
                    }
                }
                std::string pad_hdr = pad_on ? naive::generate_padding_header() : std::string{};
                if (pad_on) {
                    std::array<nghttp3::nghttp3_nv, 3> hdrs{
                        naive::h3_nv(":status", "200"), naive::h3_nv("padding", pad_hdr), naive::h3_nv("padding-type-reply", "1")};
                    if (!h.respond(hdrs, true)) co_return;
                } else {
                    std::array<nghttp3::nghttp3_nv, 1> hdrs{naive::h3_nv(":status", "200")};
                    if (!h.respond(hdrs, true)) co_return;
                }
                h.arm_padding(pad_on);
                if (child.ordered_tcp) {
                    if (co_await naive_in_detail::dial_naive_target(child, context_, policy, *dst, h) != 0 || child.closed) co_return;
                }
                child.relaying = true;
                child.touched = bundle.parent.touched = Clock::now();
                std::stop_callback sc(bundle.parent.stop.get_token(), [&]() noexcept { child.close(); });
                (void)co_await capy::when_all(
                    stream_relay::direction(child, stream_relay::upload(child, h)),
                    stream_relay::direction(child, stream_relay::download(child, h)));
                co_return;
            }
            std::optional<std::string> user_copy;
            if (http_creds_) {
                if (!naive_in_detail::match_basic_single(auth_hdr, *http_creds_)) {
                    co_await naive_in_detail::send_h3_status(h, "407", "Basic realm=\"Nexus\"", until);
                    co_return;
                }
                user_copy.emplace(reinterpret_cast<char const*>(http_creds_->username.data()), http_creds_->username_size);
            }
            if (method == "CONNECT" && protocol == "connect-udp" && connect_udp_) {
                co_await naive_in_detail::serve_connect_udp_stream(
                    server_, bundle.parent, context_, h, path,
                    user_copy ? std::optional<std::string_view>(*user_copy) : std::nullopt, until);
                co_return;
            }
            if (method != "CONNECT" || !protocol.empty()) {
                co_await naive_in_detail::send_h3_status(h, "501", {}, until);
                co_return;
            }
            auto dst = naive::parse_connect_authority(authority);
            if (!dst) { co_await naive_in_detail::send_h3_status(h, "400", {}, until); co_return; }
            auto lease = bundle.parent.quota ? bundle.parent.quota->try_acquire() : std::nullopt;
            if (bundle.parent.quota && !lease) { co_await naive_in_detail::send_h3_status(h, "503", {}, until); co_return; }
            Session child(context_);
            child.quota = std::move(lease);
            if (user_copy) child.auth_user = *user_copy;
            naive_in_detail::init_naive_child(child, bundle.parent, until);
            if (!child.admit_principal_child(bundle.parent)) { co_await naive_in_detail::send_h3_status(h, "403", {}, until); co_return; }
            child.begin_traffic(TrafficProtocol::http3_connect, dst->port);
            auto const& policy = bundle.parent.route_snapshot ? bundle.parent.route_snapshot->matcher : server_.routing_policy();
            auto code = co_await naive_in_detail::dial_naive_target(child, context_, policy, *dst, h);
            if (code != 0 || child.closed) {
                co_await naive_in_detail::send_h3_status(h, code == 2 ? "403" : "502", {}, until);
                co_return;
            }
            std::array<nghttp3::nghttp3_nv, 1> ok_hdrs{naive::h3_nv(":status", "200")};
            if (!h.respond(ok_hdrs, true)) co_return;
            child.relaying = true;
            child.touched = bundle.parent.touched = Clock::now();
            std::stop_callback sc(bundle.parent.stop.get_token(), [&]() noexcept { child.close(); });
            (void)co_await capy::when_all(
                stream_relay::direction(child, stream_relay::upload(child, h)),
                stream_relay::direction(child, stream_relay::download(child, h)));
        }

        auto bundle_worker(Bundle& bundle) -> capy::task<capy::results<>> {
            while (!bundle.parent.closed && !bundle.hooks.dead) {
                std::optional<std::int64_t> accepted;
                for (auto& [sid, st] : bundle.hooks.streams) {
                    if ((st.complete || st.failed) && !st.accepted && !st.retired) {
                        st.accepted = true;
                        accepted = sid;
                        break;
                    }
                }
                if (!accepted) {
                    if (draining_ && bundle.hooks.streams.empty()) break;
                    driver_.changed().clear();
                    if (bundle.parent.closed || bundle.hooks.dead) break;
                    (void)co_await driver_.changed().wait();
                    continue;
                }
                naive::H3StreamHandle<Bundle, Driver> h(bundle, driver_, *accepted, false);
                if (!h.state() || h.state()->failed) continue;
                try { co_await handle_h3_stream(bundle, h); }
                catch (...) { h.release(); }
            }
            co_return capy::results<>{};
        }

        auto run_bundle(Bundle& bundle) -> capy::task<> {
            std::stop_callback stop_parent(bundle.parent.stop.get_token(), [this, &bundle]() noexcept {
                bundle.hooks.stopping();
                driver_.notify();
            });
            std::vector<capy::task<capy::results<>>> workers;
            workers.reserve(8);
            for (unsigned i = 0; i < 8; ++i) workers.push_back(bundle_worker(bundle));
            (void)co_await capy::when_all(std::move(workers));
        }

        auto start_bundle(quic::SessionHandle id, Bundle& bundle) -> void {
            bundle.working = true;
            auto finished = [this, id]() noexcept {
                if (auto& entry = factory_.sessions[id.slot]) {
                    entry->working = false;
                    entry->stop();
                }
                (void)port_.request_retire(id);
                port_.maintain();
                driver_.notify();
            };
            capy::run_async(context_.get_executor(), [finished]() noexcept { finished(); },
                            [finished](std::exception_ptr) noexcept { finished(); })(run_bundle(bundle));
        }

        auto start(Endpoint ep, functional::move_only_function<void() const> failure) -> std::expected<Endpoint, std::error_code> {
            used_ = true;
            if (!factory_.retry.initialize()) return std::unexpected(std::make_error_code(std::errc::io_error));
            if (auto ec = socket_.open(ep.address().family())) return std::unexpected(ec);
            if (ep.is_v6()) if (auto ec = socket_.set_option(corosio::socket_option::v6_only(true))) return std::unexpected(ec);
            if (auto ec = socket_.bind(ep)) return std::unexpected(ec);
            local_ = socket_.local_endpoint();
            running_ = true;
            auto finished = [this, report = std::move(failure)]() mutable {
                running_ = false;
                if (!stopped_) report();
                stop();
            };
            capy::run_async(context_.get_executor(), [f = std::move(finished)](auto) mutable { f(); },
                            [this](std::exception_ptr) noexcept { running_ = false; stop(); })(driver_.run());
            return local_;
        }
        auto drain() noexcept -> void {
            draining_ = true;
            for (auto& s : factory_.sessions) if (s && s->hooks.streams.empty()) s->stop();
            driver_.notify();
        }
        auto drained() const noexcept -> bool {
            return !running_ && std::ranges::none_of(factory_.sessions, [](auto const& s) { return s.has_value(); });
        }
        auto stop() noexcept -> void {
            if (std::exchange(stopped_, true)) return;
            draining_ = true;
            for (auto& s : factory_.sessions) if (s) s->stop();
            driver_.finish();
            running_ = false;
        }
    };

    inline auto ModernHttp3Inbound::Factory::create(
        quic::SessionHandle id, Registry& reg, std::span<std::uint8_t const> source,
        ngtcp2::ngtcp2_pkt_hd const& initial, Endpoint const& peer, Clock::time_point now) noexcept
        -> std::expected<Session*, int> {
        namespace q = ::ngtcp2;
        auto verified = std::exchange(permit, {});
        auto& entry = sessions[id.slot];
        if (entry || !verified || !std::ranges::equal(verified->retry.bytes(), std::span(initial.dcid.data).first(initial.dcid.datalen)))
            return std::unexpected(q::err_invalid_argument);
        auto lease = listener.server_.acquire_session();
        if (!lease) return std::unexpected(q::err_callback_failure);
        auto settings = Transport::settings(listener.transport_);
        auto params = Transport::parameters(listener.transport_);
        if (!settings || !params) return std::unexpected(q::err_invalid_argument);
        q::ngtcp2_cid_init(&params->original_dcid, verified->original.data.data(), verified->original.size);
        params->original_dcid_present = 1;
        params->retry_scid_present = 1;
        params->retry_scid = initial.dcid;
        settings->token = initial.token;
        settings->tokenlen = initial.tokenlen;
        settings->token_type = q::NGTCP2_TOKEN_TYPE_RETRY;
        q::ngtcp2_cid cid{};
        q::ngtcp2_cid_init(&cid, source.data(), source.size());
        try {
            entry.emplace(listener, reg, id, peer, std::move(*lease));
            auto result = entry->session.start(true, initial.scid, cid, peer, *settings, *params, entry->memory.transport(), now);
            if (result) { entry.reset(); return std::unexpected(result); }
            listener.start_bundle(id, *entry);
            return &entry->session;
        } catch (...) {
            entry.reset();
            return std::unexpected(q::err_callback_failure);
        }
    }
}
