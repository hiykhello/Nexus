module;
#include <proxy/proxy_macros.h>
#include <boost/capy/ex/run_async.hpp>
#include <boost/capy/task.hpp>
#include <boost/capy/when_all.hpp>
#include <boost/corosio/endpoint.hpp>
#include <boost/corosio/io_context.hpp>
#include <boost/corosio/tcp_socket.hpp>
#include <boost/corosio/timeout.hpp>

module relay;
import std;
import proxy.v4;
import config;
import crypto;
import rulefile;
import platform.linux_random;
import platform.socket_options;
import net.udp_socket;
import net.tcp_connect;
import tls.profiles;
import tls.fingerprint;
import tls.client_handshake_io;
import tls.application_io;
import openvpn.types;
import openvpn.wire;
import openvpn.control;
import openvpn.session;
import openvpn.tls_crypt;
import capy;
import corosio;
import relay.l3_mux;
import :l3_tunnel;
import :openvpn_transport;

namespace relay {
    namespace {
        using ovpn_detail::HostState;
        using ovpn_detail::SocketBinder;
        using ovpn_detail::now_ms;

        auto trim_crlf(std::string& s) noexcept -> void {
            while (!s.empty() && (s.back() == '\n' || s.back() == '\r')) s.pop_back();
        }

        struct OpenVpnHost : HostState {
            using HostState::HostState;

            static auto run(std::shared_ptr<HostState> h) -> capy::task<> {
                struct Guard { HostState& host; ~Guard() { host.loop_active = false; } } guard{*h};
                if (!h->use_tcp) (void)co_await udp_loop(h.get());
                else (void)co_await capy::when_all(tcp_rx_loop(h.get()), tcp_tx_loop(h.get()), tcp_timer_loop(h.get()));
            }

            auto ensure_started(Session& s, DnsSlot& dns, Clock::time_point deadline) -> capy::task<bool> {
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
                    HostState& h;
                    ~Fin() {
                        if (!h.started) {
                            if (h.detour_tunnel) h.detour_tunnel->cancel();
                            if (h.tcp) h.tcp->close();
                            h.udp.close();
                        }
                        h.connecting = false;
                        h.ready_event.set();
                    }
                } fin{*this};

                auto eps = cfg.bootstrap_index
                    ? co_await resolve_bootstrap_owned(s, context, dns, *cfg.bootstrap_index, cfg.host, cfg.port, deadline)
                    : co_await resolve_local_owned(s, context, dns, cfg.host, cfg.port, deadline);
                if (stopped || s.closed || Clock::now() >= deadline || !eps || eps->empty()) co_return false;
                auto const& ep = eps->front();
                if (!use_tcp) {
                    udp_target.port = ep.port();
                    if (ep.address().is_v4()) { udp_target.family = 4; std::ranges::copy(ep.address().to_v4().to_bytes(), udp_target.address.begin()); }
                    else { udp_target.family = 6; udp_target.address = ep.address().to_v6().to_bytes(); }
                    net::UdpEndpoint local{6, {}, binding.udp_bind_port.value_or(0)};
                    if (udp_target.family == 4 && binding.inet4_bind_address) {
                        local.family = 4; std::ranges::copy(*binding.inet4_bind_address, local.address.begin());
                    } else if (udp_target.family == 6 && binding.inet6_bind_address) {
                        local.address = *binding.inet6_bind_address;
                    }
                    if (!udp.open(false, binding.network_namespace)) co_return false;
                    if (binding.configured() && SocketBinder{binding, deadline}(udp.native_handle())) co_return false;
                    if (!udp.bind(local)) co_return false;
                } else if (via) {
                    detour_session = std::make_unique<Session>(context);
                    detour_session->dns = s.dns; detour_session->local_dns = s.local_dns; detour_session->route_snapshot = s.route_snapshot;
                    detour_session->tunnel_factories = s.tunnel_factories; detour_session->direct_tcp_options = s.direct_tcp_options;
                    detour_tunnel = via->create(*detour_session, context, false, nullptr);
                    if (!detour_tunnel || co_await detour_tunnel->connect_until(ep, deadline) != TunnelConnectResult::connected)
                        co_return false;
                } else {
                    tcp.emplace(context);
                    bool prep_failed = false;
                    platform::TcpSocketOptions opts = cfg.tcp_options;
                    opts.binding = binding;
                    auto [ec, selected] = co_await net::connect_tcp_candidates(*tcp, *eps, [](auto const&, auto const&) { return true; }, opts, prep_failed, deadline);
                    (void)selected;
                    if (ec || prep_failed) co_return false;
                }

                if (!platform::secure_random(std::as_writable_bytes(std::span(&local_sid, 1))) || local_sid == 0) co_return false;
                openvpn::ControlChannel ctrl(local_sid, false);
                auto reset_wire = encode_ctrl(ctrl.begin_client_reset(now_ms()));
                if (!reset_wire || !co_await send_wire(*reset_wire)) co_return false;

                std::vector<std::uint8_t> tls_rx;
                while (!ctrl.handshake_started() && Clock::now() < deadline && !stopped) {
                    auto slice_dl = std::min(deadline, Clock::now() + std::chrono::milliseconds(400));
                    auto pkt = co_await recv_wire(slice_dl);
                    if (!pkt) {
                        if (Clock::now() >= deadline) co_return false;
                        if (!co_await send_ctrl_packets(ctrl.retransmit_due(now_ms(), 350))) co_return false;
                        continue;
                    }
                    auto cp = decode_ctrl(*pkt);
                    if (!cp) continue;
                    if (!ctrl.on_packet(*cp, now_ms())) co_return false;
                    if (auto ack = ctrl.take_ack()) {
                        auto aw = encode_ctrl(*ack);
                        if (!aw || !co_await send_wire(*aw)) co_return false;
                    }
                }
                if (!ctrl.handshake_started()) co_return false;

                auto cur_ms = now_ms();
                auto dl_ms = cur_ms + static_cast<std::uint64_t>(std::max<std::int64_t>(
                    1, std::chrono::duration_cast<std::chrono::milliseconds>(deadline - Clock::now()).count()));
                auto wall_s = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
                auto hs = tls.handshake(cur_ms, dl_ms, wall_s);
                if (!hs) co_return false;

                while (!hs->complete() && !stopped) {
                    if (!hs->tick(now_ms())) co_return false;
                    if (!hs->pending_output().empty()) {
                        auto out = hs->pending_output();
                        std::size_t n = out.size();
                        auto pkts = ctrl.enqueue_tls_bytes(out, now_ms());
                        if (pkts.empty() || !co_await send_ctrl_packets(pkts) || !hs->written(n, now_ms())) co_return false;
                        continue;
                    }
                    while (!tls_rx.empty() && hs->pending_output().empty() && !hs->complete()) {
                        auto fed = hs->feed(tls_rx, now_ms());
                        if (!fed) co_return false;
                        if (fed->consumed == 0) break;
                        tls_rx.erase(tls_rx.begin(), tls_rx.begin() + static_cast<std::ptrdiff_t>(fed->consumed));
                    }
                    if (hs->complete() || !hs->pending_output().empty()) continue;
                    auto slice_dl = std::min(deadline, Clock::now() + std::chrono::milliseconds(400));
                    auto pkt = co_await recv_wire(slice_dl);
                    if (!pkt) {
                        if (Clock::now() >= deadline) co_return false;
                        if (!co_await send_ctrl_packets(ctrl.retransmit_due(now_ms(), 350))) co_return false;
                        continue;
                    }
                    auto cp = decode_ctrl(*pkt);
                    if (!cp) continue;
                    auto chunk = ctrl.on_packet(*cp, now_ms());
                    if (!chunk) co_return false;
                    if (auto ack = ctrl.take_ack()) {
                        auto aw = encode_ctrl(*ack);
                        if (!aw || !co_await send_wire(*aw)) co_return false;
                    }
                    tls_rx.insert(tls_rx.end(), chunk->begin(), chunk->end());
                }
                if (!hs->complete()) co_return false;
                auto records = hs->take_application_records();
                if (!records) co_return false;
                tls::ApplicationIo app(std::move(*records));

                openvpn::KeyMethod2Client km_cli;
                std::expected<std::vector<std::uint8_t>, std::string> km_wire = std::unexpected(std::string{});
                std::expected<openvpn::KeyMaterial, std::string> km = std::unexpected(std::string{});
                struct SecretCleanse {
                    openvpn::KeyMethod2Client& cli;
                    std::expected<std::vector<std::uint8_t>, std::string>& wire;
                    std::expected<openvpn::KeyMaterial, std::string>& mat;
                    ~SecretCleanse() {
                        crypto::cleanse(std::span<std::uint8_t>(cli.pre_master));
                        if (!cli.password.empty())
                            crypto::cleanse(std::span<std::uint8_t>(reinterpret_cast<std::uint8_t*>(cli.password.data()), cli.password.size()));
                        if (wire) crypto::cleanse(std::span<std::uint8_t>(*wire));
                        if (mat) {
                            crypto::cleanse(std::span<std::uint8_t>(mat->tx_key));
                            crypto::cleanse(std::span<std::uint8_t>(mat->rx_key));
                            crypto::cleanse(std::span<std::uint8_t>(mat->tx_iv));
                            crypto::cleanse(std::span<std::uint8_t>(mat->rx_iv));
                        }
                    }
                } cleanse{km_cli, km_wire, km};
                if (!platform::secure_random(std::as_writable_bytes(std::span{km_cli.pre_master})) ||
                    !platform::secure_random(std::as_writable_bytes(std::span{km_cli.random1})) ||
                    !platform::secure_random(std::as_writable_bytes(std::span{km_cli.random2}))) co_return false;
                km_cli.options = std::format("V4,dev-type tun,link-mtu {},tun-mtu {},proto {},cipher {}",
                    cfg.mtu, cfg.mtu, use_tcp ? "TCPv4_CLIENT" : "UDPv4",
                    active_cipher == openvpn::Cipher::chacha20_poly1305 ? "CHACHA20-POLY1305" : "AES-256-GCM");
                km_cli.username = cfg.username;
                km_cli.password = password;
                km_cli.peer_info = "IV_VER=2.6.0\nIV_PLAT=linux\nIV_PROTO=6\nIV_NCP=2\nIV_CIPHERS=AES-256-GCM:CHACHA20-POLY1305\n";
                km_wire = openvpn::encode_key_method2_client(km_cli);
                if (!km_wire || !co_await pump_app_send(app, ctrl, *km_wire)) co_return false;

                std::vector<std::uint8_t> app_plain;
                std::optional<openvpn::KeyMethod2Server> km_srv;
                while (Clock::now() < deadline && !stopped) {
                    if (app_plain.size() >= 69) {
                        auto dec = openvpn::decode_key_method2_server(app_plain);
                        if (dec) { km_srv = std::move(*dec); app_plain.clear(); break; }
                    }
                    if (!co_await pump_app_recv(app, ctrl, tls_rx, app_plain, deadline)) co_return false;
                }
                if (!km_srv) co_return false;

                km = openvpn::derive_key_method2_keys(km_cli.pre_master, km_cli.random1, km_srv->random1,
                    km_cli.random2, km_srv->random2, ctrl.local_session_id(), ctrl.remote_session_id(), false);
                if (!km) co_return false;

                constexpr std::string_view kPushReq = "PUSH_REQUEST\0";
                if (!co_await pump_app_send(app, ctrl,
                        std::span(reinterpret_cast<std::uint8_t const*>(kPushReq.data()), kPushReq.size())))
                    co_return false;

                std::optional<openvpn::PushConfig> pushed;
                while (Clock::now() < deadline && !stopped) {
                    std::string_view sv(reinterpret_cast<char const*>(app_plain.data()), app_plain.size());
                    if (sv.find('\0') != sv.npos || sv.starts_with("PUSH_REPLY")) {
                        auto pr = openvpn::parse_push_reply(sv);
                        if (pr) { pushed = *pr; break; }
                    }
                    if (!co_await pump_app_recv(app, ctrl, tls_rx, app_plain, deadline)) co_return false;
                }
                if (!pushed) co_return false;

                auto ep_l3 = mux.endpoint();
                if (pushed->local_v4) { ep_l3.has_v4 = true; ep_l3.local_v4 = *pushed->local_v4; }
                if (pushed->local_v6) { ep_l3.has_v6 = true; ep_l3.local_v6 = *pushed->local_v6; }
                if (pushed->mtu) ep_l3.mtu = std::clamp<std::uint16_t>(*pushed->mtu, 576, 1500);
                mux.set_endpoint(ep_l3);
                if (pushed->cipher) active_cipher = *pushed->cipher;
                if (pushed->peer_id) peer_id = *pushed->peer_id;
                ping_s = pushed->ping_s;
                ping_restart_s = pushed->ping_restart_s;
                if (!data.init(active_cipher, *km, peer_id, 0)) co_return false;

                last_tx_ms = last_rx_ms = now_ms();
                loop_active = true;
                try {
                    auto keep = shared_from_this();
                    capy::run_async(context.get_executor(), []() noexcept {},
                        [keep](std::exception_ptr) noexcept { keep->stop(); })(run(keep));
                } catch (...) {
                    loop_active = false; stop(); co_return false;
                }
                started = !stopped;
                co_return started;
            }
        };

        struct OpenVpnProfile {
            config::OpenVpnOutbound cfg;
            tls::ShapedClientProfile tls;
            std::string password;
            std::optional<std::array<std::uint8_t, 256>> static_key;
            std::mutex mutex;
            std::unordered_map<io::io_context*, std::shared_ptr<OpenVpnHost>> hosts;
            std::vector<std::pair<io::io_context*, std::shared_ptr<OpenVpnHost>>> retired;
            bool shutting_down = false;

            ~OpenVpnProfile() {
                if (!password.empty())
                    crypto::cleanse(std::span<std::uint8_t>(reinterpret_cast<std::uint8_t*>(password.data()), password.size()));
                if (static_key) crypto::cleanse(std::span<std::uint8_t>(*static_key));
            }

            auto get_host(io::io_context& ctx, platform::SocketBinding const& binding, TunnelFactory const* via)
                -> std::shared_ptr<OpenVpnHost> {
                std::lock_guard lock(mutex);
                std::erase_if(retired, [](auto const& e) { return !e.second || (!e.second->loop_active && !e.second->connecting); });
                auto it = hosts.find(&ctx);
                if (it != hosts.end() && it->second) {
                    if (!it->second->stopped) return it->second;
                    if (it->second->loop_active || it->second->connecting) retired.emplace_back(&ctx, std::move(it->second));
                }
                if (shutting_down) return nullptr;
                auto h = std::make_shared<OpenVpnHost>(ctx, cfg, tls, password, static_key, binding, via);
                hosts[&ctx] = h;
                return h;
            }
        };

        using OpenVpnTunnel = l3_detail::L3Tunnel<OpenVpnHost>;
    }

    auto make_openvpn_factory(config::OpenVpnOutbound const& cfg) -> std::expected<TunnelFactory, std::string> {
        if (cfg.host.empty() || !cfg.port || !cfg.connect_timeout_ms || cfg.connect_timeout_ms > 3600000 || !cfg.tcp_options.valid())
            return std::unexpected("invalid OpenVPN outbound options");
        if (cfg.client_cert_file || cfg.client_key_file)
            return std::unexpected("OpenVPN outbound TLS client-cert-file/client-key-file requires client TLS mTLS handshake support");
        std::string pw;
        if (cfg.password_file) {
            auto f = rulefile::read_password_file(*cfg.password_file);
            if (!f) return std::unexpected("OpenVPN password-file: " + f.error());
            pw = std::move(*f); trim_crlf(pw);
        }
        std::optional<std::array<std::uint8_t, 256>> static_key;
        if (cfg.static_key_file) {
            auto f = rulefile::read_private_file(*cfg.static_key_file);
            if (!f) return std::unexpected("OpenVPN static-key-file: " + f.error());
            auto parsed = openvpn::parse_static_key_v1(std::string_view(f->bytes().data(), f->bytes().size()));
            if (!parsed) return std::unexpected("OpenVPN static-key-file: " + parsed.error());
            struct KeyWipe { std::array<std::uint8_t, 256>& k; ~KeyWipe() { crypto::cleanse(k); } } wipe{*parsed};
            static_key = *parsed;
        }
        if (cfg.tls_auth_mode != config::OpenVpnTlsAuthMode::none && !static_key)
            return std::unexpected("OpenVPN tls-auth-mode requires static-key-file");
        auto fp = tls::parse_fingerprint(config::tls_fingerprint_name(cfg.fingerprint));
        if (!fp) return std::unexpected("invalid OpenVPN TLS fingerprint");
        std::uint16_t kx = cfg.key_exchange == config::TlsKeyExchange::x25519 ? 0x001d : 0x11ec;
        auto tls_id = tls::ClientProfile::load(cfg.server_name, cfg.ca_file, kx, cfg.key_exchange == config::TlsKeyExchange::x25519_mlkem768_only);
        if (!tls_id) return std::unexpected(tls_id.error());
        tls_id->certificate_pins = cfg.certificate_sha256;
        auto shaped = tls::ShapedClientProfile::create(std::move(*tls_id), *fp);
        if (!shaped) return std::unexpected(shaped.error());
        auto profile = std::make_shared<OpenVpnProfile>(cfg, std::move(*shaped), std::move(pw), std::move(static_key));
        TunnelFactory factory{
            [profile](Session& s, io::io_context& ctx, bool rl, TcpSocketOptions const* lower) -> pro::proxy<TunnelFacade> {
                auto const& b = lower ? lower->binding : profile->cfg.tcp_options.binding;
                auto h = profile->get_host(ctx, b, nullptr);
                return h ? pro::make_proxy<TunnelFacade, OpenVpnTunnel>(s, std::move(h), profile->cfg.connect_timeout_ms, rl) : pro::proxy<TunnelFacade>{};
            },
            cfg.connect_timeout_ms,
            [profile](Session& s, io::io_context& ctx, TunnelFactory const& lower, bool rl) -> pro::proxy<TunnelFacade> {
                auto h = profile->get_host(ctx, platform::SocketBinding{}, &lower);
                return h ? pro::make_proxy<TunnelFacade, OpenVpnTunnel>(s, std::move(h), profile->cfg.connect_timeout_ms, rl) : pro::proxy<TunnelFacade>{};
            }, std::nullopt, cfg.tcp_options.configured()
        };
        factory.stop_context = [profile](io::io_context& ctx) noexcept {
            std::lock_guard lock(profile->mutex);
            profile->shutting_down = true;
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
        factory.finish_context = [profile](io::io_context& ctx) noexcept {
            std::lock_guard lock(profile->mutex);
            profile->hosts.erase(&ctx);
            std::erase_if(profile->retired, [&](auto const& e) { return e.first == &ctx; });
        };
        return factory;
    }
}
