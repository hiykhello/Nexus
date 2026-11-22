module;
#include <string.h>

module proxy;
import std;
import proxy.v4;
import config;
import crypto;
import naive.padding;
import naive.h2_connect;
import naive.h3_connect;
import naive.h3_client;
import masque.client_profile;
import masque.session;
import masque.datagram;
import quic.cid_registry;
import quic.native_memory;
import quic.datagram_port;
import quic.datagram_session;
import quic.tls_client;
import net.datagram_driver;
import net.connection_pool;
import net.packet_stream_socket;
import net.stream_relay;
import net.tcp_connect;
import net.tcp_fast_open_stream;
import net.udp_connect;
import net.datagram_frame;
import platform.ip_address;
import platform.socket_options;
import hysteria2.transport_options;
import http.connect;
import http.header;
import rulefile;
import rules;
import socks5;
import tls.profiles;
import tls.fingerprint;
import tls.byte_stream;
import tls.corosio_application;
import tls.corosio_client;
import tls.connector;
import tls.encrypted_extensions;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;

#include "naive_outbound_h3.hpp"
#include "naive_outbound_h2.hpp"

namespace proxy::naive_out_detail {
    namespace {
        auto make_h2_factory(std::unique_ptr<H2Profile> owner, std::uint32_t timeout_ms,
                             bool direct_only, bool fast_open) -> TunnelFactory {
            auto* raw = owner.get();
            auto get_slot = [](auto& prof, auto tag, nex::corosio::io_context& ctx) noexcept {
                std::lock_guard lock(prof.mutex);
                auto& vec = [&]() noexcept -> auto& {
                    if constexpr (decltype(tag)::value == 1) return prof.layered;
                    else if constexpr (decltype(tag)::value == 2) return prof.fast;
                    else return prof.physical;
                }();
                for (auto& x : vec) if (x && &x->environment.context == &ctx) return x.get();
                return static_cast<H2Worker<decltype(tag)::value>*>(nullptr);
            };
            TunnelFactory factory{
                [owner = std::move(owner), get_slot](Session& session, nex::corosio::io_context& ctx, bool relay_local,
                                                     TcpSocketOptions const* direct) -> pro::proxy<TunnelFacade> {
                    if (direct ? direct->tcp_fast_open.value_or(owner->fast_open) : owner->fast_open) {
                        auto* w = get_slot(*owner, std::integral_constant<int, 2>{}, ctx);
                        return w ? pro::make_proxy<TunnelFacade, H2Tunnel<2>>(session, *w, *owner, relay_local) : pro::proxy<TunnelFacade>{};
                    }
                    auto* w = get_slot(*owner, std::integral_constant<int, 0>{}, ctx);
                    return w ? pro::make_proxy<TunnelFacade, H2Tunnel<0>>(session, *w, *owner, relay_local) : pro::proxy<TunnelFacade>{};
                },
                timeout_ms,
                [raw, get_slot](Session& session, nex::corosio::io_context& ctx, TunnelFactory const&, bool relay_local) -> pro::proxy<TunnelFacade> {
                    auto* w = get_slot(*raw, std::integral_constant<int, 1>{}, ctx);
                    return w ? pro::make_proxy<TunnelFacade, H2Tunnel<1>>(session, *w, *raw, relay_local) : pro::proxy<TunnelFacade>{};
                },
                std::nullopt, direct_only
            };
            (void)fast_open;
            factory.start_context = [raw](OutboundContext const& env, TunnelFactory const* detour, bool direct) {
                std::lock_guard lock(raw->mutex);
                if (direct && !env.direct_options) return false;
                auto const& opts = direct ? *env.direct_options : raw->options;
                auto add_in = [&](auto tag) -> bool {
                    auto& vec = [&]() noexcept -> auto& {
                        if constexpr (decltype(tag)::value == 1) return raw->layered;
                        else if constexpr (decltype(tag)::value == 2) return raw->fast;
                        else return raw->physical;
                    }();
                    for (auto const& x : vec) if (x && &x->environment.context == &env.context) return false;
                    auto it = std::ranges::find_if(vec, [](auto const& x) { return !x; });
                    if (it == vec.end()) return false;
                    *it = std::make_unique<H2Worker<decltype(tag)::value>>(env, *raw, detour, opts, raw->max_sessions);
                    return true;
                };
                if (detour) return add_in(std::integral_constant<int, 1>{});
                if (opts.tcp_fast_open.value_or(raw->fast_open)) return add_in(std::integral_constant<int, 2>{});
                return add_in(std::integral_constant<int, 0>{});
            };
            factory.stop_context = [raw](nex::corosio::io_context& ctx) noexcept {
                std::lock_guard lock(raw->mutex);
                for (auto& w : raw->physical) if (w && &w->environment.context == &ctx) w->stop();
                for (auto& w : raw->layered) if (w && &w->environment.context == &ctx) w->stop();
                for (auto& w : raw->fast) if (w && &w->environment.context == &ctx) w->stop();
            };
            factory.finish_context = [raw](nex::corosio::io_context& ctx) noexcept {
                std::lock_guard lock(raw->mutex);
                auto drain = [&](auto& vec) {
                    for (auto& w : vec) if (w && &w->environment.context == &ctx) { if (!w->drained()) std::terminate(); w.reset(); }
                };
                drain(raw->physical);
                drain(raw->layered);
                drain(raw->fast);
            };
            return factory;
        }

        template<bool EnableDatagrams>
        auto make_h3_factory(std::unique_ptr<H3Profile> owner, std::uint32_t timeout_ms, bool direct_only) -> TunnelFactory {
            auto* raw = owner.get();
            TunnelFactory f{
                [owner = std::move(owner)](Session& s, nex::corosio::io_context& ctx, bool rl, TcpSocketOptions const*) -> pro::proxy<TunnelFacade> {
                    H3Worker<false, EnableDatagrams>* w = nullptr;
                    auto& arr = [&]() noexcept -> auto& {
                        if constexpr (EnableDatagrams) return owner->physical_udp;
                        else return owner->physical;
                    }();
                    { std::lock_guard lock(owner->mutex); for (auto& x : arr) if (x && &x->environment.context == &ctx) w = x.get(); }
                    return w ? pro::make_proxy<TunnelFacade, H3Tunnel<false, EnableDatagrams>>(s, *w, *owner, rl) : pro::proxy<TunnelFacade>{};
                },
                timeout_ms,
                [raw](Session& s, nex::corosio::io_context& ctx, TunnelFactory const&, bool rl) -> pro::proxy<TunnelFacade> {
                    H3Worker<true, EnableDatagrams>* w = nullptr;
                    auto& arr = [&]() noexcept -> auto& {
                        if constexpr (EnableDatagrams) return raw->layered_udp;
                        else return raw->layered;
                    }();
                    { std::lock_guard lock(raw->mutex); for (auto& x : arr) if (x && &x->environment.context == &ctx) w = x.get(); }
                    return w ? pro::make_proxy<TunnelFacade, H3Tunnel<true, EnableDatagrams>>(s, *w, *raw, rl) : pro::proxy<TunnelFacade>{};
                },
                std::nullopt, direct_only
            };
            f.packet_dual_family = EnableDatagrams;
            f.packet_fixed_peer = EnableDatagrams;
            f.start_context = [raw](OutboundContext const& env, TunnelFactory const* detour, bool direct) {
                std::lock_guard lock(raw->mutex);
                if (direct && !env.direct_options) return false;
                auto const& opts = direct ? *env.direct_options : raw->options;
                auto& larr = [&]() noexcept -> auto& {
                    if constexpr (EnableDatagrams) return raw->layered_udp; else return raw->layered;
                }();
                auto& parr = [&]() noexcept -> auto& {
                    if constexpr (EnableDatagrams) return raw->physical_udp; else return raw->physical;
                }();
                if (detour) {
                    auto it = std::ranges::find_if(larr, [](auto const& x) { return !x; });
                    if (it == larr.end()) return false;
                    *it = std::make_unique<H3Worker<true, EnableDatagrams>>(env, raw->host, raw->port, raw->bootstrap, *raw->client_profile, opts, detour, raw->max_sessions);
                    return true;
                }
                auto it = std::ranges::find_if(parr, [](auto const& x) { return !x; });
                if (it == parr.end()) return false;
                *it = std::make_unique<H3Worker<false, EnableDatagrams>>(env, raw->host, raw->port, raw->bootstrap, *raw->client_profile, opts, nullptr, raw->max_sessions);
                return true;
            };
            f.stop_context = [raw](nex::corosio::io_context& ctx) noexcept {
                std::lock_guard lock(raw->mutex);
                auto& parr = [&]() noexcept -> auto& { if constexpr (EnableDatagrams) return raw->physical_udp; else return raw->physical; }();
                auto& larr = [&]() noexcept -> auto& { if constexpr (EnableDatagrams) return raw->layered_udp; else return raw->layered; }();
                for (auto& w : parr) if (w && &w->environment.context == &ctx) w->stop();
                for (auto& w : larr) if (w && &w->environment.context == &ctx) w->stop();
            };
            f.finish_context = [raw](nex::corosio::io_context& ctx) noexcept {
                std::lock_guard lock(raw->mutex);
                auto& parr = [&]() noexcept -> auto& { if constexpr (EnableDatagrams) return raw->physical_udp; else return raw->physical; }();
                auto& larr = [&]() noexcept -> auto& { if constexpr (EnableDatagrams) return raw->layered_udp; else return raw->layered; }();
                for (auto& w : parr) if (w && &w->environment.context == &ctx) { if (!w->drained()) std::terminate(); w.reset(); }
                for (auto& w : larr) if (w && &w->environment.context == &ctx) { if (!w->drained()) std::terminate(); w.reset(); }
            };
            return f;
        }

        auto make_h3_client_profile(tls::ClientProfile const& tls_id, std::string_view host, std::uint16_t port,
                                    hysteria2::TransportOptions opts, tls::Fingerprint fp)
            -> std::unique_ptr<masque::ClientProfile> {
            return std::unique_ptr<masque::ClientProfile>(new masque::ClientProfile(
                masque::ClientProfile::for_http(tls_id, format_domain_authority(host, port), opts, fp)));
        }
    }
}

namespace proxy {
    auto make_naive_factory(config::NaiveOutbound const& cfg) -> std::expected<TunnelFactory, std::string> {
        using namespace naive_out_detail;
        auto pw = rulefile::read_password_file(cfg.password_file);
        if (!pw) return std::unexpected("NaiveProxy password-file: " + pw.error());
        struct Wipe {
            std::string& s;
            ~Wipe() { if (!s.empty()) crypto::cleanse(std::span<std::uint8_t>(reinterpret_cast<std::uint8_t*>(s.data()), s.size())); }
        } wipe{*pw};
        auto auth = naive::make_basic_auth(cfg.username, *pw);
        auto fp = tls::parse_fingerprint(config::tls_fingerprint_name(cfg.fingerprint));
        if (!fp) return std::unexpected("invalid NaiveProxy TLS fingerprint");
        std::uint16_t kx = cfg.key_exchange == config::TlsKeyExchange::x25519 ? 0x001d : 0x11ec;
        bool hybrid_only = cfg.key_exchange == config::TlsKeyExchange::x25519_mlkem768_only;
        std::array<std::string_view, 1> alpn{cfg.protocol == config::NaiveProtocol::h3 ? "h3" : "h2"};
        auto tls_id = tls::ClientProfile::load(cfg.server_name, cfg.ca_file, kx, hybrid_only, alpn);
        if (!tls_id) return std::unexpected(tls_id.error());
        tls_id->certificate_pins = cfg.certificate_sha256;
        if (cfg.protocol == config::NaiveProtocol::h3) {
            hysteria2::TransportOptions opts{std::chrono::milliseconds(cfg.handshake_timeout_ms),
                                            std::chrono::milliseconds(cfg.idle_timeout_ms), cfg.native_bytes, false};
            auto mp = make_h3_client_profile(*tls_id, cfg.server_name, cfg.port, opts, *fp);
            auto owner = std::make_unique<H3Profile>(
                cfg.host, cfg.port, std::move(auth), cfg.extra_headers, cfg.padding,
                cfg.bootstrap_index, cfg.connect_timeout_ms, cfg.max_sessions, cfg.tcp_options, std::move(mp));
            return make_h3_factory<false>(std::move(owner), cfg.connect_timeout_ms, cfg.tcp_options.configured());
        }
        auto shaped = tls::ShapedClientProfile::create(std::move(*tls_id), *fp);
        if (!shaped) return std::unexpected(shaped.error());
        bool fo = cfg.tcp_fast_open.value_or(cfg.tcp_options.tcp_fast_open.value_or(false));
        auto owner = std::make_unique<H2Profile>(
            cfg.host, cfg.port, std::move(auth), cfg.extra_headers, cfg.padding, false, fo,
            cfg.bootstrap_index, cfg.connect_timeout_ms, cfg.max_sessions, cfg.tcp_options, std::move(*shaped));
        return make_h2_factory(std::move(owner), cfg.connect_timeout_ms, cfg.tcp_options.configured() || fo, fo);
    }

    auto make_http_modern_factory(config::TcpProxyOutbound const& cfg) -> std::expected<TunnelFactory, std::string> {
        using namespace naive_out_detail;
        if (!cfg.tls) return std::unexpected("HTTP/2 and HTTP/3 proxy outbounds require TLS");
        std::string auth;
        if (!cfg.username.empty()) {
            auto pw = rulefile::read_password_file(cfg.password_file);
            if (!pw) return std::unexpected("HTTP proxy password-file: " + pw.error());
            auth = naive::make_basic_auth(cfg.username, *pw);
            crypto::cleanse(std::span<std::uint8_t>(reinterpret_cast<std::uint8_t*>(pw->data()), pw->size()));
        }
        auto fp = tls::parse_fingerprint(config::tls_fingerprint_name(cfg.tls->fingerprint));
        if (!fp) return std::unexpected("invalid HTTP proxy TLS fingerprint");
        std::vector<std::string_view> alpn;
        if (cfg.http_version == config::HttpProxyVersion::h3) alpn.push_back("h3");
        else if (cfg.http_version == config::HttpProxyVersion::auto_h2) { alpn.push_back("h2"); alpn.push_back("http/1.1"); }
        else alpn.push_back("h2");
        auto tls_id = tls::ClientProfile::load(cfg.tls->server_name, cfg.tls->ca_file, 0x001d, false, alpn);
        if (!tls_id) return std::unexpected(tls_id.error());
        tls_id->certificate_pins = cfg.tls->certificate_sha256;
        if (cfg.http_version == config::HttpProxyVersion::h3) {
            hysteria2::TransportOptions opts{std::chrono::milliseconds(cfg.handshake_timeout_ms),
                                            std::chrono::milliseconds(cfg.idle_timeout_ms), cfg.native_bytes, cfg.udp};
            auto mp = make_h3_client_profile(*tls_id, cfg.tls->server_name, cfg.port, opts, *fp);
            auto owner = std::make_unique<H3Profile>(
                cfg.host, cfg.port, std::move(auth), std::vector<std::pair<std::string, std::string>>{}, false,
                cfg.bootstrap_index, cfg.connect_timeout_ms, cfg.max_sessions, cfg.tcp_options, std::move(mp));
            if (cfg.udp) return make_h3_factory<true>(std::move(owner), cfg.connect_timeout_ms, cfg.tcp_options.configured());
            return make_h3_factory<false>(std::move(owner), cfg.connect_timeout_ms, cfg.tcp_options.configured());
        }
        auto shaped = tls::ShapedClientProfile::create(std::move(*tls_id), *fp);
        if (!shaped) return std::unexpected(shaped.error());
        bool fo = cfg.tcp_options.tcp_fast_open.value_or(false);
        auto owner = std::make_unique<H2Profile>(
            cfg.host, cfg.port, std::move(auth), std::vector<std::pair<std::string, std::string>>{}, false,
            cfg.http_version == config::HttpProxyVersion::auto_h2, fo,
            cfg.bootstrap_index, cfg.connect_timeout_ms, cfg.max_sessions, cfg.tcp_options, std::move(*shaped));
        return make_h2_factory(std::move(owner), cfg.connect_timeout_ms, cfg.tcp_options.configured(), fo);
    }
}
