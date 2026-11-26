module;
#include <proxy/proxy_macros.h>
#include <boost/capy/ex/async_event.hpp>
#include <boost/capy/ex/run_async.hpp>
#include <boost/capy/task.hpp>
#include <boost/capy/when_all.hpp>
#include <boost/corosio/delay.hpp>
#include <boost/corosio/endpoint.hpp>
#include <boost/corosio/io_context.hpp>
#include <boost/corosio/ipv4_address.hpp>
#include <boost/corosio/ipv6_address.hpp>
#include <boost/corosio/timeout.hpp>
module relay;
import std;
import proxy.v4;
import config;
import crypto;
import encoding.base64_key;
import rulefile;
import packet;
import tcp.send;
import tcp.receive;
import net.udp_socket;
import net.datagram_frame;
import net.packet_stream_socket;
import net.stream_relay;
import platform.ip_address;
import platform.linux_random;
import platform.socket_options;
import wireguard;
import wireguard.crypto;
import wireguard.endpoint;
import wireguard.multi_peer_outbound;
import wireguard.port;
import wireguard.port_types;
import wireguard.registry;
import wireguard.routing;
import capy;
import corosio;
import relay.l3_mux;
import :wireguard_detour;
import :l3_tunnel;

namespace relay {
    namespace {
        using wg_detail::WireGuardDetour;
        using wg_detail::WireGuardOuterSocket;
        using WgPort = wireguard::UdpPort<32, 64, 2048, 1024, wireguard::PortNoHooks,
            wireguard::PortOuterAllowAll, wireguard::ReservedProfile, WireGuardOuterSocket>;

        auto now_ms() noexcept -> std::uint64_t {
            return static_cast<std::uint64_t>(
                std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now().time_since_epoch()).count());
        }

        auto parse_allowed_prefix(std::string_view text) -> std::optional<wireguard::AllowedPrefix> {
            auto slash = text.find('/');
            if (slash == std::string_view::npos) return std::nullopt;
            auto ip = platform::parse_ip_address(text.substr(0, slash));
            unsigned bits = 0; auto ps = text.substr(slash + 1);
            auto [end, ec] = std::from_chars(ps.data(), ps.data() + ps.size(), bits);
            if (!ip || ec != std::errc{} || end != ps.data() + ps.size() || bits > (ip->size == 4 ? 32u : 128u)) return std::nullopt;
            wireguard::AllowedPrefix out{static_cast<std::uint8_t>(ip->size == 4 ? 4 : 6), ip->bytes, static_cast<std::uint8_t>(bits)};
            return wireguard::valid_prefix(out) ? std::optional(out) : std::nullopt;
        }

        using wg_detail::to_udp_endpoint;

        struct SocketBinder {
            platform::SocketBinding const& binding;
            Clock::time_point deadline;
            auto operator()(int fd) const noexcept -> std::error_code {
                return binding.configured() ? platform::apply_socket_binding(fd, binding, true, deadline) : std::error_code{};
            }
        };

        struct WgPeerConfig {
            std::string host;
            std::uint16_t port = 51820;
            wireguard::Key peer_public{};
            std::optional<wireguard::SecretKey> psk;
            std::vector<wireguard::AllowedPrefix> allowed_ips;
            wireguard::ReservedProfile reserved{};
            std::uint16_t keepalive_s = 0;
            WgPeerConfig() = default;
            WgPeerConfig(WgPeerConfig&&) noexcept = default;
            auto operator=(WgPeerConfig&&) noexcept -> WgPeerConfig& = default;
            WgPeerConfig(WgPeerConfig const&) = delete;
            auto operator=(WgPeerConfig const&) -> WgPeerConfig& = delete;
            ~WgPeerConfig() { if (psk) psk->clear(); }
        };

        struct WgProfile {
            std::optional<std::size_t> bootstrap;
            std::uint32_t timeout_ms = 10000;
            wireguard::SecretKey private_key;
            std::vector<WgPeerConfig> peers;
            L3Endpoint l3{};
            bool on_demand = false;
            std::uint16_t idle_timeout_s = 120;
            TcpSocketOptions options;

            struct PortHolder {
                std::expected<WgPort, wireguard::PortFailure> value;
                PortHolder(std::span<std::uint8_t const> key, wireguard::PortOptions opts, wireguard::ReservedProfile wp)
                    : value(WgPort::create(key, opts, {}, wp)) {}
            };

            struct Host : std::enable_shared_from_this<Host> {
                io::io_context& context;
                WgProfile const& profile;
                platform::SocketBinding binding;
                TunnelFactory const* via;
                std::unique_ptr<WireGuardDetour> detour;
                std::unique_ptr<PortHolder> port_holder;
                WgPort* port = nullptr;
                std::unique_ptr<wireguard::MultiPeerOutbound> multi;
                net::UdpSocket multi_udp;
                L3Mux mux;
                bool started = false, connecting = false, stopped = false, loop_active = false;
                std::optional<wireguard::PeerHandle> peer;
                std::stop_source stop_src;
                capy::async_event ready_event;

                static auto send_ip(void* ctx, std::span<std::uint8_t const> pkt) -> bool {
                    auto* h = static_cast<Host*>(ctx);
                    if (h->stopped) return false;
                    if (h->multi) return h->multi->enqueue_ip(pkt, Clock::now()).has_value();
                    if (!h->port) return false;
                    return h->port->enqueue_ip(pkt, Clock::now()).has_value();
                }

                Host(io::io_context& ctx, WgProfile const& p, platform::SocketBinding selected, TunnelFactory const* lower)
                    : context(ctx), profile(p), binding(std::move(selected)), via(lower), mux(p.l3, &Host::send_ip, this) {}

                static auto poll_multi_loop(Host* h) -> capy::task<capy::results<>> {
                    std::array<std::uint8_t, 4096> buf{};
                    while (!h->stopped && !h->stop_src.stop_requested() && h->multi) {
                        auto now = Clock::now();
                        auto wall = std::chrono::system_clock::now();
                        bool moved = false;
                        for (unsigned i = 0; i < 32; ++i) {
                            auto r = h->multi_udp.receive(buf);
                            if (!r) { h->stop(); co_return capy::results<>{}; }
                            if (!*r) break;
                            if ((*r)->valid) {
                                (void)h->multi->receive_udp(std::span(buf).first((*r)->size), (*r)->source, now);
                                moved = true;
                            }
                        }
                        auto out = h->multi->poll_tx(now, wall);
                        if (!out) { h->stop(); break; }
                        for (auto const& dg : *out) {
                            (void)h->multi_udp.send(dg.destination, dg.bytes);
                            moved = true;
                        }
                        auto ms = now_ms();
                        while (auto pkt = h->multi->take_rx()) {
                            h->mux.on_ip_packet(pkt->ip_packet, ms);
                            moved = true;
                        }
                        h->mux.tick(ms);
                        auto wait = moved ? std::chrono::milliseconds(1)
                                          : (h->mux.active() ? std::chrono::milliseconds(2) : std::chrono::milliseconds(10));
                        auto [ec] = co_await io::delay(wait);
                        if (ec) break;
                    }
                    h->stop();
                    co_return capy::results<>{};
                }

                static auto poll_loop(Host* h) -> capy::task<capy::results<>> {
                    while (!h->stopped && !h->stop_src.stop_requested() && h->port) {
                        auto now = Clock::now();
                        auto wall = std::chrono::system_clock::now();
                        auto prog = h->port->poll(now, wall);
                        if (!prog) { h->stop(); break; }
                        bool moved = prog->received > 0 || prog->processed > 0 || prog->sent > 0;
                        auto ms = now_ms();
                        while (auto pkt = h->port->take_packet()) {
                            h->mux.on_ip_packet(pkt->packet(), ms);
                            moved = true;
                        }
                        h->mux.tick(ms);
                        auto wait = moved ? std::chrono::milliseconds(1)
                                          : (h->mux.active() ? std::chrono::milliseconds(2) : std::chrono::milliseconds(10));
                        auto [ec] = co_await io::delay(wait);
                        if (ec) break;
                    }
                    h->stop();
                    co_return capy::results<>{};
                }

                static auto detour_io(Host* h, bool read) -> capy::task<capy::results<>> {
                    auto& outer = h->port->transport_socket();
                    auto& lower = *h->detour;
                    if (read) (void)co_await outer.read_from(lower.socket);
                    else (void)co_await outer.write_to(lower.socket, lower.peer);
                    h->stop();
                    co_return capy::results<>{};
                }

                static auto run(std::shared_ptr<Host> h) -> capy::task<> {
                    struct Guard { Host& host; ~Guard() { host.loop_active = false; } } guard{*h};
                    if (h->multi) {
                        (void)co_await poll_multi_loop(h.get());
                    } else if (h->detour) {
                        (void)co_await capy::when_all(poll_loop(h.get()), detour_io(h.get(), true), detour_io(h.get(), false));
                    } else {
                        (void)co_await poll_loop(h.get());
                    }
                }

                auto start_multi(Session& s, DnsSlot& dns, Clock::time_point deadline) -> capy::task<bool> {
                    auto created = wireguard::MultiPeerOutbound::create(profile.private_key.view());
                    if (!created) co_return false;
                    multi = std::move(*created);
                    net::UdpEndpoint local{6, {}, binding.udp_bind_port.value_or(0)};
                    if (binding.inet4_bind_address && !binding.inet6_bind_address) {
                        local.family = 4;
                        std::ranges::copy(*binding.inet4_bind_address, local.address.begin());
                    } else if (binding.inet6_bind_address) {
                        local.address = *binding.inet6_bind_address;
                    }
                    if (!multi_udp.open(false, binding.network_namespace)) co_return false;
                    if (binding.configured() && SocketBinder{binding, deadline}(multi_udp.native_handle())) co_return false;
                    if (!multi_udp.bind(local)) co_return false;

                    auto now = Clock::now();
                    for (auto const& pc : profile.peers) {
                        auto eps = profile.bootstrap
                            ? co_await resolve_bootstrap_owned(s, context, dns, *profile.bootstrap, pc.host, pc.port, deadline)
                            : co_await resolve_local_owned(s, context, dns, pc.host, pc.port, deadline);
                        if (stopped || s.closed || Clock::now() >= deadline || !eps || eps->empty()) co_return false;
                        wireguard::OutboundPeerSpec spec{};
                        spec.peer_public = pc.peer_public;
                        if (pc.psk) {
                            wireguard::SecretKey copy;
                            std::ranges::copy(pc.psk->view(), copy.writable().begin());
                            spec.psk.emplace(std::move(copy));
                        }
                        spec.endpoint = to_udp_endpoint(eps->front());
                        spec.allowed_ips = pc.allowed_ips;
                        spec.mtu = profile.l3.mtu;
                        spec.persistent_keepalive = std::chrono::seconds(pc.keepalive_s);
                        spec.reserved = pc.reserved;
                        spec.on_demand = profile.on_demand;
                        spec.idle_timeout = std::chrono::seconds(profile.idle_timeout_s);
                        if (!multi->add_peer(std::move(spec), now)) co_return false;
                    }
                    co_return true;
                }

                auto ensure_started(Session& s, DnsSlot& dns, Clock::time_point deadline) -> capy::task<bool> {
                    if (stopped || s.closed || Clock::now() >= deadline || profile.peers.empty()) co_return false;
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
                            if (!h.started && !h.loop_active) {
                                if (h.detour) h.detour->close();
                                if (h.multi) h.multi->close();
                                h.multi_udp.close();
                                h.multi.reset();
                                h.port = nullptr;
                                h.port_holder.reset();
                                h.detour.reset();
                            }
                            h.connecting = false;
                            h.ready_event.set();
                        }
                    } fin{*this};

                    if (!via && (profile.peers.size() > 1 || profile.on_demand)) {
                        if (!co_await start_multi(s, dns, deadline)) co_return false;
                    } else {
                        auto const& pc = profile.peers.front();
                        auto eps = profile.bootstrap
                            ? co_await resolve_bootstrap_owned(s, context, dns, *profile.bootstrap, pc.host, pc.port, deadline)
                            : co_await resolve_local_owned(s, context, dns, pc.host, pc.port, deadline);
                        if (stopped || s.closed || Clock::now() >= deadline || !eps || eps->empty()) co_return false;
                        auto const& ep = eps->front();
                        auto target = to_udp_endpoint(ep);
                        if (via) {
                            detour = std::make_unique<WireGuardDetour>(s, context, ep);
                            auto connected = co_await detour->connect(*via, context, deadline);
                            if (!connected || stopped || s.closed || Clock::now() >= deadline) co_return false;
                        }
                        wireguard::PortOptions popts{};
                        popts.business_bytes = 2 * 1024 * 1024;
                        port_holder = std::make_unique<PortHolder>(profile.private_key.view(), popts, pc.reserved);
                        if (!port_holder->value) { port_holder.reset(); co_return false; }
                        port = &*port_holder->value;
                        net::UdpEndpoint local{6, {}, binding.udp_bind_port.value_or(0)};
                        if (target.family == 4 && binding.inet4_bind_address) {
                            local.family = 4; std::ranges::copy(*binding.inet4_bind_address, local.address.begin());
                        } else if (target.family == 6 && binding.inet6_bind_address) {
                            local.address = *binding.inet6_bind_address;
                        }
                        auto now = Clock::now();
                        if (detour) port->transport_socket().attach(target);
                        else port->transport_socket().set_network_namespace(binding.network_namespace);
                        auto opened = detour ? port->open(local, now) :
                            port->open(local, now, Clock::time_point::max(), SocketBinder{binding, deadline});
                        if (!opened || Clock::now() >= deadline) co_return false;
                        wireguard::EndpointConfig ec{};
                        ec.peer_public = pc.peer_public;
                        ec.allowed_ips = pc.allowed_ips;
                        ec.peer = target;
                        ec.mtu = profile.l3.mtu;
                        ec.persistent_keepalive = std::chrono::seconds(pc.keepalive_s);
                        auto ph = pc.psk ? port->add_peer(std::move(ec), pc.psk->view()) : port->add_peer(std::move(ec));
                        if (!ph) { port = nullptr; port_holder.reset(); co_return false; }
                        peer = *ph;
                        for (auto const& prefix : pc.allowed_ips) {
                            if (!port->assign_route(*peer, prefix)) { port = nullptr; port_holder.reset(); co_return false; }
                        }
                        (void)port->request_handshake(*peer, now);
                    }
                    loop_active = true;
                    try {
                        auto keep = shared_from_this();
                        capy::run_async(context.get_executor(), []() noexcept {},
                            [keep](std::exception_ptr) noexcept { keep->stop(); })(run(keep));
                    } catch (...) {
                        loop_active = false;
                        stop();
                        co_return false;
                    }
                    started = !stopped;
                    co_return started;
                }

                auto stop() noexcept -> void {
                    if (stopped) return;
                    stopped = true;
                    stop_src.request_stop();
                    ready_event.set();
                    mux.reset_flows();
                    if (detour) detour->close();
                    if (port) port->stop();
                    if (multi) multi->close();
                    multi_udp.close();
                }
            };

            std::mutex mutex;
            std::unordered_map<io::io_context*, std::shared_ptr<Host>> hosts;
            std::vector<std::pair<io::io_context*, std::shared_ptr<Host>>> retired;
            std::unordered_set<io::io_context*> stopping;

            ~WgProfile() { private_key.clear(); }

            auto get_host(io::io_context& ctx, platform::SocketBinding const& binding, TunnelFactory const* via) -> std::shared_ptr<Host> {
                std::lock_guard lock(mutex);
                std::erase_if(retired, [&](auto const& e) {
                    return e.first == &ctx && (!e.second || (!e.second->loop_active && !e.second->connecting));
                });
                if (auto it = hosts.find(&ctx); it != hosts.end() && it->second) {
                    if (!it->second->stopped) return it->second;
                    if (it->second->loop_active || it->second->connecting) retired.emplace_back(&ctx, std::move(it->second));
                    hosts.erase(it);
                }
                if (stopping.contains(&ctx)) return nullptr;
                auto h = std::make_shared<Host>(ctx, *this, binding, via);
                hosts.emplace(&ctx, h);
                return h;
            }
        };

        using l3_detail::L3Tunnel;
        using WgTunnel = L3Tunnel<WgProfile::Host>;

        auto load_peer(std::string_view host, std::uint16_t port, std::string_view pub_file,
                       std::optional<std::string_view> psk_file, std::span<std::string const> allowed,
                       bool warp, std::array<std::uint8_t, 3> reserved, std::uint16_t keepalive_s)
            -> std::expected<WgPeerConfig, std::string> {
            if (host.empty() || !port) return std::unexpected("invalid WireGuard peer endpoint");
            WgPeerConfig pc;
            pc.host = host; pc.port = port; pc.keepalive_s = keepalive_s;
            auto wp = wireguard::ReservedProfile::create(warp ? wireguard::Provider::warp : wireguard::Provider::standard, reserved);
            if (!wp) return std::unexpected("invalid WireGuard reserved bytes");
            pc.reserved = *wp;
            {
                auto f = rulefile::read_regular_file(pub_file);
                if (!f) return std::unexpected("WireGuard peer-public-key-file: " + f.error());
                if (!encoding::decode_key(std::span(f->data(), f->size()), pc.peer_public))
                    return std::unexpected("WireGuard peer-public-key-file invalid base64");
            }
            if (psk_file) {
                auto f = rulefile::read_private_file(*psk_file);
                if (!f) return std::unexpected("WireGuard preshared-key-file: " + f.error());
                wireguard::SecretKey psk;
                if (!encoding::decode_key(f->bytes(), psk.writable()))
                    return std::unexpected("WireGuard preshared-key-file invalid base64");
                pc.psk.emplace(std::move(psk));
            }
            if (allowed.empty()) {
                pc.allowed_ips = {{4, {}, 0}, {6, {}, 0}};
            } else {
                for (auto const& cidr : allowed) {
                    auto p = parse_allowed_prefix(cidr);
                    if (!p) return std::unexpected("invalid WireGuard allowed-ips CIDR: " + cidr);
                    pc.allowed_ips.push_back(*p);
                }
            }
            return pc;
        }
    }

    auto make_wireguard_factory(config::WireGuardOutbound const& cfg) -> std::expected<TunnelFactory, std::string> {
        if (!cfg.connect_timeout_ms || cfg.connect_timeout_ms > 3600000 || cfg.mtu < 68 || cfg.mtu > 1500 || !cfg.tcp_options.valid())
            return std::unexpected("invalid WireGuard outbound options");
        auto profile = std::make_shared<WgProfile>();
        profile->bootstrap = cfg.bootstrap_index;
        profile->timeout_ms = cfg.connect_timeout_ms;
        profile->l3 = {cfg.has_v4, cfg.local_v4, cfg.has_v6, cfg.local_v6, cfg.mtu};
        profile->on_demand = cfg.on_demand;
        profile->idle_timeout_s = cfg.idle_timeout_s ? cfg.idle_timeout_s : 120;
        profile->options = cfg.tcp_options;
        {
            auto f = rulefile::read_private_file(cfg.private_key_file);
            if (!f) return std::unexpected("WireGuard private-key-file: " + f.error());
            if (!encoding::decode_key(f->bytes(), profile->private_key.writable()))
                return std::unexpected("WireGuard private-key-file invalid base64");
        }
        if (!cfg.peers.empty()) {
            for (auto const& p : cfg.peers) {
                auto psk = p.preshared_key_file ? std::optional<std::string_view>(*p.preshared_key_file) : std::nullopt;
                auto loaded = load_peer(p.host, p.port, p.peer_public_key_file, psk, p.allowed_ips, p.warp, p.reserved, p.keepalive_s);
                if (!loaded) return std::unexpected(loaded.error());
                profile->peers.push_back(std::move(*loaded));
            }
        } else {
            auto psk = cfg.preshared_key_file ? std::optional<std::string_view>(*cfg.preshared_key_file) : std::nullopt;
            auto loaded = load_peer(cfg.host, cfg.port, cfg.peer_public_key_file, psk, {}, cfg.warp, cfg.reserved, cfg.keepalive_s);
            if (!loaded) return std::unexpected(loaded.error());
            profile->peers.push_back(std::move(*loaded));
        }
        TunnelFactory factory{
            [profile](Session& s, io::io_context& ctx, bool relay_local, TcpSocketOptions const* lower) -> pro::proxy<TunnelFacade> {
                auto const& binding = lower ? lower->binding : profile->options.binding;
                auto h = profile->get_host(ctx, binding, nullptr);
                return h ? pro::make_proxy<TunnelFacade, WgTunnel>(s, std::move(h), profile->timeout_ms, relay_local) : pro::proxy<TunnelFacade>{};
            },
            cfg.connect_timeout_ms, [profile](Session& s, io::io_context& ctx, TunnelFactory const& lower, bool relay_local) -> pro::proxy<TunnelFacade> {
                if (profile->peers.size() > 1 || profile->on_demand) return pro::proxy<TunnelFacade>{};
                auto h = profile->get_host(ctx, platform::SocketBinding{}, &lower);
                return h ? pro::make_proxy<TunnelFacade, WgTunnel>(s, std::move(h), profile->timeout_ms, relay_local) : pro::proxy<TunnelFacade>{};
            }, std::nullopt, cfg.tcp_options.configured()};
        factory.stop_context = [profile](io::io_context& ctx) noexcept {
            std::lock_guard lock(profile->mutex);
            try { profile->stopping.insert(&ctx); } catch (...) {}
            if (auto it = profile->hosts.find(&ctx); it != profile->hosts.end() && it->second) it->second->stop();
            for (auto const& [c, h] : profile->retired) if (c == &ctx && h) h->stop();
        };
        factory.quiesced_context = [profile](io::io_context& ctx) noexcept -> bool {
            std::lock_guard lock(profile->mutex);
            auto it = profile->hosts.find(&ctx);
            bool ok = it == profile->hosts.end() || !it->second || (!it->second->loop_active && !it->second->connecting);
            for (auto const& [c, h] : profile->retired) if (c == &ctx && h && (h->loop_active || h->connecting)) ok = false;
            return ok;
        };
        factory.finish_context = [profile](io::io_context& ctx) noexcept {
            std::lock_guard lock(profile->mutex);
            profile->hosts.erase(&ctx);
            std::erase_if(profile->retired, [&](auto const& e) { return e.first == &ctx; });
            profile->stopping.erase(&ctx);
        };
        return factory;
    }

    auto make_wireguard_factory(std::string_view host, std::uint16_t port, std::string_view private_key_file,
        std::string_view peer_public_key_file, std::optional<std::string_view> preshared_key_file,
        bool has_v4, std::array<std::uint8_t, 4> local_v4, bool has_v6, std::array<std::uint8_t, 16> local_v6,
        bool warp, std::array<std::uint8_t, 3> reserved, std::uint16_t mtu, std::uint16_t keepalive_s,
        std::optional<std::size_t> bootstrap, std::uint32_t timeout_ms, TcpSocketOptions options)
        -> std::expected<TunnelFactory, std::string> {
        config::WireGuardOutbound cfg;
        cfg.host = std::string(host); cfg.port = port;
        cfg.private_key_file = std::string(private_key_file);
        cfg.peer_public_key_file = std::string(peer_public_key_file);
        if (preshared_key_file) cfg.preshared_key_file = std::string(*preshared_key_file);
        cfg.has_v4 = has_v4; cfg.local_v4 = local_v4; cfg.has_v6 = has_v6; cfg.local_v6 = local_v6;
        cfg.warp = warp; cfg.reserved = reserved; cfg.mtu = mtu; cfg.keepalive_s = keepalive_s;
        cfg.bootstrap_index = bootstrap; cfg.connect_timeout_ms = timeout_ms; cfg.tcp_options = std::move(options);
        return make_wireguard_factory(cfg);
    }
}
