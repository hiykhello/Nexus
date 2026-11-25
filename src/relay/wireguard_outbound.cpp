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
import platform.linux_random;
import platform.socket_options;
import wireguard;
import wireguard.crypto;
import wireguard.endpoint;
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

        struct SocketBinder {
            platform::SocketBinding const& binding;
            Clock::time_point deadline;
            auto operator()(int fd) const noexcept -> std::error_code {
                return binding.configured() ? platform::apply_socket_binding(fd, binding, true, deadline) : std::error_code{};
            }
        };

        struct WgProfile {
            std::string host;
            std::uint16_t port = 51820;
            std::optional<std::size_t> bootstrap;
            std::uint32_t timeout_ms = 10000;
            wireguard::SecretKey private_key;
            wireguard::Key peer_public{};
            std::optional<wireguard::SecretKey> psk;
            L3Endpoint l3{};
            wireguard::ReservedProfile wire_profile{};
            std::uint16_t keepalive_s = 0;
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
                L3Mux mux;
                bool started = false, connecting = false, stopped = false, loop_active = false;
                std::optional<wireguard::PeerHandle> peer;
                std::stop_source stop_src;
                capy::async_event ready_event;

                static auto send_ip(void* ctx, std::span<std::uint8_t const> pkt) -> bool {
                    auto* h = static_cast<Host*>(ctx);
                    if (!h->port || h->stopped) return false;
                    return h->port->enqueue_ip(pkt, Clock::now()).has_value();
                }

                Host(io::io_context& ctx, WgProfile const& p, platform::SocketBinding selected, TunnelFactory const* lower)
                    : context(ctx), profile(p), binding(std::move(selected)), via(lower), mux(p.l3, &Host::send_ip, this) {}

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
                    struct Guard {
                        Host& host;
                        ~Guard() { host.loop_active = false; }
                    } guard{*h};
                    if (h->detour) {
                        (void)co_await capy::when_all(poll_loop(h.get()), detour_io(h.get(), true), detour_io(h.get(), false));
                    } else {
                        (void)co_await poll_loop(h.get());
                    }
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
                        Host& h;
                        ~Fin() {
                            if (!h.started && !h.loop_active) {
                                if (h.detour) h.detour->close();
                                h.port = nullptr;
                                h.port_holder.reset();
                                h.detour.reset();
                            }
                            h.connecting = false;
                            h.ready_event.set();
                        }
                    } fin{*this};
                    auto eps = profile.bootstrap
                        ? co_await resolve_bootstrap_owned(s, context, dns, *profile.bootstrap, profile.host, profile.port, deadline)
                        : co_await resolve_local_owned(s, context, dns, profile.host, profile.port, deadline);
                    if (stopped || s.closed || Clock::now() >= deadline || !eps || eps->empty()) co_return false;
                    net::UdpEndpoint target{};
                    auto const& ep = eps->front();
                    target.port = ep.port();
                    if (ep.address().is_v4()) {
                        target.family = 4;
                        auto b = ep.address().to_v4().to_bytes();
                        std::ranges::copy(b, target.address.begin());
                    } else {
                        target.family = 6;
                        target.address = ep.address().to_v6().to_bytes();
                    }
                    if (via) {
                        detour = std::make_unique<WireGuardDetour>(s, context, ep);
                        auto connected = co_await detour->connect(*via, context, deadline);
                        if (!connected || stopped || s.closed || Clock::now() >= deadline) co_return false;
                    }
                    wireguard::PortOptions popts{};
                    popts.business_bytes = 2 * 1024 * 1024;
                    port_holder = std::make_unique<PortHolder>(profile.private_key.view(), popts, profile.wire_profile);
                    if (!port_holder->value) { port_holder.reset(); co_return false; }
                    port = &*port_holder->value;
                    net::UdpEndpoint local{6, {}, binding.udp_bind_port.value_or(0)};
                    if (target.family == 4 && binding.inet4_bind_address) {
                        local.family = 4;
                        std::ranges::copy(*binding.inet4_bind_address, local.address.begin());
                    } else if (target.family == 6 && binding.inet6_bind_address) {
                        local.address = *binding.inet6_bind_address;
                    }
                    auto now = Clock::now();
                    if (detour) port->transport_socket().attach(target);
                    else port->transport_socket().set_network_namespace(binding.network_namespace);
                    auto opened = detour ? port->open(local, now) :
                        port->open(local, now, Clock::time_point::max(), SocketBinder{binding,deadline});
                    if (!opened || Clock::now()>=deadline) co_return false;
                    wireguard::EndpointConfig ec{};
                    ec.peer_public = profile.peer_public;
                    ec.allowed_ips = {{4, {}, 0}, {6, {}, 0}};
                    ec.peer = target;
                    ec.mtu = profile.l3.mtu;
                    ec.persistent_keepalive = std::chrono::seconds(profile.keepalive_s);
                    auto ph = profile.psk ? port->add_peer(std::move(ec), profile.psk->view()) : port->add_peer(std::move(ec));
                    if (!ph) { port = nullptr; port_holder.reset(); co_return false; }
                    peer = *ph;
                    if (!port->assign_route(*peer, {4, {}, 0}) || !port->assign_route(*peer, {6, {}, 0})) {
                        port = nullptr; port_holder.reset(); co_return false;
                    }
                    (void)port->request_handshake(*peer, now);
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
                }
            };

            std::mutex mutex;
            std::unordered_map<io::io_context*, std::shared_ptr<Host>> hosts;
            std::vector<std::pair<io::io_context*, std::shared_ptr<Host>>> retired;
            std::unordered_set<io::io_context*> stopping;

            ~WgProfile() {
                private_key.clear();
                if (psk) psk->clear();
            }

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
    }

    auto make_wireguard_factory(std::string_view host, std::uint16_t port, std::string_view private_key_file,
        std::string_view peer_public_key_file, std::optional<std::string_view> preshared_key_file,
        bool has_v4, std::array<std::uint8_t, 4> local_v4, bool has_v6, std::array<std::uint8_t, 16> local_v6,
        bool warp, std::array<std::uint8_t, 3> reserved, std::uint16_t mtu, std::uint16_t keepalive_s,
        std::optional<std::size_t> bootstrap, std::uint32_t timeout_ms, TcpSocketOptions options)
        -> std::expected<TunnelFactory, std::string> {
        if (host.empty() || !port || !timeout_ms || timeout_ms > 3600000 || mtu < 68 || mtu > 1500 || !options.valid())
            return std::unexpected("invalid WireGuard outbound options");
        auto profile = std::make_shared<WgProfile>();
        profile->host = host;
        profile->port = port;
        profile->bootstrap = bootstrap;
        profile->timeout_ms = timeout_ms;
        profile->l3 = {has_v4, local_v4, has_v6, local_v6, mtu};
        profile->keepalive_s = keepalive_s;
        profile->options = options;
        auto wp = wireguard::ReservedProfile::create(warp ? wireguard::Provider::warp : wireguard::Provider::standard, reserved);
        if (!wp) return std::unexpected("invalid WireGuard reserved bytes");
        profile->wire_profile = *wp;
        {
            auto f = rulefile::read_private_file(private_key_file);
            if (!f) return std::unexpected("WireGuard private-key-file: " + f.error());
            if (!encoding::decode_key(f->bytes(), profile->private_key.writable()))
                return std::unexpected("WireGuard private-key-file invalid base64");
        }
        {
            auto f = rulefile::read_regular_file(peer_public_key_file);
            if (!f) return std::unexpected("WireGuard peer-public-key-file: " + f.error());
            if (!encoding::decode_key(std::span(f->data(), f->size()), profile->peer_public))
                return std::unexpected("WireGuard peer-public-key-file invalid base64");
        }
        if (preshared_key_file) {
            auto f = rulefile::read_private_file(*preshared_key_file);
            if (!f) return std::unexpected("WireGuard preshared-key-file: " + f.error());
            wireguard::SecretKey psk;
            if (!encoding::decode_key(f->bytes(), psk.writable()))
                return std::unexpected("WireGuard preshared-key-file invalid base64");
            profile->psk.emplace(std::move(psk));
        }
        TunnelFactory factory{
            [profile](Session& s, io::io_context& ctx, bool relay_local, TcpSocketOptions const* lower) -> pro::proxy<TunnelFacade> {
                auto const& binding = lower ? lower->binding : profile->options.binding;
                auto h = profile->get_host(ctx, binding, nullptr);
                return h ? pro::make_proxy<TunnelFacade, WgTunnel>(s, std::move(h), profile->timeout_ms, relay_local) : pro::proxy<TunnelFacade>{};
            },
            timeout_ms, [profile](Session& s, io::io_context& ctx, TunnelFactory const& lower, bool relay_local) -> pro::proxy<TunnelFacade> {
                auto h = profile->get_host(ctx, platform::SocketBinding{}, &lower);
                return h ? pro::make_proxy<TunnelFacade, WgTunnel>(s, std::move(h), profile->timeout_ms, relay_local) : pro::proxy<TunnelFacade>{};
            }, std::nullopt, options.configured()};
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
}
