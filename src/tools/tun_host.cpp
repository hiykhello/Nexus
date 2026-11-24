module;
#include <boost/capy/ex/run_async.hpp>
#include <boost/capy/task.hpp>
#include <boost/capy/when_all.hpp>
#include <boost/corosio/endpoint.hpp>
#include <boost/corosio/io_context.hpp>
#include <boost/corosio/ipv4_address.hpp>
#include <boost/corosio/ipv6_address.hpp>
module cli.tun_host;
import std;
import containers.inplace_vector;
import config;
import cli.dns_fakeip_backend;
import relay;
import relay.stream_relay;
import socks5;
import uot;
import rules;
import net.udp_dial;
import net.datagram_frame;
import net.ordered_datagram;
import dns.message;
import dns.input_budget;
import sniff.udp_quic;
import sniff.tcp;
import sniff.tcp_io;
import sniff.route_tcp;
import platform.ip_address;
import platform.process_owner;
import platform.socket_options;
import platform.linux_random;
import platform.tun_bridge;
import packet;
import packet.mux;
import packet.tun_device;
import packet.tun_pump;
import packet.tun_network_plan;
import packet.tun_network_types;
import cli.tun_device_runtime;
import cli.tun_event_wait;
import cli.tun_network_owner;
import packet.fd;
import packet.tun_network;
import packet.tun_default_policy;
import packet.tun_network_darwin;
import packet.tun_network_windows;
import tcp.connection;
import tcp.table;
import tcp.engine;
import udp;
import udp.route;
import cli.tun_fakeip;
import cli.tun_owner_lookup;
import cli.tun_tcp;
import cli.tun_tcp_dns;
import cli.tun_udp;
import cli.tun_udp_fragments;
import cli.tun_udp_proxy;
import cli.tun_udp_reply_fragments;
import capy;
import corosio;

namespace cli::tun_enabled {
    namespace {
        using Clock = std::chrono::steady_clock;
    }

    struct TunHost::Impl {
        packet::TunRedirectOptions redirect;
        struct TcpFlowSlot {
            capy::async_event read_changed, write_changed;
            bool closed = false;
            auto wake() noexcept -> void { read_changed.set(); write_changed.set(); }
        };
        struct UdpProxyFlow;
        struct UdpReply {
            bool ipv6 = false;
            udp::FlowId flow = 0;
            std::array<std::uint8_t, 16> source{};
            std::uint16_t source_port = 0;
            std::vector<std::uint8_t> payload;
            std::shared_ptr<UdpProxyFlow> owner;
        };
        struct UdpProxyFlow {
            relay::Session session;
            std::unique_ptr<relay::PacketTunnel> tunnel;
            net::DatagramFraming framing{};
            bool needs_uot_request = false;
            uot::Address first_target{};
            Clock::time_point connect_deadline{};
            std::size_t outbound=0;
            bool connected = false, failed = false;
            CachedUdpRoute cached_route{};
            struct Pending { std::vector<std::uint8_t> wire; std::size_t payload_size; Clock::time_point deadline; };
            std::deque<Pending> tx_queue;
            capy::async_event work;
            explicit UdpProxyFlow(corosio::io_context& ctx) : session(ctx) {}
        };
        struct UdpDirectFlow {
            net::UdpDialSockets socket;
            relay::TrafficRegistration traffic;
            std::shared_ptr<relay::RouteSnapshot const> route;
            CachedUdpRoute cached_route{};
            UdpDirectFlow(platform::SocketBinding const* binding,relay::TrafficRegistration registration,
                std::shared_ptr<relay::RouteSnapshot const> snapshot)
                :socket(binding),traffic(std::move(registration)),route(std::move(snapshot)) {}
        };
#ifdef NEXUS_ENABLE_FAKEIP
        struct UdpAliasFlow {
            // Close the socket before the session releases its mapping lease.
            relay::Session session;
            net::UdpDialSockets socket;
            net::UdpEndpoint alias, target;
            UdpAliasFlow(corosio::io_context& context,platform::SocketBinding const* binding,
                net::UdpEndpoint original) : session(context),socket(binding),alias(original) {}
        };
        using UdpAliases=std::unordered_map<udp::FlowId,std::shared_ptr<UdpAliasFlow>>;
        UdpAliases udp4_aliases,udp6_aliases;
#endif
        relay::Server& parent;
        config::TunInbound cfg;
        bool supervise_strict_network;
        relay::Server routing{relay::RoutingOnly{}};
        platform::SocketBinding udp_binding{};
        TunDeviceRuntime device;
        TunEventWait events;
        std::shared_ptr<platform::ExternalTunBridge> bridge_handle;
        Clock::time_point next_udp_sweep{};
        std::atomic_bool tx_notify{false};
        packet::DeviceLimits link_limits;
        packet::MemoryLink link, tcp4_link, udp_link, tcp6_link;
        packet::MemorySwitch mux;
        std::optional<tcp::ConnectionTable> table4;
        std::optional<tcp::ConnectionTable6> table6;
        std::optional<tcp::MemoryEngine> engine4;
        std::optional<tcp::MemoryEngine6> engine6;
        std::optional<udp::RoutedBridge4> udp4;
        std::optional<udp::RoutedBridge6> udp6;
        TunUdpFragments udp_fragments;
        TunUdpReplyFragments udp_reply_fragments;
        TunUdpOwnerCache udp_owner_cache;
        std::uint64_t udp_icmp_window_ms=0;
        unsigned udp_icmp_replies=0;
        std::uint64_t udp_self_loop_drops = 0;
        std::unordered_map<std::uint64_t, std::shared_ptr<TcpFlowSlot>> tcp4_flows, tcp6_flows;
        std::unordered_map<std::uint64_t, std::unique_ptr<UdpDirectFlow>> udp4_direct, udp6_direct;
        using UdpProxyFlows=std::unordered_map<udp::FlowId,std::vector<std::shared_ptr<UdpProxyFlow>>>;
        UdpProxyFlows udp4_proxy, udp6_proxy;
        std::deque<UdpReply> udp_replies;
        std::unique_ptr<std::uint8_t[]> udp_poll_buf;
        std::uint64_t last_udp_expire_ms = 0;
        std::array<std::uint64_t, 2> iss_key_{};
        std::uint64_t iss_counter_ = 0;
        bool iss_seeded_ = false, in_blocking_poll_ = false;
        std::thread::id pump_thread_id_{};
        std::atomic_bool stop_flag{false}, draining_flag{false}, failed_flag{false};
        std::atomic<std::size_t> active_flows{0};
        std::optional<std::string> failure_msg;
        std::mutex failure_mutex;
        std::thread worker;

        Impl(relay::Server& src, config::TunInbound opts,bool supervised)
            : parent(src), cfg(std::move(opts)),supervise_strict_network(supervised),
            link_limits{std::max<std::size_t>(cfg.mtu, 1500), 256, 512 * 1024},
            link(link_limits), tcp4_link(link_limits), udp_link(link_limits), tcp6_link(link_limits),
            mux(link, tcp4_link, udp_link, tcp6_link,true) {
            udp_binding.routing_mark = cfg.socket_mark;
        }

        auto record_failure(std::string msg) -> void {
            std::lock_guard lock(failure_mutex);
            if (!failure_msg) failure_msg = std::move(msg);
            failed_flag.store(true, std::memory_order_release);
        }

        auto udp_rx_buffer() -> std::span<std::uint8_t, 65536> {
            if (!udp_poll_buf) udp_poll_buf = std::make_unique_for_overwrite<std::uint8_t[]>(65536);
            return std::span<std::uint8_t, 65536>(udp_poll_buf.get(), 65536);
        }

        auto next_iss(std::uint64_t now) noexcept -> std::uint32_t {
            std::uint64_t x = iss_key_[0] ^ (++iss_counter_ * 0x9e3779b97f4a7c15ull) ^ (now * 0xbf58476d1ce4e5b9ull);
            x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9ull;
            x = (x ^ (x >> 27)) * 0x94d049bb133111ebull;
            return static_cast<std::uint32_t>((x ^ (x >> 31)) ^ iss_key_[1]);
        }

        auto notify_tx() noexcept -> void {
            tx_notify.store(true, std::memory_order_release);
            if (std::this_thread::get_id() == pump_thread_id_) { if (in_blocking_poll_) events.wake_local(); }
            else events.notify_async();
        }

        auto queue_udp_reply(packet::Bytes bytes) -> bool {
            bool ok = udp_reply_fragments.send(udp_link,std::move(bytes),cfg.mtu);
            if (ok) notify_tx();
            return ok;
        }

        template<bool IsV6>
        auto step_tcp(std::uint64_t now, std::uint32_t iss) -> bool {
            auto& eng = [&]() -> auto& { if constexpr (IsV6) return *engine6; else return *engine4; }();
            auto& tbl = [&]() -> auto& { if constexpr (IsV6) return *table6; else return *table4; }();
            auto& flows = [&]() -> auto& { if constexpr (IsV6) return tcp6_flows; else return tcp4_flows; }();
            auto res = eng.step(now, iss);
            if (!res) return false;
            bool moved = res->input || res->delivered;
            if (res->id) {
                auto cid = *res->id;
                if (auto* conn = tbl.get(cid); conn && !conn->send_closed() && !tbl.is_detached(cid) && !flows.contains(cid) &&
                    (conn->state() == tcp::ConnectionState::established || conn->state() == tcp::ConnectionState::peer_closed)) {
                    if (draining_flag.load(std::memory_order_acquire)) TunTcpOps::reset_or_abort(*this, tbl, eng, cid);
                    else {
                        auto slot = std::make_shared<TcpFlowSlot>();
                        flows.emplace(cid, slot);
                        capy::run_async(routing.executor_context().get_executor(), [] {}, [&tbl, &flows, cid, slot](std::exception_ptr) noexcept {
                            slot->closed = true; slot->wake(); if (flows.erase(cid)) (void)tbl.abort(cid);
                        })(TunTcpOps::handle_tcp<Impl, IsV6>(*this, cid, slot));
                    }
                }
            }
            auto svc = eng.service(now);
            if (svc && svc->output.delivered) moved = true;
            if (res->id) if (auto it = flows.find(*res->id); it != flows.end()) it->second->wake();
            if (svc && svc->id) if (auto it = flows.find(*svc->id); it != flows.end()) it->second->wake();
            return moved;
        }

        auto valid_output(packet::QueuedPacket const& output) const noexcept -> bool {
            if (output.generation && !output.generation->valid) return false;
            if (output.kind == packet::PacketKind::ordinary) return true;
            if (output.kind == packet::PacketKind::stateful_tcp_reset && !output.flow_id) return false;
            auto check = [&](std::optional<tcp::ConnectionId> cur) {
                return !cur || (output.kind == packet::PacketKind::stateful_tcp_reset && *cur == output.flow_id);
            };
            if (auto v = packet::parse_tcp4(output.bytes)) {
                std::swap(v->source, v->destination); std::swap(v->source_port, v->destination_port);
                return check(table4->find(*v));
            }
            if (auto v = packet::parse_tcp6(output.bytes)) {
                std::swap(v->source, v->destination); std::swap(v->source_port, v->destination_port);
                return check(table6->find(*v));
            }
            return false;
        }

        auto device_name() const noexcept -> std::string_view { return device.device_name(); }

        auto init_engines_and_spawn() -> std::expected<void, std::string> {
            auto t4 = tcp::ConnectionTable::create(cfg.tcp_flows, cfg.tcp_buffer);
            auto t6 = tcp::ConnectionTable6::create(cfg.tcp_flows, cfg.tcp_buffer);
            if (!t4 || !t6) return std::unexpected("failed initializing TUN TCP tables");
            table4.emplace(std::move(*t4)); table6.emplace(std::move(*t6));
            engine4.emplace(tcp4_link, *table4, rules::Matcher{}, cfg.mtu);
            engine6.emplace(tcp6_link, *table6, rules::Matcher{}, cfg.mtu);
            auto map = cfg.endpoint_independent_nat ? udp::Mapping::endpoint_independent : udp::Mapping::address_port_dependent;
            auto filtering=udp::Filtering::address_port_dependent;
            if (cfg.udp_filtering==config::TunUdpFiltering::address_dependent) filtering=udp::Filtering::address_dependent;
            if (cfg.udp_filtering==config::TunUdpFiltering::endpoint_independent) filtering=udp::Filtering::endpoint_independent;
            udp::RetirementHandler r4{this, [](void* ctx, udp::FlowId id) noexcept {
                auto* h = static_cast<Impl*>(ctx);
                if (auto it = h->udp4_direct.find(id); it != h->udp4_direct.end())
                    h->events.unwatch_udp(it->second->socket.native_handles());
                h->udp4_direct.erase(id);
#ifdef NEXUS_ENABLE_FAKEIP
                if (auto it = h->udp4_aliases.find(id); it != h->udp4_aliases.end())
                    h->events.unwatch_udp(it->second->socket.native_handles());
                TunFakeIpOps::retire_udp_alias(h->udp4_aliases,id);
#endif
                if (auto it = h->udp4_proxy.find(id); it != h->udp4_proxy.end())
                    for (auto const& flow:it->second) { flow->failed=true; flow->work.set(); flow->tunnel->cancel(); }
            }};
            udp::RetirementHandler r6{this, [](void* ctx, udp::FlowId id) noexcept {
                auto* h = static_cast<Impl*>(ctx);
                if (auto it = h->udp6_direct.find(id); it != h->udp6_direct.end())
                    h->events.unwatch_udp(it->second->socket.native_handles());
                h->udp6_direct.erase(id);
#ifdef NEXUS_ENABLE_FAKEIP
                if (auto it = h->udp6_aliases.find(id); it != h->udp6_aliases.end())
                    h->events.unwatch_udp(it->second->socket.native_handles());
                TunFakeIpOps::retire_udp_alias(h->udp6_aliases,id);
#endif
                if (auto it = h->udp6_proxy.find(id); it != h->udp6_proxy.end())
                    for (auto const& flow:it->second) { flow->failed=true; flow->work.set(); flow->tunnel->cancel(); }
            }};
            udp::Limits ul{cfg.tcp_flows, 32, cfg.udp_idle_ms};
            auto reply_mtu=cfg.udp_reply_fragment ? std::size_t{65575} : cfg.mtu;
            if (cfg.udp_reply_fragment && !udp_reply_fragments.seed())
                return std::unexpected("cannot initialize TUN fragment identification");
            udp4.emplace(rules::Matcher{}, map, filtering, ul, reply_mtu, r4);
            udp6.emplace(rules::Matcher{}, map, filtering, ul, reply_mtu, r6);
            return {};
        }

        bool start_attempted=false;

        auto start_bridge(std::shared_ptr<platform::ExternalTunBridge> bridge) -> std::expected<std::string,std::string> {
            if (stop_flag.load(std::memory_order_acquire) || std::exchange(start_attempted,true))
                return std::unexpected("TUN startup already attempted");
            struct Rollback {
                Impl& host;
                bool started=false;
                ~Rollback() {if (!started) host.stop();}
            } rollback{*this};
            routing.inherit_routing(parent, 0, 1, cfg.socket_mark);
            if (auto ok=routing.prepare_routing(1,false);!ok) return std::unexpected(ok.error().message());
            if (auto ok=routing.activate_context();!ok) return std::unexpected(ok.error().message());
            auto started = device.start_bridge(bridge, link, cfg.mtu);
            if (!started) return std::unexpected(started.error());
            if (auto err = init_engines_and_spawn(); !err) return std::unexpected(err.error());
            bridge_handle = std::move(bridge);
            events.start(routing.executor_context(), -1);
            bridge_handle->set_wake_callback([](void* ctx) noexcept {
                static_cast<TunEventWait*>(ctx)->notify_async();
            }, &events);
            worker = std::thread([this] { pump_loop(); });
            rollback.started=true;
            return *started;
        }

        auto start(std::optional<packet::PlatformTun> supplied={}) -> std::expected<std::string,std::string> {
            if (stop_flag.load(std::memory_order_acquire) || std::exchange(start_attempted,true))
                return std::unexpected("TUN startup already attempted");
            struct Rollback {
                Impl& host;
                bool started=false;
                ~Rollback() {if (!started) host.stop();}
            } rollback{*this};
#if defined(__linux__)
            if (supplied && (supplied->native_handle()<0 || cfg.inet4_address || cfg.inet6_address ||
                cfg.auto_route || cfg.strict_route || (!cfg.interface_name.empty() && cfg.interface_name!=supplied->name())))
                return std::unexpected("external TUN requires a prepared device and matching interface name");
            routing.inherit_routing(parent, 0, 1, cfg.socket_mark);
            std::optional<std::uint16_t> redirect_port;
            if (cfg.auto_redirect) {
                if (!supervise_strict_network || !cfg.strict_route)
                    return std::unexpected("TUN auto-redirect requires a supervised strict-route");
                auto port=routing.start_tun_redirect(cfg.inet4_address.has_value(),cfg.inet6_address.has_value(),cfg.dns_hijack_tcp);
                if (!port) return std::unexpected("TUN auto-redirect listener: "+port.error().message());
                redirect_port = *port;
            } else {
                if (auto ok=routing.prepare_routing(1,false);!ok) return std::unexpected(ok.error().message());
                if (auto ok=routing.activate_context();!ok) return std::unexpected(ok.error().message());
            }
            if (cfg.host_dns_resolved && (!supervise_strict_network || !cfg.strict_route))
                return std::unexpected("TUN host-dns requires a supervised strict-route and a DNS stub");
            auto req = device.prepare_linux_request(cfg, redirect, redirect_port);
            if (!req) return std::unexpected(std::move(req.error()));
            auto name = device.start_linux_device(cfg, link, supervise_strict_network, *req, std::move(supplied));
            if (!name) return std::unexpected(std::move(name.error()));
            if (auto err = init_engines_and_spawn(); !err) return std::unexpected(err.error());
            if (auto st = device.activate_strict_policy(); !st) return std::unexpected(std::move(st.error()));
            events.start(routing.executor_context(), device.native_fd(), device.uring_fd());
#else
            routing.inherit_routing(parent, 0, 1, cfg.socket_mark);
            if (auto ok=routing.prepare_routing(1,false);!ok) return std::unexpected(ok.error().message());
            if (auto ok=routing.activate_context();!ok) return std::unexpected(ok.error().message());
            auto name = device.start_other_device(cfg, link, std::move(supplied));
            if (!name) return std::unexpected(std::move(name.error()));
            if (auto err = init_engines_and_spawn(); !err) return std::unexpected(err.error());
            events.start(routing.executor_context(), device.native_fd(), device.uring_fd());
#endif
            worker = std::thread([this] { pump_loop(); });
            rollback.started=true;
            return *name;
        }

        auto pump_loop() noexcept -> void {
            pump_thread_id_ = std::this_thread::get_id();
            auto validate = [](void* ctx, packet::QueuedPacket const& out) noexcept {
                return static_cast<Impl*>(ctx)->valid_output(out);
            };
            Clock::time_point next_policy_check{};
            try {
                while (!stop_flag.load(std::memory_order_acquire)) {
                    if ((device.has_policy_health() || cfg.auto_redirect) && Clock::now() >= next_policy_check) {
                        if (!device.check_policy_health() || (cfg.auto_redirect && !routing.healthy())) {
                            record_failure("TUN strict-route policy changed");
                            break;
                        }
                        next_policy_check = Clock::now() + std::chrono::milliseconds(100);
                    }
                    tx_notify.store(false, std::memory_order_relaxed);
                    auto now = now_ms();
                    bool active = false;
                    for (int round = 0; round < 32; ++round) {
                        auto dev = device.step(validate, this);
                        if (dev.fatal_error) {
                            record_failure(dev.error_detail.empty() ? "TUN device error" : std::move(dev.error_detail));
                            stop_flag.store(true, std::memory_order_release);
                            break;
                        }
                        auto sw = mux.step();
                        if (!iss_seeded_ && (dev.input_delivered || (sw && sw->input_delivered))) {
                            if (!platform::secure_random(std::as_writable_bytes(std::span(iss_key_)))) {
                                record_failure("TUN random failure"); stop_flag.store(true, std::memory_order_release); break;
                            }
                            iss_seeded_ = true;
                        }
                        auto iss = iss_seeded_ ? next_iss(now) : std::uint32_t{0};
                        bool t4 = step_tcp<false>(now, iss);
                        bool t6 = step_tcp<true>(now, iss);
                        bool ui = TunUdpOps::process_udp_inputs(*this, now);
                        bool uo = TunUdpOps::poll_udp_outputs(*this, now);
                        bool moved = dev.input_delivered || dev.output_delivered || (sw && (sw->input_delivered || sw->output_delivered)) || t4 || t6 || ui || uo;
                        if (!moved) break;
                        active = true;
                    }
                    active_flows.store(tcp4_flows.size() + tcp6_flows.size() +
                        udp4_direct.size() + udp6_direct.size() +
                        udp4_proxy.size() + udp6_proxy.size(), std::memory_order_release);
                    if (stop_flag.load(std::memory_order_acquire)) break;
                    if (active || tx_notify.exchange(false, std::memory_order_acq_rel)) {
                        routing.poll(std::chrono::milliseconds(0));
                    } else {
                        if (!device.has_uring_rx()) events.stop_uring();
                        events.arm();
                        bool no_tcp = tcp4_flows.empty() && tcp6_flows.empty();
                        bool has_udp_or_policy = !udp4_direct.empty() || !udp6_direct.empty() ||
                            !udp4_proxy.empty() || !udp6_proxy.empty() || device.has_policy_health() || cfg.auto_redirect;
                        auto wait_ms = no_tcp ? std::chrono::milliseconds(has_udp_or_policy ? 100 : 500)
                                              : std::chrono::milliseconds(10);
                        struct PollGuard { bool& f; ~PollGuard() { f = false; } } poll_guard{in_blocking_poll_};
                        in_blocking_poll_ = true;
                        routing.poll(wait_ms);
                        in_blocking_poll_ = false;
                        events.drain_wake();
                    }
                }
            } catch (std::bad_alloc const&) {
                record_failure("TUN out of memory");
            } catch (std::exception const& ex) {
                record_failure(std::string("TUN runtime error: ") + ex.what());
            } catch (...) {
                record_failure("TUN unexpected error");
            }
            active_flows.store(0, std::memory_order_release);
            for (auto& [id, s] : tcp4_flows) { s->closed = true; s->wake(); }
            for (auto& [id, s] : tcp6_flows) { s->closed = true; s->wake(); }
            for (auto* flows:{&udp4_proxy,&udp6_proxy})
                for (auto& [id,slots]:*flows)
                    for (auto const& flow:slots) { flow->failed=true; flow->work.set(); flow->tunnel->cancel(); }
            if (bridge_handle) bridge_handle->set_wake_callback(nullptr, nullptr);
            events.stop();
            routing.stop();
#ifdef NEXUS_ENABLE_FAKEIP
            udp4_aliases.clear();
            udp6_aliases.clear();
#endif
            udp_replies.clear();
            udp4_direct.clear(); udp6_direct.clear();
            release_device();
        }

        auto release_device() noexcept -> void {
            std::string err;
            bool had = failed_flag.load(std::memory_order_acquire);
            device.release(err, had);
            if (!err.empty() && !failed_flag.load(std::memory_order_acquire))
                record_failure(std::move(err));
        }

        auto stop() noexcept -> void {
            stop_flag.store(true, std::memory_order_release);
            if (bridge_handle) bridge_handle->set_wake_callback(nullptr, nullptr);
            events.notify_async();
            if (worker.joinable()) worker.join();
            else { events.stop(); routing.stop(); release_device(); }
        }
    };

    TunHost::TunHost(relay::Server& src, config::TunInbound opts, bool supervised, packet::TunRedirectOptions redirect)
        : impl_(std::make_unique<Impl>(src, std::move(opts), supervised)) { impl_->redirect = redirect; }
    TunHost::~TunHost() { stop(); }
    auto TunHost::start() -> std::expected<std::string, std::string> { return impl_->start(); }
    auto TunHost::start(packet::PlatformTun device) -> std::expected<std::string, std::string> { return impl_->start(std::move(device)); }
    auto TunHost::start(std::shared_ptr<platform::ExternalTunBridge> bridge) -> std::expected<std::string, std::string> {
        return impl_->start_bridge(std::move(bridge));
    }
    auto TunHost::healthy() const noexcept -> bool { return !impl_->failed_flag.load(std::memory_order_acquire); }
    auto TunHost::queue_outbound_probe(std::shared_ptr<relay::OutboundProbe> probe) -> bool { return impl_->routing.queue_outbound_probe(std::move(probe)); }
    auto TunHost::failure() const -> std::optional<std::string> { std::lock_guard lock(impl_->failure_mutex); return impl_->failure_msg; }
    auto TunHost::begin_drain() noexcept -> void { if (impl_) impl_->draining_flag.store(true, std::memory_order_release); }
    auto TunHost::drained() const noexcept -> bool {
        return !impl_ || !impl_->worker.joinable() || impl_->active_flows.load(std::memory_order_acquire) == 0;
    }
    auto TunHost::stop() noexcept -> void { if (impl_) impl_->stop(); }
}
