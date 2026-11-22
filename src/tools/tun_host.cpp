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
import nexus.compat;
import config;
import cli.dns_fakeip_backend;
import cli.tun_network_owner;
import proxy;
import proxy.stream_relay;
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
import platform.socket_options;
import platform.linux_random;
import packet;
import packet.mux;
import packet.fd;
import packet.tun_linux;
import packet.tun_network_types;
import packet.tun_network;
import packet.tun_default_policy;
import tcp.connection;
import tcp.table;
import tcp.engine;
import udp;
import udp.route;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;

#include "tun_udp_fragments.hpp"
#include "tun_udp_reply_fragments.hpp"

namespace cli::tun_enabled {
    namespace {
        using Clock = std::chrono::steady_clock;

        auto now_ms() noexcept -> std::uint64_t {
            return static_cast<std::uint64_t>(
                std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now().time_since_epoch()).count());
        }

        auto parse_cidr_addr(std::string_view text, bool ipv6) -> std::optional<packet::TunAddress> {
            auto slash = text.find('/');
            if (slash == std::string_view::npos) return std::nullopt;
            unsigned pfx = 0;
            auto ps = text.substr(slash + 1);
            auto [end, ec] = std::from_chars(ps.data(), ps.data() + ps.size(), pfx);
            auto parsed = platform::parse_ip_address(text.substr(0, slash));
            if (ec != std::errc{} || end != ps.data() + ps.size() || !parsed || (parsed->size == 16) != ipv6)
                return std::nullopt;
            packet::TunAddress out{.family = static_cast<std::uint8_t>(ipv6 ? 6 : 4), .prefix = static_cast<std::uint8_t>(pfx)};
            std::copy_n(parsed->bytes.begin(), parsed->size, out.bytes.begin());
            return out;
        }

        auto mask_network(packet::TunAddress addr) noexcept -> packet::TunAddress {
            std::size_t n = addr.family == 6 ? 16 : 4;
            std::size_t keep = addr.prefix / 8, rem = addr.prefix % 8;
            if (keep < n && rem) addr.bytes[keep] &= static_cast<std::uint8_t>(255u << (8 - rem));
            for (std::size_t i = keep + (rem != 0); i < n; ++i) addr.bytes[i] = 0;
            return addr;
        }
    }

    struct TunHost::Impl {
        packet::TunRedirectOptions redirect;
        struct TcpFlowSlot {
            nex::capy::async_event changed;
            bool closed = false;
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
            proxy::Session session;
            std::unique_ptr<proxy::PacketTunnel> tunnel;
            net::DatagramFraming framing{};
            bool needs_uot_request = false;
            uot::Address first_target{};
            Clock::time_point connect_deadline{};
            std::size_t outbound=0;
            bool connected = false, failed = false;
            struct Pending {
                std::vector<std::uint8_t> wire;
                std::size_t payload_size;
                Clock::time_point deadline;
            };
            std::deque<Pending> tx_queue;
            nex::capy::async_event work;
            explicit UdpProxyFlow(nex::corosio::io_context& ctx) : session(ctx) {}
        };
        struct UdpDirectFlow {
            net::UdpDialSockets socket;
            proxy::TrafficRegistration traffic;
            std::shared_ptr<proxy::RouteSnapshot const> route;
            UdpDirectFlow(platform::SocketBinding const* binding,proxy::TrafficRegistration registration,
                std::shared_ptr<proxy::RouteSnapshot const> snapshot)
                :socket(binding),traffic(std::move(registration)),route(std::move(snapshot)) {}
        };
#ifdef NEXUS_ENABLE_FAKEIP
        struct UdpAliasFlow {
            // Close the socket before the session releases its mapping lease.
            proxy::Session session;
            net::UdpDialSockets socket;
            net::UdpEndpoint alias, target;
            UdpAliasFlow(nex::corosio::io_context& context,platform::SocketBinding const* binding,
                net::UdpEndpoint original) : session(context),socket(binding),alias(original) {}
        };
        using UdpAliases=std::unordered_map<udp::FlowId,std::shared_ptr<UdpAliasFlow>>;
        UdpAliases udp4_aliases,udp6_aliases;
#endif
        proxy::Server& parent;
        config::TunInbound cfg;
        bool supervise_strict_network;
        proxy::Server routing{proxy::RoutingOnly{}};
        platform::SocketBinding udp_binding{};
        std::optional<packet::LinuxTun> tun;
        std::optional<packet::TunNetworkLease<>> lease;
        std::optional<packet::TunDefaultPolicy<>> default_policy;
        std::optional<StrictTunOwner> network_owner;
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
        std::uint64_t udp_icmp_window_ms=0;
        unsigned udp_icmp_replies=0;
        std::optional<packet::FdPump> pump;
        std::unordered_map<std::uint64_t, std::shared_ptr<TcpFlowSlot>> tcp4_flows, tcp6_flows;
        std::unordered_map<std::uint64_t, std::unique_ptr<UdpDirectFlow>> udp4_direct, udp6_direct;
        using UdpProxyFlows=std::unordered_map<udp::FlowId,std::vector<std::shared_ptr<UdpProxyFlow>>>;
        UdpProxyFlows udp4_proxy, udp6_proxy;
        std::deque<UdpReply> udp_replies;
        std::atomic_bool stop_flag{false}, failed_flag{false};
        std::optional<std::string> failure_msg;
        std::mutex failure_mutex;
        std::thread worker;

        Impl(proxy::Server& src, config::TunInbound opts,bool supervised)
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

        auto queue_udp_reply(packet::Bytes bytes) -> bool {
            return udp_reply_fragments.send(udp_link,std::move(bytes),cfg.mtu);
        }

#include "tun_tcp.hpp"
#include "tun_fakeip.hpp"
#include "tun_udp.hpp"

        template<bool IsV6>
        auto step_tcp(std::uint64_t now, std::uint32_t iss) -> bool {
            auto& eng = [&]() -> auto& { if constexpr (IsV6) return *engine6; else return *engine4; }();
            auto& tbl = [&]() -> auto& { if constexpr (IsV6) return *table6; else return *table4; }();
            auto& flows = [&]() -> auto& { if constexpr (IsV6) return tcp6_flows; else return tcp4_flows; }();
            auto res = eng.step(now, iss);
            if (!res) return false;
            bool moved = res->input || res->delivered;
            if (res->id) {
                if (auto* conn = tbl.get(*res->id);
                    conn && (conn->state() == tcp::ConnectionState::established || conn->state() == tcp::ConnectionState::peer_closed) &&
                    !conn->send_closed() && !flows.contains(*res->id)) {
                    auto slot = std::make_shared<TcpFlowSlot>();
                    flows.emplace(*res->id, slot);
                    nex::capy::run_async(routing.executor_context().get_executor(), [] {}, [slot](std::exception_ptr) noexcept {
                        slot->closed = true; slot->changed.set();
                    })(handle_tcp<IsV6>(*res->id, slot));
                }
            }
            auto svc = eng.service(now);
            if (svc && svc->output.delivered) moved = true;
            for (auto& [id, slot] : flows) slot->changed.set();
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

        bool start_attempted=false;

        auto start(std::optional<packet::LinuxTun> supplied={}) -> std::expected<std::string,std::string> {
            if (stop_flag.load(std::memory_order_acquire) || std::exchange(start_attempted,true))
                return std::unexpected("TUN startup already attempted");
            struct Rollback {
                Impl& host;
                bool started=false;
                ~Rollback() {if (!started) host.stop();}
            } rollback{*this};
            if (supplied && (supplied->native_handle()<0 || cfg.inet4_address || cfg.inet6_address ||
                cfg.auto_route || cfg.strict_route || (!cfg.interface_name.empty() && cfg.interface_name!=supplied->name())))
                return std::unexpected("external TUN requires a prepared device and matching interface name");
            routing.inherit_routing(parent, 0, 1, cfg.socket_mark);
            StrictTunRequest request;
            if (cfg.auto_redirect) {
                if (!supervise_strict_network || !cfg.strict_route)
                    return std::unexpected("TUN auto-redirect requires a supervised strict-route");
                auto port=routing.start_tun_redirect(cfg.inet4_address.has_value(),cfg.inet6_address.has_value(),cfg.dns_hijack_tcp);
                if (!port) return std::unexpected("TUN auto-redirect listener: "+port.error().message());
                request.redirect=redirect;
                request.redirect.port=*port;
                request.redirect.exclude_mptcp=cfg.exclude_mptcp;
            } else {
                if (auto ok=routing.prepare_routing(1,false);!ok) return std::unexpected(ok.error().message());
                if (auto ok=routing.activate_context();!ok) return std::unexpected(ok.error().message());
            }
            if (cfg.host_dns_resolved) {
#ifndef NEXUS_TUN_HOST_DNS
                return std::unexpected("TUN host-dns backend is not enabled in this build");
#else
                if (!supervise_strict_network || !cfg.strict_route || cfg.host_dns_server.empty() ||
                    cfg.host_dns_server.size()>=request.dns_stub.size())
                    return std::unexpected("TUN host-dns requires a supervised strict-route and a DNS stub");
                std::ranges::copy(cfg.host_dns_server,request.dns_stub.begin());
#endif
            }
            auto& nopts=request.network;
            nopts.mtu=cfg.mtu;
            if (cfg.inet4_address) {
                auto address=parse_cidr_addr(*cfg.inet4_address,false);
                if (!address) return std::unexpected("invalid inet4-address");
                nopts.addresses[nopts.address_count++]=*address;
                if (!cfg.strict_route && address->prefix<32) nopts.routes[nopts.route_count++]=mask_network(*address);
                if (cfg.auto_route && !cfg.strict_route) {
                    nopts.routes[nopts.route_count++]={4,{0},1};
                    nopts.routes[nopts.route_count++]={4,{128},1};
                }
            }
            if (cfg.inet6_address) {
                auto address=parse_cidr_addr(*cfg.inet6_address,true);
                if (!address) return std::unexpected("invalid inet6-address");
                nopts.addresses[nopts.address_count++]=*address;
                if (!cfg.strict_route && address->prefix<128) nopts.routes[nopts.route_count++]=mask_network(*address);
                if (cfg.auto_route && !cfg.strict_route) {
                    nopts.routes[nopts.route_count++]={6,{0},1};
                    nopts.routes[nopts.route_count++]={6,{128},1};
                }
            }
            if (cfg.strict_route) {
                if (cfg.interface_name.size()>=request.name.size()) return std::unexpected("invalid TUN interface-name");
                std::ranges::copy(cfg.interface_name,request.name.begin());
                if (cfg.socket_mark) request.policy.mark=*cfg.socket_mark;
                request.policy.include_mark=cfg.include_routing_mark;
                request.policy.exclude_mark=cfg.exclude_routing_mark;
                for (auto const& text : cfg.route_excludes) {
                    auto prefix=parse_cidr_addr(text,text.contains(':'));
                    if (!prefix || request.exclude_count==request.excludes.size()) return std::unexpected("invalid TUN route-exclude");
                    auto normalized=mask_network(*prefix);
                    if (std::ranges::contains(std::span(request.excludes).first(request.exclude_count),normalized))
                        return std::unexpected("duplicate TUN route-exclude");
                    request.excludes[request.exclude_count++]=normalized;
                }
                if (cfg.route_exclude_private) {
                    constexpr std::array private_routes{
                        packet::TunAddress{4,{10},8}, packet::TunAddress{4,{172,16},12},
                        packet::TunAddress{4,{192,168},16}, packet::TunAddress{4,{100,64},10},
                        packet::TunAddress{4,{169,254},16}, packet::TunAddress{6,{0xfc},7},
                        packet::TunAddress{6,{0xfe,0x80},10}
                    };
                    for (auto const& prefix : private_routes) {
                        if (!(prefix.family==4 ? cfg.inet4_address : cfg.inet6_address)) continue;
                        if (!std::ranges::contains(std::span(request.excludes).first(request.exclude_count),prefix))
                            request.excludes[request.exclude_count++]=prefix;
                    }
                }
            }
            request.multi_queue=cfg.multi_queue;
            if (supplied) tun.emplace(std::move(*supplied));
            else if (cfg.strict_route && supervise_strict_network) {
                network_owner.emplace();
                auto started=network_owner->start(request);
                if (!started) return std::unexpected(std::move(started.error()));
                tun.emplace(std::move(*started));
            } else {
                auto t=packet::LinuxTun::create(cfg.interface_name,{.multi_queue=cfg.multi_queue});
                if (!t) return std::unexpected("failed creating TUN device "+cfg.interface_name);
                tun.emplace(std::move(*t));
            }
            if (nopts.address_count && !network_owner) {
                auto tok = tun->claim_network();
                if (!tok) return std::unexpected("failed claiming TUN network");
                if (auto st = packet::TunNetworkLease<>::emplace_into(lease, std::move(*tok), nopts); !st)
                    return std::unexpected(std::format("failed configuring TUN netlink (code={} stage={} sys={})",
                        static_cast<int>(st.error().code), static_cast<int>(st.error().stage), st.error().system.message()));
                if (auto st = lease->start(Clock::now() + std::chrono::seconds(5)); !st) {
                    auto err = std::format("failed starting TUN interface (code={} stage={} sys={})",
                        static_cast<int>(st.error().code), static_cast<int>(st.error().stage), st.error().system.message());
                    lease.reset();
                    return std::unexpected(std::move(err));
                }
            }
            auto t4 = tcp::ConnectionTable::create(cfg.tcp_flows, cfg.tcp_buffer);
            auto t6 = tcp::ConnectionTable6::create(cfg.tcp_flows, cfg.tcp_buffer);
            auto p = packet::FdPump::create(tun->native_handle(), link, cfg.mtu);
            if (!t4 || !t6 || !p) return std::unexpected("failed initializing TUN engines");
            table4.emplace(std::move(*t4)); table6.emplace(std::move(*t6)); pump.emplace(std::move(*p));
            engine4.emplace(tcp4_link, *table4, rules::Matcher{}, cfg.mtu);
            engine6.emplace(tcp6_link, *table6, rules::Matcher{}, cfg.mtu);
            auto map = cfg.endpoint_independent_nat ? udp::Mapping::endpoint_independent : udp::Mapping::address_port_dependent;
            auto filtering=udp::Filtering::address_port_dependent;
            if (cfg.udp_filtering==config::TunUdpFiltering::address_dependent) filtering=udp::Filtering::address_dependent;
            if (cfg.udp_filtering==config::TunUdpFiltering::endpoint_independent) filtering=udp::Filtering::endpoint_independent;
            udp::RetirementHandler r4{this, [](void* ctx, udp::FlowId id) noexcept {
                auto* h = static_cast<Impl*>(ctx); h->udp4_direct.erase(id);
#ifdef NEXUS_ENABLE_FAKEIP
                h->retire_udp_alias(h->udp4_aliases,id);
#endif
                if (auto it = h->udp4_proxy.find(id); it != h->udp4_proxy.end()) {
                    for (auto const& flow:it->second) {
                        flow->failed=true;
                        flow->work.set();
                        flow->tunnel->cancel();
                    }
                }
            }};
            udp::RetirementHandler r6{this, [](void* ctx, udp::FlowId id) noexcept {
                auto* h = static_cast<Impl*>(ctx); h->udp6_direct.erase(id);
#ifdef NEXUS_ENABLE_FAKEIP
                h->retire_udp_alias(h->udp6_aliases,id);
#endif
                if (auto it = h->udp6_proxy.find(id); it != h->udp6_proxy.end()) {
                    for (auto const& flow:it->second) {
                        flow->failed=true;
                        flow->work.set();
                        flow->tunnel->cancel();
                    }
                }
            }};
            udp::Limits ul{cfg.tcp_flows, 32, cfg.udp_idle_ms};
            auto reply_mtu=cfg.udp_reply_fragment ? std::size_t{65575} : cfg.mtu;
            if (cfg.udp_reply_fragment && !udp_reply_fragments.seed())
                return std::unexpected("cannot initialize TUN fragment identification");
            udp4.emplace(rules::Matcher{}, map, filtering, ul, reply_mtu, r4);
            udp6.emplace(rules::Matcher{}, map, filtering, ul, reply_mtu, r6);

            if (cfg.strict_route && !network_owner) {
                if (!lease) return std::unexpected("TUN strict-route requires an address");
                default_policy.emplace();
                auto deadline = Clock::now() + std::chrono::seconds(3);
                auto excludes=std::span(request.excludes).first(request.exclude_count);
                auto installed = default_policy->start(*lease, request.policy, deadline, deadline + std::chrono::seconds(2),excludes);
                if (!installed) return std::unexpected(std::format("TUN strict-route installation failed (code={})",
                    static_cast<int>(installed.error().code)));
            }
            std::string name(tun->name());
            worker = std::thread([this] { pump_loop(); });
            rollback.started=true;
            return name;
        }

        auto pump_loop() noexcept -> void {
            auto validate = [](void* ctx, packet::QueuedPacket const& out) noexcept {
                return static_cast<Impl*>(ctx)->valid_output(out);
            };
            Clock::time_point next_policy_check{};
            while (!stop_flag.load(std::memory_order_acquire)) {
                if ((default_policy || network_owner) && Clock::now() >= next_policy_check) {
                    if ((default_policy && !default_policy->check()) || (network_owner && !network_owner->healthy()) ||
                        (cfg.auto_redirect && !routing.healthy())) {
                        record_failure("TUN strict-route policy changed");
                        break;
                    }
                    next_policy_check = Clock::now() + std::chrono::milliseconds(100);
                }
                auto now = now_ms();
                bool active = false;
                std::uint32_t iss{};
                bool have_iss = false;
                for (int round = 0; round < 32; ++round) {
                    auto dev = pump->step(validate, this);
                    auto sw = mux.step();
                    if (!have_iss && (dev.input_delivered || (sw && sw->input_delivered))) {
                        if (!platform::secure_random(std::as_writable_bytes(std::span(&iss, 1)))) {
                            record_failure("TUN random failure"); stop_flag.store(true, std::memory_order_release); break;
                        }
                        have_iss = true;
                    }
                    bool t4 = step_tcp<false>(now, iss);
                    bool t6 = step_tcp<true>(now, iss);
                    bool ui = process_udp_inputs(now);
                    bool uo = poll_udp_outputs(now);
                    bool moved = dev.input_delivered || dev.output_delivered || (sw && (sw->input_delivered || sw->output_delivered)) || t4 || t6 || ui || uo;
                    if (!moved) break;
                    active = true;
                    iss += 64000u;
                }
                if (stop_flag.load(std::memory_order_acquire)) break;
                routing.poll(active ? std::chrono::milliseconds(0) : std::chrono::milliseconds(2));
                if (!active) std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
            for (auto& [id, s] : tcp4_flows) { s->closed = true; s->changed.set(); }
            for (auto& [id, s] : tcp6_flows) { s->closed = true; s->changed.set(); }
            for (auto* flows:{&udp4_proxy,&udp6_proxy})
                for (auto& [id,slots]:*flows)
                    for (auto const& flow:slots) {
                        flow->failed=true;
                        flow->work.set();
                        flow->tunnel->cancel();
                    }
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
            pump.reset();
            if (default_policy) {
                (void)default_policy->stop(Clock::now() + std::chrono::seconds(3));
                if (!default_policy->drained()) record_failure("TUN strict-route cleanup could not be verified");
                default_policy.reset();
            }
            if (lease) { (void)lease->stop(Clock::now() + std::chrono::seconds(3)); lease.reset(); }
            if (tun) { tun->close(); tun.reset(); }
            if (network_owner) {
                if (!network_owner->stop() && !failed_flag.load(std::memory_order_acquire))
                    record_failure("TUN strict-route cleanup could not be verified");
                network_owner.reset();
            }
        }

        auto stop() noexcept -> void {
            stop_flag.store(true, std::memory_order_release);
            if (worker.joinable()) worker.join();
            else { routing.stop(); release_device(); }
        }
    };

    TunHost::TunHost(proxy::Server& src, config::TunInbound opts, bool supervised, packet::TunRedirectOptions redirect)
        : impl_(std::make_unique<Impl>(src, std::move(opts), supervised)) { impl_->redirect = redirect; }
    TunHost::~TunHost() { stop(); }
    auto TunHost::start() -> std::expected<std::string, std::string> { return impl_->start(); }
    auto TunHost::start(packet::LinuxTun device) -> std::expected<std::string, std::string> { return impl_->start(std::move(device)); }
    auto TunHost::healthy() const noexcept -> bool { return !impl_->failed_flag.load(std::memory_order_acquire); }
    auto TunHost::queue_outbound_probe(std::shared_ptr<proxy::OutboundProbe> probe) -> bool { return impl_->routing.queue_outbound_probe(std::move(probe)); }
    auto TunHost::failure() const -> std::optional<std::string> { std::lock_guard lock(impl_->failure_mutex); return impl_->failure_msg; }
    auto TunHost::stop() noexcept -> void { if (impl_) impl_->stop(); }
}
