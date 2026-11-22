module;
#include <proxy/proxy_macros.h>
#include <boost/capy/buffers.hpp>
#include <boost/capy/ex/run_async.hpp>
#include <boost/capy/task.hpp>
#include <boost/capy/when_all.hpp>
#include <boost/corosio/endpoint.hpp>
#include <boost/corosio/io_context.hpp>
#include <boost/corosio/ipv4_address.hpp>
#include <boost/corosio/ipv6_address.hpp>
#include <boost/corosio/socket_option.hpp>
#include <boost/corosio/udp_socket.hpp>

module proxy;
import std;
import proxy.v4;
import rules;
import http.connect;
import uot;
import net.datagram_frame;
import net.udp_socket;
import platform.ip_address;
import sniff.udp_quic;
import sniff.stun;
import dns.message;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;

namespace proxy {
    namespace {
        auto endpoint_to_udp(io::endpoint const& ep) noexcept -> net::UdpEndpoint {
            net::UdpEndpoint u{};
            u.port = ep.port();
            if (ep.address().is_v6()) {
                u.family = 6;
                std::ranges::copy(ep.address().to_v6().to_bytes(), u.address.begin());
            } else {
                u.family = 4;
                std::ranges::copy(ep.address().to_v4().to_bytes(), u.address.begin());
            }
            return u;
        }

        auto detect_udp_protocol(std::span<std::uint8_t const> payload) noexcept -> std::optional<rules::Protocol> {
            if (dns::parse_query(payload).has_value()) return rules::Protocol::dns;
            if (sniff::stun_datagram(payload)) return rules::Protocol::stun;
            if (sniff::sniff_quic_datagram(payload).status != sniff::QuicProbeStatus::unrelated) return rules::Protocol::quic;
            return std::nullopt;
        }
    }

    class FixedUdpInbound {
        struct Flow {
            Session session;
            io::endpoint client;
            Clock::time_point last_active;
            std::chrono::milliseconds idle_timeout;
            std::optional<io::udp_socket> upstream;
            io::endpoint resolved_target;
            pro::proxy<TunnelFacade> tunnel;
            net::DatagramFraming framing{};
            bool needs_uot = false, connected = false, active = true;
            std::deque<std::vector<std::uint8_t>> tx_queue;
            nex::capy::async_event work;
            explicit Flow(io::io_context& ctx, io::endpoint c, std::chrono::milliseconds idle)
                : session(ctx), client(c), last_active(Clock::now()), idle_timeout(idle) {}
            auto cancel() noexcept -> void {
                active = false;
                work.set();
                if (upstream) upstream->close();
                if (tunnel) tunnel->cancel();
                session.close();
            }
        };

        Server& server_;
        io::udp_socket socket_;
        std::string target_host_;
        std::uint16_t target_port_;
        net::ProxyAddress target_addr_{};
        std::chrono::milliseconds idle_timeout_;
        std::vector<std::shared_ptr<Flow>> flows_;
        bool stopping_ = false, draining_ = false;
        static constexpr std::size_t kMaxFlows = 512;

        auto decide_route(Flow& flow, std::span<std::uint8_t const> payload) -> std::optional<std::size_t> {
            auto const& policy = flow.session.route_snapshot ? flow.session.route_snapshot->matcher : server_.routing_policy();
            auto proto = detect_udp_protocol(payload);
            if (flow.session.ordered_tcp && flow.session.ordered_tcp->udp) {
                auto const& ord = *flow.session.ordered_tcp;
                rules::ProgramInput input{};
                input.network = rules::Network::udp;
                input.port = target_port_;
                input.protocol = proto;
                if (target_addr_.family == net::ProxyAddressFamily::domain) input.explicit_domain = target_host_;
                else input.ip = target_host_;
                if (flow.session.inbound) input.inbound = *flow.session.inbound;
                auto src_str = flow.client.address().to_string();
                input.source_ip = src_str;
                input.source_port = flow.client.port();
                rules::ProgramCursor cursor;
                for (;;) {
                    auto next = cursor.poll(ord.program, input);
                    if (!next) return std::nullopt;
                    if (next->kind == rules::ProgramPreflightKind::uncertain) {
                        if (ord.unknown_policy != sniff::UnknownRoutePolicy::skip || !cursor.skip_unknown(next->rule_index))
                            return std::nullopt;
                        continue;
                    }
                    if (next->kind == rules::ProgramPreflightKind::exhausted)
                        return policy.choose_outbound(ord.fallback, target_host_);
                    auto step = *next->step;
                    if (step.action.udp_timeout_ms)
                        flow.idle_timeout = std::chrono::milliseconds(step.action.udp_timeout_ms);
                    else if (step.action.udp_adaptive_timeout)
                        flow.idle_timeout = std::chrono::milliseconds(
                            rules::adaptive_udp_timeout_ms(proto, target_port_, static_cast<std::uint32_t>(idle_timeout_.count())));
                    if (step.action.kind == rules::ProgramActionKind::reject) return std::nullopt;
                    if (step.action.kind == rules::ProgramActionKind::route) {
                        auto chosen = policy.choose_outbound(step.action.outbound, target_host_);
                        return chosen == 1 ? std::nullopt : std::optional(chosen);
                    }
                    if (!cursor.complete(step)) return std::nullopt;
                }
            }
            rules::MatchInput m{};
            if (target_addr_.family == net::ProxyAddressFamily::domain) m.domain = target_host_;
            else m.ip = target_host_;
            m.port = target_port_;
            m.network = rules::Network::udp;
            if (flow.session.inbound) m.inbound = *flow.session.inbound;
            auto matched = policy.match(m);
            if (!matched || *matched == 1) return std::nullopt;
            return *matched;
        }

        auto run_flow(std::shared_ptr<Flow> flow, std::size_t outbound) -> capy::task<> {
            struct Guard {
                FixedUdpInbound& self; std::shared_ptr<Flow> f;
                ~Guard() { f->cancel(); std::erase(self.flows_, f); }
            } guard{*this, flow};
            auto& ctx = server_.executor_context();
            auto deadline = Clock::now() + std::chrono::milliseconds(flow->session.direct_connect_timeout_ms);
            if (outbound == 0) {
                io::endpoint dst;
                if (target_addr_.family == net::ProxyAddressFamily::domain) {
                    auto src = endpoint_to_udp(flow->client);
                    auto eps = co_await resolve_udp_domain(flow->session, ctx, target_host_, target_port_, deadline, &src);
                    if (!eps || eps->empty() || stopping_ || !flow->active) co_return;
                    dst = eps->front();
                } else {
                    if (target_addr_.family == net::ProxyAddressFamily::ipv6) {
                        std::array<unsigned char, 16> b{};
                        std::copy_n(target_addr_.bytes.begin(), 16, b.begin());
                        dst = {io::ipv6_address(b), target_port_};
                    } else {
                        std::array<unsigned char, 4> b{};
                        std::copy_n(target_addr_.bytes.begin(), 4, b.begin());
                        dst = {io::ipv4_address(b), target_port_};
                    }
                }
                flow->resolved_target = dst;
                flow->upstream.emplace(ctx);
                if (flow->upstream->open(dst.address().is_v6() ? io::family::v6 : io::family::v4)) co_return;
                if (flow->upstream->bind(dst.address().is_v6() ? io::endpoint(io::ipv6_address::any(), 0) : io::endpoint(io::ipv4_address::any(), 0))) co_return;
                flow->connected = true;
                auto writer = [&]() -> capy::task<capy::results<>> {
                    while (!stopping_ && flow->active) {
                        if (flow->tx_queue.empty()) {
                            flow->work.clear();
                            auto [ec] = co_await flow->work.wait();
                            if (ec) break;
                            continue;
                        }
                        auto pkt = std::move(flow->tx_queue.front());
                        flow->tx_queue.pop_front();
                        auto [ec, n] = co_await flow->upstream->send_to(capy::const_buffer(pkt.data(), pkt.size()), flow->resolved_target);
                        if (ec) break;
                        flow->last_active = Clock::now();
                        flow->session.count_traffic(true, n);
                    }
                    flow->cancel();
                    co_return capy::results<>{};
                };
                auto reader = [&]() -> capy::task<capy::results<>> {
                    std::array<std::uint8_t, 65536> buf{};
                    while (!stopping_ && flow->active) {
                        io::endpoint peer;
                        auto [ec, n] = co_await flow->upstream->recv_from(capy::mutable_buffer(buf.data(), buf.size()), peer);
                        if (ec || !n || stopping_ || !flow->active) break;
                        if (peer != flow->resolved_target) continue;
                        flow->last_active = Clock::now();
                        flow->session.count_traffic(false, n);
                        (void)co_await socket_.send_to(capy::const_buffer(buf.data(), n), flow->client);
                    }
                    flow->cancel();
                    co_return capy::results<>{};
                };
                (void)co_await capy::when_all(writer(), reader());
                co_return;
            }
            if (!flow->session.tunnel_factories || outbound < 2 || outbound - 2 >= flow->session.tunnel_factories->size()) co_return;
            auto const& factory = (*flow->session.tunnel_factories)[outbound - 2];
            flow->tunnel = factory(flow->session, ctx, false);
            if (!flow->tunnel) co_return;
            auto pt = flow->tunnel->packet_transport();
            if (pt.kind == net::PacketTransportKind::framed) {
                flow->framing = pt.framing;
                if (co_await flow->tunnel->connect_packets(target_addr_, deadline) != TunnelConnectResult::connected) co_return;
            } else if (flow->tunnel->has_uot()) {
                flow->framing = {net::AddressWire::uot, false, false};
                if (co_await flow->tunnel->connect_uot_until(deadline) != TunnelConnectResult::connected) co_return;
                auto req = uot::encode_request({false, target_addr_});
                if (!req || !co_await flow->tunnel->send(*req)) co_return;
            } else co_return;
            flow->session.select_traffic_path(ConnectPath::tunnel);
            flow->connected = true;
            auto writer = [&]() -> capy::task<capy::results<>> {
                while (!stopping_ && flow->active) {
                    if (flow->tx_queue.empty()) {
                        flow->work.clear();
                        auto [ec] = co_await flow->work.wait();
                        if (ec) break;
                        continue;
                    }
                    auto pkt = std::move(flow->tx_queue.front());
                    flow->tx_queue.pop_front();
                    auto wire = net::encode_datagram(flow->framing, target_addr_, pkt);
                    if (!wire || !co_await flow->tunnel->send(*wire)) break;
                    flow->last_active = Clock::now();
                    flow->session.count_traffic(true, pkt.size());
                }
                flow->cancel();
                co_return capy::results<>{};
            };
            auto reader = [&]() -> capy::task<capy::results<>> {
                std::array<std::uint8_t, 65536> buf{};
                net::DatagramDecoder dec(flow->framing, target_addr_);
                while (!stopping_ && flow->active) {
                    auto n = co_await flow->tunnel->read(buf);
                    if (!n || !*n || stopping_ || !flow->active) break;
                    auto span = std::span(buf).first(*n);
                    while (!span.empty()) {
                        auto step = dec.feed(span);
                        span = span.subspan(step.consumed);
                        if (step.status == net::DatagramStatus::accepted) {
                            if (auto dg = dec.packet()) {
                                flow->last_active = Clock::now();
                                flow->session.count_traffic(false, dg->payload.size());
                                (void)co_await socket_.send_to(capy::const_buffer(dg->payload.data(), dg->payload.size()), flow->client);
                            }
                            (void)dec.consume();
                        } else if (step.status != net::DatagramStatus::incomplete) {
                            flow->cancel();
                            co_return capy::results<>{};
                        }
                    }
                }
                flow->cancel();
                co_return capy::results<>{};
            };
            (void)co_await capy::when_all(writer(), reader());
        }

        auto recv_loop() -> capy::task<> {
            std::array<std::uint8_t, 65536> buf{};
            while (!stopping_ && !draining_) {
                io::endpoint client;
                auto [ec, n] = co_await socket_.recv_from(capy::mutable_buffer(buf.data(), buf.size()), client);
                if (ec || stopping_ || draining_) break;
                if (!n || !client.port()) continue;
                auto payload = std::span(buf).first(n);
                std::shared_ptr<Flow> flow;
                for (auto const& f : flows_) {
                    if (f->active && f->client == client) { flow = f; break; }
                }
                if (!flow) {
                    if (flows_.size() >= kMaxFlows) continue;
                    auto lease = server_.acquire_session();
                    if (!lease) continue;
                    flow = std::make_shared<Flow>(server_.executor_context(), client, idle_timeout_);
                    server_.attach_session(flow->session, std::move(*lease));
                    flow->session.datagram_source = endpoint_to_udp(client);
                    flow->session.relaying = true;
                    flow->session.begin_traffic(TrafficProtocol::socks_udp, target_port_);
                    flow->session.select_traffic_path(ConnectPath::datagrams);
                    auto outbound = decide_route(*flow, payload);
                    if (!outbound) { flow->session.close(); continue; }
                    flows_.push_back(flow);
                    capy::run_async(server_.executor_context().get_executor(), [] {}, [](std::exception_ptr) noexcept {})(
                        run_flow(flow, *outbound));
                }
                if (flow->tx_queue.size() < 64) {
                    flow->tx_queue.emplace_back(payload.begin(), payload.end());
                    flow->last_active = Clock::now();
                    flow->work.set();
                }
            }
        }

    public:
        FixedUdpInbound(Server& server, std::string host, std::uint16_t port, net::ProxyAddress addr, std::uint32_t idle_ms)
            : server_(server), socket_(server.executor_context()), target_host_(std::move(host)),
              target_port_(port), target_addr_(addr), idle_timeout_(idle_ms) {}

        auto start(io::endpoint ep) -> std::expected<std::uint16_t, std::error_code> {
            bool v6 = ep.address().is_v6();
            if (auto ec = socket_.open(v6 ? io::family::v6 : io::family::v4)) return std::unexpected(ec);
            if (v6) (void)socket_.set_option(io::socket_option::v6_only(true));
            if (auto ec = socket_.bind(ep)) { socket_.close(); return std::unexpected(ec); }
            auto bound = socket_.local_endpoint().port();
            capy::run_async(server_.executor_context().get_executor(), [] {}, [](std::exception_ptr) noexcept {})(recv_loop());
            return bound;
        }

        auto poll(Clock::time_point now) -> void {
            for (auto& f : flows_) {
                if (f->active && now - f->last_active >= f->idle_timeout) f->cancel();
            }
        }
        auto drain() noexcept -> void { draining_ = true; socket_.close(); }
        auto stop() noexcept -> void {
            stopping_ = true; draining_ = true;
            socket_.close();
            for (auto& f : flows_) f->cancel();
        }
    };

    auto Server::set_fixed_udp_target(std::string_view host, std::uint16_t port, std::uint32_t idle_ms) -> bool {
        if (running || (listener && listener->is_open()) || !sessions.empty() || !workers.empty() ||
            host.empty() || host.size() > 253 || !port || idle_ms < 1000 || idle_ms > 3600000) return false;
        auto auth = host.contains(':') ? "[" + std::string(host) + "]:" + std::to_string(port) : std::string(host) + ":" + std::to_string(port);
        auto parsed = http::parse_destination_authority(auth);
        if (parsed.status != http::ConnectStatus::accepted) return false;
        net::ProxyAddress addr{};
        addr.port = port;
        if (parsed.kind == http::HostKind::domain) {
            addr.family = net::ProxyAddressFamily::domain;
            addr.length = static_cast<std::uint8_t>(parsed.host.size());
            std::ranges::copy(parsed.host, addr.bytes.begin());
        } else {
            addr.family = parsed.kind == http::HostKind::ipv4 ? net::ProxyAddressFamily::ipv4 : net::ProxyAddressFamily::ipv6;
            addr.length = parsed.kind == http::HostKind::ipv4 ? 4 : 16;
            std::ranges::copy_n(parsed.address.begin(), addr.length, addr.bytes.begin());
        }
        fixed_udp_inbound = std::make_shared<FixedUdpInbound>(*this, std::string(host), port, addr, idle_ms);
        return true;
    }

    auto Server::start_fixed_udp(io::endpoint ep) -> std::expected<std::uint16_t, std::error_code> {
        if (!fixed_udp_inbound) return std::unexpected(std::make_error_code(std::errc::invalid_argument));
        if (auto active = activate_context(); !active) { stop(); return std::unexpected(active.error()); }
        auto bound = fixed_udp_inbound->start(ep);
        if (!bound) { stop(); return std::unexpected(bound.error()); }
        bound_listener = io::endpoint(ep.address(), *bound);
        inbound_type = Inbound::fixed_udp;
        running = true;
        accepting = true;
        return *bound;
    }

    auto Server::poll_fixed_udp(Clock::time_point now) -> void { if (fixed_udp_inbound) fixed_udp_inbound->poll(now); }
    auto Server::drain_fixed_udp() noexcept -> void { if (fixed_udp_inbound) fixed_udp_inbound->drain(); }
    auto Server::stop_fixed_udp() noexcept -> void { if (fixed_udp_inbound) fixed_udp_inbound->stop(); }
}
