module;
#if !defined(_WIN32)
#include <cstring>
#include <netinet/in.h>
#include <sys/socket.h>
#endif
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

module relay;
import std;
import proxy.v4;
import rules;
import http.connect;
import uot;
import net.datagram_frame;
import net.udp_socket;
import platform.ip_address;
import platform.udp_batch;
import sniff.udp_quic;
import sniff.stun;
import dns.message;
import capy;
import corosio;

namespace relay {
    namespace {
        struct EndpointKey {
            std::array<std::uint8_t, 16> addr{};
            std::uint16_t port = 0; std::uint8_t family = 0;
            auto operator==(EndpointKey const&) const noexcept -> bool = default;
        };
        struct EndpointKeyHash {
            auto operator()(EndpointKey const& k) const noexcept -> std::size_t {
                std::uint64_t h = 14695981039346656037ull, a = 0, b = 0;
                auto mix = [&](std::uint64_t v) noexcept { h = (h ^ v) * 1099511628211ull; };
                mix((static_cast<std::uint64_t>(k.family) << 16) | k.port);
                std::memcpy(&a, k.addr.data(), 8); mix(a);
                if (k.family == 6) { std::memcpy(&b, k.addr.data() + 8, 8); mix(b); }
                return static_cast<std::size_t>(h);
            }
        };
        auto make_endpoint_key(io::endpoint const& ep) noexcept -> EndpointKey {
            EndpointKey k{}; k.port = ep.port();
            if (ep.address().is_v6()) { k.family = 6; auto b = ep.address().to_v6().to_bytes(); std::memcpy(k.addr.data(), b.data(), 16); }
            else { k.family = 4; auto b = ep.address().to_v4().to_bytes(); std::memcpy(k.addr.data(), b.data(), 4); }
            return k;
        }
#if !defined(_WIN32)
        constexpr std::size_t kUdpRecvBatch = 16;
        auto sockaddr_to_io_endpoint(sockaddr_storage const& s, socklen_t len) noexcept -> std::optional<io::endpoint> {
            if (s.ss_family == AF_INET && len >= static_cast<socklen_t>(sizeof(sockaddr_in))) {
                sockaddr_in in{}; std::memcpy(&in, &s, sizeof(in));
                io::ipv4_address::bytes_type b{}; std::memcpy(b.data(), &in.sin_addr, 4);
                return io::endpoint(io::ipv4_address(b), platform::net_to_host16(in.sin_port));
            }
            if (s.ss_family == AF_INET6 && len >= static_cast<socklen_t>(sizeof(sockaddr_in6))) {
                sockaddr_in6 in6{}; std::memcpy(&in6, &s, sizeof(in6));
                io::ipv6_address::bytes_type b{}; std::memcpy(b.data(), &in6.sin6_addr, 16);
                return io::endpoint(io::ipv6_address(b), platform::net_to_host16(in6.sin6_port));
            }
            return std::nullopt;
        }
        auto io_endpoint_to_sockaddr(io::endpoint const& ep, sockaddr_storage& out) noexcept -> socklen_t {
            out = {};
            if (ep.address().is_v6()) {
                sockaddr_in6 in6{}; in6.sin6_family = AF_INET6; in6.sin6_port = platform::host_to_net16(ep.port());
                auto v6 = ep.address().to_v6(); auto b = v6.to_bytes();
                std::memcpy(&in6.sin6_addr, b.data(), 16); in6.sin6_scope_id = static_cast<std::uint32_t>(v6.scope_id());
                std::memcpy(&out, &in6, sizeof(in6)); return static_cast<socklen_t>(sizeof(in6));
            }
            sockaddr_in in{}; in.sin_family = AF_INET; in.sin_port = platform::host_to_net16(ep.port());
            auto b = ep.address().to_v4().to_bytes(); std::memcpy(&in.sin_addr, b.data(), 4);
            std::memcpy(&out, &in, sizeof(in)); return static_cast<socklen_t>(sizeof(in));
        }
        template<class KeepGoing, class OnPacket>
        auto drain_udp_recv_batch(int fd, int max_rounds, KeepGoing&& keep_going, OnPacket&& on_packet) -> void {
            if (fd < 0 || !keep_going()) return;
            thread_local std::unique_ptr<std::uint8_t[]> slab;
            thread_local bool in_use = false;
            if (in_use) return;
            if (!slab) slab = std::make_unique_for_overwrite<std::uint8_t[]>(kUdpRecvBatch * 65536);
            in_use = true;
            struct BusyGuard { bool* f; ~BusyGuard() { *f = false; } } bg{&in_use};
            std::array<platform::UdpRecvSlot, kUdpRecvBatch> slots{};
            for (std::size_t i = 0; i < kUdpRecvBatch; ++i) { slots[i].data = slab.get() + i * 65536; slots[i].capacity = 65536; }
            for (int r = 0; r < max_rounds && keep_going(); ++r) {
                auto got = platform::recv_udp_batch(fd, slots);
                if (!got || *got == 0) break;
                for (std::size_t i = 0; i < *got && keep_going(); ++i) {
                    if (slots[i].truncated || !slots[i].received) continue;
                    if (auto ep = sockaddr_to_io_endpoint(slots[i].peer, slots[i].peer_len))
                        on_packet(*ep, std::span(slots[i].data, slots[i].received));
                }
                if (*got < kUdpRecvBatch) break;
            }
        }
#endif
        struct PacketBufPool {
            std::vector<std::vector<std::uint8_t>> free_;
            auto acquire(std::span<std::uint8_t const> bytes) -> std::vector<std::uint8_t> {
                std::vector<std::uint8_t> out;
                if (!free_.empty()) { out = std::move(free_.back()); free_.pop_back(); }
                out.assign(bytes.begin(), bytes.end());
                return out;
            }
            auto release(std::vector<std::uint8_t>&& buf) noexcept -> void {
                if (free_.size() < 64 && buf.capacity() > 0 && buf.capacity() <= 8192) {
                    buf.clear(); try { free_.push_back(std::move(buf)); } catch (...) {}
                }
            }
        };

        auto endpoint_to_udp(io::endpoint const& ep) noexcept -> net::UdpEndpoint {
            net::UdpEndpoint u{}; u.port = ep.port();
            if (ep.address().is_v6()) { u.family = 6; std::ranges::copy(ep.address().to_v6().to_bytes(), u.address.begin()); }
            else { u.family = 4; std::ranges::copy(ep.address().to_v4().to_bytes(), u.address.begin()); }
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
            capy::async_event work;
            explicit Flow(io::io_context& ctx, io::endpoint c, std::chrono::milliseconds idle)
                : session(ctx), client(c), last_active(Clock::now()), idle_timeout(idle) {}
            auto cancel() noexcept -> void {
                active = false; work.set();
                if (upstream) upstream->close();
                if (tunnel) tunnel->cancel();
                session.close();
            }
        };
        struct DownPacket { io::endpoint to; std::vector<std::uint8_t> data; };
        Server& server_; io::udp_socket socket_; std::string target_host_;
        std::uint16_t target_port_; net::ProxyAddress target_addr_{};
        std::chrono::milliseconds idle_timeout_;
        std::unordered_map<EndpointKey, std::shared_ptr<Flow>, EndpointKeyHash> flows_;
        std::deque<DownPacket> tx_down_; PacketBufPool buf_pool_; capy::async_event tx_down_ev_;
        bool stopping_ = false, draining_ = false, down_writer_active_ = false;
        std::size_t active_tasks_ = 0; bool* server_active_flag_ = nullptr;
        static constexpr std::size_t kMaxFlows = 512, kMaxDownQueue = 512;

        auto sync_active_flag() noexcept -> void {
            if (server_active_flag_) *server_active_flag_ = (active_tasks_ > 0 || !flows_.empty() || !tx_down_.empty());
        }
        auto enqueue_reply(io::endpoint const& client, std::span<std::uint8_t const> bytes) noexcept -> void {
            if (stopping_ || bytes.empty() || tx_down_.size() >= kMaxDownQueue) return;
            try { tx_down_.push_back({client, buf_pool_.acquire(bytes)}); tx_down_ev_.set(); } catch (...) {}
        }
        auto down_writer_loop() -> capy::task<> {
            struct Done { FixedUdpInbound& self; ~Done() { self.down_writer_active_ = false; if (self.draining_ && self.flows_.empty()) self.socket_.close(); } } done{*this};
            while (!stopping_) {
                if (tx_down_.empty()) {
                    if (draining_ && flows_.empty()) break;
                    tx_down_ev_.clear();
                    if (!tx_down_.empty()) continue;
                    if (auto [ec] = co_await tx_down_ev_.wait(); ec) break;
                    continue;
                }
#if !defined(_WIN32)
                if (int const fd = socket_.native_handle(); fd >= 0) {
                    auto const n = std::min(tx_down_.size(), platform::kUdpBatchMax);
                    std::array<sockaddr_storage, platform::kUdpBatchMax> peers{};
                    std::array<platform::UdpSendSlot, platform::kUdpBatchMax> slots{};
                    for (std::size_t i = 0; i < n; ++i) {
                        auto plen = io_endpoint_to_sockaddr(tx_down_[i].to, peers[i]);
                        slots[i] = {reinterpret_cast<sockaddr const*>(&peers[i]), plen, tx_down_[i].data.data(), tx_down_[i].data.size()};
                    }
                    if (auto sent = platform::send_udp_batch(fd, std::span(slots).first(n)); sent && *sent > 0) {
                        for (std::size_t i = 0; i < *sent; ++i) { buf_pool_.release(std::move(tx_down_.front().data)); tx_down_.pop_front(); }
                        continue;
                    }
                }
#endif
                auto pkt = std::move(tx_down_.front()); tx_down_.pop_front();
                (void)co_await socket_.send_to(capy::const_buffer(pkt.data.data(), pkt.data.size()), pkt.to);
                buf_pool_.release(std::move(pkt.data));
            }
        }
        auto decide_route(Flow& flow, std::span<std::uint8_t const> payload) -> std::optional<std::size_t> {
            auto const& policy = flow.session.route_snapshot ? flow.session.route_snapshot->matcher : server_.routing_policy();
            auto proto = detect_udp_protocol(payload);
            if (flow.session.ordered_tcp && flow.session.ordered_tcp->udp) {
                auto const& ord = *flow.session.ordered_tcp;
                rules::ProgramInput input{.port = target_port_, .network = rules::Network::udp, .protocol = proto, .source_port = flow.client.port()};
                if (target_addr_.family == net::ProxyAddressFamily::domain) input.explicit_domain = target_host_; else input.ip = target_host_;
                if (flow.session.inbound) input.inbound = *flow.session.inbound;
                auto src_str = flow.client.address().to_string(); input.source_ip = src_str;
                rules::ProgramCursor cursor;
                for (;;) {
                    auto next = cursor.poll(ord.program, input);
                    if (!next) return std::nullopt;
                    if (next->kind == rules::ProgramPreflightKind::uncertain) {
                        if (ord.unknown_policy != sniff::UnknownRoutePolicy::skip || !cursor.skip_unknown(next->rule_index)) return std::nullopt;
                        continue;
                    }
                    if (next->kind == rules::ProgramPreflightKind::exhausted) return policy.choose_outbound(ord.fallback, target_host_);
                    auto step = *next->step;
                    if (step.action.udp_timeout_ms) flow.idle_timeout = std::chrono::milliseconds(step.action.udp_timeout_ms);
                    else if (step.action.udp_adaptive_timeout)
                        flow.idle_timeout = std::chrono::milliseconds(rules::adaptive_udp_timeout_ms(proto, target_port_, static_cast<std::uint32_t>(idle_timeout_.count())));
                    if (step.action.kind == rules::ProgramActionKind::reject) return std::nullopt;
                    if (step.action.kind == rules::ProgramActionKind::route) {
                        auto chosen = policy.choose_outbound(step.action.outbound, target_host_);
                        return chosen == 1 ? std::nullopt : std::optional(chosen);
                    }
                    if (!cursor.complete(step)) return std::nullopt;
                }
            }
            rules::MatchInput m{.port = target_port_, .network = rules::Network::udp};
            if (target_addr_.family == net::ProxyAddressFamily::domain) m.domain = target_host_; else m.ip = target_host_;
            if (flow.session.inbound) m.inbound = *flow.session.inbound;
            auto matched = policy.match(m);
            return (!matched || *matched == 1) ? std::nullopt : std::optional(*matched);
        }

        auto run_flow(std::shared_ptr<Flow> flow, std::size_t outbound, EndpointKey key) -> capy::task<> {
            struct Guard {
                FixedUdpInbound& self; std::shared_ptr<Flow> f; EndpointKey key;
                ~Guard() {
                    f->cancel();
                    if (auto it = self.flows_.find(key); it != self.flows_.end() && it->second == f) self.flows_.erase(it);
                    self.tx_down_ev_.set();
                }
            } guard{*this, flow, key};
            std::stop_callback stop_flow(flow->session.stop.get_token(), [f = flow.get()]() noexcept { f->cancel(); });
            auto& ctx = server_.executor_context();
            auto deadline = Clock::now() + std::chrono::milliseconds(flow->session.direct_connect_timeout_ms);
            if (outbound == 0) {
                io::endpoint dst;
                if (target_addr_.family == net::ProxyAddressFamily::domain) {
                    auto src = endpoint_to_udp(flow->client);
                    auto eps = co_await resolve_udp_domain(flow->session, ctx, target_host_, target_port_, deadline, &src);
                    if (!eps || eps->empty() || stopping_ || !flow->active) co_return;
                    dst = eps->front();
                } else if (target_addr_.family == net::ProxyAddressFamily::ipv6) {
                    std::array<unsigned char, 16> b{}; std::copy_n(target_addr_.bytes.begin(), 16, b.begin());
                    dst = {io::ipv6_address(b), target_port_};
                } else {
                    std::array<unsigned char, 4> b{}; std::copy_n(target_addr_.bytes.begin(), 4, b.begin());
                    dst = {io::ipv4_address(b), target_port_};
                }
                flow->resolved_target = dst; flow->upstream.emplace(ctx);
                if (flow->upstream->open(dst.address().is_v6() ? io::family::v6 : io::family::v4)) co_return;
                if (flow->upstream->bind(dst.address().is_v6() ? io::endpoint(io::ipv6_address::any(), 0) : io::endpoint(io::ipv4_address::any(), 0))) co_return;
                flow->connected = true;
                auto writer = [&]() -> capy::task<capy::results<>> {
#if !defined(_WIN32)
                    sockaddr_storage dst_ss{}; auto const dst_len = io_endpoint_to_sockaddr(flow->resolved_target, dst_ss);
#endif
                    while (!stopping_ && flow->active) {
                        if (flow->tx_queue.empty()) { flow->work.clear(); if (auto [ec] = co_await flow->work.wait(); ec) break; continue; }
#if !defined(_WIN32)
                        if (int const fd = flow->upstream->native_handle(); fd >= 0) {
                            auto const n = std::min(flow->tx_queue.size(), platform::kUdpBatchMax);
                            std::array<platform::UdpSendSlot, platform::kUdpBatchMax> slots{};
                            for (std::size_t i = 0; i < n; ++i)
                                slots[i] = {reinterpret_cast<sockaddr const*>(&dst_ss), dst_len, flow->tx_queue[i].data(), flow->tx_queue[i].size()};
                            auto sent = platform::send_udp_batch(fd, std::span(slots).first(n));
                            if (sent && *sent > 0) {
                                std::size_t total = 0;
                                for (std::size_t i = 0; i < *sent; ++i) {
                                    total += flow->tx_queue.front().size(); buf_pool_.release(std::move(flow->tx_queue.front())); flow->tx_queue.pop_front();
                                }
                                flow->session.touched = flow->last_active = Clock::now(); flow->session.count_traffic(true, total); continue;
                            }
                            if (!sent) {
                                if (sent.error() != std::errc::message_size) break;
                                buf_pool_.release(std::move(flow->tx_queue.front())); flow->tx_queue.pop_front(); continue;
                            }
                        }
#endif
                        auto pkt = std::move(flow->tx_queue.front()); flow->tx_queue.pop_front();
                        auto [ec, n] = co_await flow->upstream->send_to(capy::const_buffer(pkt.data(), pkt.size()), flow->resolved_target);
                        buf_pool_.release(std::move(pkt));
                        if (ec) { if (ec == std::errc::message_size) continue; break; }
                        flow->session.touched = flow->last_active = Clock::now(); flow->session.count_traffic(true, n);
                    }
                    flow->cancel(); co_return capy::results<>{};
                };
                auto reader = [&]() -> capy::task<capy::results<>> {
                    std::array<std::uint8_t, 65536> buf;
                    while (!stopping_ && flow->active) {
                        io::endpoint peer;
                        auto [ec, n] = co_await flow->upstream->recv_from(capy::mutable_buffer(buf.data(), buf.size()), peer);
                        if (ec || !n || stopping_ || !flow->active) break;
                        auto now = Clock::now(); std::size_t batch_bytes = 0;
                        auto on_reply = [&](io::endpoint const& p, std::span<std::uint8_t const> d) {
                            if (p == flow->resolved_target) { batch_bytes += d.size(); enqueue_reply(flow->client, d); }
                        };
                        on_reply(peer, std::span(buf.data(), n));
#if !defined(_WIN32)
                        drain_udp_recv_batch(flow->upstream->native_handle(), 1, [&] { return !stopping_ && flow->active; }, on_reply);
#endif
                        if (batch_bytes) { flow->session.touched = flow->last_active = now; flow->session.count_traffic(false, batch_bytes); }
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
                    if (flow->tx_queue.empty()) { flow->work.clear(); if (auto [ec] = co_await flow->work.wait(); ec) break; continue; }
                    auto pkt = std::move(flow->tx_queue.front()); flow->tx_queue.pop_front();
                    auto wire = net::encode_datagram(flow->framing, target_addr_, pkt);
                    auto const pkt_len = pkt.size();
                    buf_pool_.release(std::move(pkt));
                    if (!wire || !co_await flow->tunnel->send(*wire)) break;
                    flow->session.touched = flow->last_active = Clock::now(); flow->session.count_traffic(true, pkt_len);
                }
                flow->cancel();
                co_return capy::results<>{};
            };
            auto reader = [&]() -> capy::task<capy::results<>> {
                std::array<std::uint8_t, 65536> buf;
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
                                flow->session.touched = flow->last_active = Clock::now();
                                flow->session.count_traffic(false, dg->payload.size());
                                enqueue_reply(flow->client, dg->payload);
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

        auto handle_incoming(io::endpoint const& client, std::span<std::uint8_t const> payload, Clock::time_point now) -> void {
            if (payload.empty() || !client.port()) return;
            auto const key = make_endpoint_key(client);
            std::shared_ptr<Flow> flow;
            if (auto it = flows_.find(key); it != flows_.end() && it->second->active) flow = it->second;
            if (!flow) {
                if (server_.shedding_memory() || flows_.size() >= kMaxFlows) return;
                auto lease = server_.acquire_session();
                if (!lease) return;
                flow = std::make_shared<Flow>(server_.executor_context(), client, idle_timeout_);
                server_.attach_session(flow->session, std::move(*lease));
                flow->session.datagram_source = endpoint_to_udp(client);
                flow->session.relaying = true;
                flow->session.begin_traffic(TrafficProtocol::socks_udp, target_port_);
                flow->session.select_traffic_path(ConnectPath::datagrams);
                auto outbound = decide_route(*flow, payload);
                if (!outbound) { flow->session.close(); return; }
                flows_.insert_or_assign(key, flow);
                ++active_tasks_; sync_active_flag();
                auto finish = [self = this]() noexcept { --self->active_tasks_; self->sync_active_flag(); };
                try {
                    capy::run_async(server_.executor_context().get_executor(), finish,
                        [finish](std::exception_ptr) noexcept { finish(); })(run_flow(flow, *outbound, key));
                } catch (...) { flows_.erase(key); finish(); flow->session.close(); return; }
            }
            if (flow->tx_queue.size() < 64) {
                flow->tx_queue.push_back(buf_pool_.acquire(payload));
                flow->session.touched = flow->last_active = now;
                flow->work.set();
            }
        }

        auto recv_loop() -> capy::task<> {
            std::array<std::uint8_t, 65536> buf;
            while (!stopping_ && !draining_) {
                io::endpoint client;
                auto [ec, n] = co_await socket_.recv_from(capy::mutable_buffer(buf.data(), buf.size()), client);
                if (ec || stopping_ || draining_) break;
                auto now = Clock::now();
                handle_incoming(client, std::span(buf).first(n), now);
#if !defined(_WIN32)
                drain_udp_recv_batch(socket_.native_handle(), 2, [&] { return !stopping_ && !draining_; },
                    [&](io::endpoint const& ep, std::span<std::uint8_t const> d) { handle_incoming(ep, d, now); });
#endif
            }
        }

    public:
        FixedUdpInbound(Server& server, std::string host, std::uint16_t port, net::ProxyAddress addr, std::uint32_t idle_ms)
            : server_(server), socket_(server.executor_context()), target_host_(std::move(host)),
              target_port_(port), target_addr_(addr), idle_timeout_(idle_ms) { flows_.reserve(64); }

        auto start(io::endpoint ep, bool& active_flag) -> std::expected<std::uint16_t, std::error_code> {
            server_active_flag_ = &active_flag;
            bool v6 = ep.address().is_v6();
            if (auto ec = socket_.open(v6 ? io::family::v6 : io::family::v4)) return std::unexpected(ec);
            if (v6) (void)socket_.set_option(io::socket_option::v6_only(true));
            if (auto ec = socket_.bind(ep)) { socket_.close(); return std::unexpected(ec); }
            auto bound = socket_.local_endpoint().port();
            down_writer_active_ = true;
            auto finish = [self = this]() noexcept { --self->active_tasks_; self->sync_active_flag(); };
            auto on_err = [finish](std::exception_ptr) noexcept { finish(); };
            auto spawn = [&](capy::task<> t) -> bool {
                ++active_tasks_; sync_active_flag();
                try { capy::run_async(server_.executor_context().get_executor(), finish, on_err)(std::move(t)); return true; }
                catch (...) { finish(); return false; }
            };
            if (!spawn(down_writer_loop())) { down_writer_active_ = false; socket_.close(); return std::unexpected(std::make_error_code(std::errc::not_enough_memory)); }
            if (!spawn(recv_loop())) { stop(); return std::unexpected(std::make_error_code(std::errc::not_enough_memory)); }
            return bound;
        }
        auto poll(Clock::time_point now) -> void { for (auto& [k, f] : flows_) if (f->active && now - f->last_active >= f->idle_timeout) f->cancel(); }
        auto drain() noexcept -> void { draining_ = true; tx_down_ev_.set(); if (!down_writer_active_ || (flows_.empty() && tx_down_.empty())) socket_.close(); }
        auto stop() noexcept -> void { stopping_ = true; draining_ = true; tx_down_.clear(); tx_down_ev_.set(); socket_.close(); for (auto& [k, f] : flows_) f->cancel(); sync_active_flag(); }
    };

    auto Server::set_fixed_udp_target(std::string_view host, std::uint16_t port, std::uint32_t idle_ms) -> bool {
        if (running || (listener && listener->is_open()) || !sessions.empty() || !workers.empty() ||
            host.empty() || host.size() > 253 || !port || idle_ms < 1000 || idle_ms > 3600000) return false;
        auto auth = host.contains(':') ? "[" + std::string(host) + "]:" + std::to_string(port) : std::string(host) + ":" + std::to_string(port);
        auto parsed = http::parse_destination_authority(auth);
        if (parsed.status != http::ConnectStatus::accepted) return false;
        net::ProxyAddress addr{.port = port};
        if (parsed.kind == http::HostKind::domain) {
            addr.family = net::ProxyAddressFamily::domain; addr.length = static_cast<std::uint8_t>(parsed.host.size());
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
        auto bound = fixed_udp_inbound->start(ep, accept_task_active);
        if (!bound) { stop(); return std::unexpected(bound.error()); }
        bound_listener = io::endpoint(ep.address(), *bound); inbound_type = Inbound::fixed_udp;
        running = true; accepting = true;
        return *bound;
    }

    auto Server::poll_fixed_udp(Clock::time_point now) -> void { if (fixed_udp_inbound) fixed_udp_inbound->poll(now); }
    auto Server::drain_fixed_udp() noexcept -> void { if (fixed_udp_inbound) fixed_udp_inbound->drain(); }
    auto Server::stop_fixed_udp() noexcept -> void { if (fixed_udp_inbound) fixed_udp_inbound->stop(); }
}
