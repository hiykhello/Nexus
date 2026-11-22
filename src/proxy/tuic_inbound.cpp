module;
#include <boost/capy/ex/run_async.hpp>
#include <boost/capy/task.hpp>
#include <boost/capy/when_all.hpp>
#include <boost/corosio/delay.hpp>
#include <boost/corosio/endpoint.hpp>
#include <boost/corosio/io_context.hpp>
#include <boost/corosio/ipv4_address.hpp>
#include <boost/corosio/ipv6_address.hpp>
module proxy.tuic_host;
import std;
import proxy;
import proxy.session_quota;
import proxy.principal_limits;
import net.principal_bytes;
import proxy.stream_relay;
import tuic.wire;
import tuic.application;
import tuic.transport_options;
import tuic.stream;
import tuic.server;
import tls.server_credential;
import quic.cid_registry;
import quic.datagram_port;
import socks5;
import rules;
import net.udp_route;
import net.udp_dial;
import net.udp_authorization;
import net.stream_relay;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;

namespace proxy {
    namespace {
        using Clock = std::chrono::steady_clock;

        struct TuicHooks {
            Server& routing;
            tuic::Listener<TuicHooks>* listener = nullptr;
            std::vector<tuic::UserCredential> const& users;
            std::mutex mutex;
            struct PendingStream { quic::SessionHandle session; tuic::StreamHandle stream; tuic::TargetAddress target; };
            std::deque<PendingStream> pending_streams;
            std::deque<std::pair<quic::SessionHandle, tuic::IncomingUdpPacket>> pending_udp;
            struct UdpEntry {
                quic::SessionHandle session;
                SessionQuota::Lease quota;
                std::optional<SessionQuota::Lease> principal_lease;
                PrincipalBudget const* principal;
                auto reserve(bool upstream,std::size_t size,Clock::time_point now) const
                    -> std::optional<PrincipalBytes::Reservation> {
                    if (principal) return principal->bytes().reserve_datagram(upstream,size,now);
                    return std::optional<PrincipalBytes::Reservation>(std::in_place);
                }
                net::UdpDialSockets socket;
                net::UdpAuthorization sources;
                TrafficRegistration traffic;
                std::shared_ptr<RouteSnapshot const> route;
                Clock::time_point touched=Clock::now();
                bool over_stream=false;
                UdpEntry(quic::SessionHandle s,SessionQuota::Lease lease,TrafficRegistration registration,
                    std::shared_ptr<RouteSnapshot const> snapshot,std::optional<SessionQuota::Lease> principal_quota,
                    PrincipalBudget const* budget)
                    :session(s),quota(std::move(lease)),principal_lease(std::move(principal_quota)),principal(budget),
                     traffic(std::move(registration)),route(std::move(snapshot)) {}
            };
            std::unordered_map<std::uint64_t, UdpEntry> udp_sockets;
            std::array<std::size_t, 32> active_tasks{};

            std::array<std::optional<SessionQuota::Lease>,32> principals;
            auto admit_authenticated(quic::SessionHandle h,std::size_t user) noexcept -> bool {
                auto const* policy=routing.principal_policy();
                if (!policy || user>=users.size()) return true;
                auto const* budget=policy->find(users[user].name);
                if (!budget) return true;
                principals[h.slot]=budget->acquire(PrincipalResource::connection);
                return principals[h.slot].has_value();
            }
            auto authenticated(quic::SessionHandle, std::size_t) noexcept -> void {}
            auto connect_stream(quic::SessionHandle h, tuic::StreamHandle s, tuic::TargetAddress const& t) -> void {
                std::lock_guard lock(mutex);
                pending_streams.push_back({h, s, t});
                ++active_tasks[h.slot];
            }
            auto udp_packet(quic::SessionHandle h, tuic::IncomingUdpPacket pkt) -> void {
                std::lock_guard lock(mutex);
                if (pending_udp.size() < 256) pending_udp.emplace_back(h, std::move(pkt));
            }
            auto udp_dissociate(quic::SessionHandle h, std::uint16_t assoc_id) -> void {
                std::uint64_t key = (std::uint64_t{h.slot} << 16) | assoc_id;
                udp_sockets.erase(key);
            }
            auto transport_closed(quic::SessionHandle h) noexcept -> void {
                std::erase_if(udp_sockets,[&](auto const& item) { return item.second.session==h; });
                std::erase_if(pending_udp,[&](auto const& item) { return item.first==h; });
            }
            auto session_drained(quic::SessionHandle h) const noexcept -> bool {
                return active_tasks[h.slot] == 0;
            }
            auto session_destroyed(quic::SessionHandle h) noexcept -> void {
                principals[h.slot].reset();
            }
        };

        auto udp_peer(nex::corosio::endpoint const& endpoint) -> net::UdpEndpoint {
            auto address=endpoint.address();
            net::UdpEndpoint peer{address.is_v4() ? std::uint8_t{4} : std::uint8_t{6},{},endpoint.port()};
            if (address.is_v4()) {
                auto bytes=address.to_v4().to_bytes();
                std::ranges::copy(bytes,peer.address.begin());
            } else peer.address=address.to_v6().to_bytes();
            return peer;
        }

        auto to_socks5_request(tuic::TargetAddress const& t) -> socks5::Request {
            socks5::Request req{};
            req.status = socks5::Status::accepted;
            req.port = t.port;
            if (t.type == tuic::AddressType::ipv4) {
                req.address_type = 1; req.address_length = 4;
                std::copy_n(t.address.begin(), 4, req.address.begin());
            } else if (t.type == tuic::AddressType::ipv6) {
                req.address_type = 4; req.address_length = 16;
                std::copy_n(t.address.begin(), 16, req.address.begin());
            } else if (t.type == tuic::AddressType::domain && t.domain.size() <= req.address.size()) {
                req.address_type = 3; req.address_length = static_cast<std::uint8_t>(t.domain.size());
                std::ranges::copy(t.domain, req.address.begin());
            } else req.status = socks5::Status::invalid_address;
            return req;
        }
    }

    struct TuicHost::Impl {
        struct Worker {
            Server routing{RoutingOnly{}};
            TuicHooks hooks;
            tuic::Listener<TuicHooks> listener;
            Worker(Server& parent, std::size_t idx, std::size_t count, tls::ServerCredential const& cred,
                   std::vector<tuic::UserCredential> const& users, tuic::ClientTransportOptions opts)
                : hooks{routing, nullptr, users},
                  listener(routing.executor_context(), cred, users, opts, hooks) {
                routing.inherit_routing(parent, idx, count);
                hooks.listener = &listener;
            }
        };

        Server& parent;
        tls::ServerCredential const& credential;
        std::vector<tuic::UserCredential> users;
        tuic::ClientTransportOptions options;
        std::vector<std::unique_ptr<Worker>> workers;
        std::vector<std::thread> threads;
        std::atomic_bool stop_flag{false}, failed_flag{false};

        static auto handle_stream(Worker& w, quic::SessionHandle h, tuic::StreamHandle s, tuic::TargetAddress target)
            -> nex::capy::task<> {
            struct Done { Worker& w; quic::SessionHandle h; ~Done() {
                std::lock_guard lock(w.hooks.mutex);
                if (w.hooks.active_tasks[h.slot] > 0) --w.hooks.active_tasks[h.slot];
                w.listener.notify();
            }} done{w, h};

            auto* app = w.listener.app(h);
            if (!app || app->stopping()) co_return;
            tuic::TcpStream<typename tuic::Listener<TuicHooks>::App,tuic::Listener<TuicHooks>> ch(
                *app,w.listener,s);
            auto lease = w.routing.acquire_session();
            if (!lease) co_return;
            Session session(w.routing.executor_context());
            w.routing.attach_session(session,std::move(*lease));
            if (auto user=app->auth_user();user && *user<w.hooks.users.size() &&
                !session.admit_principal(w.hooks.users[*user].name,PrincipalResource::stream)) {
                session.close(); co_return;
            }
            auto req = to_socks5_request(target);
            if (req.status != socks5::Status::accepted) { session.close(); co_return; }
            session.begin_traffic(TrafficProtocol::tuic,req.port);
            auto const& policy=session.route_snapshot ? session.route_snapshot->matcher : w.routing.routing_policy();
            if (auto code = co_await dial_destination(session,w.routing.executor_context(),policy,req,session.handshake_deadline);
                code || session.closed) { session.close(); co_return; }

            std::stop_callback cancel_channel(session.stop.get_token(),[&]() noexcept {ch.cancel();});
            session.relaying = true;
            session.touched = Clock::now();
            (void)co_await nex::capy::when_all(
                stream_relay::direction(session, stream_relay::upload(session, ch)),
                stream_relay::direction(session, stream_relay::download(session, ch)));
            session.close();
        }

        auto pump_worker(Worker& w) noexcept -> void {
            auto& ctx = w.routing.executor_context();
            nex::capy::run_async(ctx.get_executor(), [](auto) noexcept {}, [&](std::exception_ptr) noexcept {
                failed_flag.store(true, std::memory_order_release);
            })(w.listener.run());
            while (!stop_flag.load(std::memory_order_acquire)) {
                w.routing.start_pending_probe();
                ctx.restart();
                ctx.run_for(std::chrono::milliseconds(10));
                w.routing.maintain_dns_transports();
                w.routing.process_traffic_closes();
                std::deque<TuicHooks::PendingStream> streams;
                std::deque<std::pair<quic::SessionHandle, tuic::IncomingUdpPacket>> udps;
                {
                    std::lock_guard lock(w.hooks.mutex);
                    streams.swap(w.hooks.pending_streams);
                    udps.swap(w.hooks.pending_udp);
                }
                for (auto& st : streams) {
                    nex::capy::run_async(ctx.get_executor(), [] {}, [&](std::exception_ptr) noexcept {})(
                        handle_stream(w, st.session, st.stream, std::move(st.target)));
                }
                auto now=Clock::now();
                std::erase_if(w.hooks.udp_sockets,[&](auto const& item) {
                    return item.second.traffic.close_requested() || now-item.second.touched>=std::chrono::minutes(5);
                });
                for (auto& [h,pkt] : udps) {
                    if (pkt.destination.type!=tuic::AddressType::ipv4 &&
                        pkt.destination.type!=tuic::AddressType::ipv6) continue;
                    auto peer=w.listener.initial_peer(h);
                    auto* app=w.listener.app(h);
                    if (!peer || !app || app->stopping()) continue;
                    auto user=app->auth_user();
                    std::optional<std::string_view> name;
                    if (user && *user<w.hooks.users.size() && !w.hooks.users[*user].name.empty())
                        name=w.hooks.users[*user].name;
                    auto source=udp_peer(*peer);
                    net::UdpEndpoint destination{
                        pkt.destination.type==tuic::AddressType::ipv4 ? std::uint8_t{4} : std::uint8_t{6},
                        pkt.destination.address,pkt.destination.port};
                    std::uint64_t key=(std::uint64_t{h.slot}<<16) | pkt.assoc_id;
                    auto it=w.hooks.udp_sockets.find(key);
                    auto snapshot=it==w.hooks.udp_sockets.end() ? w.routing.current_route_snapshot() : it->second.route;
                    auto const& policy=snapshot ? snapshot->matcher : w.routing.routing_policy();
                    auto v4=destination.family==4;
                    auto selected=net::udp_select(policy,{v4 ? net::UdpTargetKind::ipv4 : net::UdpTargetKind::ipv6,
                        std::span(destination.address).first(v4 ? 4 : 16),destination.port},destination,&source,name);
                    if (!selected || selected->outbound!=0) continue;
                    destination=selected->target;
                    if (it==w.hooks.udp_sockets.end()) {
                        auto lease=w.routing.acquire_session();
                        if (!lease) continue;
                        auto const* limits=w.routing.principal_policy();
                        auto const* budget=limits && name ? limits->find(*name) : nullptr;
                        auto principal=budget ? budget->acquire(PrincipalResource::stream) : std::nullopt;
                        if (budget && !principal) continue;
                        auto traffic=w.routing.track_traffic(TrafficProtocol::tuic_udp,ConnectPath::datagrams,source,destination.port,true);
                        it=w.hooks.udp_sockets.try_emplace(key,h,std::move(*lease),std::move(traffic),std::move(snapshot),
                            std::move(principal),budget).first;
                    }
                    auto& entry=it->second;
                    auto credit=entry.reserve(true,pkt.payload.size(),Clock::now());
                    if (!credit) continue;
                    auto authorization=entry.sources.begin(destination);
                    if (!authorization) continue;
                    auto sent=entry.socket.send(destination,pkt.payload);
                    (void)entry.sources.finish(*authorization,sent.has_value());
                    if (sent) {
                        credit->complete(pkt.payload.size());
                        entry.touched=now;
                        entry.over_stream=pkt.over_stream;
                        entry.traffic.count(true,pkt.payload.size());
                    }
                }
                for (auto& [key, entry] : w.hooks.udp_sockets) {
                    std::array<std::uint8_t, 65535> rx{};
                    for (int k = 0; k < 8; ++k) {
                        auto pkt=entry.socket.receive(rx);
                        if (!pkt || !*pkt) break;
                        if (!(**pkt).valid || !entry.sources.accepts((**pkt).source)) continue;
                        auto* app = w.listener.app(entry.session);
                        if (!app) break;
                        tuic::TargetAddress src{};
                        src.type = (**pkt).source.family == 4 ? tuic::AddressType::ipv4 : tuic::AddressType::ipv6;
                        src.address = (**pkt).source.address;
                        src.port = (**pkt).source.port;
                        auto credit=entry.reserve(false,(**pkt).size,Clock::now());
                        if (!credit) continue;
                        // The stream mode can queue a prefix of the fragments
                        // before a later fragment fails admission.
                        if (entry.over_stream) credit->submit();
                        if (app->send_udp(static_cast<std::uint16_t>(key & 0xffffu),src,
                                std::span(rx).first((**pkt).size),entry.over_stream)) {
                            credit->complete((**pkt).size);
                            entry.touched=now;
                            entry.traffic.count(false,(**pkt).size);
                            w.listener.notify();
                        }
                    }
                }
            }
            w.listener.stop();
            // Stop the routing sessions while they can still notify their QUIC
            // transport owners. Their join releases the final transport pins.
            w.routing.stop();
            w.listener.maintain();
        }
    };

    TuicHost::TuicHost(Server& routing_source, tls::ServerCredential const& credential,
                       std::vector<tuic::UserCredential> users, tuic::ClientTransportOptions options)
        : impl_(std::make_unique<Impl>(routing_source, credential, std::move(users), options)) {}

    TuicHost::~TuicHost() { stop(); }

    auto TuicHost::start(nex::corosio::endpoint listen_ep, unsigned count) -> std::expected<std::uint16_t, std::string> {
        if (count != 1) return std::unexpected("TUIC requires workers=1");
        auto prepared = impl_->parent.prepare_routing(count, true);
        if (!prepared) return std::unexpected(prepared.error().message());
        auto w = std::make_unique<Impl::Worker>(impl_->parent, 0, count, impl_->credential, impl_->users, impl_->options);
        auto activated = w->routing.activate_context();
        if (!activated) return std::unexpected(activated.error().message());
        auto bound = w->listener.prepare(listen_ep);
        if (!bound) return std::unexpected(bound.error().message());
        w->listener.start();
        impl_->workers.push_back(std::move(w));
        impl_->threads.emplace_back([this, ptr = impl_->workers.back().get()] { impl_->pump_worker(*ptr); });
        return bound->port();
    }

    auto TuicHost::healthy() const noexcept -> bool { return !impl_->failed_flag.load(std::memory_order_acquire); }
    auto TuicHost::queue_outbound_probe(std::shared_ptr<OutboundProbe> probe) -> bool {
        return !impl_->workers.empty() && impl_->workers.front()->routing.queue_outbound_probe(std::move(probe));
    }

    auto TuicHost::stop() noexcept -> void {
        if (!impl_) return;
        impl_->stop_flag.store(true, std::memory_order_release);
        for (auto& t : impl_->threads) if (t.joinable()) t.join();
        impl_->threads.clear();
        impl_->workers.clear();
        impl_->parent.stop();
    }
}
