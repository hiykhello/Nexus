// SOCKS5 UDP tunnel sender and reader coroutine tasks.
module;
#ifdef NEXUS_TEST_UOT_WRITE_RACE
#include <cerrno>
#include <cstdlib>
#include <fcntl.h>
#include <unistd.h>
#endif

module relay;
import :session_udp_alias_tunnel;
import std;
import capy;
import corosio;
import net.datagram_frame;
import net.lazy_readers;
import socks5;
import socks5.udp_ingress;
import socks5.udp_tunnel_authorization;
import uot;
import xudp;
import xudp.client_io;

namespace relay::session_udp_detail {
#ifdef NEXUS_ENABLE_SOCKS_UDP
    auto uot_sender(Session& session, io::io_context& context, socks5::UdpIngress& ingress, UotState& state)
        -> capy::task<capy::results<>> {
        using namespace std::chrono_literals;
        try {
            std::optional<Clock::time_point> retry_deadline;
            while (!session.closed) {
                ingress.changed().clear();
                auto packet = ingress.pending_tunnel();
                if (!packet) { auto [error] = co_await ingress.changed().wait(); if (error) session.close(); continue; }
                if (Clock::now() >= packet->deadline) { retry_deadline.reset(); ingress.complete_tunnel(); continue; }
#ifdef NEXUS_ENABLE_FAKEIP
                if (packet->alias) {
                    auto outbound = packet->outbound - 2;
                    auto sent = UotAliasTunnels::Send::dropped;
                    if (session.tunnel_factories && outbound < session.tunnel_factories->size()) {
                        if (!state.aliases) state.aliases = std::make_unique<UotAliasTunnels>(state.alias_cap, state.ordinary_limit());
                        sent = co_await state.aliases->send(session, context, state.readers, *packet,
                            (*session.tunnel_factories)[outbound]);
                    }
                    if (sent == UotAliasTunnels::Send::retry) {
                        auto [error] = co_await io::delay(1ms);
                        if (error) session.close();
                        continue;
                    }
                    ingress.complete_tunnel(sent == UotAliasTunnels::Send::forwarded);
                    continue;
                }
#endif
                state.active_deadline = retry_deadline ? std::min(packet->deadline, *retry_deadline) : packet->deadline;
                ingress.wake();
                retry_deadline.reset();
                struct ActivePacket { UotState& state; ~ActivePacket() { state.active_deadline.reset(); } } active{state};
                if (Clock::now() >= *state.active_deadline) { session.close(); break; }
                auto outbound = packet->outbound - 2;
                if (!session.tunnel_factories || outbound >= session.tunnel_factories->size()) {
                    ingress.complete_tunnel(); continue;
                }
                auto const& factory = (*session.tunnel_factories)[outbound];
                auto target = packet->target;
                auto cancel_victim = [](UotSlot& v) noexcept {
                    v.rotating = true; v.ready = false; v.readiness.clear();
#ifdef NEXUS_ENABLE_VLESS
                    if (v.xudp_client) v.xudp_client->cancel();
                    else
#endif
                    if (v.tunnel) v.tunnel->cancel();
                };
                std::size_t index = 0; bool evicted = false;
                if (factory.packet_fixed_peer) {
                    auto sel = state.fixed.select_or_evict(outbound, target, cancel_victim);
                    if (!sel) { ingress.complete_tunnel(); continue; }
                    index = state.routed.soft_cap() + sel->index; evicted = sel->evicted;
                } else {
                    auto key = (static_cast<std::uint64_t>(outbound) << 1) | (!factory.packet_dual_family && target.address_type == 4 ? 1u : 0u);
                    auto sel = state.routed.select_or_evict(key, cancel_victim);
                    if (!sel) { ingress.complete_tunnel(); continue; }
                    index = sel->index; evicted = sel->evicted;
                }
                auto& slot = state.slot_at(index);
                if (evicted) {
                    while (!session.closed && slot.reader_active && Clock::now() < *state.active_deadline) {
                        slot.reader_done.clear();
                        if (!slot.reader_active) break;
                        auto [error] = co_await io::timeout(slot.reader_done.wait(), *state.active_deadline);
                        if (error && session.closed) break;
                    }
                    if (session.closed || Clock::now() >= *state.active_deadline) { session.close(); break; }
#ifdef NEXUS_ENABLE_VLESS
                    slot.xudp_client.reset(); slot.xudp_session = 0;
#endif
                    slot.tunnel = {}; slot.authorization = {}; slot.rotating = false;
                }
                if (!slot.tunnel) {
                    state.active_deadline = std::min(*state.active_deadline, Clock::now() + std::chrono::milliseconds(factory.timeout_ms));
                    ingress.wake();
                    slot.tunnel = factory(session, context);
                    if (!slot.tunnel) { ingress.complete_tunnel(); continue; }
                    auto transport = slot.tunnel->packet_transport();
                    if (transport.kind == net::PacketTransportKind::none) { slot.tunnel = {}; ingress.complete_tunnel(); continue; }
                    if (Clock::now() >= *state.active_deadline) { session.close(); break; }
                    auto connected = co_await slot.tunnel->connect_packets(uot_address(target), *state.active_deadline);
                    if (session.closed || Clock::now() >= *state.active_deadline) { session.close(); break; }
                    if (connected != TunnelConnectResult::connected) { session.close(); break; }
#ifdef NEXUS_ENABLE_VLESS
                    if (transport.kind == net::PacketTransportKind::xudp) {
                        slot.xudp_stream.tunnel = &slot.tunnel;
                        slot.xudp_stream.deadline = &state.active_deadline; slot.xudp_stream.closed = &session.closed;
                        slot.xudp_client = std::make_unique<xudp::ClientIo<XudpStream>>(slot.xudp_stream, 1);
                    } else
#endif
                    {
                        if (transport.kind != net::PacketTransportKind::framed) { slot.tunnel = {}; ingress.complete_tunnel(); continue; }
                        slot.framing = transport.framing;
                        if (transport.needs_uot_request) {
                            auto request = uot::encode_request({false, uot_address(target)});
                            if (!request || Clock::now() >= *state.active_deadline || !co_await slot.tunnel->send(*request) || session.closed || Clock::now() >= *state.active_deadline) { session.close(); break; }
                        }
                    }
                    slot.rotating = false;
                    slot.ready = true;
                    if (!state.readers.request(index)) { session.close(); state.cancel(); break; }
                    slot.readiness.set();
                }
                if (session.closed || Clock::now() >= *state.active_deadline) { session.close(); break; }
                auto credit = session.reserve_principal_datagram(true, packet->packet.data.size());
                if (!credit) { ingress.complete_tunnel(); continue; }
#ifdef NEXUS_ENABLE_VLESS
                if (slot.xudp_client) {
                    credit->submit();
                    auto address = xudp_address(target); bool sent = false;
                    if (slot.xudp_session) {
                        auto id = slot.xudp_session;
                        auto result = co_await slot.xudp_client->send(id, address, packet->packet.data);
                        if (result) sent = true;
                        else if (result.error() != xudp::ClientIoError::session || slot.xudp_session) { session.close(); break; }
                    }
                    if (!sent) {
                        auto id = co_await slot.xudp_client->open(address, packet->packet.data);
                        if (!id && id.error() == xudp::ClientIoError::exhausted) {
                            // The reader may be suspended inside the old client. Cancel it,
                            // wait until it has left, then destroy the client before its tunnel.
                            slot.rotating = true; slot.ready = false; slot.readiness.clear(); slot.xudp_client->cancel();
                            while (!session.closed && slot.reader_active && Clock::now() < *state.active_deadline) {
                                slot.reader_done.clear();
                                if (!slot.reader_active) break;
                                auto [error] = co_await io::timeout(slot.reader_done.wait(), *state.active_deadline);
                                if (error && session.closed) break;
                            }
                            if (session.closed || Clock::now() >= *state.active_deadline) { session.close(); break; }
                            slot.xudp_client.reset(); slot.tunnel = {};
                            retry_deadline = state.active_deadline;
                            credit->complete(0);
                            continue; // Retry the same queued datagram on a fresh stream.
                        }
                        if (!id) { session.close(); break; }
                        slot.xudp_session = *id;
                    }
                    credit->complete(packet->packet.data.size());
                    session.count_traffic(true, packet->packet.data.size());
                    if (session.closed || Clock::now() >= *state.active_deadline) { session.close(); break; }
                    session.touched = Clock::now(); ingress.complete_tunnel(true); continue;
                }
#endif
                auto frame = net::encode_datagram(slot.framing, uot_address(target), packet->packet.data);
                if (!frame) { ingress.complete_tunnel(); continue; }
                auto token = slot.authorization.begin(target);
                if (!token) { ingress.complete_tunnel(); continue; }
                if (Clock::now() >= *state.active_deadline) {
                    (void)slot.authorization.finish(*token, false); session.close(); break;
                }
                credit->submit();
                auto sent = co_await slot.tunnel->send(*frame);
                if (sent) {
                    credit->complete(packet->packet.data.size());
                    session.count_traffic(true, packet->packet.data.size());
                }
#ifdef NEXUS_TEST_UOT_WRITE_RACE
                // Hold the authorization transaction open after the peer can
                // receive the frame, making the reply/write race reproducible.
                if (auto gate = std::getenv("NEXUS_TEST_UOT_WRITE_RACE")) {
                    auto fd = std::atoi(gate);
                    (void)::fcntl(fd, F_SETFL, ::fcntl(fd, F_GETFL) | O_NONBLOCK);
                    char release;
                    while (!session.closed) {
                        auto n = ::read(fd, &release, 1);
                        if (n == 1) { if (release == 'f') sent = false; break; }
                        if (n == 0 || (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)) { sent = false; break; }
                        auto [error] = co_await io::delay(1ms);
                        if (error) { sent = false; break; }
                    }
                }
#endif
                sent = sent && !session.closed && Clock::now() < *state.active_deadline;
                (void)slot.authorization.finish(*token, sent);
                if (!sent || session.closed) { session.close(); break; }
                session.touched = Clock::now(); ingress.complete_tunnel(true);
            }
            state.cancel(); co_return capy::results<>{};
        } catch (...) { state.cancel(); session.close(); throw; }
    }

    auto uot_reader(Session& session, socks5::UdpIngress& ingress, UotState& state, std::size_t index)
        -> capy::task<capy::results<>> {
        using namespace std::chrono_literals;
        try {
#ifdef NEXUS_ENABLE_FAKEIP
            if (index >= state.ordinary_limit())
                co_return co_await state.aliases->read(session, ingress, state.readers, index - state.ordinary_limit());
#endif
            auto& slot = state.slot_at(index);
            for (;;) {
                while (!session.closed && !state.readers.stopped() && !slot.ready) {
                    auto [error] = co_await slot.readiness.wait(); if (error) session.close();
                }
                if (session.closed || state.readers.stopped()) co_return capy::results<>{};
                slot.reader_active = true;
#ifdef NEXUS_ENABLE_VLESS
                if (slot.xudp_client) {
                    while (!session.closed && !slot.rotating) {
                        auto reply = co_await slot.xudp_client->read();
                        if (!reply) { if (!slot.rotating) session.close(); break; }
                        if (reply->action == xudp::Incoming::ended) {
                            if (reply->session == slot.xudp_session) slot.xudp_session = 0;
                            continue;
                        }
                        if (!reply->source || (reply->source->family != xudp::Family::ipv4 && reply->source->family != xudp::Family::ipv6)) { session.close(); break; }
                        socks5::UdpPeer source{reply->source->family == xudp::Family::ipv4 ? std::uint8_t{1} : std::uint8_t{4}, {}, reply->source->port};
                        std::copy_n(reply->source->bytes.begin(), reply->source->length, source.address.begin());
                        for (;;) {
                            auto queued = ingress.queue_tunnel_reply(source, reply->payload);
                            if (!queued) { session.close(); break; }
                            if (*queued != socks5::UdpReplyStatus::busy) break;
                            auto [error] = co_await io::delay(1ms); if (error || session.closed) { session.close(); break; }
                        }
                    }
                } else
#endif
                {
                    auto peer = index < state.routed.soft_cap() ? net::ProxyAddress{} : uot_address(state.fixed.peer(index - state.routed.soft_cap()));
                    co_await uot_read_framed(session, ingress, slot.tunnel, slot.authorization, slot.framing, peer, nullptr, &slot.rotating);
                    if (!slot.rotating) session.close();
                }
                slot.reader_active = false; slot.reader_done.set();
                if (!slot.rotating || session.closed) co_return capy::results<>{};
            }
        } catch (...) { session.close(); throw; }
    }
#endif
}
