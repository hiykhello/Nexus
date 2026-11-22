#ifdef NEXUS_ENABLE_VLESS
        struct XudpStream {
            pro::proxy<TunnelFacade>* tunnel=nullptr;
            std::optional<Clock::time_point>* deadline=nullptr;
            bool const* closed=nullptr;
            auto write(std::span<std::uint8_t const> bytes) -> capy::task<bool> {
                auto until=deadline && *deadline ? **deadline : Clock::time_point::max();
                if ((closed && *closed) || Clock::now()>=until) {cancel();co_return false;}
                auto sent=co_await (*tunnel)->send(bytes);
                // ClientIo commits reply authorization only after this returns.
                if (!sent || (closed && *closed) || Clock::now()>=until) {cancel();co_return false;}
                co_return true;
            }
            auto read(std::span<std::uint8_t> bytes) -> capy::task<std::expected<std::size_t,std::string>> { co_return co_await (*tunnel)->read(bytes); }
            auto cancel() noexcept -> void { if (tunnel && *tunnel) (*tunnel)->cancel(); }
        };
#endif
        struct UotSlot {
            pro::proxy<TunnelFacade> tunnel;
            socks5::UdpTunnelAuthorization authorization;
            net::DatagramFraming framing;
#ifdef NEXUS_ENABLE_VLESS
            XudpStream xudp_stream;
            std::unique_ptr<xudp::ClientIo<XudpStream>> xudp_client;
            std::uint16_t xudp_session=0;
            bool xudp_rotating=false, xudp_reader_active=false;
#endif
            bool ready=false;
            nex::capy::async_event readiness;
        };
        constexpr std::size_t routed_udp_slots=32;
        constexpr std::size_t fixed_udp_slots=16;
        constexpr std::size_t ordinary_udp_slots=routed_udp_slots+fixed_udp_slots;
        auto uot_address(socks5::UdpPeer) -> uot::Address;
#ifdef NEXUS_ENABLE_VLESS
        auto xudp_address(socks5::UdpPeer) -> xudp::Address;
#endif
#include "session_udp_framed.hpp"
#include "session_udp_alias_tunnel.hpp"
        struct UotState {
            std::array<UotSlot,routed_udp_slots> slots;
            net::FixedDatagramSlots<UotSlot,socks5::UdpPeer,fixed_udp_slots> fixed;
            auto slot_at(std::size_t index) noexcept -> UotSlot& {
                return index<routed_udp_slots ? slots[index] : fixed.slot(index-routed_udp_slots);
            }
#ifdef NEXUS_ENABLE_FAKEIP
            std::unique_ptr<UotAliasTunnels> aliases;
            UotAliasTunnels::Readers readers;
#else
            net::LazyReaders<ordinary_udp_slots> readers;
#endif
            std::optional<Clock::time_point> active_deadline;
            auto cancel() noexcept -> void {
                readers.stop();
#ifdef NEXUS_ENABLE_FAKEIP
                if (aliases) aliases->cancel();
#endif
                auto close=[](UotSlot& slot) noexcept {
#ifdef NEXUS_ENABLE_VLESS
                if (slot.xudp_client) slot.xudp_client->cancel();
                else
#endif
                if (slot.tunnel) slot.tunnel->cancel();
                    slot.readiness.set();
                };
                std::ranges::for_each(slots,close);
                fixed.for_each(close);
            }
        };
        auto uot_address(socks5::UdpPeer peer) -> uot::Address {
            uot::Address out; out.family=peer.address_type==1 ? uot::Family::ipv4 : uot::Family::ipv6;
            out.length=peer.address_type==1 ? 4 : 16; out.port=peer.port;
            std::copy_n(peer.address.begin(),out.length,out.bytes.begin()); return out;
        }
#ifdef NEXUS_ENABLE_VLESS
        auto xudp_address(socks5::UdpPeer peer) -> xudp::Address {
            xudp::Address out; out.family=peer.address_type==1 ? xudp::Family::ipv4 : xudp::Family::ipv6;
            out.length=peer.address_type==1 ? 4 : 16; out.port=peer.port;
            std::copy_n(peer.address.begin(),out.length,out.bytes.begin()); return out;
        }
#endif
        auto uot_sender(Session& session, io::io_context& context, socks5::UdpIngress& ingress, UotState& state)
            -> capy::task<capy::results<>> {
            using namespace std::chrono_literals;
            try {
                std::optional<Clock::time_point> retry_deadline;
                while (!session.closed) {
                    ingress.changed().clear();
                    auto packet=ingress.pending_tunnel();
                    if (!packet) { auto [error]=co_await ingress.changed().wait(); if (error) session.close(); continue; }
                    if (Clock::now()>=packet->deadline) { retry_deadline.reset(); ingress.complete_tunnel(); continue; }
#ifdef NEXUS_ENABLE_FAKEIP
                    if (packet->alias) {
                        auto outbound=packet->outbound-2;
                        auto sent=UotAliasTunnels::Send::dropped;
                        if (session.tunnel_factories && outbound<session.tunnel_factories->size()) {
                            if (!state.aliases) state.aliases=std::make_unique<UotAliasTunnels>();
                            sent=co_await state.aliases->send(session,context,state.readers,*packet,
                                (*session.tunnel_factories)[outbound]);
                        }
                        if (sent==UotAliasTunnels::Send::retry) {
                            auto [error]=co_await io::delay(1ms);
                            if (error) session.close();
                            continue;
                        }
                        ingress.complete_tunnel(sent==UotAliasTunnels::Send::forwarded);
                        continue;
                    }
#endif
                    state.active_deadline=retry_deadline ? std::min(packet->deadline,*retry_deadline) : packet->deadline;
                    ingress.wake();
                    retry_deadline.reset();
                    struct ActivePacket { UotState& state; ~ActivePacket(){state.active_deadline.reset();} } active{state};
                    if (Clock::now()>=*state.active_deadline) { session.close(); break; }
                    auto outbound=packet->outbound-2;
                    if (!session.tunnel_factories || outbound>=session.tunnel_factories->size()) {
                        ingress.complete_tunnel(); continue;
                    }
                    auto const& factory=(*session.tunnel_factories)[outbound];
                    auto index=outbound*2+(!factory.packet_dual_family && packet->target.address_type==4 ? 1 : 0);
                    if (index>=routed_udp_slots) { ingress.complete_tunnel(); continue; }
                    auto target=packet->target;
                    if (factory.packet_fixed_peer) {
                        auto fixed=state.fixed.select(outbound,target);
                        if (!fixed) { ingress.complete_tunnel(); continue; }
                        index=routed_udp_slots+*fixed;
                    }
                    auto& slot=state.slot_at(index);
                    if (!slot.tunnel) {
                        state.active_deadline=std::min(*state.active_deadline,Clock::now()+std::chrono::milliseconds(factory.timeout_ms));
                        ingress.wake();
                        slot.tunnel=factory(session,context);
                        if (!slot.tunnel) { ingress.complete_tunnel(); continue; }
                        auto transport=slot.tunnel->packet_transport();
                        if (transport.kind==net::PacketTransportKind::none) { slot.tunnel={}; ingress.complete_tunnel(); continue; }
                        if (Clock::now()>=*state.active_deadline) {session.close();break;}
                        auto connected=co_await slot.tunnel->connect_packets(uot_address(target),*state.active_deadline);
                        if (session.closed || Clock::now()>=*state.active_deadline) { session.close(); break; }
                        if (connected!=TunnelConnectResult::connected) { session.close(); break; }
#ifdef NEXUS_ENABLE_VLESS
                        if (transport.kind==net::PacketTransportKind::xudp) {
                            slot.xudp_stream.tunnel=&slot.tunnel;
                            slot.xudp_stream.deadline=&state.active_deadline;slot.xudp_stream.closed=&session.closed;
                            slot.xudp_client=std::make_unique<xudp::ClientIo<XudpStream>>(slot.xudp_stream,1);
                        } else
#endif
                        {
                            if (transport.kind!=net::PacketTransportKind::framed) { slot.tunnel={}; ingress.complete_tunnel(); continue; }
                            slot.framing=transport.framing;
                            if (transport.needs_uot_request) {
                                auto request=uot::encode_request({false,uot_address(target)});
                                if (!request || Clock::now()>=*state.active_deadline || !co_await slot.tunnel->send(*request) || session.closed || Clock::now()>=*state.active_deadline) { session.close(); break; }
                            }
                        }
#ifdef NEXUS_ENABLE_VLESS
                        slot.xudp_rotating=false;
#endif
                        slot.ready=true;
                        if(!state.readers.request(index)) {session.close();state.cancel();break;}
                        slot.readiness.set();
                    }
                    if (session.closed || Clock::now()>=*state.active_deadline) { session.close(); break; }
                    auto credit=session.reserve_principal_datagram(true,packet->packet.data.size());
                    if (!credit) {ingress.complete_tunnel();continue;}
#ifdef NEXUS_ENABLE_VLESS
                    if (slot.xudp_client) {
                        credit->submit();
                        auto address=xudp_address(target); bool sent=false;
                        if (slot.xudp_session) {
                            auto id=slot.xudp_session;
                            auto result=co_await slot.xudp_client->send(id,address,packet->packet.data);
                            if (result) sent=true;
                            else if (result.error()!=xudp::ClientIoError::session || slot.xudp_session) { session.close(); break; }
                        }
                        if (!sent) {
                            auto id=co_await slot.xudp_client->open(address,packet->packet.data);
                            if (!id && id.error()==xudp::ClientIoError::exhausted) {
                                // The reader may be suspended inside the old client. Cancel it,
                                // wait until it has left, then destroy the client before its tunnel.
                                slot.xudp_rotating=true; slot.ready=false; slot.readiness.clear(); slot.xudp_client->cancel();
                                while (!session.closed && slot.xudp_reader_active && Clock::now()<*state.active_deadline) {
                                    auto [error]=co_await io::delay(1ms); if (error) session.close();
                                }
                                if (session.closed || Clock::now()>=*state.active_deadline) { session.close(); break; }
                                slot.xudp_client.reset(); slot.tunnel={};
                                retry_deadline=state.active_deadline;
                                credit->complete(0);
                                continue; // Retry the same queued datagram on a fresh stream.
                            }
                            if (!id) { session.close(); break; }
                            slot.xudp_session=*id;
                        }
                        credit->complete(packet->packet.data.size());
                        session.count_traffic(true,packet->packet.data.size());
                        if (session.closed || Clock::now()>=*state.active_deadline) { session.close(); break; }
                        session.touched=Clock::now(); ingress.complete_tunnel(true); continue;
                    }
#endif
                    auto frame=net::encode_datagram(slot.framing,uot_address(target),packet->packet.data);
                    if (!frame) { ingress.complete_tunnel(); continue; }
                    auto token=slot.authorization.begin(target);
                    if (!token) { ingress.complete_tunnel(); continue; }
                    if (Clock::now()>=*state.active_deadline) {
                        (void)slot.authorization.finish(*token,false);session.close();break;
                    }
                    credit->submit();
                    auto sent=co_await slot.tunnel->send(*frame);
                    if (sent) {
                        credit->complete(packet->packet.data.size());
                        session.count_traffic(true,packet->packet.data.size());
                    }
#ifdef NEXUS_TEST_UOT_WRITE_RACE
                    // Hold the authorization transaction open after the peer can
                    // receive the frame, making the reply/write race reproducible.
                    if (auto gate=std::getenv("NEXUS_TEST_UOT_WRITE_RACE")) {
                        auto fd=std::atoi(gate);
                        (void)::fcntl(fd,F_SETFL,::fcntl(fd,F_GETFL)|O_NONBLOCK);
                        char release;
                        while (!session.closed) {
                            auto n=::read(fd,&release,1);
                            if (n==1) { if (release=='f') sent=false; break; }
                            if (n==0 || (errno!=EAGAIN && errno!=EWOULDBLOCK && errno!=EINTR)) { sent=false; break; }
                            auto [error]=co_await io::delay(1ms);
                            if (error) { sent=false; break; }
                        }
                    }
#endif
                    sent=sent && !session.closed && Clock::now()<*state.active_deadline;
                    (void)slot.authorization.finish(*token,sent);
                    if (!sent || session.closed) { session.close(); break; }
                    session.touched=Clock::now(); ingress.complete_tunnel(true);
                }
                state.cancel(); co_return capy::results<>{};
            } catch (...) { state.cancel(); session.close(); throw; }
        }
        auto uot_reader(Session& session, socks5::UdpIngress& ingress, UotState& state, std::size_t index)
            -> capy::task<capy::results<>> {
            using namespace std::chrono_literals;
            try {
#ifdef NEXUS_ENABLE_FAKEIP
                if (index>=ordinary_udp_slots)
                    co_return co_await state.aliases->read(session,ingress,state.readers,index-ordinary_udp_slots);
#endif
                auto& slot=state.slot_at(index);
#ifdef NEXUS_ENABLE_VLESS
                for (;;) {
                    while (!session.closed && !state.readers.stopped() && !slot.ready) {
                        auto [error]=co_await slot.readiness.wait();if(error)session.close();
                    }
                    if (session.closed || state.readers.stopped()) co_return capy::results<>{};
                    if (!slot.xudp_client) break;
                    slot.xudp_reader_active=true;
                    while (!session.closed && !slot.xudp_rotating) {
                        auto reply=co_await slot.xudp_client->read();
                        if (!reply) { if (!slot.xudp_rotating) session.close(); break; }
                        if (reply->action==xudp::Incoming::ended) {
                            if (reply->session==slot.xudp_session) slot.xudp_session=0;
                            continue;
                        }
                        if (!reply->source || (reply->source->family!=xudp::Family::ipv4 && reply->source->family!=xudp::Family::ipv6)) { session.close(); break; }
                        socks5::UdpPeer source{reply->source->family==xudp::Family::ipv4 ? std::uint8_t{1} : std::uint8_t{4},{},reply->source->port};
                        std::copy_n(reply->source->bytes.begin(),reply->source->length,source.address.begin());
                        for (;;) {
                            auto queued=ingress.queue_tunnel_reply(source,reply->payload);
                            if (!queued) { session.close(); break; }
                            if (*queued!=socks5::UdpReplyStatus::busy) break;
                            auto [error]=co_await io::delay(1ms); if (error || session.closed) { session.close(); break; }
                        }
                    }
                    slot.xudp_reader_active=false;
                    if (!slot.xudp_rotating || session.closed) co_return capy::results<>{};
                }
#else
                while (!session.closed && !state.readers.stopped() && !slot.ready) {
                    auto [error]=co_await slot.readiness.wait();if(error)session.close();
                }
#endif
                if(session.closed || state.readers.stopped())co_return capy::results<>{};
                auto peer=index<routed_udp_slots ? net::ProxyAddress{} : uot_address(state.fixed.peer(index-routed_udp_slots));
                co_await uot_read_framed(session,ingress,slot.tunnel,slot.authorization,slot.framing,peer);
                session.close();
                co_return capy::results<>{};
            } catch (...) { session.close(); throw; }
        }
