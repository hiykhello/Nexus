export module net.stream_datagrams;
import std;
import net.datagram_frame;
export import net.ordered_datagram;
import net.udp_direct;
import net.lazy_readers;
import platform.stream_peer;
import rules;
import uot;
import xudp;
import xudp.client_sessions;
import xudp.client_io;
import capy;
import corosio;
import sniff.udp_quic;
export import net.stream_datagram_quic;
export import net.stream_datagram_reply;

export namespace net::stream_datagrams {
    using Clock=std::chrono::steady_clock;
    namespace capy = ::capy;
    namespace io = ::corosio;
    struct NoHooks {};

    inline auto peer_address(UdpEndpoint const& peer) -> ProxyAddress {
        ProxyAddress address; address.family=peer.family==4 ? ProxyAddressFamily::ipv4 : ProxyAddressFamily::ipv6;
        address.length=peer.family==4 ? 4 : 16; address.port=peer.port;
        std::copy_n(peer.address.begin(),address.length,address.bytes.begin()); return address;
    }
    template<class Tunnel>
    struct MultiplexStream {
        Tunnel* tunnel=nullptr;
        std::optional<Clock::time_point>* deadline=nullptr;
        bool const* closed=nullptr;
        auto write(std::span<std::uint8_t const> bytes) -> capy::task<bool> {
            // ClientIo commits its authorization immediately after write returns.
            // Report a late successful transport write as failure before that commit.
            auto until=deadline && *deadline ? **deadline : Clock::time_point::max();
            if ((closed && *closed) || Clock::now()>=until) { cancel(); co_return false; }
            auto sent=co_await (*tunnel)->send(bytes);
            if (!sent || (closed && *closed) || Clock::now()>=until) { cancel(); co_return false; }
            co_return true;
        }
        auto read(std::span<std::uint8_t> bytes) { return (*tunnel)->read(bytes); }
        auto cancel() noexcept -> void { if (tunnel && *tunnel) (*tunnel)->cancel(); }
    };
    // A stream association owns bounded queues, direct reply authorization and
    // at most one outbound stream per route/address family. Protocols supply
    // only the authenticated stream, framing and initial plaintext.
    template<class Session,class Stream,class Resolver,class Hooks=NoHooks>
    struct Server {
        using hooks=Hooks;
        using Tunnel=std::remove_cvref_t<decltype(std::declval<Session&>().tunnel)>;
        struct Packet {
            ProxyAddress destination; std::vector<std::uint8_t> payload;
            static constexpr auto budget=std::chrono::seconds(10);
            Clock::time_point received,deadline;
            std::optional<sniff::QuicProbeResult> quic;
            rules::IngressMetadata ingress;
            Packet(ProxyAddress target,std::vector<std::uint8_t> bytes,Clock::time_point at,
                rules::IngressMetadata metadata={})
                :destination(target),payload(std::move(bytes)),received(at),deadline(at+budget),ingress(metadata) {}
        };
        struct Slot {
            Tunnel tunnel; UdpAuthorization authorization; DatagramFraming framing;
            MultiplexStream<Tunnel> stream;
            std::unique_ptr<xudp::ClientIo<MultiplexStream<Tunnel>>> client;
            std::uint16_t id=0;
            bool ready=false,rotating=false,reader_active=false;
            capy::async_event readiness,reader_done,auth_wake;
            std::optional<Clock::time_point> active_deadline;
        };
        Session& session; io::io_context& context; Stream& incoming;
        rules::RouteProgram const& policy; Resolver resolver; OrderedRouter ordered;
        UdpDirect direct; DirectSocketWait direct_wake;
        std::optional<UdpEndpoint> source; DatagramFraming framing; ProxyAddress destination;
        static constexpr std::size_t ordinary_slots=4096, fixed_slots=512;
        RoutedDatagramSlots<Slot,ordinary_slots> routed;
        FixedDatagramSlots<Slot,UdpEndpoint,fixed_slots> fixed;
        LazyReaders<0> readers;
        std::deque<Packet> pending; std::size_t pending_bytes=0;
        bool resolving=false,canceled=false; Clock::time_point deadline{}; Slot* forwarding=nullptr;
        capy::async_event pending_wake,space_wake,timeout_wake;
        Server(Session& owner,io::io_context& executor,Stream& stream,rules::RouteProgram const& rules,Resolver resolve,
            DatagramFraming format,ProxyAddress target={},std::optional<UdpEndpoint> peer={},OrderedRouter router={},
            std::size_t routed_cap=ordinary_slots,std::size_t fixed_cap=fixed_slots)
            : session(owner),context(executor),incoming(stream),policy(rules),resolver(std::move(resolve)),ordered(std::move(router)),direct(rules,owner.direct_tcp_options ? &owner.direct_tcp_options->binding : nullptr),direct_wake(executor),source(peer),framing(format),destination(target),routed(routed_cap),fixed(fixed_cap),readers(routed_cap+fixed_cap) {}
        auto slot_at(std::size_t index) -> Slot& { return index<routed.soft_cap() ? routed.slot(index) : fixed.slot(index-routed.soft_cap()); }
        auto notify_pending() noexcept -> void { pending_wake.set(); timeout_wake.set(); }
        auto wake_all() noexcept -> void {
            pending_wake.set(); space_wake.set(); timeout_wake.set(); direct_wake.notify();
            auto w=[](Slot& s) noexcept { s.readiness.set(); s.reader_done.set(); s.auth_wake.set(); };
            routed.for_each(w); fixed.for_each(w);
        }
        auto cancel() noexcept -> void {
            readers.stop(); direct_wake.stop(); wake_all();
            auto close=[](Slot& slot) noexcept { if (slot.client) slot.client->cancel(); else if (slot.tunnel) slot.tunnel->cancel(); slot.readiness.set(); };
            routed.for_each(close); fixed.for_each(close);
        }
        ~Server() { cancel(); direct.close(); }
    };

    template<class State>
    auto forward(State& state,std::size_t outbound,UdpEndpoint target,std::span<std::uint8_t const> payload,
                 Clock::time_point deadline) -> capy::task<bool> {
        if (!state.session.tunnel_factories || outbound>=state.session.tunnel_factories->size()) co_return false;
        auto const& factory=(*state.session.tunnel_factories)[outbound];
        if (state.session.closed || Clock::now()>=deadline) co_return false;
        auto cancel_victim=[](typename State::Slot& v) noexcept {
            v.rotating=true; v.ready=false; v.readiness.clear();
            if (v.client) v.client->cancel(); else if (v.tunnel) v.tunnel->cancel();
            v.auth_wake.set();
        };
        std::size_t index=0; bool evicted=false;
        if (factory.packet_fixed_peer) {
            auto sel=state.fixed.select_or_evict(outbound,target,cancel_victim);
            if (!sel) co_return false;
            index=state.routed.soft_cap()+sel->index; evicted=sel->evicted;
        } else {
            auto key=(static_cast<std::uint64_t>(outbound) << 1) | (!factory.packet_dual_family && target.family==6 ? 1u : 0u);
            auto sel=state.routed.select_or_evict(key,cancel_victim);
            if (!sel) co_return false;
            index=sel->index; evicted=sel->evicted;
        }
        auto& slot=state.slot_at(index);
        slot.active_deadline=deadline;state.forwarding=&slot;state.timeout_wake.set();
        slot.stream.tunnel=&slot.tunnel;slot.stream.deadline=&slot.active_deadline;slot.stream.closed=&state.session.closed;
        struct Guard {
            State& state; typename State::Slot& slot;
            ~Guard() {slot.active_deadline.reset();state.forwarding=nullptr;}
        } guard{state,slot};
        auto expired=[&] {return Clock::now()>=*slot.active_deadline;};
        auto drain_reader=[&]() -> capy::task<bool> {
            while (!state.session.closed && !expired() && slot.reader_active) {
                slot.reader_done.clear();
                if (!slot.reader_active) break;
                auto [error]=co_await io::timeout(slot.reader_done.wait(),*slot.active_deadline);
                if (error && state.session.closed) break;
            }
            if (state.session.closed || expired()) { state.session.close(); state.cancel(); co_return false; }
            co_return true;
        };
        if (evicted) {
            if (!co_await drain_reader()) co_return false;
            slot.client.reset(); slot.tunnel={}; slot.id=0; slot.authorization={}; slot.rotating=false;
        }
        for (;;) {
            if(state.session.closed)co_return false;
            if(expired()) {state.session.close();state.cancel();co_return false;}
            if (!slot.tunnel) {
                slot.active_deadline=std::min(*slot.active_deadline,Clock::now()+std::chrono::milliseconds(factory.timeout_ms));
                state.timeout_wake.set();
                slot.tunnel=factory(state.session,state.context);
                if (!slot.tunnel) co_return false;
                auto transport=slot.tunnel->packet_transport();
                if (transport.kind==PacketTransportKind::none) { slot.tunnel={}; co_return false; }
                if(expired()) {state.session.close();state.cancel();co_return false;}
                auto connected=co_await slot.tunnel->connect_packets(peer_address(target),*slot.active_deadline);
                if (state.session.closed) co_return false;
                if (expired()) {state.session.close();state.cancel();co_return false;}
                if (connected!=decltype(connected)::connected) { state.session.close(); co_return false; }
                if (transport.kind==PacketTransportKind::xudp) {
                    slot.client=std::make_unique<xudp::ClientIo<std::remove_reference_t<decltype(slot.stream)>>>(slot.stream,1);
                } else {
                    slot.framing=transport.framing;
                    if (transport.needs_uot_request) {
                        auto request=uot::encode_request({false,peer_address(target)});
                        if (!request || !co_await slot.stream.write(*request) || expired()) { state.session.close(); state.cancel(); co_return false; }
                    }
                }
                slot.rotating=false; slot.ready=true;
                if(!state.readers.request(index)) {state.session.close();state.cancel();co_return false;}
                slot.readiness.set();
            }
            if (slot.client) {
                xudp::Address address; address.family=target.family==4 ? xudp::Family::ipv4 : xudp::Family::ipv6;
                address.length=target.family==4 ? 4 : 16; address.port=target.port;
                std::copy_n(target.address.begin(),address.length,address.bytes.begin());
                bool sent=false;
                if (slot.id) {
                    auto result=co_await slot.client->send(slot.id,address,payload);
                    if(expired()) {state.session.close();state.cancel();co_return false;}
                    if (result) sent=true;
                    else if (result.error()!=xudp::ClientIoError::session || slot.id) { state.session.close(); co_return false; }
                }
                if (!sent) {
                    auto opened=co_await slot.client->open(address,payload);
                    if(expired()) {state.session.close();state.cancel();co_return false;}
                    if (!opened && opened.error()==xudp::ClientIoError::exhausted) {
                        slot.rotating=true; slot.ready=false; slot.readiness.clear(); slot.client->cancel();
                        if (!co_await drain_reader()) co_return false;
                        slot.client.reset(); slot.tunnel={}; continue;
                    }
                    if (!opened) { state.session.close(); co_return false; }
                    slot.id=*opened;
                }
                co_return !state.session.closed;
            }
            auto wire=encode_datagram(slot.framing,peer_address(target),payload);
            if (!wire) co_return false;
            auto token=slot.authorization.begin(target);
            if (!token) co_return false;
            auto sent=co_await slot.stream.write(*wire);
            if constexpr (requires { State::hooks::after_send(state,sent); }) sent=co_await State::hooks::after_send(state,sent);
            sent=sent && !state.session.closed && !expired();
            (void)slot.authorization.finish(*token,sent);
            slot.auth_wake.set();
            if (!sent) {state.session.close();state.cancel();}
            co_return sent && !state.session.closed;
        }
    }

    template<class State>
    auto send(State& state,typename State::Packet& packet) -> capy::task<> {
        using namespace std::chrono_literals;
        auto deadline=packet.deadline;
        if(state.session.closed || Clock::now()>=deadline)co_return;
        DatagramResult frame{DatagramStatus::accepted,0,packet.destination,packet.payload};
        auto const& address=frame.destination;
        auto kind=address.family==ProxyAddressFamily::ipv4 ? UdpTargetKind::ipv4 : address.family==ProxyAddressFamily::ipv6 ? UdpTargetKind::ipv6 : UdpTargetKind::domain;
        UdpTarget target{kind,std::span(address.bytes).first(address.length),address.port};
        auto source=state.source ? &*state.source : nullptr;
        auto allowed=[&](UdpEndpoint const& candidate) {
            if constexpr (requires { state.incoming.allows_target(candidate); })
                return state.incoming.allows_target(candidate);
            return true;
        };
        auto delivered=[&](auto& credit,bool ordered,UdpSelection const& selection) {
            credit.complete(frame.payload.size());
            state.session.record_datagram_route(ordered,selection);
            state.session.count_traffic(true,frame.payload.size());
            state.session.touched=Clock::now();
        };
        if(state.ordered) {
            if constexpr (requires { state.incoming.native_packets; })
                state.session.ingress=packet.ingress;
            state.resolving=true;state.canceled=false;state.deadline=deadline;state.timeout_wake.set();
            OrderedSniffer inspect=[&](Clock::time_point until) {return inspect_quic(state,packet,until);};
            auto choice=co_await state.ordered(address,frame.payload,packet.received,state.deadline,inspect);
            deadline=state.deadline;
            state.resolving=false;
            if (!choice || state.canceled || state.session.closed || Clock::now()>=deadline || choice->outbound==1) co_return;
            if (choice->dns_reply) {
                if (!co_await send_reply(state,frame.destination,*choice->dns_reply,deadline)) state.session.close();
                co_return;
            }
            for(auto candidate:choice->candidates) while(!state.session.closed && Clock::now()<deadline) {
                auto checked=udp_validate_candidate(target,candidate);if(!checked)break;
                if (!allowed(*checked)) break;
                UdpSelection selected{*checked,choice->outbound,choice->rule};
                auto credit=reserve_datagram_bytes(state.session,true,frame.payload.size());
                if (!credit) co_return;
                if(choice->outbound>=2) {
                    credit->submit();
                    if (co_await forward(state,choice->outbound-2,*checked,frame.payload,deadline))
                        delivered(*credit,true,selected);
                    co_return;
                }
                auto sent=state.direct.send_selected(target,*checked,frame.payload,deadline);
                state.direct_wake.watch(state.direct.native_handles()); state.direct_wake.notify();
                if (sent) {
                    delivered(*credit,true,selected);
                    co_return;
                }
                auto error=std::get_if<std::error_code>(&sent.error());
                if(!error || (*error!=std::errc::resource_unavailable_try_again && *error!=std::errc::interrupted))break;
                auto [delay_error]=co_await io::delay(5ms);if(delay_error){state.session.close();co_return;}
            }
            co_return;
        }
        if (!udp_select_preflight(state.policy,target,source,state.session.auth_user,state.session.source_interface,packet.ingress)) co_return;
        std::vector<UdpEndpoint> candidates;
        if (kind==UdpTargetKind::domain) {
            state.resolving=true; state.canceled=false; state.deadline=deadline; state.timeout_wake.set();
            auto endpoints=co_await state.resolver(std::string(reinterpret_cast<char const*>(target.address.data()),target.address.size()),target.port,deadline);
            state.resolving=false;
            if (!endpoints || state.canceled || state.session.closed || Clock::now()>=deadline) co_return;
            for (auto const& endpoint:*endpoints) {
                if (endpoint.address().is_v6() && endpoint.address().to_v6().scope_id()) continue;
                UdpEndpoint peer{endpoint.address().is_v4() ? std::uint8_t{4} : std::uint8_t{6},{},endpoint.port()};
                if (peer.family==4) { auto bytes=endpoint.address().to_v4().to_bytes(); std::ranges::copy(bytes,peer.address.begin()); }
                else { auto bytes=endpoint.address().to_v6().to_bytes(); std::ranges::copy(bytes,peer.address.begin()); }
                candidates.push_back(peer);
            }
        } else {
            UdpEndpoint peer{kind==UdpTargetKind::ipv4 ? std::uint8_t{4} : std::uint8_t{6},{},target.port};
            std::ranges::copy(target.address,peer.address.begin()); candidates.push_back(peer);
        }
        for (auto candidate:candidates) while (!state.session.closed && Clock::now()<deadline) {
            auto selected=udp_select(state.policy,target,candidate,source,state.session.auth_user,state.session.source_interface,packet.ingress);
            if (!selected || !allowed(selected->target)) break;
            auto credit=reserve_datagram_bytes(state.session,true,frame.payload.size());
            if (!credit) co_return;
            if (selected->outbound>=2) {
                credit->submit();
                if (co_await forward(state,selected->outbound-2,selected->target,frame.payload,deadline))
                    delivered(*credit,false,*selected);
                co_return;
            }
            auto sent=state.direct.send_selected(target,selected->target,frame.payload,deadline);
            state.direct_wake.watch(state.direct.native_handles()); state.direct_wake.notify();
            if (sent) {
                delivered(*credit,false,*selected);
                co_return;
            }
            auto error=std::get_if<std::error_code>(&sent.error());
            if (!error || (*error!=std::errc::resource_unavailable_try_again && *error!=std::errc::interrupted)) break;
            auto [delay_error]=co_await io::delay(5ms);
            if (delay_error) { state.session.close(); co_return; }
        }
    }
    template<class State>
    auto upload(State& state,std::span<std::uint8_t const> initial) -> capy::task<capy::results<>> {
        using namespace std::chrono_literals;
        try {
            DatagramDecoder decoder(state.framing,state.destination);
            std::array<std::uint8_t,16384> bytes{};
            while (!state.session.closed) {
                auto input=initial; initial={};
                if (input.empty()) {
                    auto n=co_await state.incoming.read(bytes,Clock::now()+300s);
                    if (!n || !*n || *n>bytes.size()) break;
                    input=std::span(bytes).first(*n);
                }
                std::size_t offset=0;
                while (offset<input.size() && !state.session.closed) {
                    auto fed=decoder.feed(input.subspan(offset)); offset+=fed.consumed;
                    if (fed.status==DatagramStatus::incomplete) break;
                    if (fed.status!=DatagramStatus::accepted || !decoder.packet()) { state.session.close(); break; }
                    auto packet=*decoder.packet(); bool reported=false;
                    auto received=Clock::now();
                    auto deadline=received+State::Packet::budget;
                    while (!state.session.closed && Clock::now()<deadline && (state.pending.size()>=64 || state.pending_bytes+packet.payload.size()>1024*1024)) {
                        if constexpr (requires { State::hooks::queue_full(state,packet.payload.size()); }) {
                            if (!reported) { State::hooks::queue_full(state,packet.payload.size()); reported=true; }
                        }
                        bool closed;
                        if constexpr (requires { state.incoming.peer_closed(); }) closed=state.incoming.peer_closed();
                        else closed=platform::stream_peer_closed(state.session.client.native_handle());
                        if (closed) { state.session.close(); break; }
                        state.space_wake.clear();
                        if (state.pending.size()<64 && state.pending_bytes+packet.payload.size()<=1024*1024) break;
                        (void)co_await io::timeout(state.space_wake.wait(),std::min(deadline,Clock::now()+250ms));
                    }
                    if (state.session.closed) break;
                    if(Clock::now()>=deadline) {(void)decoder.consume();continue;}
                    state.pending.push_back({packet.destination,{packet.payload.begin(),packet.payload.end()},received});
                    state.pending_bytes+=packet.payload.size(); state.notify_pending(); (void)decoder.consume();
                }
            }
        } catch (...) { state.session.close(); state.cancel(); throw; }
        state.session.close(); state.cancel(); co_return capy::results<>{};
    }
    template<class State>
    auto process(State& state) -> capy::task<capy::results<>> {
        using namespace std::chrono_literals;
        try {
            while (!state.session.closed) {
                state.pending_wake.clear();
                if (state.pending.empty()) { auto [error]=co_await state.pending_wake.wait(); if (error) state.session.close(); continue; }
                auto packet=std::move(state.pending.front()); state.pending.pop_front(); state.pending_bytes-=packet.payload.size();
                state.space_wake.set();
                co_await send(state,packet);
            }
        } catch (...) { state.session.close(); state.cancel(); throw; }
        co_return capy::results<>{};
    }

    template<class State>
    auto download(State& state) -> capy::task<capy::results<>> {
        using namespace std::chrono_literals;
        try {
            std::array<std::uint8_t,65536> bytes{};
            while (!state.session.closed) {
                bool dropped=false; auto result=state.direct.poll(bytes,&dropped);
                if (!result) { state.session.close(); break; }
                if (*result) {
                    auto const& reply=**result;
                    if (!co_await send_reply(state,peer_address(reply.source),std::span(bytes).first(reply.size))) {
                        state.session.close(); break;
                    }
                    continue;
                }
                state.direct_wake.watch(state.direct.native_handles());
                if (!co_await state.direct_wake.wait(dropped)) { state.session.close(); break; }
            }
        } catch (...) { state.session.close(); state.cancel(); throw; }
        state.session.close(); state.cancel(); co_return capy::results<>{};
    }
    template<class State>
    auto tunnel_download(State& state,std::size_t index) -> capy::task<capy::results<>> {
        using namespace std::chrono_literals;
        try {
            auto& slot=state.slot_at(index);
            for (;;) {
                while (!state.session.closed && !state.readers.stopped() && !slot.ready) {
                    auto [error]=co_await slot.readiness.wait();if(error)state.session.close();
                }
                if (state.session.closed || state.readers.stopped()) co_return capy::results<>{};
                slot.reader_active=true;
                if (slot.client) {
                    while (!state.session.closed && !slot.rotating) {
                        auto reply=co_await slot.client->read();
                        if (!reply) { if (!slot.rotating) state.session.close(); break; }
                        if (reply->action==xudp::Incoming::ended) { if (reply->session==slot.id) slot.id=0; continue; }
                        if (!reply->source || (reply->source->family!=xudp::Family::ipv4 && reply->source->family!=xudp::Family::ipv6)) { state.session.close(); break; }
                        ProxyAddress source; source.family=reply->source->family==xudp::Family::ipv4 ? ProxyAddressFamily::ipv4 : ProxyAddressFamily::ipv6;
                        source.length=reply->source->length; source.port=reply->source->port;
                        std::copy_n(reply->source->bytes.begin(),source.length,source.bytes.begin());
                        if (!co_await send_reply(state,source,reply->payload)) { state.session.close(); break; }
                    }
                } else {
                    auto peer=index<state.routed.soft_cap() ? ProxyAddress{} : peer_address(state.fixed.peer(index-state.routed.soft_cap()));
                    DatagramDecoder decoder(slot.framing,peer);
                    std::array<std::uint8_t,16384> bytes{};
                    while (!state.session.closed && !slot.rotating) {
                        auto n=co_await slot.tunnel->read(bytes);
                        if (!n || !*n) { if (!slot.rotating) state.session.close(); break; }
                        std::size_t offset=0;
                        while (offset<*n && !state.session.closed && !slot.rotating) {
                            auto fed=decoder.feed(std::span(bytes).subspan(offset,*n-offset)); offset+=fed.consumed;
                            if (fed.status==DatagramStatus::incomplete) break;
                            auto packet=decoder.packet();
                            if (fed.status!=DatagramStatus::accepted || !packet || packet->destination.family==ProxyAddressFamily::domain) { state.session.close(); break; }
                            UdpEndpoint source{packet->destination.family==ProxyAddressFamily::ipv4 ? std::uint8_t{4} : std::uint8_t{6},{},packet->destination.port};
                            std::copy_n(packet->destination.bytes.begin(),packet->destination.length,source.address.begin()); bool reported=false;
                            while (!state.session.closed && !slot.rotating && slot.authorization.classify(source)==UdpReplyAuthorization::pending) {
                                if constexpr (requires { State::hooks::reply_pending(state); }) { if (!reported) { State::hooks::reply_pending(state); reported=true; } }
                                slot.auth_wake.clear();
                                if (slot.authorization.classify(source)!=UdpReplyAuthorization::pending) break;
                                auto [error]=slot.active_deadline ? co_await io::timeout(slot.auth_wake.wait(),*slot.active_deadline) : co_await slot.auth_wake.wait();
                                if (error && state.session.closed) break;
                            }
                            if (!state.session.closed && !slot.rotating && slot.authorization.accepts(source)) {
                                if (!co_await send_reply(state,packet->destination,packet->payload)) { state.session.close(); break; }
                            }
                            (void)decoder.consume();
                        }
                    }
                }
                slot.reader_active=false; slot.reader_done.set();
                if (!slot.rotating || state.session.closed) { state.cancel(); co_return capy::results<>{}; }
            }
        } catch (...) { state.session.close(); state.cancel(); throw; }
        state.cancel(); co_return capy::results<>{};
    }
    template<class State>
    auto timeout(State& state) -> capy::task<capy::results<>> {
        using namespace std::chrono_literals;
        if constexpr (requires { state.timeout_wake; }) {
            auto hook = [&]() noexcept { if constexpr (requires { state.wake_all(); }) state.wake_all(); };
            std::optional<std::stop_callback<decltype(hook)>> stop_cb;
            if constexpr (requires { state.session.stop; }) stop_cb.emplace(state.session.stop.get_token(), hook);
            while (!state.session.closed) {
                state.timeout_wake.clear();
                if (state.session.closed) break;
                auto now=Clock::now(); std::optional<Clock::time_point> next;
                auto clamp=[&](Clock::time_point tp) {if (!next || tp<*next) next=tp;};
                if (state.forwarding && state.forwarding->active_deadline) {
                    if (now>=*state.forwarding->active_deadline) { state.session.close(); state.cancel(); break; }
                    clamp(*state.forwarding->active_deadline);
                }
                if (state.resolving && !state.canceled) {
                    if (now>=state.deadline) { state.canceled=true; if (state.session.cancel_dns) state.session.cancel_dns(state.session.dns_operation); }
                    else clamp(state.deadline);
                }
                if (next) (void)co_await io::timeout(state.timeout_wake.wait(),*next);
                else if (auto [error]=co_await state.timeout_wake.wait(); error) break;
            }
        } else {
            while (!state.session.closed) {
                if (state.forwarding && state.forwarding->active_deadline && Clock::now()>=*state.forwarding->active_deadline) { state.session.close(); state.cancel(); break; }
                if (state.resolving && !state.canceled && Clock::now()>=state.deadline) { state.canceled=true; if (state.session.cancel_dns) state.session.cancel_dns(state.session.dns_operation); }
                auto [error]=co_await io::delay(5ms); if (error) state.session.close();
            }
        }
        state.cancel(); co_return capy::results<>{};
    }
    template<class State>
    auto tasks(State& state,std::span<std::uint8_t const> initial={}) -> std::vector<capy::task<capy::results<>>> {
        std::vector<capy::task<capy::results<>>> result;
        if constexpr (!requires {state.incoming.native_packets;}) result.push_back(upload(state,initial));
        result.push_back(process(state));
        result.push_back(download(state)); result.push_back(timeout(state));
        if(state.session.tunnel_factories && !state.session.tunnel_factories->empty())
            result.push_back(state.readers.run([&state](std::size_t index) {return tunnel_download(state,index);}));
        return result;
    }
}
