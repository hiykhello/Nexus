import std;
import crypto;
import wireguard;
import wireguard.crypto;
import wireguard.endpoint;
import wireguard.registry;
import wireguard.host;

namespace {
    using namespace wireguard;
    using namespace std::chrono_literals;
    using Host=PeerHost<2,4,512,2>;
    auto key(unsigned first) -> ::crypto::X25519Private {
        Key bytes; for (std::size_t i=0;i<32;++i) bytes[i]=static_cast<std::uint8_t>(first+i);
        auto value=::crypto::X25519Private::from_bytes(bytes); if (!value) std::terminate(); return std::move(*value);
    }
    auto public_key(unsigned first) -> Key { auto private_key=key(first); auto value=private_key.public_key(); if (!value) std::terminate(); return *value; }
    auto address(unsigned node,unsigned suffix=0) -> EndpointAddress { return {4,{198,51,100,static_cast<std::uint8_t>(node)},static_cast<std::uint16_t>(10000+node+suffix)}; }
    auto prefix(unsigned node) -> AllowedPrefix { return {4,{10,0,0,static_cast<std::uint8_t>(node)},32}; }
    auto config(unsigned remote,unsigned remote_key) -> EndpointConfig {
        EndpointConfig result; result.peer_public=public_key(remote_key); result.peer=address(remote); result.allowed_ips={prefix(remote)}; return result;
    }
    auto inner(unsigned from,unsigned to,unsigned marker=1) -> std::array<std::uint8_t,24> {
        std::array<std::uint8_t,24> result{0x45,0,0,24,0,0,0,0,64,253,0,0,10,0,0,static_cast<std::uint8_t>(from),10,0,0,static_cast<std::uint8_t>(to)};
        for (std::size_t i=20;i<result.size();++i) result[i]=static_cast<std::uint8_t>(marker+i);
        return result;
    }
    struct Peers {
        // Both local owners share one local identity/UDP port and have
        // separate direct peer state; no host pointer outlives these owners.
        std::expected<Endpoint,EndpointFailure> b=Endpoint::create(key(0),config(2,32));
        std::expected<Endpoint,EndpointFailure> c=Endpoint::create(key(0),config(3,64));
        std::expected<Endpoint,EndpointFailure> remote_b=Endpoint::create(key(32),config(1,0));
        std::expected<Endpoint,EndpointFailure> remote_c=Endpoint::create(key(64),config(1,0));
    };
    auto queue_dispatch(Host& host,PeerHandle peer,Endpoint& endpoint,std::span<std::uint8_t const> wire,EndpointAddress source,Clock::time_point now)
        -> std::expected<EndpointReceived,EndpointFailure> {
        if (!host.enqueue_indexed(wire,source,true)) return std::unexpected(EndpointFailure{EndpointError::protocol,{}});
        auto candidate=host.take();
        if (!candidate || candidate->peer!=peer || !host.valid(*candidate)) return std::unexpected(EndpointFailure{EndpointError::protocol,{}});
        auto result=endpoint.receive(candidate->wire(),candidate->source,true,now);
        if (!host.registry().sync(peer,endpoint)) return std::unexpected(EndpointFailure{EndpointError::protocol,{}});
        return result;
    }
    auto establish(Host& host,PeerHandle peer,Endpoint& local,Endpoint& remote,unsigned node,Clock::time_point now,unsigned epoch=1) -> bool {
        if (!local.request_handshake(now)) return false;
        auto polled=local.poll(now);
        if (!polled || !polled->handshake || !host.registry().sync(peer,local)) return false;
        auto request=*polled->handshake;
        auto reservation=host.registry().reserve(peer,request.ticket,7);
        auto timestamp=make_timestamp(epoch,0);
        if (!reservation || !timestamp || !host.registry().valid(*reservation)) return false;
        auto hello=local.initiate(request,reservation->index,key(96+epoch+node),*timestamp,0ms,now,IndexMode::exact);
        if (!hello || !host.registry().sync(peer,local) || host.registry().valid(*reservation) || !local.complete_send(hello->serial,true,now)) return false;
        auto accepted=remote.receive(hello->bytes,address(1),true,now+1ms);
        if (!accepted || !accepted->handshake) return false;
        auto response=remote.respond(*accepted->handshake,100+node,key(128+epoch+node),now+2ms);
        if (!response || !remote.complete_send(response->serial,true,now+2ms)) return false;
        accepted=queue_dispatch(host,peer,local,response->bytes,address(node),now+3ms);
        if (!accepted || !local.status().current) return false;
        auto confirm=local.poll(now+3ms);
        if (!confirm || !confirm->datagram || !local.complete_send(confirm->datagram->serial,true,now+3ms)) return false;
        accepted=remote.receive(confirm->datagram->bytes,address(1),true,now+4ms);
        return accepted && accepted->key_confirmed && host.registry().sync(peer,local);
    }
    auto emit(Endpoint& endpoint,unsigned source,unsigned destination,unsigned marker,Clock::time_point now) -> std::optional<EndpointDatagram> {
        if (!endpoint.enqueue(inner(source,destination,marker),now)) return {};
        auto output=endpoint.poll(now);
        if (!output || !output->datagram || output->datagram->kind!=OutboundKind::data || !endpoint.complete_send(output->datagram->serial,true,now)) return {};
        return std::move(*output->datagram);
    }
    auto global_preflight_and_authentication() -> bool {
        Peers peers; Host host; auto a=host.registry().add(),b=host.registry().add(); auto now=Clock::time_point(10s);
        if (!a || !b || !peers.b || !peers.c || !peers.remote_b || !peers.remote_c ||
            !establish(host,*a,*peers.b,*peers.remote_b,2,now) || !establish(host,*b,*peers.c,*peers.remote_c,3,now)) return false;
        if (peers.b->status().current!=7 || peers.c->status().current!=8 || host.registry().status().indexes!=2) return false;
        auto conflicting_snapshot=peers.c->receiver_indexes();
        auto free=std::ranges::find(conflicting_snapshot,false,&ReceiverIndex::used);
        if (free==conflicting_snapshot.end()) return false;
        *free=ReceiverIndex{true,7,1};
        auto rejected_sync=host.registry().sync(*b,conflicting_snapshot,peers.c->status().latest_attempt);
        if (rejected_sync || rejected_sync.error().code!=HostError::index_conflict || host.registry().lookup(7)->peer!=*a ||
            host.registry().lookup(8)->peer!=*b || peers.c->status().current!=8 || peers.c->status().peer!=address(3)) return false;
        // A conflicting global reservation is rejected before touching the
        // established second peer's keys, replay state or endpoint address.
        now+=10s;
        if (!peers.c->request_handshake(now)) return false;
        auto request=peers.c->poll(now); auto before=peers.c->status();
        if (!request || !request->handshake || !host.registry().sync(*b,*peers.c)) return false;
        auto conflicting=host.registry().reserve(*b,request->handshake->ticket,7,IndexMode::exact);
        if (conflicting || conflicting.error().code!=HostError::index_conflict || peers.c->status().current!=before.current || peers.c->status().peer!=before.peer || peers.c->status().indexes!=before.indexes) return false;
        auto timestamp=make_timestamp(2,0); if (!timestamp) return false;
        auto local_conflict=peers.c->initiate(*request->handshake,8,key(200),*timestamp,0ms,now,IndexMode::exact);
        if (local_conflict || local_conflict.error().code!=EndpointError::index_conflict || peers.c->status().current!=before.current || peers.c->status().handshake || peers.c->status().indexes!=before.indexes) return false;
        auto reservation=host.registry().reserve(*b,request->handshake->ticket,7);
        if (!reservation || reservation->index!=9 || !host.registry().release(*reservation) || !host.registry().sync(*b,*peers.c)) return false;
        auto wire=emit(*peers.remote_b,2,1,1,now+1ms); if (!wire) return false;
        auto forged=wire->bytes; forged.back()^=1;
        auto accepted=queue_dispatch(host,*a,*peers.b,forged,address(2,10),now+1ms);
        if (accepted || peers.b->status().peer!=address(2)) return false;
        auto spoofed=emit(*peers.remote_b,99,1,2,now+2ms); if (!spoofed) return false;
        accepted=queue_dispatch(host,*a,*peers.b,spoofed->bytes,address(2,11),now+2ms);
        if (accepted || accepted.error().code!=EndpointError::disallowed_source || peers.b->status().peer!=address(2)) return false;
        accepted=queue_dispatch(host,*a,*peers.b,wire->bytes,address(2,12),now+3ms);
        auto expected=inner(2,1,1);
        if (!accepted || !std::ranges::equal(accepted->packet,expected) || !accepted->peer_changed || peers.b->status().peer!=address(2,12)) return false;
        auto replay=queue_dispatch(host,*a,*peers.b,wire->bytes,address(2,13),now+4ms);
        return !replay && replay.error().protocol==Error::replay && peers.b->status().peer==address(2,12) && peers.c->status().peer==address(3);
    }
    auto generations_queue_and_deletion() -> bool {
        Peers peers; Host host; auto a=host.registry().add(),b=host.registry().add(); auto now=Clock::time_point(10s);
        if (!a || !b || !establish(host,*a,*peers.b,*peers.remote_b,2,now) || !establish(host,*b,*peers.c,*peers.remote_c,3,now)) return false;
        auto held=emit(*peers.remote_b,2,1,8,now+1s);
        if (!held || !host.enqueue_indexed(held->bytes,address(2,1),true)) return false;
        auto candidate=host.take(); if (!candidate || !host.valid(*candidate)) return false;
        if (!establish(host,*a,*peers.b,*peers.remote_b,2,now+30s,2) || peers.b->status().previous!=7 || peers.b->status().current!=9 || host.registry().status().indexes!=3) return false;
        if (!host.valid(*candidate)) return false;
        auto accepted=peers.b->receive(candidate->wire(),candidate->source,true,now+30s+5ms);
        auto expected=inner(2,1,8);
        if (!accepted || !std::ranges::equal(accepted->packet,expected) || peers.b->status().peer!=address(2,1) || !host.registry().sync(*a,*peers.b)) return false;
        if (!host.enqueue_indexed(held->bytes,address(2,2),true)) return false;
        auto expired=peers.b->poll(now+180s+4ms);
        if (!expired || peers.b->status().previous || !host.registry().sync(*a,*peers.b) || host.valid(*candidate) || host.status().packets || host.take() || host.registry().lookup(7)) return false;
        // The other peer may reuse the numeric index after expiry, but never
        // the old candidate's handle/ticket binding or queued work.
        if (!peers.c->request_handshake(now+181s)) return false;
        auto request=peers.c->poll(now+181s);
        if (!request || !request->handshake || !host.registry().sync(*b,*peers.c)) return false;
        auto reuse=host.registry().reserve(*b,request->handshake->ticket,7,IndexMode::exact);
        if (!reuse || reuse->index!=7 || host.valid(*candidate)) return false;
        auto old_handle=*a;
        if (!host.registry().erase(old_handle) || host.valid(*candidate)) return false;
        peers.b->close();
        auto replacement=host.registry().add();
        if (!replacement || replacement->slot!=old_handle.slot || replacement->generation==old_handle.generation || host.registry().valid(old_handle) || host.valid(*candidate)) return false;
        // A pending entropy result cannot install or release anything after
        // deletion/reuse, even when both ticket and numeric index coincide.
        if (!host.registry().erase(*b) || host.registry().valid(*reuse) || host.registry().release(*reuse)) return false;
        peers.c->close();
        auto replacement_b=host.registry().add();
        if (!replacement_b || !host.registry().sync(*replacement_b,{},1)) return false;
        auto fresh=host.registry().reserve(*replacement_b,1,7,IndexMode::exact);
        return fresh && !host.registry().valid(*reuse) && host.registry().release(*fresh) && !host.registry().status().indexes;
    }
    auto stale_prepare_and_failed_install() -> bool {
        Peers peers; Host host; auto peer=host.registry().add(); auto now=Clock::time_point(10s);
        if (!peer || !peers.b || !peers.remote_b || !establish(host,*peer,*peers.b,*peers.remote_b,2,now)) return false;
        now+=10s;
        if (!peers.b->request_handshake(now)) return false;
        auto first=peers.b->poll(now);
        if (!first || !first->handshake || !host.registry().sync(*peer,*peers.b)) return false;
        auto reservation=host.registry().reserve(*peer,first->handshake->ticket,7);
        if (!reservation) return false;
        // The host may process other control input while entropy is pending.
        // Advancing the Endpoint ticket invalidates the old reservation first.
        auto retry=peers.b->poll(now+5s);
        if (!retry || !retry->handshake || retry->handshake->ticket==first->handshake->ticket || !host.registry().sync(*peer,*peers.b) || host.registry().valid(*reservation)) return false;
        auto stamp=make_timestamp(2,0); if (!stamp) return false;
        auto stale=peers.b->initiate(*first->handshake,reservation->index,key(201),*stamp,0ms,now+5s,IndexMode::exact);
        if (stale || stale.error().code!=EndpointError::stale_attempt || peers.b->status().current!=7 || peers.b->status().indexes!=1 || host.registry().lookup(reservation->index)) return false;
        auto fresh=host.registry().reserve(*peer,retry->handshake->ticket,7);
        if (!fresh || fresh->index!=8) return false;
        auto invalid_jitter=peers.b->initiate(*retry->handshake,fresh->index,key(202),*stamp,334ms,now+5s,IndexMode::exact);
        if (invalid_jitter || !host.registry().release(*fresh) || !host.registry().sync(*peer,*peers.b) || peers.b->status().current!=7 || peers.b->status().peer!=address(2) || host.registry().status().indexes!=1) return false;
        auto wire=emit(*peers.remote_b,2,1,3,now+5s+1ms); if (!wire) return false;
        auto accepted=queue_dispatch(host,*peer,*peers.b,wire->bytes,address(2),now+5s+1ms);
        return accepted && std::ranges::equal(accepted->packet,inner(2,1,3));
    }
}

auto main() -> int {
    if (!global_preflight_and_authentication()) { std::println("WireGuard host global preflight/exact index/authenticated dispatch failed"); return 1; }
    if (!generations_queue_and_deletion()) { std::println("WireGuard host generation overlap/queued expiry/deletion failed"); return 2; }
    if (!stale_prepare_and_failed_install()) { std::println("WireGuard host stale preparation/failed install rollback failed"); return 3; }
    std::println("WireGuard host two peers sharing identity, global exact reservations, authenticated source/roam, generation overlap, queued expiry, deletion and preparation rollback passed");
}
