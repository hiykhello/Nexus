import std;
import wireguard;
import wireguard.endpoint;
import wireguard.registry;
import wireguard.host;

namespace {
    using namespace wireguard;
    auto snapshot(IndexReservation const& reservation) -> ReceiverIndexes {
        ReceiverIndexes result{}; result[0]={true,reservation.index,reservation.ticket}; return result;
    }
    auto transport(std::uint32_t index) -> std::array<std::uint8_t,transport_overhead> {
        std::array<std::uint8_t,transport_overhead> wire{}; wire[0]=4; store_le32(std::span(wire).subspan<4,4>(),index); return wire;
    }
    auto source() -> EndpointAddress { return {4,{198,51,100,1},10001}; }
    auto reservations_and_transactions() -> bool {
        PeerRegistry<2> registry;
        auto a=registry.add(),b=registry.add();
        if (!a || !b || registry.add() || a->slot==b->slot || !registry.valid(*a) || registry.reserve(*a,1,7)) return false;
        if (!registry.sync(*a,{},1) || !registry.sync(*b,{},1)) return false;
        auto first=registry.reserve(*a,1,7,IndexMode::exact);
        if (!first || !registry.valid(*first) || registry.lookup(7) || registry.reserve(*a,1,8)) return false;
        auto clash=registry.reserve(*b,1,7,IndexMode::exact);
        if (clash || clash.error().code!=HostError::index_conflict || registry.status().indexes!=1) return false;
        auto probed=registry.reserve(*b,1,7);
        if (!probed || probed->index!=8 || !registry.valid(*probed)) return false;
        auto published=snapshot(*first);
        if (!registry.sync(*a,published,1) || registry.valid(*first) || !registry.lookup(7) || registry.lookup(7)->peer!=*a) return false;
        if (!registry.sync(*b,{},1) || !registry.valid(*probed) || registry.release(*first)) return false;
        auto before=registry.status();
        auto conflicts=published; conflicts[1]={true,probed->index,probed->ticket};
        auto refused=registry.sync(*a,conflicts,2);
        if (refused || refused.error().code!=HostError::index_conflict || registry.status().indexes!=before.indexes ||
            registry.status().reservations!=before.reservations || registry.latest(*a)!=1 || !registry.valid(*probed) || !registry.lookup(7)) return false;
        auto duplicate=published; duplicate[1]=duplicate[0];
        if (registry.sync(*a,duplicate,1) || !registry.lookup(7)) return false;
        auto unreserved=published; unreserved[1]={true,99,1};
        refused=registry.sync(*a,unreserved,1);
        if (refused || refused.error().code!=HostError::unreserved_index || !registry.lookup(7)) return false;
        if (!registry.sync(*b,snapshot(*probed),1) || registry.valid(*probed) || registry.lookup(8)->peer!=*b) return false;
        if (!registry.sync(*a,published,2)) return false;
        auto preparing=registry.reserve(*a,2,9); if (!preparing) return false;
        auto stale_snapshot=published; stale_snapshot[1]={true,preparing->index,preparing->ticket};
        refused=registry.sync(*a,stale_snapshot,3);
        if (refused || refused.error().code!=HostError::stale_attempt || !registry.valid(*preparing) || registry.latest(*a)!=2) return false;
        if (!registry.sync(*a,published,3) || registry.valid(*preparing) || registry.lookup(9) || registry.release(*preparing)) return false;
        auto replacing=registry.reserve(*a,3,9); if (!replacing || !registry.release(*replacing) || registry.valid(*replacing)) return false;
        auto newer=registry.reserve(*a,3,9);
        if (!newer || newer->serial==replacing->serial || registry.valid(*replacing) || registry.release(*replacing)) return false;
        if (!registry.erase(*a) || registry.valid(*a) || registry.valid(*newer) || registry.lookup(7) || registry.lookup(9)) return false;
        auto replacement=registry.add();
        if (!replacement || replacement->slot!=a->slot || replacement->generation==a->generation || registry.valid(*a) || registry.sync(*a,published,3)) return false;
        if (!registry.sync(*replacement,{},1)) return false;
        auto reused=registry.reserve(*replacement,1,7,IndexMode::exact);
        return reused && registry.sync(*replacement,snapshot(*reused),1) && registry.lookup(7)->peer==*replacement && registry.lookup(8)->peer==*b;
    }
    auto bounded_indexes_and_wrap() -> bool {
        PeerRegistry<1> registry; auto peer=registry.add(); if (!peer) return false;
        ReceiverIndexes owned{};
        for (std::uint64_t ticket=1;ticket<=owned.size();++ticket) {
            if (!registry.sync(*peer,owned,ticket)) return false;
            auto reservation=registry.reserve(*peer,ticket,std::numeric_limits<std::uint32_t>::max()); if (!reservation) return false;
            auto expected=std::numeric_limits<std::uint32_t>::max()+static_cast<std::uint32_t>(ticket-1);
            if (reservation->index!=expected) return false;
            owned[ticket-1]={true,reservation->index,ticket};
            if (!registry.sync(*peer,owned,ticket)) return false;
        }
        if (!registry.sync(*peer,owned,9)) return false;
        auto full=registry.reserve(*peer,9,1);
        if (full || full.error().code!=HostError::indexes_full || registry.status().indexes!=8 || registry.status().reservations) return false;
        owned[0]={};
        if (!registry.sync(*peer,owned,9)) return false;
        auto available=registry.reserve(*peer,9,std::numeric_limits<std::uint32_t>::max(),IndexMode::exact);
        return available && available->index==std::numeric_limits<std::uint32_t>::max() && registry.status().indexes==8;
    }
    auto wire_classification() -> bool {
        PeerRegistry<1> registry; auto peer=registry.add();
        if (!peer || !registry.sync(*peer,{},1)) return false;
        auto index=registry.reserve(*peer,1,23);
        if (!index || !registry.sync(*peer,snapshot(*index),1)) return false;
        Response response; response.receiver=23;
        CookieReply cookie; cookie.receiver=23;
        auto data=transport(23);
        auto response_bytes=encode(response);
        auto cookie_bytes=encode(cookie);
        for (auto wire:{std::span<std::uint8_t const>(response_bytes),std::span<std::uint8_t const>(cookie_bytes),std::span<std::uint8_t const>(data)}) {
            auto binding=registry.classify(wire); if (!binding || binding->peer!=*peer || binding->index!=23 || binding->ticket!=1) return false;
        }
        auto initiation=encode(Initiation{}); auto refused=registry.classify(initiation);
        if (refused || refused.error().code!=HostError::initiation_peer_required) return false;
        data[1]=1; refused=registry.classify(data);
        if (refused || refused.error().protocol!=Error::invalid_reserved) return false;
        data[1]=0; store_le32(std::span(data).subspan<4,4>(),999);
        refused=registry.classify(data);
        return !refused && refused.error().code==HostError::no_peer;
    }
    auto scheduling_and_stale_packets() -> bool {
        PeerHost<2,4,256,2> host; auto& registry=host.registry();
        auto a=registry.add(),b=registry.add();
        if (!a || !b || !registry.sync(*a,{},1) || !registry.sync(*b,{},1)) return false;
        auto ai=registry.reserve(*a,1,7),bi=registry.reserve(*b,1,8);
        if (!ai || !bi || !registry.sync(*a,snapshot(*ai),1) || !registry.sync(*b,snapshot(*bi),1)) return false;
        auto awire=transport(7),bwire=transport(8);
        if (!host.enqueue_indexed(awire,source(),true) || !host.enqueue_indexed(awire,source(),true)) return false;
        auto full=host.enqueue_indexed(awire,source(),true);
        if (full || full.error().code!=HostError::peer_queue_full || host.status().packets!=2) return false;
        if (host.enqueue_indexed(bwire,source(),false) || !host.enqueue_indexed(bwire,source(),true) || !host.enqueue_indexed(bwire,source(),true)) return false;
        if (host.status().packets!=4 || host.status().bytes!=4*awire.size()) return false;
        auto first=host.take(),second=host.take(),third=host.take(),fourth=host.take();
        if (!first || !second || !third || !fourth || first->peer!=*a || second->peer!=*b || third->peer!=*a || fourth->peer!=*b ||
            first->serial>=third->serial || second->serial>=fourth->serial || host.take() || host.status().packets || host.status().bytes) return false;
        if (!host.valid(*first) || !registry.sync(*a,{},2) || host.valid(*first) || registry.lookup(7)) return false;
        auto new_index=registry.reserve(*a,2,7); if (!new_index || !registry.sync(*a,snapshot(*new_index),2)) return false;
        if (host.valid(*first) || !host.enqueue_indexed(awire,source(),true) || !host.enqueue_indexed(bwire,source(),true)) return false;
        auto held=host.take(); if (!held) return false;
        auto deleted=held->peer;
        if (!registry.erase(deleted) || host.valid(*held)) return false;
        auto reused=registry.add();
        if (!reused || reused->generation==deleted.generation || reused->slot!=deleted.slot) return false;
        auto remaining=host.take(); if (!remaining || remaining->peer==deleted || host.valid(*held)) return false;
        auto initiation=encode(Initiation{});
        if (!host.enqueue_initiation(*reused,initiation,source(),true)) return false;
        auto candidate=host.take();
        if (!candidate || candidate->binding || candidate->peer!=*reused || !host.valid(*candidate)) return false;
        std::array<std::uint8_t,257> huge{}; huge[0]=4; store_le32(std::span(huge).subspan<4,4>(),remaining->binding->index);
        auto oversized=host.enqueue_indexed(huge,source(),true);
        if (oversized || oversized.error().code!=HostError::packet_too_large || host.status().packets) return false;
        auto valid_wire=transport(remaining->binding->index);
        if (!host.enqueue_indexed(valid_wire,source(),true)) return false;
        host.clear(); return !host.status().packets && !host.status().bytes;
    }
    auto total_queue_limit() -> bool {
        PeerHost<2,3,256,2> host; auto& registry=host.registry();
        auto a=registry.add(),b=registry.add();
        if (!a || !b || !registry.sync(*a,{},1) || !registry.sync(*b,{},1)) return false;
        auto ai=registry.reserve(*a,1,7),bi=registry.reserve(*b,1,8);
        if (!ai || !bi || !registry.sync(*a,snapshot(*ai),1) || !registry.sync(*b,snapshot(*bi),1)) return false;
        auto awire=transport(7),bwire=transport(8);
        if (!host.enqueue_indexed(awire,source(),true) || !host.enqueue_indexed(awire,source(),true) || !host.enqueue_indexed(bwire,source(),true)) return false;
        auto full=host.enqueue_indexed(bwire,source(),true);
        if (full || full.error().code!=HostError::queue_full || host.status().packets!=3 || host.status().bytes!=3*awire.size()) return false;
        if (!registry.erase(*a) || host.status().packets!=1 || host.status().bytes!=bwire.size()) return false;
        auto one=host.take(); return one && one->peer==*b && !host.take();
    }
}

auto main() -> int {
    if (!reservations_and_transactions()) { std::println("WireGuard global reservations/transaction rollback failed"); return 1; }
    if (!bounded_indexes_and_wrap()) { std::println("WireGuard registry capacity/index wrap failed"); return 2; }
    if (!wire_classification()) { std::println("WireGuard receiver-index classification failed"); return 3; }
    if (!scheduling_and_stale_packets()) { std::println("WireGuard bounded fair ingress/stale packet checks failed"); return 4; }
    if (!total_queue_limit()) { std::println("WireGuard total packet/byte bound failed"); return 5; }
    std::println("WireGuard fixed registry/reservation rollback, peer generations, bounded fair ingress and stale task checks passed; sizeof registry32={} host32/32x2048={}",sizeof(PeerRegistry<>),sizeof(PeerHost<>));
}
