import std;
import udp;
import test.scheduled_link;

namespace u = udp;
namespace p = ::packet;

namespace {
    constexpr u::Endpoint4 local{{10, 0, 0, 2}, 40000}, local2{{10, 0, 0, 3}, 40000};
    constexpr u::Endpoint4 a{{192, 0, 2, 1}, 53}, a2{{192, 0, 2, 1}, 54}, b{{198, 51, 100, 2}, 53};

    auto scheduled_network() -> bool {
        p::MemoryLink link({1500, 1, 1500});
        ScheduledLink network(3, 100);
        u::Bridge4 bridge(u::Mapping::endpoint_independent, u::Filtering::address_port_dependent, {1, 1, 10});
        auto one = p::make_udp4(local.address, a.address, local.port, a.port, p::Bytes{1});
        auto two = p::make_udp4(local.address, a.address, local.port, a.port, p::Bytes{2});
        if (!one || !two || !network.send(p::Side::first, *one, 5) ||
            !network.send(p::Side::first, *two, 3) || !network.send(p::Side::first, *one, 3) ||
            !network.send(p::Side::first, *two, 2, true)) return false;
        auto full = network.send(p::Side::first, *one, 4);
        if (full || full.error() != ScheduledLink::Error::capacity || network.size() != 3) return false;
        auto early = network.advance(2, link);
        if (!early || *early != 0) return false;
        auto delivered = network.advance(3, link);
        if (!delivered || *delivered != 1 || network.size() != 2) return false;
        auto packet = link.receive(p::Side::second);
        if (!packet || !*packet) return false;
        auto send = bridge.prepare(**packet, 3);
        if (!send || send->payload != p::Bytes{2} || !bridge.complete(send->flow, send->token, true, 3)) return false;
        auto resumed = network.advance(3, link);
        if (!resumed || *resumed != 1) return false;
        packet = link.receive(p::Side::second);
        if (!packet || !*packet) return false;
        auto next = bridge.prepare(**packet, 3);
        if (!next || next->flow != send->flow || next->payload != p::Bytes{1} ||
            !bridge.complete(next->flow, next->token, true, 3)) return false;
        auto later = network.advance(5, link);
        if (!later || *later != 1 || network.size()) return false;
        packet = link.receive(p::Side::second);
        if (!packet || !*packet || **packet != *one) return false;
        auto reversed = network.advance(4, link);
        return !reversed && reversed.error() == ScheduledLink::Error::time_reversed;
    }

    struct Retired { std::array<u::FlowId, 8> ids{}; std::size_t count = 0; };
    auto record_retirement(void* context, u::FlowId id) noexcept -> void {
        auto& retired = *static_cast<Retired*>(context);
        if (retired.count < retired.ids.size()) retired.ids[retired.count++] = id;
    }
    auto retirement() -> bool {
        Retired retired;
        u::FlowTable table(u::Mapping::endpoint_independent, u::Filtering::address_port_dependent,
                           {2, 1, 10}, {&retired, record_retirement});
        auto first = table.open_send(local, a, 0);
        if (!first) return false;
        // A later unrelated operation implicitly expires the first flow.
        auto second = table.open_send(local2, a, 10);
        if (!second || retired.count != 1 || retired.ids[0] != first->first) return false;
        auto late = table.finish_send(first->first, first->second, true, 10);
        if (late || late.error() != u::Error::stale_send || retired.count != 1) return false;
        if (!table.close(second->first, 11) || retired.count != 2 || retired.ids[1] != second->first) return false;
        if (table.close(second->first, 11) || retired.count != 2) return false;
        u::FlowTable rollback(u::Mapping::endpoint_independent, u::Filtering::address_port_dependent,
                              {1, 0, 10}, {&retired, record_retirement});
        auto failed = rollback.open_send(local, a, 0);
        if (failed || failed.error() != u::Error::peer_limit || rollback.size() || retired.count != 3) return false;
        if (!retired.ids[2]) return false;
        u::Bridge6 bridge(u::Mapping::endpoint_independent, u::Filtering::address_port_dependent,
                          {1, 1, 10}, 1500, {&retired, record_retirement});
        p::Address6 source{0x20,1,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,1};
        p::Address6 destination = source; destination.back() = 2;
        auto packet = p::make_udp6(source, destination, 1234, 53, p::Bytes{1});
        if (!packet) return false;
        auto outgoing = bridge.prepare(*packet, 0);
        if (!outgoing || !bridge.close(outgoing->flow, 1)) return false;
        return retired.count == 4 && retired.ids[3] == outgoing->flow;
    }
    auto shutdown() -> bool {
        Retired retired;
        u::FlowTable table(u::Mapping::address_port_dependent, u::Filtering::address_port_dependent,
                           {3, 1, 10}, {&retired, record_retirement});
        auto old = table.open_send(local, a, 0);
        auto active = table.open_send(local, b, 5);
        if (!old || !active) return false;
        auto reversed = table.clear(4);
        if (reversed || reversed.error() != u::Error::time_reversed || table.size() != 2 || retired.count) return false;
        auto cleared = table.clear(10);
        if (!cleared || *cleared != 2 || table.size() != 0 || retired.count != 2 ||
            retired.ids[0] != old->first || retired.ids[1] != active->first) return false;
        auto late_old = table.finish_send(old->first, old->second, true, 10);
        auto late_active = table.finish_send(active->first, active->second, true, 10);
        if (late_old || late_old.error() != u::Error::stale_send || late_active ||
            late_active.error() != u::Error::stale_send) return false;
        auto empty = table.clear(10);
        auto fresh = table.open_send(local, a, 10);
        return empty && *empty == 0 && retired.count == 2 && fresh &&
               fresh->first != old->first && fresh->first != active->first;
    }

    auto mappings() -> bool {
        for (auto mapping : {u::Mapping::endpoint_independent, u::Mapping::address_dependent,
                             u::Mapping::address_port_dependent}) {
            u::FlowTable table(mapping, u::Filtering::address_port_dependent);
            auto first = table.open(local, a, 0), second = table.open(local, a2, 0),
                 third = table.open(local, b, 0), other_local = table.open(local2, a, 0);
            if (!first || !second || !third || !other_local || *first == *other_local) return false;
            if ((*first == *second) != (mapping != u::Mapping::address_port_dependent)) return false;
            if ((*first == *third) != (mapping == u::Mapping::endpoint_independent)) return false;
            auto sent = table.transmit(*first, a, 1, [] { return true; });
            auto wrong = table.transmit(*first, b, 1, [] { return true; });
            if (!sent || (static_cast<bool>(wrong) != (mapping == u::Mapping::endpoint_independent))) return false;
            if (!wrong && wrong.error() != u::Error::remote_mismatch) return false;
        }
        return true;
    }
    auto filters() -> bool {
        for (auto filtering : {u::Filtering::endpoint_independent, u::Filtering::address_dependent,
                               u::Filtering::address_port_dependent}) {
            u::FlowTable table(u::Mapping::endpoint_independent, filtering, {4, 1, 100});
            auto id = table.open(local, a, 10);
            if (!id) return false;
            auto before_send = table.accept_reply(*id, a, 11);
            if (before_send || before_send.error() != u::Error::forbidden) return false;
            if (!table.transmit(*id, a, 12, [] { return true; })) return false;
            auto exact = table.accept_reply(*id, a, 13);
            auto same_address = table.accept_reply(*id, a2, 14);
            auto other_address = table.accept_reply(*id, b, 15);
            if (!exact || *exact != local) return false;
            if (static_cast<bool>(same_address) != (filtering != u::Filtering::address_port_dependent)) return false;
            if (static_cast<bool>(other_address) != (filtering == u::Filtering::endpoint_independent)) return false;
            auto send_b = table.transmit(*id, b, 16, [] { return true; });
            if (static_cast<bool>(send_b) != (filtering == u::Filtering::endpoint_independent)) return false;
            if (!send_b && send_b.error() != u::Error::peer_limit) return false;
            if (filtering != u::Filtering::endpoint_independent) {
                auto rejected = table.accept_reply(*id, b, 17);
                if (rejected || rejected.error() != u::Error::forbidden) return false;
            }
        }
        return true;
    }
    auto combinations() -> bool {
        for (auto mapping : {u::Mapping::endpoint_independent, u::Mapping::address_dependent,
                             u::Mapping::address_port_dependent}) {
            for (auto filtering : {u::Filtering::endpoint_independent, u::Filtering::address_dependent,
                                   u::Filtering::address_port_dependent}) {
                u::FlowTable table(mapping, filtering, {3, 3, 50});
                auto id_a = table.open(local, a, 0), id_a2 = table.open(local, a2, 0), id_b = table.open(local, b, 0);
                if (!id_a || !id_a2 || !id_b || !table.transmit(*id_a, a, 1, [] { return true; })) return false;
                if (!table.transmit(*id_a2, a2, 2, [] { return true; }) || !table.transmit(*id_b, b, 3, [] { return true; })) return false;
                if (!table.accept_reply(*id_a, a, 4) || !table.accept_reply(*id_a2, a2, 4) ||
                    !table.accept_reply(*id_b, b, 4)) return false;
                auto cross = table.accept_reply(*id_a, b, 4);
                bool allowed = filtering == u::Filtering::endpoint_independent ||
                               mapping == u::Mapping::endpoint_independent;
                if (static_cast<bool>(cross) != allowed) return false;
            }
        }
        u::FlowTable no_peers(u::Mapping::endpoint_independent, u::Filtering::address_port_dependent, {1, 0, 10});
        auto id = no_peers.open(local, a, 0);
        if (!id) return false;
        auto no_slot = no_peers.transmit(*id, a, 1, [] { return true; });
        auto reply = no_peers.accept_reply(*id, a, 2);
        return !no_slot && no_slot.error() == u::Error::peer_limit && !reply && reply.error() == u::Error::forbidden;
    }
    auto transactional_send() -> bool {
        u::FlowTable table(u::Mapping::endpoint_independent, u::Filtering::address_port_dependent, {1, 1, 10});
        auto id = table.open(local, a, 0);
        if (!id) return false;
        try { (void)table.transmit(*id, a, 1, []() -> bool { throw 1; }); return false; }
        catch (int) {}
        if (table.accept_reply(*id, a, 2)) return false;
        auto owned = std::make_unique<bool>(true);
        auto sender = [value = std::move(owned)] { return *value; };
        if (!table.transmit(*id, b, 3, sender)) return false;
        auto failed_existing = table.transmit(*id, b, 4, [] { return false; });
        if (failed_existing || failed_existing.error() != u::Error::send_failed || !table.accept_reply(*id, b, 5)) return false;
        bool called = false;
        auto full = table.transmit(*id, a, 6, [&] { called = true; return true; });
        if (full || full.error() != u::Error::peer_limit || called) return false;
        auto expired = table.expire(15);
        return expired && *expired == 1;
    }
    auto asynchronous_send() -> bool {
        u::FlowTable table(u::Mapping::endpoint_independent, u::Filtering::address_port_dependent, {2, 1, 10});
        auto id = table.open(local, a, 0);
        if (!id) return false;
        auto token = table.begin_send(*id, a, 1);
        if (!token || table.accept_reply(*id, a, 2)) return false;
        auto busy = table.begin_send(*id, b, 3);
        if (busy || busy.error() != u::Error::send_in_progress) return false;
        auto wrong = table.finish_send(*id, *token + 1, true, 4);
        if (wrong || wrong.error() != u::Error::stale_send) return false;
        if (!table.finish_send(*id, *token, true, 5) || !table.accept_reply(*id, a, 6)) return false;
        auto duplicate = table.finish_send(*id, *token, true, 6);
        if (duplicate || duplicate.error() != u::Error::stale_send) return false;
        auto full = table.begin_send(*id, b, 7);
        if (full || full.error() != u::Error::peer_limit) return false;
        auto pending = table.begin_send(*id, a, 8);
        if (!pending) return false;
        auto expired = table.finish_send(*id, *pending, true, 16);
        if (expired || expired.error() != u::Error::stale_send || table.size() != 0) return false;
        auto fresh = table.open(local, a, 16);
        if (!fresh || *fresh == *id) return false;
        auto cancel_token = table.begin_send(*fresh, b, 17);
        if (!cancel_token) return false;
        auto cancelled = table.finish_send(*fresh, *cancel_token, false, 18);
        if (cancelled || cancelled.error() != u::Error::send_failed || table.accept_reply(*fresh, b, 18)) return false;
        auto pending_again = table.begin_send(*fresh, a, 19);
        if (!pending_again || !table.close(*fresh, 19)) return false;
        auto late = table.finish_send(*fresh, *pending_again, true, 20);
        if (late || late.error() != u::Error::stale_send) return false;
        return true;
    }
    auto lifetime() -> bool {
        u::FlowTable table(u::Mapping::endpoint_independent, u::Filtering::address_port_dependent, {1, 2, 10});
        auto first = table.open(local, a, 100);
        if (!first || !table.transmit(*first, a, 101, [] { return true; })) return false;
        auto full = table.open(local2, a, 102);
        if (full || full.error() != u::Error::capacity || table.size() != 1) return false;
        auto backwards = table.open(local, a, 99);
        if (backwards || backwards.error() != u::Error::time_reversed || table.size() != 1) return false;
        auto forged = table.accept_reply(*first, b, 109);
        if (forged || forged.error() != u::Error::forbidden) return false;
        auto same = table.open(local, a, 110); // Opening alone does not refresh an unsent flow.
        if (!same || *same != *first) return false;
        auto expired = table.accept_reply(*first, a, 111);
        if (expired || expired.error() != u::Error::no_flow || table.size() != 0) return false;
        auto second = table.open(local2, a, 111);
        if (!second || *second == *first || !table.transmit(*second, a, 111, [] { return true; })) return false;
        if (!table.accept_reply(*second, a, 120)) return false; // Allowed replies refresh the deadline.
        auto still = table.expire(129);
        if (!still || *still != 0 || table.size() != 1) return false;
        auto gone = table.expire(130);
        if (!gone || *gone != 1 || table.size() != 0) return false;
        auto third = table.open(local, b, 131);
        if (!third || !table.close(*third, 132) || table.size() != 0) return false;
        auto closed = table.accept_reply(*third, b, 132);
        auto repeat_close = table.close(*third, 132);
        auto fourth = table.open(local, b, 132);
        if (closed || closed.error() != u::Error::no_flow || repeat_close ||
            repeat_close.error() != u::Error::no_flow || !fourth || *fourth == *third) return false;
        u::FlowTable invalid(u::Mapping::endpoint_independent, u::Filtering::endpoint_independent, {1, 1, 0});
        auto bad = invalid.open(local, a, 0);
        if (bad || bad.error() != u::Error::invalid_config) return false;
        u::FlowTable empty(u::Mapping::endpoint_independent, u::Filtering::endpoint_independent, {0, 0, 1});
        auto none = empty.open(local, a, 0);
        if (none || none.error() != u::Error::capacity) return false;
        return true;
    }
    auto bridge() -> bool {
        u::Bridge4 bridge(u::Mapping::endpoint_independent, u::Filtering::address_port_dependent, {1, 2, 10}, 32);
        u::Bridge4 no_peer(u::Mapping::endpoint_independent, u::Filtering::address_port_dependent, {1, 0, 10});
        auto packet_a = p::make_udp4(local.address, a.address, local.port, a.port, {});
        auto packet_b = p::make_udp4(local2.address, b.address, local2.port, b.port, {});
        if (!packet_a || !packet_b) return false;
        for (auto const* packet : {&*packet_a, &*packet_b}) {
            auto result = no_peer.prepare(*packet, 0);
            if (result || std::get<u::Error>(result.error()) != u::Error::peer_limit || no_peer.size() != 0) return false;
        }
        p::Bytes payload{1, 2, 3, 4};
        auto packet = p::make_udp4(local.address, a.address, local.port, a.port, payload);
        if (!packet) return false;
        auto invalid = *packet; invalid.back() ^= 1;
        auto bad = bridge.prepare(invalid, 0);
        if (bad || !std::holds_alternative<p::PacketError>(bad.error()) || bridge.size() != 0) return false;
        auto outgoing = bridge.prepare(*packet, 0);
        if (!outgoing || outgoing->remote != a || outgoing->payload != payload) return false;
        packet->back() = 0;
        if (outgoing->payload != payload) return false;
        auto busy_packet = p::make_udp4(local.address, b.address, local.port, b.port, payload);
        if (!busy_packet) return false;
        auto busy = bridge.prepare(*busy_packet, 1);
        if (busy || !std::holds_alternative<u::Error>(busy.error()) ||
            std::get<u::Error>(busy.error()) != u::Error::send_in_progress) return false;
        if (bridge.reply(outgoing->flow, a, payload, 1)) return false;
        auto failed = bridge.complete(outgoing->flow, outgoing->token, false, 2);
        if (failed || failed.error() != u::Error::send_failed || bridge.reply(outgoing->flow, a, payload, 2)) return false;
        auto retry = bridge.prepare(*busy_packet, 3);
        if (!retry || retry->flow != outgoing->flow || !bridge.complete(retry->flow, retry->token, true, 4)) return false;
        auto forged = bridge.reply(retry->flow, a, payload, 5);
        if (forged || std::get<u::Error>(forged.error()) != u::Error::forbidden) return false;
        auto too_big = bridge.reply(retry->flow, b, p::Bytes(5), 9);
        if (too_big || std::get<p::PacketError>(too_big.error()) != p::PacketError::too_large) return false;
        auto result = bridge.reply(retry->flow, b, payload, 10);
        if (!result) return false;
        auto parsed = p::parse_udp4(*result);
        if (!parsed || parsed->source != b.address || parsed->destination != local.address ||
            parsed->source_port != b.port || parsed->destination_port != local.port ||
            !std::ranges::equal(parsed->payload, payload)) return false;
        auto expired = bridge.expire(20);
        return expired && *expired == 1 && !bridge.reply(retry->flow, b, payload, 20);
    }
    auto bridge6() -> bool {
        u::Endpoint6 local{{0x20,1,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,1}, 1234};
        u::Endpoint6 remote{{0x20,1,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,2}, 53};
        auto other = remote; other.port++;
        p::Bytes payload{1, 2, 3};
        auto input = p::make_udp6(local.address, remote.address, local.port, remote.port, payload);
        if (!input) return false;
        u::Bridge6 bridge(u::Mapping::endpoint_independent, u::Filtering::address_port_dependent, {1, 1, 10}, 51);
        auto invalid = *input; invalid.back() ^= 1;
        if (bridge.prepare(invalid, 0) || bridge.size() != 0) return false;
        auto send = bridge.prepare(*input, 0);
        if (!send || send->remote != remote || send->payload != payload || bridge.reply(send->flow, remote, payload, 1)) return false;
        input->back() ^= 1;
        if (send->payload != payload || !bridge.complete(send->flow, send->token, true, 1)) return false;
        if (bridge.reply(send->flow, other, payload, 2)) return false;
        auto too_large = bridge.reply(send->flow, remote, p::Bytes(4), 9);
        if (too_large || std::get<p::PacketError>(too_large.error()) != p::PacketError::too_large) return false;
        auto reply = bridge.reply(send->flow, remote, payload, 9);
        if (!reply) return false;
        auto parsed = p::parse_udp6(*reply);
        if (!parsed || parsed->source != remote.address || parsed->destination != local.address ||
            parsed->source_port != remote.port || parsed->destination_port != local.port ||
            !std::ranges::equal(parsed->payload, payload)) return false;
        auto expired = bridge.expire(19);
        return expired && *expired == 1 && !bridge.reply(send->flow, remote, payload, 19);
    }
    auto memory_roundtrip() -> bool {
        p::MemoryLink device;
        u::FlowTable table(u::Mapping::endpoint_independent, u::Filtering::address_port_dependent);
        p::Bytes data{'h', 'e', 'l', 'l', 'o'};
        auto request = p::make_udp4(local.address, a.address, local.port, a.port, data);
        if (!request || !device.send(p::Side::first, *request)) return false;
        auto incoming = device.receive(p::Side::second);
        if (!incoming || !*incoming) return false;
        auto datagram = p::parse_udp4(**incoming);
        if (!datagram) return false;
        u::Endpoint4 from{datagram->source, datagram->source_port}, to{datagram->destination, datagram->destination_port};
        auto id = table.open(from, to, 10);
        if (!id) return false;
        p::Bytes simulated_outbound(datagram->payload.begin(), datagram->payload.end());
        if (simulated_outbound != data || !table.transmit(*id, to, 11, [] { return true; })) return false;
        auto unauthorized = table.accept_reply(*id, b, 12);
        if (unauthorized || unauthorized.error() != u::Error::forbidden) return false;
        auto target = table.accept_reply(*id, to, 13);
        if (!target || *target != local) return false;
        auto reply = p::make_udp4(to.address, target->address, to.port, target->port, simulated_outbound);
        if (!reply || !device.send(p::Side::second, *reply)) return false;
        auto packet = device.receive(p::Side::first);
        if (!packet || !*packet) return false;
        auto received = p::parse_udp4(**packet);
        return received && received->source == a.address && received->destination == local.address &&
               received->source_port == a.port && received->destination_port == local.port &&
               std::ranges::equal(received->payload, data);
    }
}

int main() {
    if (!scheduled_network()) { std::cerr << "UDP scheduled network failed\n"; return 1; }
    if (!retirement()) { std::cerr << "UDP flow retirement notification failed\n"; return 1; }
    if (!shutdown()) { std::cerr << "UDP flow shutdown failed\n"; return 1; }
    if (!mappings()) { std::cerr << "UDP mapping failed\n"; return 1; }
    if (!filters()) { std::cerr << "UDP filtering failed\n"; return 1; }
    if (!combinations()) { std::cerr << "UDP mapping/filter combinations failed\n"; return 1; }
    if (!transactional_send()) { std::cerr << "UDP transactional send failed\n"; return 1; }
    if (!asynchronous_send()) { std::cerr << "UDP asynchronous lifecycle failed\n"; return 1; }
    if (!lifetime()) { std::cerr << "UDP lifetime and bounds failed\n"; return 1; }
    if (!bridge()) { std::cerr << "UDP packet bridge failed\n"; return 1; }
    if (!bridge6()) { std::cerr << "IPv6 UDP bridge failed\n"; return 1; }
    if (!memory_roundtrip()) { std::cerr << "UDP memory roundtrip failed\n"; return 1; }
    std::cout << "UDP mapping, filtering, deadlines and memory roundtrip passed\n";
}
