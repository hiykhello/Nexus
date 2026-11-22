import std;
import crypto;
import wireguard;
import wireguard.crypto;
import wireguard.noise;
import wireguard.session;
import wireguard.endpoint;

namespace {
    using namespace wireguard;
    using namespace std::chrono_literals;
    namespace crypto = ::crypto;
    auto key(unsigned first) -> crypto::X25519Private {
        Key bytes; for (std::size_t i=0;i<32;++i) bytes[i]=static_cast<std::uint8_t>(first+i);
        auto value=crypto::X25519Private::from_bytes(bytes); if (!value) std::terminate(); return std::move(*value);
    }
    auto public_key(unsigned first) -> Key { auto private_key=key(first); auto value=private_key.public_key(); if (!value) std::terminate(); return *value; }
    auto outer(bool a,unsigned suffix=0) -> EndpointAddress { return {4,{198,51,100,static_cast<std::uint8_t>(a ? 1 : 2)},static_cast<std::uint16_t>((a ? 10001 : 10002)+suffix)}; }
    auto prefix(bool a,bool ipv6) -> AllowedPrefix {
        AllowedPrefix result; result.family=ipv6 ? 6 : 4; result.bits=ipv6 ? 128 : 32;
        if (ipv6) { result.address[0]=0xfd; result.address[1]=0x42; result.address[15]=a ? 1 : 2; }
        else { result.address[0]=10; result.address[3]=a ? 1 : 2; }
        return result;
    }
    auto config(bool a) -> EndpointConfig {
        EndpointConfig result; result.peer_public=public_key(a ? 32 : 0); result.peer=outer(!a);
        result.allowed_ips={prefix(!a,false),prefix(!a,true)}; return result;
    }
    auto inner(bool from_a,bool ipv6,unsigned marker=1,std::size_t payload=4) -> std::vector<std::uint8_t> {
        auto header=ipv6 ? 40u : 20u;
        std::vector<std::uint8_t> result(header+payload);
        result[0]=ipv6 ? 0x60 : 0x45;
        if (ipv6) {
            result[4]=static_cast<std::uint8_t>(payload>>8); result[5]=static_cast<std::uint8_t>(payload); result[6]=253; result[7]=64;
            result[8]=result[24]=0xfd; result[9]=result[25]=0x42; result[23]=from_a ? 1 : 2; result[39]=from_a ? 2 : 1;
        } else {
            result[2]=static_cast<std::uint8_t>(result.size()>>8); result[3]=static_cast<std::uint8_t>(result.size()); result[8]=64; result[9]=253;
            result[12]=result[16]=10; result[15]=from_a ? 1 : 2; result[19]=from_a ? 2 : 1;
            std::uint32_t checksum=0; for (std::size_t i=0;i<20;i+=2) checksum+=(std::uint16_t(result[i])<<8)|result[i+1];
            while (checksum>>16) checksum=(checksum&65535)+(checksum>>16);
            checksum=~checksum; result[10]=static_cast<std::uint8_t>(checksum>>8); result[11]=static_cast<std::uint8_t>(checksum);
        }
        for (std::size_t i=header;i<result.size();++i) result[i]=static_cast<std::uint8_t>(marker+i-header);
        return result;
    }
    struct Pair {
        std::expected<Endpoint,EndpointFailure> a,b;
        Pair(EndpointConfig a_config=config(true),EndpointConfig b_config=config(false))
            : a(Endpoint::create(key(0),std::move(a_config))),b(Endpoint::create(key(32),std::move(b_config))) {}
    };
    struct Exchange { EndpointDatagram initiation,response,confirmation; std::uint64_t ticket_a=0,ticket_b=0; };
    auto exchange(Pair& pair,Clock::time_point now,Exchange& saved,unsigned epoch=1,bool confirm=true) -> bool {
        if (!pair.a || !pair.b || !pair.a->request_handshake(now)) return false;
        auto requested=pair.a->poll(now); if (!requested || !requested->handshake) return false;
        auto timestamp=make_timestamp(epoch,0); if (!timestamp) return false;
        saved.ticket_a=requested->handshake->ticket;
        auto initiation=pair.a->initiate(*requested->handshake,7,key(64+epoch),*timestamp,0ms,now);
        if (!initiation || !pair.a->complete_send(initiation->serial,true,now)) return false;
        saved.initiation=std::move(*initiation);
        auto received=pair.b->receive(saved.initiation.bytes,outer(true),true,now+1ms);
        if (!received || !received->handshake) return false;
        saved.ticket_b=received->handshake->ticket;
        auto response=pair.b->respond(*received->handshake,7,key(96+epoch),now+2ms);
        if (!response || !pair.b->complete_send(response->serial,true,now+2ms)) return false;
        saved.response=std::move(*response);
        auto accepted=pair.a->receive(saved.response.bytes,outer(false),true,now+3ms);
        if (!accepted || !pair.a->status().current || !pair.b->status().pending) return false;
        if (!confirm) return true;
        auto output=pair.a->poll(now+3ms);
        if (!output || !output->datagram || output->datagram->kind!=OutboundKind::keepalive) return false;
        saved.confirmation=std::move(*output->datagram);
        if (!pair.a->complete_send(saved.confirmation.serial,true,now+3ms)) return false;
        auto confirmed=pair.b->receive(saved.confirmation.bytes,outer(true),true,now+4ms);
        return confirmed && confirmed->keepalive && confirmed->key_confirmed && pair.b->status().current && !pair.b->status().pending;
    }
    auto send(Endpoint& from,Endpoint& to,bool a,bool ipv6,Clock::time_point now,unsigned marker=1) -> std::optional<EndpointDatagram> {
        auto packet=inner(a,ipv6,marker);
        if (!from.enqueue(packet,now)) return {};
        auto output=from.poll(now); if (!output || !output->datagram) return {};
        auto sent=std::move(*output->datagram);
        if (!from.complete_send(sent.serial,true,now)) return {};
        auto received=to.receive(sent.bytes,outer(a),true,now);
        if (!received || received->packet!=packet || received->keepalive) return {};
        return sent;
    }
    auto configuration_and_ip() -> bool {
        static_assert(!std::is_move_constructible_v<Endpoint> && !std::is_copy_constructible_v<Endpoint>);
        Pair pair; if (!pair.a || !pair.b) return false;
        auto bad=config(true); bad.mtu=67; if (Endpoint::create(key(0),std::move(bad))) return false;
        for (auto mtu:{endpoint_max_inner_mtu+1,max_datagram_size-transport_overhead}) {
            bad=config(true); bad.mtu=mtu; if (Endpoint::create(key(0),std::move(bad))) return false;
        }
        bad=config(true); bad.allowed_ips.push_back(bad.allowed_ips[0]); if (Endpoint::create(key(0),std::move(bad))) return false;
        bad=config(true); bad.allowed_ips[0].bits=24; if (Endpoint::create(key(0),std::move(bad))) return false;
        bad=config(true); bad.peer_public={}; if (Endpoint::create(key(0),std::move(bad))) return false;
        for (bool ipv6:{false,true}) {
            auto packet=inner(true,ipv6); auto parsed=parse_inner_packet(packet);
            if (!parsed || parsed->family!=(ipv6 ? 6 : 4) || parsed->packet.size()!=packet.size() || !prefix_contains(prefix(true,ipv6),parsed->family,std::span(parsed->source).first(ipv6 ? 16 : 4))) return false;
            auto padded=packet; padded.insert(padded.end(),15,173); parsed=parse_inner_packet(padded);
            if (!parsed || parsed->packet.size()!=packet.size()) return false;
            for (std::size_t size=0;size<packet.size();++size) if (parse_inner_packet(std::span(packet).first(size))) return false;
            auto invalid=packet; invalid[0]=ipv6 ? 0x70 : 0x44; if (parse_inner_packet(invalid)) return false;
        }
        auto before=pair.a->status();
        if (pair.a->enqueue(inner(false,false),Clock::time_point(1s)) || pair.a->status().queued_packets!=before.queued_packets) return false;
        pair.a->close(); auto polled=pair.a->poll(Clock::time_point(2s));
        return !polled && polled.error().code==EndpointError::closed && !pair.a->status().indexes;
    }
    auto maximum_mtu() -> bool {
        static_assert(endpoint_max_outer_payload==65507 && endpoint_max_inner_mtu==65475);
        auto a=config(true),b=config(false); a.mtu=b.mtu=endpoint_max_inner_mtu;
        Pair pair(std::move(a),std::move(b)); Exchange setup; auto now=Clock::time_point(10s);
        if (!exchange(pair,now,setup)) return false;
        for (bool ipv6:{false,true}) {
            now+=1s;
            auto packet=inner(true,ipv6,7,endpoint_max_inner_mtu-(ipv6 ? 40 : 20));
            auto too_big=inner(true,ipv6,8,endpoint_max_inner_mtu+1-(ipv6 ? 40 : 20));
            auto rejected=pair.a->enqueue(too_big,now);
            if (rejected || rejected.error().code!=EndpointError::invalid_packet || pair.a->status().queued_packets) return false;
            if (!pair.a->enqueue(packet,now)) return false;
            auto output=pair.a->poll(now);
            if (!output || !output->datagram || output->datagram->bytes.size()!=endpoint_max_outer_payload || !pair.a->complete_send(output->datagram->serial,true,now)) return false;
            auto received=pair.b->receive(output->datagram->bytes,outer(true),true,now);
            if (!received || received->packet!=packet || pair.a->status().queued_packets || pair.a->status().queued_bytes) return false;
        }
        return true;
    }
    auto generation_and_roaming() -> bool {
        Pair pair; Exchange first;
        auto start=Clock::time_point(10s);
        if (!exchange(pair,start,first)) return false;
        auto initial_a=pair.a->status().current,initial_b=pair.b->status().current;
        if (!initial_a || !initial_b || *initial_a!=7 || *initial_b!=7) return false;
        if (!send(*pair.a,*pair.b,true,false,start+10ms) || !send(*pair.b,*pair.a,false,true,start+11ms)) return false;
        // Keep a valid old-generation packet unobserved until after rekey.
        auto old=inner(true,true,9);
        if (!pair.a->enqueue(old,start+12ms)) return false;
        auto held=pair.a->poll(start+12ms);
        if (!held || !held->datagram || !pair.a->complete_send(held->datagram->serial,true,start+12ms)) return false;
        Exchange second;
        if (!exchange(pair,start+30s,second,2,false)) return false;
        if (pair.a->status().previous!=initial_a || pair.b->status().current!=initial_b || !pair.b->status().pending || *pair.b->status().pending==*initial_b) return false;
        auto pending=*pair.b->status().pending;
        // A rekey responder continues sending on its confirmed current key.
        if (!send(*pair.b,*pair.a,false,false,start+30s+4ms)) return false;
        auto confirm=pair.a->poll(start+30s+5ms);
        if (!confirm || !confirm->datagram || !pair.a->complete_send(confirm->datagram->serial,true,start+30s+5ms)) return false;
        auto activated=pair.b->receive(confirm->datagram->bytes,outer(true,8),true,start+30s+6ms);
        if (!activated || !activated->key_confirmed || pair.b->status().current!=pending || pair.b->status().previous!=initial_b || pair.b->status().peer!=outer(true,8)) return false;
        auto previous=pair.b->receive(held->datagram->bytes,outer(true,9),true,start+30s+7ms);
        if (!previous || previous->packet!=old || pair.b->status().peer!=outer(true,9)) return false;
        auto replay=pair.b->receive(held->datagram->bytes,outer(true,10),true,start+30s+8ms);
        if (replay || pair.b->status().peer!=outer(true,9)) return false;
        auto forged=confirm->datagram->bytes; forged.back()^=1;
        auto bad=pair.b->receive(forged,outer(true,11),true,start+30s+9ms);
        if (bad || pair.b->status().peer!=outer(true,9)) return false;
        // Unknown indexes and disallowed outer sources do not roam the peer.
        forged=confirm->datagram->bytes; store_le32(std::span(forged).subspan<4,4>(),123456);
        if (pair.b->receive(forged,outer(true,12),true,start+30s+10ms) || pair.b->receive(second.initiation.bytes,outer(true,13),false,start+30s+11ms) || pair.b->status().peer!=outer(true,9)) return false;
        auto expired=pair.b->receive(held->datagram->bytes,outer(true,14),true,start+180s+3ms);
        if (expired || pair.b->status().previous || pair.b->status().indexes!=1 || pair.b->status().peer!=outer(true,9)) return false;
        auto done=pair.b->poll(start+210s+3ms);
        return done && !pair.b->status().current && !pair.b->status().indexes;
    }
    auto authenticated_ip_before_roaming() -> bool {
        Pair pair;
        auto start=Clock::time_point(10s);
        auto identity=key(0); auto remote=public_key(32);
        auto client=Handshake::create(identity,remote); if (!client) return false;
        auto stamp=make_timestamp(1,0); if (!stamp) return false;
        auto hello=client->initiate(111,*stamp,key(64)); if (!hello) return false;
        auto accepted=pair.b->receive(*hello,outer(true),true,start);
        if (!accepted || !accepted->handshake) return false;
        auto reply=pair.b->respond(*accepted->handshake,0,key(96),start+1ms);
        if (!reply || !pair.b->complete_send(reply->serial,true,start+1ms) || !client->consume_response(reply->bytes)) return false;
        auto session=client->finish(start+2ms); if (!session) return false;
        auto invalid=inner(true,false); invalid[3]=255;
        auto wire=session->seal(invalid,start+3ms); if (!wire) return false;
        auto rejected=pair.b->receive(*wire,outer(true,1),true,start+3ms);
        if (rejected || rejected.error().code!=EndpointError::invalid_packet || pair.b->status().peer!=outer(true) || pair.b->status().current || !pair.b->status().pending) return false;
        auto spoofed=inner(true,false); spoofed[15]=99;
        wire=session->seal(spoofed,start+4ms); if (!wire) return false;
        rejected=pair.b->receive(*wire,outer(true,2),true,start+4ms);
        if (rejected || rejected.error().code!=EndpointError::disallowed_source || pair.b->status().peer!=outer(true) || pair.b->status().current) return false;
        // Even a rejected inner packet consumes its authenticated replay bit.
        auto replay=pair.b->receive(*wire,outer(true,3),true,start+5ms);
        if (replay || replay.error().protocol!=Error::replay || pair.b->status().peer!=outer(true)) return false;
        wire=session->seal({},start+6ms); if (!wire) return false;
        auto confirmed=pair.b->receive(*wire,outer(true,4),true,start+6ms);
        if (!confirmed || !confirmed->key_confirmed || !confirmed->keepalive || pair.b->status().current!=0 || pair.b->status().pending || pair.b->status().peer!=outer(true,4)) return false;
        // Outbound routing checks destination; receive routing checks source.
        Pair both; Exchange complete;
        if (!exchange(both,start,complete)) return false;
        if (!both.a->enqueue(spoofed,start+10ms)) return false;
        auto output=both.a->poll(start+10ms);
        if (!output || !output->datagram || !both.a->complete_send(output->datagram->serial,true,start+10ms)) return false;
        rejected=both.b->receive(output->datagram->bytes,outer(true,5),true,start+11ms);
        return !rejected && rejected.error().code==EndpointError::disallowed_source && both.b->status().peer==outer(true);
    }
    auto stale_attempts_and_indexes() -> bool {
        Pair pair; auto start=Clock::time_point(10s);
        if (!pair.a || !pair.b || !pair.a->request_handshake(start)) return false;
        auto initial=pair.a->poll(start); if (!initial || !initial->handshake) return false;
        auto next=pair.a->poll(start+5s); if (!next || !next->handshake || next->handshake->ticket==initial->handshake->ticket) return false;
        auto stamp=make_timestamp(1,0); if (!stamp) return false;
        auto stale=pair.a->initiate(*initial->handshake,7,key(64),*stamp,0ms,start+5s);
        if (stale || stale.error().code!=EndpointError::stale_attempt || pair.a->status().indexes) return false;
        auto old=pair.a->initiate(*next->handshake,7,key(65),*stamp,0ms,start+5s);
        if (!old || !pair.a->output_valid(old->serial)) return false;
        auto retry=pair.a->poll(start+10s);
        if (!retry || !retry->handshake || pair.a->output_valid(old->serial) || pair.a->status().indexes || pair.a->complete_send(old->serial,true,start+10s)) return false;
        auto newer=make_timestamp(2,0); if (!newer) return false;
        auto fresh=pair.a->initiate(*retry->handshake,7,key(66),*newer,0ms,start+10s);
        if (!fresh || !pair.a->complete_send(fresh->serial,true,start+10s)) return false;
        // Old and current attempts deliberately reuse the same numeric index.
        auto old_request=pair.b->receive(old->bytes,outer(true),true,start+10s+1ms);
        if (!old_request || !old_request->handshake) return false;
        auto old_response=pair.b->respond(*old_request->handshake,7,key(96),start+10s+2ms);
        if (!old_response || !pair.b->complete_send(old_response->serial,true,start+10s+2ms)) return false;
        auto refused=pair.a->receive(old_response->bytes,outer(false,1),true,start+10s+3ms);
        if (refused || pair.a->status().current || pair.a->status().peer!=outer(false) || pair.a->status().handshake!=7) return false;
        auto current_request=pair.b->receive(fresh->bytes,outer(true),true,start+10s+30ms);
        if (!current_request || !current_request->handshake || pair.b->status().pending) return false;
        auto late=pair.b->respond(*old_request->handshake,7,key(97),start+10s+30ms);
        if (late || late.error().code!=EndpointError::stale_attempt || pair.b->status().indexes) return false;
        auto response=pair.b->respond(*current_request->handshake,7,key(98),start+10s+31ms);
        if (!response || !pair.b->complete_send(response->serial,true,start+10s+31ms) || !pair.a->receive(response->bytes,outer(false),true,start+10s+32ms)) return false;
        auto confirmed=pair.a->poll(start+10s+33ms);
        if (!confirmed || !confirmed->datagram || !pair.a->complete_send(confirmed->datagram->serial,true,start+10s+33ms) || !pair.b->receive(confirmed->datagram->bytes,outer(true),true,start+10s+34ms)) return false;
        auto after=pair.a->receive(old_response->bytes,outer(false,2),true,start+10s+35ms);
        return !after && pair.a->status().indexes==1 && pair.b->status().indexes==1 && pair.a->status().peer==outer(false);
    }
    auto queue_retry_and_stop() -> bool {
        auto limited=config(true); limited.queue_packets=2;
        auto endpoint=Endpoint::create(key(0),limited); auto now=Clock::time_point(10s);
        if (!endpoint || !endpoint->enqueue(inner(true,false),now) || !endpoint->enqueue(inner(true,true),now) || endpoint->enqueue(inner(true,false),now)) return false;
        auto request=endpoint->poll(now); auto stamp=make_timestamp(1,0);
        if (!request || !request->handshake || !stamp) return false;
        auto wire=endpoint->initiate(*request->handshake,7,key(64),*stamp,333ms,now);
        if (!wire) return false;
        auto early=endpoint->poll(now+5332ms); if (!early || early->handshake || !endpoint->output_valid(wire->serial)) return false;
        auto retry=endpoint->poll(now+5333ms);
        if (!retry || !retry->handshake || endpoint->output_valid(wire->serial) || endpoint->status().indexes || endpoint->status().queued_packets!=2) return false;
        auto gave_up=endpoint->poll(now+90s);
        if (!gave_up || !gave_up->gave_up || gave_up->handshake || endpoint->status().queued_packets || endpoint->status().queued_bytes || endpoint->status().indexes) return false;
        auto idle=endpoint->poll(now+91s); if (!idle || idle->gave_up || idle->handshake) return false;
        if (!endpoint->enqueue(inner(true,false),now+92s)) return false;
        auto resumed=endpoint->poll(now+92s); if (!resumed || !resumed->handshake || resumed->handshake->ticket<=retry->handshake->ticket) return false;
        auto reversed=endpoint->poll(now+91s); if (reversed || reversed.error().code!=EndpointError::clock || endpoint->status().queued_packets!=1) return false;
        endpoint->close();
        if (endpoint->status().indexes || endpoint->status().queued_packets || endpoint->output_valid(wire->serial)) return false;
        auto stopped=endpoint->initiate(*resumed->handshake,7,key(65),*stamp,0ms,now+93s);
        if (stopped || stopped.error().code!=EndpointError::closed) return false;
        auto bytes=config(true); bytes.mtu=68; bytes.queue_bytes=68;
        auto byte_limited=Endpoint::create(key(0),std::move(bytes));
        if (!byte_limited || !byte_limited->enqueue(inner(true,false,1,48),now) || byte_limited->enqueue(inner(true,false,2),now) || byte_limited->status().queued_bytes!=68) return false;
        // Fresh traffic must not extend an existing 90s retry window.
        auto continuous=Endpoint::create(key(0),config(true));
        if (!continuous || !continuous->enqueue(inner(true,false),now)) return false;
        auto first=continuous->poll(now); if (!first || !first->handshake) return false;
        for (unsigned step=1;step<9;++step) {
            auto at=now+std::chrono::seconds(step*10);
            if (!continuous->enqueue(inner(true,false,step),at)) return false;
            auto retrying=continuous->poll(at);
            if (!retrying || !retrying->handshake || retrying->gave_up) return false;
        }
        auto abandoned=continuous->poll(now+90s);
        if (!abandoned || !abandoned->gave_up || abandoned->handshake || continuous->status().queued_packets || continuous->status().queued_bytes) return false;
        if (!continuous->enqueue(inner(true,false),now+91s)) return false;
        auto restarted=continuous->poll(now+91s);
        return restarted && restarted->handshake && restarted->handshake->ticket>first->handshake->ticket;
    }
    auto timers_and_backpressure() -> bool {
        Pair pair; Exchange setup; auto start=Clock::time_point(10s);
        if (!exchange(pair,start,setup) || !send(*pair.a,*pair.b,true,false,start+1s)) return false;
        auto early=pair.b->poll(start+10999ms); if (!early || early->datagram) return false;
        auto due=pair.b->poll(start+11s);
        if (!due || !due->datagram || due->datagram->kind!=OutboundKind::keepalive || !pair.b->output_valid(due->datagram->serial)) return false;
        auto blocked=pair.b->poll(start+12s); if (!blocked || blocked->datagram) return false;
        if (!pair.b->complete_send(due->datagram->serial,false,start+12s)) return false;
        blocked=pair.b->poll(start+12s); if (!blocked || blocked->datagram) return false;
        auto again=pair.b->poll(start+13s);
        if (!again || !again->datagram || !pair.b->complete_send(again->datagram->serial,true,start+13s) || !pair.a->receive(again->datagram->bytes,outer(false),true,start+13s)) return false;
        auto idle=pair.b->poll(start+23s); if (!idle || idle->datagram || idle->handshake) return false;
        if (!send(*pair.a,*pair.b,true,false,start+30s) || !send(*pair.a,*pair.b,true,true,start+31s)) return false;
        early=pair.a->poll(start+44999ms); if (!early || early->handshake) return false;
        due=pair.a->poll(start+45s);
        if (!due || !due->handshake || due->handshake->reason!=HandshakeReason::rekey) return false;
        // An idle key does not trigger perpetual 120s handshakes.
        Pair idle_pair; Exchange idle_setup;
        if (!exchange(idle_pair,start,idle_setup)) return false;
        auto old=idle_pair.a->poll(start+120s+3ms);
        if (!old || old->handshake || old->datagram || !idle_pair.a->enqueue(inner(true,false),start+120s+3ms)) return false;
        auto rekey=idle_pair.a->poll(start+120s+3ms);
        if (!rekey || !rekey->handshake || rekey->handshake->reason!=HandshakeReason::rekey || idle_pair.a->status().queued_packets!=1) return false;
        Pair received; Exchange received_setup;
        if (!exchange(received,start,received_setup) || !send(*received.b,*received.a,false,false,start+105s+3ms)) return false;
        auto receive_rekey=received.a->poll(start+105s+3ms);
        if (!receive_rekey || !receive_rekey->handshake || receive_rekey->handshake->reason!=HandshakeReason::rekey) return false;
        auto persistent_a=config(true); persistent_a.persistent_keepalive=5s;
        Pair persistent(persistent_a); Exchange persistent_setup;
        if (!exchange(persistent,start,persistent_setup)) return false;
        early=persistent.a->poll(start+5002ms); if (!early || early->datagram) return false;
        due=persistent.a->poll(start+5003ms);
        if (!due || !due->datagram || due->datagram->kind!=OutboundKind::keepalive) return false;
        Pair pending; Exchange pending_setup;
        if (!exchange(pending,start,pending_setup,1,false) || !pending.b->enqueue(inner(false,false),start+4ms)) return false;
        early=pending.b->poll(start+14999ms); if (!early || early->handshake || early->datagram) return false;
        auto lost_confirmation=pending.b->poll(start+15s+2ms);
        return lost_confirmation && lost_confirmation->handshake && !pending.b->status().pending && !pending.b->status().indexes;
    }
}

auto main() -> int {
    if (!configuration_and_ip()) { std::println("endpoint configuration/IP checks failed"); return 1; }
    if (!maximum_mtu()) { std::println("endpoint maximum UDP MTU checks failed"); return 7; }
    if (!generation_and_roaming()) { std::println("endpoint generations/roaming checks failed"); return 2; }
    if (!authenticated_ip_before_roaming()) { std::println("endpoint authenticated IP admission checks failed"); return 3; }
    if (!stale_attempts_and_indexes()) { std::println("endpoint stale attempt/index checks failed"); return 4; }
    if (!queue_retry_and_stop()) { std::println("endpoint queue/retry/stop checks failed"); return 5; }
    if (!timers_and_backpressure()) { std::println("endpoint timer/backpressure checks failed"); return 6; }
    std::println("WireGuard endpoint IP/source authorization, generation overlap, stale attempts/indexes, bounded queues, timers, backpressure and stop passed");
}
