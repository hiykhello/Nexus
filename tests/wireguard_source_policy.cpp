import std;
import crypto;
import wireguard;
import wireguard.crypto;
import wireguard.noise;
import wireguard.session;
import wireguard.endpoint;
import wireguard.registry;
import wireguard.routing;

namespace {
    using namespace wireguard;
    using namespace std::chrono_literals;
    static_assert(std::same_as<AllowedPrefix,routing::Prefix> && std::same_as<PeerHandle,routing::PeerHandle>);
    auto key(unsigned first) -> ::crypto::X25519Private {
        Key bytes; for (std::size_t i=0;i<32;++i) bytes[i]=static_cast<std::uint8_t>(first+i);
        auto value=::crypto::X25519Private::from_bytes(bytes); if (!value) std::terminate(); return std::move(*value);
    }
    auto public_key(unsigned first) -> Key { auto private_key=key(first); auto value=private_key.public_key(); if (!value) std::terminate(); return *value; }
    auto outer(unsigned node,unsigned suffix=0) -> EndpointAddress { return {4,{198,51,100,static_cast<std::uint8_t>(node)},static_cast<std::uint16_t>(10000+node+suffix)}; }
    auto prefix(unsigned node,bool ipv6) -> AllowedPrefix {
        AllowedPrefix result{ipv6 ? std::uint8_t{6} : std::uint8_t{4},{},ipv6 ? std::uint8_t{128} : std::uint8_t{32}};
        if (ipv6) { result.address[0]=0xfd; result.address[1]=0x42; result.address[15]=static_cast<std::uint8_t>(node); }
        else { result.address[0]=10; result.address[1]=42; result.address[3]=static_cast<std::uint8_t>(node); }
        return result;
    }
    auto config(unsigned node,bool restricted) -> EndpointConfig {
        EndpointConfig result; result.peer_public=public_key((node-1)*32); result.peer=outer(node);
        result.allowed_ips=restricted ? std::vector{prefix(node,false),prefix(node,true)} : std::vector<AllowedPrefix>{{4,{},0},{6,{},0}};
        return result;
    }
    auto packet(unsigned source,bool ipv6) -> std::vector<std::uint8_t> {
        auto header=ipv6 ? 40u : 20u;
        std::vector<std::uint8_t> result(header+4); result[0]=ipv6 ? 0x60 : 0x45;
        if (ipv6) {
            result[5]=4; result[6]=253; result[7]=64;
            result[8]=result[24]=0xfd; result[9]=result[25]=0x42; result[23]=static_cast<std::uint8_t>(source); result[39]=1;
        } else {
            result[3]=24; result[8]=64; result[9]=253;
            result[12]=result[16]=10; result[13]=result[17]=42; result[15]=static_cast<std::uint8_t>(source); result[19]=1;
        }
        result[header]=1; result[header+1]=2; result[header+2]=3; result[header+3]=4; return result;
    }
    struct Pair {
        unsigned node;
        ::crypto::X25519Private remote_identity;
        std::expected<Endpoint,EndpointFailure> local;
        std::expected<Handshake,Error> remote;
        std::optional<Session> session;
        explicit Pair(unsigned value=2,bool restricted=false) : node(value),remote_identity(key((value-1)*32)),
            local(Endpoint::create(key(0),config(value,restricted))),remote(Handshake::create(remote_identity,public_key(0))) {}
    };
    auto establish(Pair& pair,SourcePolicyView policy,Clock::time_point now,unsigned epoch=1) -> bool {
        if (!pair.local || !pair.remote) return false;
        auto timestamp=make_timestamp(epoch,0); if (!timestamp) return false;
        auto hello=pair.remote->initiate(100+pair.node,*timestamp,key(96+pair.node+epoch)); if (!hello) return false;
        auto received=pair.local->receive(*hello,outer(pair.node),true,now,false,policy);
        if (!received || !received->handshake) return false;
        auto response=pair.local->respond(*received->handshake,7,key(128+pair.node+epoch),now+1ms);
        if (!response || !pair.local->complete_send(response->serial,true,now+1ms) || !pair.remote->consume_response(response->bytes)) return false;
        auto session=pair.remote->finish(now+2ms); if (!session) return false;
        pair.session.emplace(std::move(*session));
        return pair.local->status().pending && !pair.local->status().current;
    }
    auto receive(Pair& pair,std::span<std::uint8_t const> wire,unsigned suffix,Clock::time_point now,SourcePolicyView policy={})
        -> std::expected<EndpointReceived,EndpointFailure> {
        return pair.local->receive(wire,outer(pair.node,suffix),true,now,false,policy);
    }
    auto empty_enabled_and_default_compatibility() -> bool {
        PeerRegistry<1> registry; auto peer=registry.add(); routing::RouteTable<1,4> table;
        auto now=Clock::time_point(10s);
        if (!peer || !table.activate(*peer)) return false;
        Pair pair; auto policy=table.view(*peer);
        if (!establish(pair,policy,now)) return false;
        auto bytes=packet(2,false); auto wire=pair.session->seal(bytes,now+3ms);
        if (!wire) return false;
        auto refused=receive(pair,*wire,1,now+3ms,policy);
        if (refused || refused.error().code!=EndpointError::disallowed_source || pair.local->status().current || !pair.local->status().pending || pair.local->status().peer!=outer(2)) return false;
        auto replay=receive(pair,*wire,2,now+4ms,policy);
        if (replay || replay.error().protocol!=Error::replay || pair.local->status().current || pair.local->status().peer!=outer(2)) return false;
        // Keepalive carries no inner address; an active peer may confirm its
        // authenticated key even when the enabled routing table has no IPs.
        wire=pair.session->seal({},now+5ms); if (!wire) return false;
        auto confirmed=receive(pair,*wire,3,now+5ms,policy);
        if (!confirmed || !confirmed->keepalive || !confirmed->key_confirmed || !pair.local->status().current || pair.local->status().pending || pair.local->status().peer!=outer(2,3)) return false;
        // The prior synchronous view is not retained by the Endpoint.
        wire=pair.session->seal(bytes,now+6ms); if (!wire) return false;
        auto accepted=receive(pair,*wire,4,now+6ms);
        return accepted && accepted->packet==bytes && pair.local->status().peer==outer(2,4) && !table.status().prefixes;
    }
    auto global_winner_before_promotion_and_roam() -> bool {
        PeerRegistry<2> registry; auto b=registry.add(),c=registry.add(); routing::RouteTable<2,8> table;
        auto now=Clock::time_point(10s);
        if (!b || !c || !table.activate(*b) || !table.activate(*c) || !table.assign(*b,{4,{},0}) || !table.assign(*b,{6,{},0}) ||
            !table.assign(*c,prefix(2,false)) || !table.assign(*c,prefix(2,true))) return false;
        Pair first(2),second(3);
        if (!establish(first,table.view(*b),now) || !establish(second,table.view(*c),now)) return false;
        std::vector<std::uint8_t> old;
        for (bool ipv6:{false,true}) {
            auto bytes=packet(2,ipv6); auto wire=first.session->seal(bytes,now+3ms); if (!wire) return false;
            if (!ipv6) old=*wire;
            auto refused=receive(first,*wire,1,now+3ms,table.view(*b));
            if (refused || refused.error().code!=EndpointError::disallowed_source || first.local->status().current || !first.local->status().pending || first.local->status().peer!=outer(2)) return false;
            auto authorized=second.session->seal(bytes,now+3ms); if (!authorized) return false;
            auto accepted=receive(second,*authorized,1,now+3ms,table.view(*c));
            if (!accepted || accepted->packet!=bytes || !second.local->status().current || second.local->status().peer!=outer(3,1)) return false;
        }
        auto bytes=packet(2,false); auto valid=first.session->seal(bytes,now+4ms); if (!valid) return false;
        auto corrupted=*valid; corrupted.back()^=1;
        auto refused=receive(first,corrupted,2,now+4ms,table.view(*b));
        if (refused || refused.error().protocol!=Error::authentication || first.local->status().current || first.local->status().peer!=outer(2)) return false;
        // Reassigning the exact prefix changes both outbound choice and the
        // authenticated inbound owner; a failed tag has not poisoned replay.
        if (!table.assign(*b,prefix(2,false)) || !table.assign(*b,prefix(2,true))) return false;
        auto accepted=receive(first,*valid,3,now+5ms,table.view(*b));
        if (!accepted || !accepted->key_confirmed || accepted->packet!=bytes || first.local->status().peer!=outer(2,3)) return false;
        auto destination=prefix(2,false);
        if (table.lookup(4,std::span(destination.address).first(4))!=*b) return false;
        auto replay=receive(first,old,4,now+6ms,table.view(*b));
        if (replay || replay.error().protocol!=Error::replay || first.local->status().peer!=outer(2,3)) return false;
        auto now_unauthorized=second.session->seal(bytes,now+4ms); if (!now_unauthorized) return false;
        refused=receive(second,*now_unauthorized,2,now+4ms,table.view(*c));
        return !refused && refused.error().code==EndpointError::disallowed_source && second.local->status().peer==outer(3,1) && second.local->status().current;
    }
    auto local_policy_and_inner_validation_still_precede_global() -> bool {
        PeerRegistry<1> registry; auto peer=registry.add(); routing::RouteTable<1,4> table;
        auto now=Clock::time_point(10s);
        if (!peer || !table.activate(*peer) || !table.assign(*peer,{4,{},0}) || !table.assign(*peer,{6,{},0})) return false;
        Pair pair(2,true); auto policy=table.view(*peer);
        if (!establish(pair,policy,now)) return false;
        for (bool ipv6:{false,true}) {
            auto spoofed=packet(99,ipv6); auto wire=pair.session->seal(spoofed,now+3ms);
            auto source=prefix(99,ipv6);
            if (!wire || !policy.permits(source.family,std::span(source.address).first(ipv6 ? 16 : 4))) return false;
            auto refused=receive(pair,*wire,1,now+3ms,policy);
            if (refused || refused.error().code!=EndpointError::disallowed_source || pair.local->status().current || pair.local->status().peer!=outer(2)) return false;
            auto malformed=packet(2,ipv6); malformed[ipv6 ? 5 : 3]=255;
            wire=pair.session->seal(malformed,now+3ms); if (!wire) return false;
            refused=receive(pair,*wire,2,now+3ms,policy);
            if (refused || refused.error().code!=EndpointError::invalid_packet || pair.local->status().current || pair.local->status().peer!=outer(2)) return false;
        }
        auto bytes=packet(2,true); auto wire=pair.session->seal(bytes,now+4ms); if (!wire) return false;
        auto accepted=receive(pair,*wire,3,now+4ms,policy);
        return accepted && accepted->key_confirmed && accepted->packet==bytes && pair.local->status().peer==outer(2,3);
    }
    auto deleted_generation_and_reused_receiver() -> bool {
        PeerRegistry<1> registry; auto peer=registry.add(); routing::RouteTable<1,4> table;
        auto now=Clock::time_point(10s);
        if (!peer || !table.activate(*peer) || !table.assign(*peer,{4,{},0})) return false;
        Pair old; auto old_view=table.view(*peer);
        if (!establish(old,old_view,now)) return false;
        auto keepalive=old.session->seal({},now+3ms); if (!keepalive || !receive(old,*keepalive,1,now+3ms,old_view)) return false;
        auto held_keepalive=old.session->seal({},now+4ms); if (!held_keepalive) return false;
        auto old_wire=old.session->seal(packet(2,false),now+4ms); if (!old_wire) return false;
        if (!registry.erase(*peer) || !table.erase(*peer) || old_view.current()) return false;
        auto rejected=receive(old,*old_wire,2,now+4ms,old_view);
        if (rejected || rejected.error().code!=EndpointError::disallowed_source || old.local->status().peer!=outer(2,1)) return false;
        old.local->close();
        auto replacement=registry.add();
        if (!replacement || replacement->generation==peer->generation || !table.activate(*replacement) || table.status().prefixes) return false;
        Pair fresh; auto fresh_view=table.view(*replacement); now+=1s;
        if (!establish(fresh,fresh_view,now,2)) return false;
        auto wire=fresh.session->seal(packet(2,false),now+3ms); if (!wire) return false;
        rejected=receive(fresh,*wire,1,now+3ms,fresh_view);
        if (rejected || rejected.error().code!=EndpointError::disallowed_source || fresh.local->status().current || fresh.local->status().peer!=outer(2)) return false;
        if (!table.assign(*replacement,{4,{},0}) || table.erase(*peer) || table.activate(*peer) || table.status().prefixes!=1) return false;
        wire=fresh.session->seal(packet(2,false),now+4ms); if (!wire) return false;
        rejected=receive(fresh,*wire,2,now+4ms,old_view);
        if (rejected || rejected.error().code!=EndpointError::disallowed_source || fresh.local->status().current || fresh.local->status().peer!=outer(2)) return false;
        auto accepted=receive(fresh,*wire,3,now+5ms,fresh_view);
        if (!accepted || !accepted->key_confirmed || fresh.local->status().current!=7 || fresh.local->status().peer!=outer(2,3)) return false;
        // The numeric receiver is 7 in both generations; old ciphertext must
        // still fail AEAD after the host slot has been reused.
        rejected=receive(fresh,*old_wire,4,now+6ms,fresh_view);
        if (rejected || rejected.error().protocol!=Error::authentication || fresh.local->status().peer!=outer(2,3) || fresh.local->status().current!=7) return false;
        auto next=fresh.session->seal(packet(2,false),now+7ms); if (!next) return false;
        accepted=receive(fresh,*next,5,now+7ms,fresh_view);
        return accepted && accepted->packet==packet(2,false) && fresh.local->status().peer==outer(2,5);
    }
}

auto main() -> int {
    if (!empty_enabled_and_default_compatibility()) { std::println("WireGuard enabled empty routing/default compatibility failed"); return 1; }
    if (!global_winner_before_promotion_and_roam()) { std::println("WireGuard global source winner before promotion/roam failed"); return 2; }
    if (!local_policy_and_inner_validation_still_precede_global()) { std::println("WireGuard local policy/inner validation ordering failed"); return 3; }
    if (!deleted_generation_and_reused_receiver()) { std::println("WireGuard deleted route generation/reused receiver failed"); return 4; }
    std::println("WireGuard global source owner after AEAD/replay/local IP checks, before key promotion/roam, default compatibility and peer deletion passed");
}
