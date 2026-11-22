import std;
import crypto;
import wireguard;
import wireguard.cookie;
import wireguard.crypto;
import wireguard.noise;
import wireguard.session;
import wireguard.admission;
import wireguard.initiation;
import wireguard.identity;
import wireguard.endpoint;
import wireguard.registry;
import wireguard.routing;

namespace {
    using namespace wireguard;
    using namespace std::chrono_literals;
    auto key(unsigned first) -> ::crypto::X25519Private {
        Key bytes; for (std::size_t i=0;i<32;++i) bytes[i]=static_cast<std::uint8_t>(first+i);
        auto value=::crypto::X25519Private::from_bytes(bytes); if (!value) std::terminate(); return std::move(*value);
    }
    auto public_key(unsigned first) -> Key { auto value=key(first).public_key(); if (!value) std::terminate(); return *value; }
    auto outer(unsigned node,unsigned suffix=0) -> EndpointAddress { return {4,{198,51,100,static_cast<std::uint8_t>(node)},static_cast<std::uint16_t>(10000+node+suffix)}; }
    auto prefix(unsigned node) -> AllowedPrefix { return {4,{10,42,0,static_cast<std::uint8_t>(node)},32}; }
    auto config(unsigned node,unsigned first) -> EndpointConfig {
        EndpointConfig result; result.peer_public=public_key(first); result.peer=outer(node); result.allowed_ips={{4,{},0}}; return result;
    }
    auto packet(unsigned node) -> std::array<std::uint8_t,24> { return {0x45,0,0,24,0,0,0,0,64,253,0,0,10,42,0,static_cast<std::uint8_t>(node),10,42,0,1,1,2,3,4}; }
    struct Context {
        ::crypto::X25519Private local=key(0);
        std::expected<IdentityIngress,identity::Failure> ingress=IdentityIngress::create(local);
        PeerRegistry<2> registry;
        PeerKeys<2> peers;
        routing::RouteTable<2,8> routes;
        std::optional<PeerHandle> b,c;
        Context() {
            auto first=registry.add(),second=registry.add();
            if (!first || !second || !peers.activate(*first,public_key(32)) || !peers.activate(*second,public_key(64)) || !routes.activate(*first) || !routes.activate(*second)) return;
            b=*first; c=*second;
        }
    };
    auto select(Context& context,std::span<std::uint8_t const> wire,unsigned node,Clock::time_point now)
        -> std::expected<identity::Received,identity::Failure> { return context.ingress->receive(wire,outer(node),true,now,context.peers.view()); }
    auto start(Handshake& remote,Clock::time_point,unsigned epoch=1) -> std::optional<std::array<std::uint8_t,initiation_size>> {
        auto timestamp=make_timestamp(epoch,0); if (!timestamp) return {};
        auto wire=remote.initiate(100+epoch,*timestamp,key(96+epoch)); return wire ? std::optional(*wire) : std::nullopt;
    }
    auto respond(Context& context,PeerHandle peer,Endpoint& endpoint,HandshakeRequest request,Clock::time_point now) -> std::optional<EndpointDatagram> {
        if (!context.registry.sync(peer,endpoint)) return {};
        auto reserved=context.registry.reserve(peer,request.ticket,7); if (!reserved) return {};
        auto wire=endpoint.respond(request,reserved->index,key(128+request.ticket),now,IndexMode::exact);
        if (!wire) { (void)context.registry.release(*reserved); return {}; }
        if (!context.registry.sync(peer,endpoint) || !endpoint.complete_send(wire->serial,true,now)) return {};
        return std::move(*wire);
    }
    auto wrong_peer_then_selected_timestamp_auth() -> bool {
        Context context;
        auto local_b=Endpoint::create(key(0),config(2,32)),local_c=Endpoint::create(key(0),config(3,64));
        auto remote_identity=key(32); auto remote=Handshake::create(remote_identity,public_key(0)); auto now=Clock::time_point(10s);
        if (!context.b || !context.c || !context.ingress || !local_b || !local_c || !remote || !context.routes.assign(*context.b,prefix(2))) return false;
        auto wire=start(*remote,now); if (!wire) return false;
        auto received=select(context,*wire,2,now);
        if (!received || !received->selected || received->selected->peer()!=*context.b) return false;
        // Wrong endpoint configuration must not commit a timestamp, create an
        // attempt or roam, even though the key-table lookup named peer B.
        auto wrong=local_c->receive_selected(std::move(*received->selected),context.peers.view(),now,context.routes.view(*context.b));
        if (wrong || wrong.error().protocol!=Error::authentication || local_c->status().latest_attempt || local_c->status().peer!=outer(3) || received->selected->take(context.peers.view())) return false;
        received=select(context,*wire,2,now+1ms);
        if (!received || !received->selected) return false;
        auto accepted=local_b->receive_selected(std::move(*received->selected),context.peers.view(),now+1ms,context.routes.view(*context.b));
        if (!accepted || !accepted->handshake || accepted->cookie || local_b->status().latest_attempt!=1) return false;
        context.ingress->cancel_cookie();
        auto response=respond(context,*context.b,*local_b,*accepted->handshake,now+2ms);
        if (!response || !remote->consume_response(response->bytes)) return false;
        auto session=remote->finish(now+3ms); if (!session) return false;
        // The same initiation is now replay; selecting its static again does
        // not confer authority to replace the already accepted generation.
        received=select(context,*wire,2,now+30ms);
        if (!received || !received->selected) return false;
        auto replay=local_b->receive_selected(std::move(*received->selected),context.peers.view(),now+30ms,context.routes.view(*context.b));
        if (replay || replay.error().protocol!=Error::replay || local_b->status().latest_attempt!=1 || !local_b->status().pending || local_b->status().current) return false;
        auto data=session->seal(packet(2),now+31ms); if (!data) return false;
        auto delivered=local_b->receive(*data,outer(2,10),true,now+31ms,false,context.routes.view(*context.b));
        return delivered && delivered->key_confirmed && std::ranges::equal(delivered->packet,packet(2)) && local_b->status().peer==outer(2,10);
    }
    auto partial_static_is_not_timestamp_authentication() -> bool {
        Context context; auto endpoint=Endpoint::create(key(0),config(2,32));
        auto remote_identity=key(32); auto remote=Handshake::create(remote_identity,public_key(0)); auto now=Clock::time_point(10s);
        if (!context.b || !context.ingress || !endpoint || !remote) return false;
        auto wire=start(*remote,now); if (!wire) return false;
        auto damaged=*wire; damaged[88]^=1;
        auto generator=CookieGenerator::create(public_key(0)); if (!generator || !generator->apply(damaged,now)) return false;
        auto selected=select(context,damaged,2,now);
        if (!selected || !selected->selected) return false;
        auto refused=endpoint->receive_selected(std::move(*selected->selected),context.peers.view(),now,context.routes.view(*context.b));
        if (refused || refused.error().protocol!=Error::authentication || endpoint->status().latest_attempt || endpoint->status().peer!=outer(2)) return false;
        auto cancelled=select(context,*wire,2,now+1ms); if (!cancelled || !cancelled->selected) return false;
        cancelled->selected->close();
        refused=endpoint->receive_selected(std::move(*cancelled->selected),context.peers.view(),now+1ms,context.routes.view(*context.b));
        if (refused || refused.error().code!=EndpointError::stale_attempt || endpoint->status().latest_attempt) return false;
        // A view for another peer or a disabled view fails before committing
        // the valid timestamp; the same authentic packet can still succeed.
        selected=select(context,*wire,2,now+1ms); if (!selected || !selected->selected) return false;
        refused=endpoint->receive_selected(std::move(*selected->selected),context.peers.view(),now+1ms,context.routes.view(*context.c));
        if (refused || refused.error().code!=EndpointError::disallowed_source || endpoint->status().latest_attempt) return false;
        selected=select(context,*wire,2,now+2ms); if (!selected || !selected->selected) return false;
        refused=endpoint->receive_selected(std::move(*selected->selected),context.peers.view(),now+2ms,{});
        if (refused || refused.error().code!=EndpointError::disallowed_source || endpoint->status().latest_attempt) return false;
        selected=select(context,*wire,2,now+3ms); if (!selected || !selected->selected) return false;
        auto accepted=endpoint->receive_selected(std::move(*selected->selected),context.peers.view(),now+3ms,context.routes.view(*context.b));
        return accepted && accepted->handshake && endpoint->status().latest_attempt==1 && !endpoint->status().current;
    }
    auto deleted_map_or_route_token_cannot_return() -> bool {
        Context context; auto endpoint=Endpoint::create(key(0),config(2,32));
        auto remote_identity=key(32); auto remote=Handshake::create(remote_identity,public_key(0)); auto now=Clock::time_point(10s);
        if (!context.b || !context.ingress || !endpoint || !remote) return false;
        auto wire=start(*remote,now); if (!wire) return false;
        auto selected=select(context,*wire,2,now); if (!selected || !selected->selected || !context.peers.erase(*context.b)) return false;
        auto refused=endpoint->receive_selected(std::move(*selected->selected),context.peers.view(),now,context.routes.view(*context.b));
        if (refused || refused.error().code!=EndpointError::stale_attempt || endpoint->status().latest_attempt || endpoint->status().peer!=outer(2)) return false;
        if (!context.routes.erase(*context.b) || !context.registry.erase(*context.b)) return false;
        auto replacement=context.registry.add();
        if (!replacement || replacement->generation==context.b->generation || !context.peers.activate(*replacement,public_key(32)) || !context.routes.activate(*replacement)) return false;
        selected=select(context,*wire,2,now+1ms); if (!selected || !selected->selected || selected->selected->peer()!=*replacement) return false;
        refused=endpoint->receive_selected(std::move(*selected->selected),context.peers.view(),now+1ms,context.routes.view(*context.b));
        if (refused || refused.error().code!=EndpointError::disallowed_source || endpoint->status().latest_attempt) return false;
        selected=select(context,*wire,2,now+2ms); if (!selected || !selected->selected) return false;
        endpoint->close();
        refused=endpoint->receive_selected(std::move(*selected->selected),context.peers.view(),now+2ms,context.routes.view(*replacement));
        return !refused && refused.error().code==EndpointError::closed && !endpoint->status().indexes;
    }
    auto wrong_psk_rejects_response() -> bool {
        auto local_identity=key(0),remote_identity=key(32); Key psk{}; psk[0]=1;
        auto responder=Handshake::create(local_identity,public_key(32),psk),initiator=Handshake::create(remote_identity,public_key(0));
        TimestampGuard timestamp; auto now=Clock::time_point(10s);
        if (!responder || !initiator) return false;
        auto wire=start(*initiator,now); if (!wire) return false;
        auto opened=OpenedInitiation::open(local_identity,*wire);
        if (!opened || !responder->consume_opened(std::move(*opened),timestamp,now)) return false;
        auto response=responder->respond(7,key(200));
        if (!response) return false;
        auto rejected=initiator->consume_response(*response);
        // IKpsk2 mixes PSK in the response, not the incoming initiation.
        return !rejected && rejected.error()==Error::authentication && !initiator->finish(now);
    }
}

auto main() -> int {
    if (!wrong_peer_then_selected_timestamp_auth()) { std::println("WireGuard selected identity/peer timestamp authentication failed"); return 1; }
    if (!partial_static_is_not_timestamp_authentication()) { std::println("WireGuard partial static is not full admission failed"); return 2; }
    if (!deleted_map_or_route_token_cannot_return()) { std::println("WireGuard selected token deletion/route/stop failed"); return 3; }
    if (!wrong_psk_rejects_response()) { std::println("WireGuard selected PSK response rejection failed"); return 4; }
    std::println("WireGuard shared identity selected ss/timestamp, response PSK, route/key generations and single-consumption failure/stop checks passed");
}
