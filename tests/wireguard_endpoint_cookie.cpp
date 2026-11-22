import std;
import crypto;
import wireguard;
import wireguard.cookie;
import wireguard.crypto;
import wireguard.endpoint;

namespace {
    using namespace wireguard;
    using namespace std::chrono_literals;
    auto key(unsigned first) -> ::crypto::X25519Private {
        Key bytes; for (std::size_t i=0;i<32;++i) bytes[i]=static_cast<std::uint8_t>(first+i);
        auto value=::crypto::X25519Private::from_bytes(bytes); if (!value) std::terminate(); return std::move(*value);
    }
    auto public_key(unsigned first) -> Key { auto private_key=key(first); auto value=private_key.public_key(); if (!value) std::terminate(); return *value; }
    auto secret(unsigned first) -> SecretKey {
        SecretKey value; for (std::size_t i=0;i<32;++i) value.writable()[i]=static_cast<std::uint8_t>(first+i); return value;
    }
    auto outer(bool a,unsigned suffix=0) -> EndpointAddress { return {4,{198,51,100,static_cast<std::uint8_t>(a ? 1 : 2)},static_cast<std::uint16_t>((a ? 10001 : 10002)+suffix)}; }
    auto config(bool a) -> EndpointConfig {
        EndpointConfig result; result.peer_public=public_key(a ? 32 : 0); result.peer=outer(!a); result.allowed_ips={{4,{},0}}; return result;
    }
    struct Pair {
        std::expected<Endpoint,EndpointFailure> a=Endpoint::create(key(0),config(true)),b=Endpoint::create(key(32),config(false));
    };
    auto begin(Endpoint& endpoint,Clock::time_point now,unsigned epoch=1,std::uint32_t seed=7) -> std::optional<EndpointDatagram> {
        if (!endpoint.request_handshake(now)) return {};
        auto request=endpoint.poll(now); auto timestamp=make_timestamp(epoch,0);
        if (!request || !request->handshake || !timestamp) return {};
        auto wire=endpoint.initiate(*request->handshake,seed,key(64+epoch),*timestamp,0ms,now);
        if (!wire || !endpoint.complete_send(wire->serial,true,now)) return {};
        return std::move(*wire);
    }
    auto retry(Endpoint& endpoint,Clock::time_point now,unsigned epoch=2,std::uint32_t seed=8) -> std::optional<EndpointDatagram> {
        auto request=endpoint.poll(now); auto timestamp=make_timestamp(epoch,0);
        if (!request || !request->handshake || request->handshake->reason!=HandshakeReason::retry || !timestamp) return {};
        auto wire=endpoint.initiate(*request->handshake,seed,key(64+epoch),*timestamp,0ms,now);
        if (!wire || !endpoint.complete_send(wire->serial,true,now)) return {};
        return std::move(*wire);
    }
    auto confirm(Pair& pair,HandshakeRequest request,Clock::time_point now,unsigned a_suffix=0) -> bool {
        auto response=pair.b->respond(request,11,key(96),now);
        if (!response || !pair.b->complete_send(response->serial,true,now)) return false;
        auto received=pair.a->receive(response->bytes,outer(false),true,now+1ms);
        if (!received || !pair.a->status().current || !pair.b->status().pending) return false;
        auto output=pair.a->poll(now+1ms);
        if (!output || !output->datagram || !pair.a->complete_send(output->datagram->serial,true,now+1ms)) return false;
        received=pair.b->receive(output->datagram->bytes,outer(true,a_suffix),true,now+2ms,true);
        return received && received->key_confirmed && pair.b->status().current && !pair.b->status().pending;
    }
    auto gate_source_and_scope() -> bool {
        Pair pair; auto now=Clock::time_point(10s); std::array<std::uint8_t,24> nonce{};
        if (!pair.a || !pair.b) return false;
        auto hello=begin(*pair.a,now); if (!hello) return false;
        auto missing=pair.b->receive(hello->bytes,outer(true),true,now,true);
        if (missing || missing.error().code!=EndpointError::cookie_secret || pair.b->status().latest_attempt) return false;
        if (!pair.b->rotate_cookie_secret(secret(128),now)) return false;
        auto first=pair.b->receive(hello->bytes,outer(true),true,now+1ms,true);
        if (!first || !first->cookie || first->handshake || first->peer_changed || pair.b->status().indexes || pair.b->status().latest_attempt) return false;
        auto bad=hello->bytes; bad[bad.size()-32]^=1;
        auto rejected=pair.b->receive(bad,outer(true,1),true,now+2ms,true);
        if (rejected || rejected.error().protocol!=Error::authentication || pair.b->status().peer!=outer(true)) return false;
        if (pair.b->receive(hello->bytes,outer(true,1),false,now+3ms,true)) return false;
        auto unchanged=pair.b->poll(now+3ms);
        if (!unchanged || !unchanged->cookie || unchanged->cookie->ticket!=first->cookie->ticket) return false;
        // A syntactically valid MAC1 with broken Noise ciphertext must be
        // challenged before any DH, timestamp commit or peer roaming.
        auto malformed=hello->bytes; malformed[40]^=1;
        auto generator=CookieGenerator::create(public_key(32));
        if (!generator || !generator->apply(malformed,now+4ms)) return false;
        auto before_noise=pair.b->receive(malformed,outer(true,2),true,now+4ms,true);
        if (!before_noise || !before_noise->cookie || before_noise->handshake || pair.b->status().latest_attempt || pair.b->status().peer!=outer(true)) return false;
        auto latest=pair.b->receive(hello->bytes,outer(true,1),true,now+5ms,true);
        if (!latest || !latest->cookie || latest->cookie->ticket==first->cookie->ticket || pair.b->respond_cookie(*first->cookie,nonce,now+5ms)) return false;
        auto reply=pair.b->respond_cookie(*latest->cookie,nonce,now+5ms);
        if (!reply || reply->kind!=OutboundKind::cookie || reply->destination!=outer(true,1) || reply->bytes.size()!=cookie_size || !pair.b->complete_send(reply->serial,true,now+5ms)) return false;
        if (pair.b->respond_cookie(*latest->cookie,nonce,now+5ms)) return false;
        rejected=pair.a->receive(reply->bytes,outer(false,1),true,now+6ms);
        if (rejected || pair.a->status().peer!=outer(false)) return false;
        bad=reply->bytes; bad.back()^=1;
        rejected=pair.a->receive(bad,outer(false),true,now+7ms);
        if (rejected || rejected.error().protocol!=Error::authentication) return false;
        bad=reply->bytes; store_le32(std::span(bad).subspan<4,4>(),999);
        if (pair.a->receive(bad,outer(false),true,now+8ms)) return false;
        auto consumed=pair.a->receive(reply->bytes,outer(false),true,now+9ms);
        if (!consumed || !consumed->cookie_consumed || consumed->peer_changed || consumed->handshake || consumed->cookie || pair.a->status().current) return false;
        if (pair.a->receive(reply->bytes,outer(false),true,now+10ms)) return false;
        auto early=pair.a->poll(now+4999ms); if (!early || early->handshake) return false;
        auto fresh=retry(*pair.a,now+5s); if (!fresh || std::ranges::all_of(std::span(fresh->bytes).last(16),[](auto c) { return !c; })) return false;
        // Cookie is bound to the exact outer source port. A mismatch must not
        // consume the Noise timestamp, so the correct source still succeeds.
        auto wrong_source=pair.b->receive(fresh->bytes,outer(true),true,now+5s+1ms,true);
        if (!wrong_source || !wrong_source->cookie || wrong_source->handshake || pair.b->status().latest_attempt) return false;
        auto accepted=pair.b->receive(fresh->bytes,outer(true,1),true,now+5s+2ms,true);
        if (!accepted || !accepted->handshake || accepted->cookie || !accepted->peer_changed || pair.b->status().peer!=outer(true,1)) return false;
        auto old_challenge=pair.b->respond_cookie(*wrong_source->cookie,nonce,now+5s+2ms);
        return !old_challenge && confirm(pair,*accepted->handshake,now+5s+3ms,1);
    }
    auto response_cookie_and_retry() -> bool {
        Pair pair; auto now=Clock::time_point(10s); std::array<std::uint8_t,24> nonce{};
        if (!pair.a || !pair.b || !pair.a->rotate_cookie_secret(secret(128),now)) return false;
        auto hello=begin(*pair.a,now); if (!hello) return false;
        auto accepted=pair.b->receive(hello->bytes,outer(true),true,now+1ms);
        if (!accepted || !accepted->handshake) return false;
        auto response=pair.b->respond(*accepted->handshake,11,key(96),now+2ms);
        if (!response || !pair.b->complete_send(response->serial,true,now+2ms)) return false;
        auto gated=pair.a->receive(response->bytes,outer(false),true,now+3ms,true);
        if (!gated || !gated->cookie || gated->handshake || pair.a->status().current || !pair.a->status().handshake || !pair.b->status().pending) return false;
        auto reply=pair.a->respond_cookie(*gated->cookie,nonce,now+4ms);
        if (!reply || !pair.a->complete_send(reply->serial,true,now+4ms)) return false;
        auto consumed=pair.b->receive(reply->bytes,outer(true),true,now+5ms);
        if (!consumed || !consumed->cookie_consumed || consumed->peer_changed || pair.b->status().current || !pair.b->status().pending) return false;
        auto early=pair.b->poll(now+1s); if (!early || early->handshake || early->datagram) return false;
        auto fresh=retry(*pair.a,now+5s); if (!fresh) return false;
        accepted=pair.b->receive(fresh->bytes,outer(true),true,now+5s+1ms);
        if (!accepted || !accepted->handshake || pair.b->status().pending) return false;
        response=pair.b->respond(*accepted->handshake,11,key(97),now+5s+2ms);
        if (!response || std::ranges::all_of(std::span(response->bytes).last(16),[](auto c) { return !c; }) || !pair.b->complete_send(response->serial,true,now+5s+2ms)) return false;
        accepted=pair.a->receive(response->bytes,outer(false),true,now+5s+3ms,true);
        if (!accepted || accepted->cookie || !pair.a->status().current) return false;
        auto output=pair.a->poll(now+5s+3ms);
        if (!output || !output->datagram || !pair.a->complete_send(output->datagram->serial,true,now+5s+3ms)) return false;
        accepted=pair.b->receive(output->datagram->bytes,outer(true),true,now+5s+4ms);
        return accepted && accepted->key_confirmed && pair.b->status().current && !pair.b->status().pending;
    }
    auto stale_replies_and_window() -> bool {
        Pair pair; auto now=Clock::time_point(10s); std::array<std::uint8_t,24> nonce{};
        if (!pair.a || !pair.b || !pair.b->rotate_cookie_secret(secret(128),now)) return false;
        auto old=begin(*pair.a,now); if (!old) return false;
        auto gated=pair.b->receive(old->bytes,outer(true),true,now+1ms,true);
        if (!gated || !gated->cookie) return false;
        auto reply=pair.b->respond_cookie(*gated->cookie,nonce,now+2ms);
        if (!reply || !pair.b->complete_send(reply->serial,true,now+2ms)) return false;
        // The numeric receiver index is reused; the old reply must still fail
        // against the new attempt's MAC1 and leave the live request unchanged.
        auto fresh=retry(*pair.a,now+5s,2,7); if (!fresh) return false;
        auto refused=pair.a->receive(reply->bytes,outer(false),true,now+5s+1ms);
        if (refused || refused.error().protocol!=Error::authentication || pair.a->status().handshake!=7) return false;
        gated=pair.b->receive(fresh->bytes,outer(true),true,now+5s+2ms,true);
        if (!gated || !gated->cookie) return false;
        reply=pair.b->respond_cookie(*gated->cookie,nonce,now+5s+3ms);
        if (!reply || !pair.b->complete_send(reply->serial,true,now+5s+3ms)) return false;
        auto consumed=pair.a->receive(reply->bytes,outer(false),true,now+89s);
        if (!consumed || !consumed->cookie_consumed) return false;
        auto abandoned=pair.a->poll(now+90s);
        if (!abandoned || !abandoned->gave_up || abandoned->handshake || pair.a->status().indexes) return false;
        // A peer that never supplies a cookie still gets ordinary fresh Noise
        // retries with zero MAC2; cookie support must not become mandatory.
        auto none=Endpoint::create(key(0),config(true)); if (!none) return false;
        auto initial=begin(*none,now); if (!initial) return false;
        auto retried=retry(*none,now+5s);
        return retried && std::ranges::all_of(std::span(retried->bytes).last(16),[](auto c) { return !c; });
    }
    auto challenge_expiry_rotation_and_backpressure() -> bool {
        Pair pair; auto now=Clock::time_point(10s); std::array<std::uint8_t,24> nonce{};
        if (!pair.a || !pair.b || !pair.b->rotate_cookie_secret(secret(128),now)) return false;
        auto hello=begin(*pair.a,now); if (!hello) return false;
        auto gated=pair.b->receive(hello->bytes,outer(true),true,now+1ms,true);
        if (!gated || !gated->cookie) return false;
        auto stale=pair.b->respond_cookie(*gated->cookie,nonce,now+5s+1ms);
        if (stale || stale.error().code!=EndpointError::stale_attempt) return false;
        auto expired=pair.b->poll(now+5s+1ms); if (!expired || expired->cookie) return false;
        gated=pair.b->receive(hello->bytes,outer(true),true,now+5s+2ms,true);
        if (!gated || !gated->cookie) return false;
        auto reply=pair.b->respond_cookie(*gated->cookie,nonce,now+5s+3ms);
        if (!reply || !pair.b->output_valid(reply->serial)) return false;
        // A new unauthenticated request owns one replacement slot. Its nonce
        // preparation cannot complete an old ticket or send obsolete bytes.
        auto next=pair.b->receive(hello->bytes,outer(true,1),true,now+5s+4ms,true);
        if (!next || !next->cookie || pair.b->output_valid(reply->serial) || pair.b->complete_send(reply->serial,true,now+5s+4ms)) return false;
        reply=pair.b->respond_cookie(*next->cookie,nonce,now+5s+5ms);
        if (!reply) return false;
        auto blocked=pair.b->poll(now+5s+5ms);
        if (!blocked || blocked->cookie || blocked->datagram || blocked->handshake || !pair.b->output_valid(reply->serial)) return false;
        if (!pair.b->rotate_cookie_secret(secret(160),now+5s+6ms) || pair.b->output_valid(reply->serial)) return false;
        if (pair.b->respond_cookie(*next->cookie,nonce,now+5s+6ms)) return false;
        auto no_secret=pair.b->receive(hello->bytes,outer(true),true,now+125s+6ms,true);
        if (no_secret || no_secret.error().code!=EndpointError::cookie_secret || no_secret.error().protocol!=Error::expired) return false;
        pair.b->close();
        auto stopped=pair.b->rotate_cookie_secret(secret(192),now+126s);
        return !stopped && stopped.error().code==EndpointError::closed && !pair.b->status().indexes && !pair.b->output_valid(reply->serial);
    }
    auto challenge_behind_business_send() -> bool {
        Pair pair; auto now=Clock::time_point(10s);
        if (!pair.a || !pair.b) return false;
        auto hello=begin(*pair.a,now); if (!hello) return false;
        auto accepted=pair.b->receive(hello->bytes,outer(true),true,now+1ms);
        if (!accepted || !accepted->handshake || !confirm(pair,*accepted->handshake,now+2ms)) return false;
        now+=10s;
        if (!pair.b->rotate_cookie_secret(secret(128),now)) return false;
        std::array<std::uint8_t,20> packet{0x45,0,0,20,0,0,0,0,64,253,0,0,10,0,0,2,10,0,0,1};
        if (!pair.b->enqueue(packet,now)) return false;
        auto held=pair.b->poll(now); if (!held || !held->datagram || held->datagram->kind!=OutboundKind::data) return false;
        auto before=pair.b->status();
        hello=begin(*pair.a,now,2); if (!hello) return false;
        auto gated=pair.b->receive(hello->bytes,outer(true,1),true,now+1ms,true);
        if (!gated || gated->cookie || gated->handshake || !pair.b->output_valid(held->datagram->serial)) return false;
        auto blocked=pair.b->poll(now+1ms);
        if (!blocked || blocked->cookie || blocked->datagram || blocked->handshake || pair.b->status().current!=before.current ||
            pair.b->status().latest_attempt!=before.latest_attempt || pair.b->status().peer!=before.peer) return false;
        if (!pair.b->complete_send(held->datagram->serial,true,now+2ms)) return false;
        auto ready=pair.b->poll(now+2ms); if (!ready || !ready->cookie) return false;
        std::array<std::uint8_t,24> nonce{};
        auto reply=pair.b->respond_cookie(*ready->cookie,nonce,now+2ms);
        if (!reply || reply->destination!=outer(true,1) || pair.b->status().current!=before.current) return false;
        pair.b->close(); return !pair.b->output_valid(reply->serial) && !pair.b->status().indexes;
    }
}

auto main() -> int {
    if (!gate_source_and_scope()) { std::println("endpoint cookie gate/source/scope failed"); return 1; }
    if (!response_cookie_and_retry()) { std::println("endpoint response cookie/retry failed"); return 2; }
    if (!stale_replies_and_window()) { std::println("endpoint stale cookie/window/no-cookie retry failed"); return 3; }
    if (!challenge_expiry_rotation_and_backpressure()) { std::println("endpoint cookie challenge expiry/rotation/backpressure failed"); return 4; }
    if (!challenge_behind_business_send()) { std::println("endpoint cookie behind business send failed"); return 5; }
    std::println("WireGuard Endpoint cookie-before-Noise gate, source binding, initiation/response retry, stale tickets/replies, expiry/rotation and stop passed");
}
