import std;
import crypto;
import wireguard;
import wireguard.cookie;
import wireguard.crypto;
import wireguard.noise;
import wireguard.admission;
import wireguard.initiation;
import wireguard.identity;
import wireguard.routing;

namespace {
    using namespace wireguard;
    using namespace std::chrono_literals;
    template<class KeyArgument> concept CanBorrowIdentity=requires(KeyArgument&& key) { IdentityIngress::create(std::forward<KeyArgument>(key)); };
    static_assert(CanBorrowIdentity<::crypto::X25519Private&> && CanBorrowIdentity<::crypto::X25519Private const&>);
    static_assert(!CanBorrowIdentity<::crypto::X25519Private> && !CanBorrowIdentity<::crypto::X25519Private const>);
    struct Counts {
        static inline unsigned dh=0,decrypt=0;
        static auto static_dh() noexcept -> void { ++dh; }
        static auto static_decrypt() noexcept -> void { ++decrypt; }
        static auto reset() noexcept -> void { dh=decrypt=0; }
    };
    auto key(unsigned first) -> ::crypto::X25519Private {
        Key bytes; for (std::size_t i=0;i<32;++i) bytes[i]=static_cast<std::uint8_t>(first+i);
        auto value=::crypto::X25519Private::from_bytes(bytes); if (!value) std::terminate(); return std::move(*value);
    }
    auto public_key(unsigned first) -> Key { auto value=key(first).public_key(); if (!value) std::terminate(); return *value; }
    auto secret(unsigned first) -> SecretKey {
        SecretKey result; for (std::size_t i=0;i<32;++i) result.writable()[i]=static_cast<std::uint8_t>(first+i); return result;
    }
    auto outer(unsigned suffix=0) -> admission::Address { return {4,{198,51,100,2},static_cast<std::uint16_t>(10002+suffix)}; }
    auto hello(unsigned remote_key=32,unsigned epoch=1) -> std::array<std::uint8_t,initiation_size> {
        auto remote=key(remote_key); auto attempt=Handshake::create(remote,public_key(0)); auto timestamp=make_timestamp(epoch,0);
        if (!attempt || !timestamp) std::terminate(); auto wire=attempt->initiate(7,*timestamp,key(96+epoch)); if (!wire) std::terminate(); return *wire;
    }
    auto fixed_keys_and_tombstones() -> bool {
        PeerKeys<2> peers; routing::PeerHandle a{0,1},b{1,1}; auto ka=public_key(32),kb=public_key(64);
        if (peers.activate({2,1},ka) || peers.activate({0,0},ka) || peers.activate(a,Key{}) || !peers.activate(a,ka) || !peers.activate(a,ka) || peers.size()!=1) return false;
        auto duplicate=peers.activate(b,ka);
        if (duplicate || duplicate.error().code!=identity::ErrorCode::duplicate_key || peers.size()!=1 || peers.view().find(ka)!=a) return false;
        if (!peers.activate(b,kb) || peers.size()!=2 || peers.view().find(kb)!=b || peers.activate(a,kb)) return false;
        auto change=peers.activate(a,public_key(96));
        if (change || change.error().code!=identity::ErrorCode::identity_changed || !peers.view().matches(a,ka)) return false;
        if (!peers.erase(a) || peers.view().find(ka) || peers.activate(a,ka) || peers.erase(a) || peers.size()!=1) return false;
        routing::PeerHandle a2{0,2};
        if (!peers.activate(a2,ka) || peers.view().matches(a,ka) || peers.erase(a) || peers.activate(a,ka) || peers.view().find(ka)!=a2) return false;
        routing::PeerHandle a3{0,3};
        if (peers.activate(a3,kb) || !peers.view().matches(a2,ka) || !peers.activate(a3,public_key(96)) || peers.view().find(ka) || peers.view().find(public_key(96))!=a3) return false;
        PeerKeys<1> last; routing::PeerHandle final{0,std::numeric_limits<std::uint64_t>::max()};
        return last.activate(final,ka) && last.erase(final) && !last.activate(final,ka) && !last.activate(a,ka);
    }
    auto source_limit_boundaries() -> bool {
        identity::HandshakeLimiter<2> limit;
        auto first=outer(), alternate_port=outer(1), second=outer(), third=outer();
        second.address[3]=3;third.address[3]=4;
        auto now=Clock::time_point(10s);
        for (unsigned i=0;i<5;++i) if (!limit.allow(first,now)) return false;
        if (limit.allow(alternate_port,now) || limit.allow(first,now+49ms)) return false;
        if (!limit.allow(first,now+50ms) || limit.allow(first,now+50ms)) return false;
        if (!limit.allow(second,now+50ms) || limit.allow(third,now+50ms)) return false;
        if (limit.allow(first,now+49ms)) return false;
        if (!limit.allow(first,now+900ms) || !limit.allow(second,now+900ms) || limit.allow(third,now+900ms)) return false;
        if (limit.allow(third,now+1900ms) || !limit.allow(third,now+1901ms)) return false;
        limit.clear();
        admission::Address ipv6{6,{0x20,0x01,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,1},9000};
        auto bad=first;bad.address[4]=1;
        return limit.allow(first,now+1901ms) && limit.allow(ipv6,now+1901ms) && !limit.allow(bad,now+1901ms);
    }
    auto one_static_open_and_one_consume() -> bool {
        auto local=key(0); auto wire=hello(); Counts::reset();
        auto opened=OpenedInitiation::open<Counts>(local,wire);
        if (!opened || Counts::dh!=1 || Counts::decrypt!=1 || !opened->valid() || opened->remote_public()!=public_key(32) || opened->local_public()!=public_key(0)) return false;
        auto moved=std::move(*opened);
        if (opened->valid() || !moved.valid() || opened->take()) return false;
        auto state=moved.take();
        if (!state || moved.valid() || moved.take() || state->remote_public!=public_key(32) || state->sender!=7) return false;
        state->clear();
        if (std::ranges::any_of(state->remote_public,[](auto c) { return c!=0; }) || std::ranges::any_of(state->transcript.chain.view(),[](auto c) { return c!=0; })) return false;
        auto bad=wire; bad[40]^=1; auto macs=CookieGenerator::create(public_key(0));
        if (!macs || !macs->apply(bad,Clock::time_point(10s))) return false;
        Counts::reset(); auto broken=OpenedInitiation::open<Counts>(local,bad);
        if (broken || broken.error()!=Error::authentication || Counts::dh!=1 || Counts::decrypt!=1) return false;
        bad=wire; bad[116]^=1; Counts::reset(); broken=OpenedInitiation::open<Counts>(local,bad);
        if (broken || broken.error()!=Error::authentication || Counts::dh || Counts::decrypt) return false;
        auto admitted=AdmittedHandshake::authenticate(public_key(0),wire); if (!admitted) return false;
        auto wrong=key(64); Counts::reset(); broken=OpenedInitiation::open<Counts>(wrong,std::move(*admitted));
        if (broken || broken.error()!=Error::authentication || Counts::dh || Counts::decrypt) return false;
        return !admitted->take();
    }
    auto dispatch_and_late_peer_deletion() -> bool {
        auto local=key(0); auto ingress=IdentityIngress::create(local); PeerKeys<32> peers;
        if (!ingress) return false;
        for (std::uint16_t slot=0;slot<32;++slot) if (!peers.activate({slot,1},public_key(32+slot))) return false;
        auto wire=hello(63); Counts::reset(); auto received=ingress->receive<Counts>(wire,outer(),true,Clock::time_point(10s),peers.view());
        if (!received || !received->selected || received->cookie || received->selected->peer()!=routing::PeerHandle{31,1} || Counts::dh!=1 || Counts::decrypt!=1) return false;
        if (!peers.erase({31,1}) || !peers.activate({31,2},public_key(63))) return false;
        auto stale=received->selected->take(peers.view());
        if (stale || stale.error().code!=identity::ErrorCode::stale_peer || received->selected->take(peers.view())) return false;
        Counts::reset(); received=ingress->receive<Counts>(wire,outer(),true,Clock::time_point(10s+1ms),peers.view());
        if (!received || !received->selected || received->selected->peer()!=routing::PeerHandle{31,2} || Counts::dh!=1 || Counts::decrypt!=1) return false;
        auto selected=received->selected->take(peers.view());
        if (!selected || selected->peer!=routing::PeerHandle{31,2} || selected->source!=outer() || !selected->opened.valid()) return false;
        Counts::reset(); auto unknown=ingress->receive<Counts>(hello(200),outer(),true,Clock::time_point(10s+2ms),peers.view());
        if (unknown || unknown.error().code!=identity::ErrorCode::unknown_peer || Counts::dh!=1 || Counts::decrypt!=1) return false;
        Counts::reset(); auto denied=ingress->receive<Counts>(wire,outer(),false,Clock::time_point(10s+3ms),peers.view());
        if (denied || Counts::dh || Counts::decrypt) return false;
        ingress->close(); auto stopped=ingress->receive<Counts>(wire,outer(),true,Clock::time_point(10s+4ms),peers.view());
        return !stopped && stopped.error().code==identity::ErrorCode::closed;
    }
    auto port_cookie_before_any_dh() -> bool {
        auto local=key(0); auto ingress=IdentityIngress::create(local); PeerKeys<2> peers;
        routing::PeerHandle peer{0,1}; auto now=Clock::time_point(10s); std::array<std::uint8_t,24> nonce{};
        if (!ingress || !peers.activate(peer,public_key(32))) return false;
        auto wire=hello(); auto generator=CookieGenerator::create(public_key(0));
        if (!generator || !generator->apply(wire,now) || !ingress->rotate_cookie_secret(secret(128),now)) return false;
        Counts::reset(); auto gated=ingress->receive<Counts>(wire,outer(),true,now+1ms,peers.view(),true);
        if (!gated || !gated->cookie || gated->selected || Counts::dh || Counts::decrypt) return false;
        auto first=*gated->cookie;
        auto bad=wire; bad[116]^=1;
        auto refused=ingress->receive<Counts>(bad,outer(1),true,now+2ms,peers.view(),true);
        if (refused || Counts::dh || Counts::decrypt) return false;
        auto pending=ingress->poll_cookie(now+2ms); if (!pending || !*pending || (**pending).ticket!=first.ticket) return false;
        // Broken encrypted static with a recomputed public MAC1 must get a
        // challenge without triggering even one DH/decryption operation.
        auto malformed=wire; malformed[40]^=1; if (!generator->apply(malformed,now+3ms)) return false;
        auto before_noise=ingress->receive<Counts>(malformed,outer(1),true,now+3ms,peers.view(),true);
        if (!before_noise || !before_noise->cookie || before_noise->selected || Counts::dh || Counts::decrypt || ingress->respond_cookie(first,nonce,now+3ms)) return false;
        if (!generator->apply(wire,now+4ms)) return false;
        gated=ingress->receive<Counts>(wire,outer(),true,now+4ms,peers.view(),true);
        if (!gated || !gated->cookie || Counts::dh || Counts::decrypt) return false;
        auto reply=ingress->respond_cookie(*gated->cookie,nonce,now+5ms);
        if (!reply || reply->destination!=outer() || !ingress->cookie_output_valid(reply->request.ticket) || !generator->consume(reply->bytes,now+6ms)) return false;
        auto fresh=hello(32,2); if (!generator->apply(fresh,now+5s)) return false;
        auto held=ingress->receive<Counts>(fresh,outer(1),true,now+5s,peers.view(),true,false);
        if(held || !held.error().admission || held.error().admission->code!=admission::ErrorCode::busy ||
           !ingress->cookie_output_valid(reply->request.ticket) || Counts::dh || Counts::decrypt)return false;
        auto wrong_source=ingress->receive<Counts>(fresh,outer(1),true,now+5s,peers.view(),true);
        if (!wrong_source || !wrong_source->cookie || wrong_source->selected || ingress->cookie_output_valid(reply->request.ticket) || Counts::dh || Counts::decrypt) return false;
        // Invalid MAC1/MAC2 never consume quota, even if a spoofed source
        // uses the same address as a reachable peer.
        for(unsigned i=0;i<10;++i) {
            auto invalid_mac1=fresh;invalid_mac1[116]^=1;
            auto denied=ingress->receive<Counts>(invalid_mac1,outer(),true,now+5s,peers.view(),true);
            if(denied || Counts::dh || Counts::decrypt)return false;
            auto invalid_mac2=fresh;invalid_mac2.back()^=1;
            auto challenge=ingress->receive<Counts>(invalid_mac2,outer(),true,now+5s,peers.view(),true);
            if(!challenge || !challenge->cookie || challenge->selected || Counts::dh || Counts::decrypt)return false;
        }
        auto received=ingress->receive<Counts>(fresh,outer(),true,now+5s+1ms,peers.view(),true);
        if (!received || !received->selected || received->cookie || Counts::dh!=1 || Counts::decrypt!=1) return false;
        auto selected=received->selected->take(peers.view()); if (!selected || selected->source!=outer()) return false;
        ingress->cancel_cookie(); if (ingress->respond_cookie(*wrong_source->cookie,nonce,now+5s+2ms)) return false;
        // A valid MAC2 gates both initiation and response through the same
        // source quota, before another static DH/decrypt or host queue entry.
        for(unsigned i=0;i<3;++i) {
            auto again=ingress->receive<Counts>(fresh,outer(),true,now+5s+2ms,peers.view(),true);
            if(!again || !again->selected || Counts::dh!=i+2 || Counts::decrypt!=i+2)return false;
        }
        std::array<std::uint8_t,response_size> response{};response[0]=2;
        if(!generator->apply(response,now+5s+2ms))return false;
        auto admitted_response=ingress->admit_response(response,outer(),true,now+5s+2ms,true);
        if(!admitted_response || !admitted_response->admitted)return false;
        auto throttled=ingress->receive<Counts>(fresh,outer(),true,now+5s+2ms,peers.view(),true);
        if(throttled || throttled.error().code!=identity::ErrorCode::rate_limited || Counts::dh!=4 || Counts::decrypt!=4)return false;
        admitted_response=ingress->admit_response(response,outer(),true,now+5s+2ms,true);
        if(admitted_response || admitted_response.error().code!=identity::ErrorCode::rate_limited)return false;
        auto ungated=ingress->receive<Counts>(fresh,outer(),true,now+5s+2ms,peers.view(),false);
        if(!ungated || !ungated->selected || Counts::dh!=5 || Counts::decrypt!=5)return false;
        auto resumed=ingress->receive<Counts>(fresh,outer(),true,now+5s+52ms,peers.view(),true);
        if(!resumed || !resumed->selected || Counts::dh!=6 || Counts::decrypt!=6)return false;
        auto expired=ingress->receive<Counts>(fresh,outer(),true,now+120s,peers.view(),true);
        return !expired && expired.error().admission && expired.error().admission->code==admission::ErrorCode::cookie_secret && Counts::dh==6 && Counts::decrypt==6;
    }
}

auto main() -> int {
    if (!source_limit_boundaries()) { std::println("WireGuard source handshake rate limit failed"); return 5; }
    if (!fixed_keys_and_tombstones()) { std::println("WireGuard identity fixed key map/tombstones failed"); return 1; }
    if (!one_static_open_and_one_consume()) { std::println("WireGuard one static decrypt/token consumption failed"); return 2; }
    if (!dispatch_and_late_peer_deletion()) { std::println("WireGuard identity dispatch/deleted peer token failed"); return 3; }
    if (!port_cookie_before_any_dh()) { std::println("WireGuard port cookie before static DH failed"); return 4; }
    std::println("WireGuard one static DH/decrypt before fixed key lookup, move-only consumption, key tombstones and port cookie gate passed; sizeof keys32={} admission={} opened={} selected={}",sizeof(PeerKeys<>),sizeof(CookieAdmission),sizeof(OpenedInitiation),sizeof(SelectedInitiation));
}
