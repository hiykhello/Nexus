import std;
import crypto;
import wireguard;
import wireguard.crypto;
import wireguard.noise;
import wireguard.session;
import wireguard.cookie;

namespace {
    using namespace wireguard;
    using namespace std::chrono_literals;
    template<std::size_t N> auto sequence(unsigned first) -> std::array<std::uint8_t,N> {
        std::array<std::uint8_t,N> result; for (std::size_t i=0;i<N;++i) result[i]=static_cast<std::uint8_t>(first+i); return result;
    }
    auto hex(std::span<std::uint8_t const> input) -> std::string {
        constexpr std::string_view alphabet="0123456789abcdef";
        std::string result; result.reserve(input.size()*2);
        for (auto byte:input) { result.push_back(alphabet[byte>>4]); result.push_back(alphabet[byte&15]); } return result;
    }
    // Fixed output from tests/wireguard_reference.py using Go X25519/x-crypto.
    auto expected_vectors() -> std::map<std::string,std::string> {
        return {
            {"cookie","0300000078563412c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d72a0d2a55e639ec1eac5c8e2398c45604e80c114de20e586d2a52e6616470fd42"},
            {"initiation","010000007856341279a631eede1bf9c98f12032cdeadd0e7a079398fc786b88cc846ec89af85a51af0225eb421886af8f54fb31289d49dcd82b0f6f3279d40d7cff913fece0c64ad226eef3320755b393b72f16842c8d7ee78a74e93718a56b09df4ecc1f7e2d2e3e544ecb189a8759680aee8b331d48eb3ae4dca46c2ba5c28cac992fd00000000000000000000000000000000"},
            {"initiator-data","04000000f0debc9a0100000000000000bf31815ac5bb90e8bb1805a637d2b55b2857074eb1bdc72d5c1f2c1de50b51ed8e0c3b0fb555ffeab2f68ee54cc9f88800a8bd3b05d271927066988883ef8291"},
            {"keepalive","04000000f0debc9a0000000000000000c05b5687dc9e973b4033587e96b81434"},
            {"responder-data","0400000078563412000000000000000007da3c881a45f4d4d4a5b07047ab2cb39bd6cc03b98a1ece79c0602863cb3e7578b29ae5b43181993dc5f46283b4ac5a"},
            {"response","02000000f0debc9a78563412675dd574ed7789310b3d2e7681f3790b466c773b1521fecf36577958371ea52f20dc002c94988950a05a23701866746199e9a0fc1fa1d7ee9f0ea290b41489c200000000000000000000000000000000"},
            {"with-cookie","010000007856341279a631eede1bf9c98f12032cdeadd0e7a079398fc786b88cc846ec89af85a51af0225eb421886af8f54fb31289d49dcd82b0f6f3279d40d7cff913fece0c64ad226eef3320755b393b72f16842c8d7ee78a74e93718a56b09df4ecc1f7e2d2e3e544ecb189a8759680aee8b331d48eb3ae4dca46c2ba5c28cac992fd4c584d832e26d4a64e91f8defd2e26a7"},
        };
    }
    auto vector_cases(std::map<std::string,std::string>& vectors) -> int {
        auto a=::crypto::X25519Private::from_bytes(sequence<32>(0)),b=::crypto::X25519Private::from_bytes(sequence<32>(32));
        auto x=::crypto::X25519Private::from_bytes(sequence<32>(64)),y=::crypto::X25519Private::from_bytes(sequence<32>(96));
        if (!a || !b || !x || !y) return 1;
        auto ap=a->public_key(),bp=b->public_key(); if (!ap || !bp) return 2;
        auto psk=sequence<32>(128);
        auto initiator=Handshake::create(*a,*bp,psk),responder=Handshake::create(*b,*ap,psk);
        if (!initiator || !responder || initiator->finish(Clock::time_point{})) return 3;
        auto timestamp=make_timestamp(1793494318,0x12000000); if (!timestamp) return 4;
        auto request=initiator->initiate(0x12345678,*timestamp,std::move(*x)); if (!request) return 5;
        vectors["initiation"]=hex(*request);
        TimestampGuard replay;
        auto now=Clock::time_point(10s);
        if (!responder->consume_initiation(*request,replay,now)) return 6;
        auto response=responder->respond(0x9abcdef0,std::move(*y)); if (!response) return 7;
        vectors["response"]=hex(*response);
        if (!initiator->consume_response(*response)) return 8;
        auto first=initiator->finish(now),second=responder->finish(now);
        if (!first || !second || initiator->finish(now) || responder->finish(now) || second->confirmed() || second->seal({},now) || second->next_counter()) return 9;
        auto keepalive=first->seal({},now); if (!keepalive) return 10;
        vectors["keepalive"]=hex(*keepalive);
        auto opened=second->open(*keepalive,now);
        if (!opened || !opened->empty() || !second->confirmed() || second->open(*keepalive,now)) return 11;
        auto payload=sequence<33>(0);
        auto data=first->seal(payload,now); if (!data) return 12;
        vectors["initiator-data"]=hex(*data);
        auto corrupted=*data; corrupted.back()^=1;
        auto wrong=second->open(corrupted,now);
        if (wrong || second->last_received()) return 13;
        opened=second->open(*data,now);
        if (!opened || opened->size()!=48 || !std::ranges::equal(std::span(*opened).first(33),payload) ||
            std::ranges::any_of(std::span(*opened).subspan(33),[](auto byte) { return byte!=0; }) || second->open(*data,now)) return 14;
        auto back=second->seal(sequence<17>(1),now); if (!back) return 15;
        vectors["responder-data"]=hex(*back);
        opened=first->open(*back,now);
        if (!opened || opened->size()!=32 || !std::ranges::equal(std::span(*opened).first(17),sequence<17>(1))) return 16;
        auto generator=CookieGenerator::create(*bp);
        auto checker=CookieChecker::create(*bp,SecretKey(sequence<32>(160)),now);
        if (!generator || !checker) return 17;
        auto original=*request;
        if (!generator->apply(original,now) || original!=*request || !checker->check(original,{sequence<4>(192),12345},now,false)) return 18;
        std::array<std::uint8_t,4> source{192,0,2,10};
        if (checker->check(original,{source,12345},now,true)) return 19;
        auto cookie=checker->reply(original,{source,12345},sequence<24>(192),now); if (!cookie) return 20;
        vectors["cookie"]=hex(*cookie);
        auto bad_cookie=*cookie; bad_cookie.back()^=1;
        if (generator->consume(bad_cookie,now) || !generator->consume(*cookie,now) || generator->consume(*cookie,now)) return 21;
        auto with_cookie=*request;
        if (!generator->apply(with_cookie,now) || !checker->check(with_cookie,{source,12345},now,true) || checker->check(with_cookie,{source,12346},now,true)) return 22;
        vectors["with-cookie"]=hex(with_cookie);
        source[3]^=1;
        if (checker->check(with_cookie,{source,12345},now,true) || checker->check(with_cookie,{source,12345},now+120s,true)) return 23;
        auto expired=*request;
        if (!generator->apply(expired,now+120s) || expired!=*request || checker->reply(original,{source,12345},sequence<24>(216),now+120s)) return 24;
        if (!checker->rotate(SecretKey(sequence<32>(170)),now+120s) || !checker->reply(original,{source,12345},sequence<24>(216),now+120s)) return 25;
        // A moved session keeps counter/replay state and closes its source.
        auto moved=std::move(*first);
        if (first->seal({},now) || moved.next_counter()!=2 || !moved.rekey_due(now+120s) || second->rekey_due(now+120s) ||
            !moved.receive_rekey_due(now+105s) || moved.receive_rekey_due(now+104s)) return 26;
        if (!moved.seal({},now+179s) || moved.seal({},now+180s) || moved.open(*back,now)) return 27;
        return 0;
    }
    auto authentication_cases() -> int {
        auto a=::crypto::X25519Private::from_bytes(sequence<32>(0)),b=::crypto::X25519Private::from_bytes(sequence<32>(32));
        if (!a || !b) return 1;
        auto ap=a->public_key(),bp=b->public_key(); if (!ap || !bp) return 2;
        if (Handshake::create(*a,Key{}) || Handshake::create(*a,*bp,sequence<31>(0))) return 3;
        auto now=Clock::time_point(10s); auto timestamp=make_timestamp(1,0); if (!timestamp) return 4;
        auto x=::crypto::X25519Private::from_bytes(sequence<32>(64)); if (!x) return 5;
        auto client=Handshake::create(*a,*bp); if (!client) return 6;
        auto request=client->initiate(1,*timestamp,std::move(*x)); if (!request) return 7;
        TimestampGuard replay;
        for (auto offset:{8u,40u,88u,116u}) {
            auto server=Handshake::create(*b,*ap); if (!server) return 8;
            auto bad=*request; bad[offset]^=1;
            // MAC1 is public-key derived; valid MAC1 cannot substitute for
            // authenticated identity and timestamp ciphertext.
            if (offset!=116 && !detail::add_macs(bad,*bp)) return 9;
            if (server->consume_initiation(bad,replay,now) || replay.last()!=Timestamp{}) return 10;
        }
        auto server=Handshake::create(*b,*ap); if (!server || !server->consume_initiation(*request,replay,now)) return 11;
        auto again=Handshake::create(*b,*ap);
        if (!again || again->consume_initiation(*request,replay,now+1s)) return 12;
        auto y=::crypto::X25519Private::from_bytes(sequence<32>(96)); if (!y) return 13;
        auto response=server->respond(2,std::move(*y)); if (!response) return 14;
        for (auto offset:{8u,12u,44u,60u}) {
            auto bad=*response; bad[offset]^=1;
            if (offset!=60 && !detail::add_macs(bad,*ap)) return 15;
            if (client->consume_response(bad)) return 16;
        }
        if (!client->consume_response(*response)) return 17;
        auto first=client->finish(now),second=server->finish(now);
        if (!first || !second) return 18;
        auto confirm=first->seal({},now); if (!confirm || !second->open(*confirm,now)) return 19;
        std::array<std::vector<std::uint8_t>,3> packets;
        for (std::size_t i=0;i<3;++i) { auto wire=first->seal(sequence<20>(i),now,21); if (!wire) return 20; packets[i]=std::move(*wire); }
        for (auto index:{2u,0u,1u}) {
            auto plaintext=second->open(packets[index],now);
            if (!plaintext || plaintext->size()!=21 || !std::ranges::equal(std::span(*plaintext).first(20),sequence<20>(index))) return 21;
        }
        if (second->open(packets[0],now) || first->seal(sequence<22>(0),now,21) || first->next_counter()!=4) return 22;
        // Different PSKs authenticate the initiation but cannot finish Noise.
        auto wrong=Handshake::create(*b,*ap,sequence<32>(1));
        auto fresh=Handshake::create(*a,*bp); x=::crypto::X25519Private::from_bytes(sequence<32>(65));
        TimestampGuard guard;
        if (!wrong || !fresh || !x) return 23;
        auto other=fresh->initiate(3,*timestamp,std::move(*x));
        if (!other || !wrong->consume_initiation(*other,guard,now)) return 24;
        y=::crypto::X25519Private::from_bytes(sequence<32>(97)); if (!y) return 25;
        auto rejection=wrong->respond(4,std::move(*y)); if (!rejection || fresh->consume_response(*rejection) || fresh->finish(now)) return 26;
        // One timestamp/rate transaction wins under concurrent attempts.
        TimestampGuard concurrent; std::atomic<unsigned> accepted{0}; std::barrier gate(8);
        std::vector<std::jthread> threads;
        for (unsigned i=0;i<8;++i) threads.emplace_back([&] { gate.arrive_and_wait(); if (concurrent.commit_authenticated(*timestamp,now)) ++accepted; });
        threads.clear();
        if (accepted!=1 || concurrent.last()!=*timestamp) return 27;
        auto later=make_timestamp(2,0); if (!later) return 28;
        if (concurrent.commit_authenticated(*later,now+20ms) || concurrent.last()!=*timestamp || !concurrent.commit_authenticated(*later,now+21ms)) return 29;
        return 0;
    }
}

auto main(int argc,char** argv) -> int {
    std::map<std::string,std::string> vectors;
    auto result=vector_cases(vectors);
    if (result) { std::println("WireGuard vector/lifetime case {} failed",result); return result; }
    if (vectors!=expected_vectors()) { std::println("WireGuard independent fixed vector mismatch"); return 99; }
    if (argc==2 && std::string_view(argv[1])=="--vectors") {
        std::print("{{"); bool first=true;
        for (auto const& [key,value]:vectors) { std::print("{}\"{}\":\"{}\"",first ? "" : ",",key,value); first=false; }
        std::println("}}"); return 0;
    }
    result=authentication_cases();
    if (result) { std::println("WireGuard authentication case {} failed",result); return 100+result; }
    std::println("WireGuard Noise IKpsk2, cookie binding, key confirmation, authenticated replay, expiry and concurrent timestamps passed");
}
