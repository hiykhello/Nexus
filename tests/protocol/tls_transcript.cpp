import std;
import tls.transcript;
import tls.schedule;
namespace c = ::crypto;
namespace t=tls;
auto hex(std::string_view value) -> c::Bytes {
    auto nibble=[](char ch) { return ch<='9' ? ch-'0' : ch-'a'+10; };
    c::Bytes out; for (std::size_t i=0;i<value.size();i+=2) out.push_back(static_cast<std::uint8_t>((nibble(value[i])<<4)|nibble(value[i+1])));
    return out;
}
int main() {
    auto hello=hex("010000c00303cb34ecb1e78163ba1c38c6dacb196a6dffa21a8d9912ec18a2ef6283024dece7000006130113031302010000910000000b0009000006736572766572ff01000100000a00140012001d0017001800190100010101020103010400230000003300260024001d002099381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c002b0003020304000d0020001e040305030603020308040805080604010501060102010402050206020202002d00020101001c00024001");
    auto server=hex("020000560303a6af06a4121860dc5e6e60249cd34c95930c8ac5cb1434dac155772ed3e2692800130100002e00330024001d0020c9828876112095fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f002b00020304");
    auto transcript=t::Transcript::create(c::Hash::sha256);
    if (!transcript || hello.size()!=196 || server.size()!=90 || !transcript->append(hello)) return 1;
    auto first=transcript->snapshot(), repeat=transcript->snapshot();
    if (!first || !repeat || *first!=*repeat) return 1;
    auto malformed=hello; malformed[3]--;
    if (transcript->append(malformed).error()!=t::TranscriptError::malformed_message || transcript->snapshot()!=first) return 1;
    if (!transcript->append(server)) return 1;
    auto hash=transcript->snapshot();
    if (!hash || *hash!=hex("860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8")) return 1;
    auto handshake=hex("1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac");
    auto traffic=t::derive_secret(c::Hash::sha256,handshake,"c hs traffic",*hash);
    if (!traffic || !std::ranges::equal(traffic->view(),hex("b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21"))) return 1;
    if (transcript->hello_retry_request().error()!=t::TranscriptError::invalid_retry_state) return 1;
    for (auto alg : {c::Hash::sha256,c::Hash::sha384}) {
        auto hrr=t::Transcript::create(alg); if (!hrr) return 1;
        if (hrr->hello_retry_request().error()!=t::TranscriptError::invalid_retry_state) return 1;
        auto small=hex("01000003010203"), retry=hex("020000020405");
        if (!hrr->append(small) || !hrr->hello_retry_request() || !hrr->append(retry)) return 1;
        if (hrr->hello_retry_request().error()!=t::TranscriptError::invalid_retry_state) return 1;
        auto got=hrr->snapshot();
        auto expected=alg==c::Hash::sha256 ? hex("909ee986f5d8dcd55820d490b04f50034c7554fe225b4aa5bdffcc29babbb618") :
            hex("5a16d202bedcbb79c7ba606485dd319f5e6aa9a4b652568beeca2363a3da25111bf452536e1cf136f60304ffcc6c9da0");
        if (!got || *got!=expected || hrr->append(hex("fe000000")).error()!=t::TranscriptError::malformed_message) return 1;
    }
    auto digest=c::DigestContext::create(c::Hash::sha256);
    c::Bytes a{'a'}, bc{'b','c'};
    if (!digest || !digest->update(a) || !digest->update(bc)) return 1;
    auto actual=digest->snapshot(), expected=c::digest(c::Hash::sha256,c::Bytes{'a','b','c'});
    if (!actual || actual!=expected) return 1;
    std::cout << "TLS transcript RFC 8448 and HelloRetryRequest passed\n";
}
