import std;
import tls.hello;
import tls.key_share;
import tls.handshake;
import tls.transcript;
namespace t=tls; namespace c = ::crypto;
auto hex(std::string_view s) -> std::vector<std::uint8_t> { auto n=[](char x){return x<='9'? x-'0':x-'a'+10;}; std::vector<std::uint8_t> b; for (std::size_t i=0;i<s.size();i+=2) b.push_back(static_cast<std::uint8_t>((n(s[i])<<4)|n(s[i+1]))); return b; }
int main() {
    auto wire=hex("010000c00303cb34ecb1e78163ba1c38c6dacb196a6dffa21a8d9912ec18a2ef6283024dece7000006130113031302010000910000000b0009000006736572766572ff01000100000a00140012001d0017001800190100010101020103010400230000003300260024001d002099381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c002b0003020304000d0020001e040305030603020308040805080604010501060102010402050206020202002d00020101001c00024001");
    auto d=t::HandshakeDecoder::create(); if (!d) return 1; std::vector<t::HandshakeMessage> messages;
    for (auto byte:wire) { auto part=d->feed(std::span{&byte,1}); if (!part) return 2; for (auto& m:*part) messages.push_back(std::move(m)); }
    if (messages.size()!=1 || messages[0].type!=1 || !d->finish()) return 3;
    auto hello=t::ClientHello::parse(messages[0].body); if (!hello || !hello->validate_tls13()) return 4;
    auto ext=hello->extension(51); if (!ext) return 5; auto share=t::KeyShare::parse_client(ext->data);
    auto pub=hex("99381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c");
    if (!share || share->size()!=1 || (*share)[0].group!=0x1d || (*share)[0].key_exchange!=pub || t::KeyShare::encode_client(*share)!=ext->data) return 6;
    auto body=hello->encode(); if (!body || *body!=messages[0].body) return 7;
    auto encoded=t::HandshakeDecoder::encode(1,*body); if (!encoded || *encoded!=wire) return 8;
    auto transcript=t::Transcript::create(c::Hash::sha256); if (!transcript || !transcript->append(*encoded)) return 9;
    auto expected=c::digest(c::Hash::sha256,wire); auto actual=transcript->snapshot(); if (!expected || !actual || *actual!=*expected) return 10;
    std::cout << "TLS ClientHello framing, key_share and transcript integration passed\n";
}
