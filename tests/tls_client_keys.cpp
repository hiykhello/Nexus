import std;
import nexus.tls.client_keys;
namespace t=nexus::tls; namespace c=nexus::crypto;
auto hex(std::string_view s) -> c::Bytes { auto n=[](char x){return x<='9'?x-'0':x-'a'+10;}; c::Bytes b; for (std::size_t i=0;i<s.size();i+=2) b.push_back(static_cast<std::uint8_t>((n(s[i])<<4)|n(s[i+1]))); return b; }
int main() {
    auto client_wire=hex("010000c00303cb34ecb1e78163ba1c38c6dacb196a6dffa21a8d9912ec18a2ef6283024dece7000006130113031302010000910000000b0009000006736572766572ff01000100000a00140012001d0017001800190100010101020103010400230000003300260024001d002099381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c002b0003020304000d0020001e040305030603020308040805080604010501060102010402050206020202002d00020101001c00024001");
    auto server_wire=hex("020000560303a6af06a4121860dc5e6e60249cd34c95930c8ac5cb1434dac155772ed3e2692800130100002e00330024001d0020c9828876112095fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f002b00020304");
    auto private_bytes=hex("49af42ba7f7994852d713ef2784bcbcaa7911de26adc5642cb634540e7ea5005");
    auto key=c::X25519Private::from_bytes(private_bytes); if (!key) return 1;
    auto result=t::client_handshake_keys(client_wire,server_wire,std::move(*key));
    if (!result || key->public_key().error()!=c::Error::invalid_key) return 2;
    if (!std::ranges::equal(result->client_traffic.view(),hex("b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21")) ||
        !std::ranges::equal(result->server_traffic.view(),hex("b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38"))) return 3;
    auto sk=t::expand_label(c::Hash::sha256,result->server_traffic.view(),"key",{},16), si=t::expand_label(c::Hash::sha256,result->server_traffic.view(),"iv",{},12);
    if (!sk || !si) return 4;
    auto peer=t::RecordLayer::create(t::RecordDirection::send,c::Aead::aes_128_gcm,sk->view(),si->view()); if (!peer) return 5;
    c::Bytes plaintext{8,0,0,2,0,0}; auto wire=peer->seal(t::ContentType::handshake,plaintext);
    if (!wire) return 6; auto opened=result->read.open(*wire); if (!opened || opened->content!=plaintext || opened->type!=t::ContentType::handshake) return 7;
    auto wrong=c::X25519Private::generate(); if (!wrong) return 8;
    auto mismatch=t::client_handshake_keys(client_wire,server_wire,std::move(*wrong)); if (mismatch || mismatch.error()!=t::ClientKeyError::key_mismatch || wrong->public_key().error()!=c::Error::invalid_key) return 9;
    auto key2=c::X25519Private::from_bytes(private_bytes); if (!key2) return 10;
    auto malformed=server_wire; malformed[3]--; auto failure=t::client_handshake_keys(client_wire,malformed,std::move(*key2));
    if (failure || failure.error()!=t::ClientKeyError::malformed_hello || key2->public_key().error()!=c::Error::invalid_key) return 11;
    for (auto suite : {std::uint8_t{2},std::uint8_t{3}}) {
        auto alternate=server_wire; alternate[40]=suite;
        auto k=c::X25519Private::from_bytes(private_bytes); if (!k) return 12;
        auto epoch=t::client_handshake_keys(client_wire,alternate,std::move(*k)); if (!epoch) return 13;
        auto hash=suite==2 ? c::Hash::sha384 : c::Hash::sha256;
        auto alg=suite==2 ? c::Aead::aes_256_gcm : c::Aead::chacha20_poly1305;
        if (epoch->hash!=hash) return 14;
        auto ek=t::expand_label(hash,epoch->client_traffic.view(),"key",{},32), ei=t::expand_label(hash,epoch->client_traffic.view(),"iv",{},12);
        if (!ek || !ei) return 15;
        auto peer_read=t::RecordLayer::create(t::RecordDirection::receive,alg,ek->view(),ei->view());
        auto ciphertext=epoch->write.seal(t::ContentType::handshake,plaintext);
        if (!peer_read || !ciphertext) return 16;
        auto received=peer_read->open(*ciphertext); if (!received || received->content!=plaintext) return 17;
    }
    auto low_order=server_wire; std::ranges::fill(std::span{low_order}.subspan(52,32),0);
    auto k=c::X25519Private::from_bytes(private_bytes); if (!k) return 18;
    auto rejected=t::client_handshake_keys(client_wire,low_order,std::move(*k));
    if (rejected || rejected.error()!=t::ClientKeyError::invalid_peer) return 19;
    std::cout << "TLS client handshake keys RFC 8448 and record integration passed\n";
}
