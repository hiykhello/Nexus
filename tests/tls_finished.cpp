import std;
import tls.finished;
#include "support/rfc8448_server_flight.hpp"
namespace t=tls; namespace c = ::crypto;
auto hex(std::string_view s) -> c::Bytes { auto n=[](char x){return x<='9'?x-'0':x-'a'+10;}; c::Bytes b; for (std::size_t i=0;i<s.size();i+=2) b.push_back(static_cast<std::uint8_t>((n(s[i])<<4)|n(s[i+1]))); return b; }
auto make(c::Hash alg) -> t::ClientFinished {
    auto transcript=t::Transcript::create(alg); if (!transcript) std::abort();
    if (!transcript->append(c::Bytes{1,0,0,1,0x42}) || !transcript->append(c::Bytes{2,0,0,1,0x43})) std::abort();
    auto len=alg==c::Hash::sha256?32u:48u;
    return t::ClientFinished(alg,std::move(*transcript),t::Secret(c::Bytes(len,4)),t::Secret(c::Bytes(len,3)));
}
int main() {
    auto client_wire=hex("010000c00303cb34ecb1e78163ba1c38c6dacb196a6dffa21a8d9912ec18a2ef6283024dece7000006130113031302010000910000000b0009000006736572766572ff01000100000a00140012001d0017001800190100010101020103010400230000003300260024001d002099381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c002b0003020304000d0020001e040305030603020308040805080604010501060102010402050206020202002d00020101001c00024001");
    auto server_wire=hex("020000560303a6af06a4121860dc5e6e60249cd34c95930c8ac5cb1434dac155772ed3e2692800130100002e00330024001d0020c9828876112095fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f002b00020304");
    auto flight=hex(rfc8448_server_flight); if (flight.size()!=657) return 8;
    auto transcript=t::Transcript::create(c::Hash::sha256); if (!transcript || !transcript->append(client_wire) || !transcript->append(server_wire)) return 9;
    std::size_t pos=0; for (auto size : {40u,445u,136u}) {
        if (!transcript->append(std::span{flight}.subspan(pos,size))) return 10; pos+=size;
    }
    t::ClientFinished rfc(c::Hash::sha256,std::move(*transcript),
        t::Secret(hex("b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21")),
        t::Secret(hex("b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38")));
    if (!rfc.verify_server(std::span{flight}.subspan(pos))) return 11;
    auto client_finished=rfc.make_client();
    if (!client_finished || *client_finished!=hex("14000020a8ec436d677634ae525ac1fcebe11a039ec17694fac6e98527b642f2edd5ce61")) return 12;
    for (auto alg:{c::Hash::sha256,c::Hash::sha384}) {
        auto len=alg==c::Hash::sha256?32u:48u;
        auto server=hex(alg==c::Hash::sha256 ? "07198a08cb96a8c0c2596a59f3b9a0a957b49ae3cda57eebba01ccae5a7347d7" : "4a0d791a23c86456615920dbcbdcc18fb6ea00f02eb9667946e0a4b9adeaa203e13db37034d3262acf6c9efe306d36bb");
        auto expected_client=hex(alg==c::Hash::sha256 ? "a9b309b1ec066f653b06c7f867288d2e745ea3999651e0d9540b71c84e255e5d" : "671665fc27ed8797b63a5c0b5f5e880301ee4f4bea9c89a3b1b544d48239df32c164019c21d4299fccf71f53be531d5c");
        auto expected_hash=hex(alg==c::Hash::sha256 ? "9a56c9dd039f03bbd6b1d7e353de3c217fc35b6fc9c9e035dd7208e4262041ce" : "0ef69672d1453a94394aaf70d8de6ef2161bce2ba4a580e31055105385c1f97ba1af3f2564dfc735026e9787abaca246");
        c::Bytes wire{20,0,0,static_cast<std::uint8_t>(len)}; wire.insert(wire.end(),server.begin(),server.end());
        auto state=make(alg); if (state.make_client().error()!=t::FinishedError::invalid_state) return 1;
        if (!state.verify_server(wire) || state.verify_server(wire).error()!=t::FinishedError::invalid_state) return 2;
        auto response=state.make_client(); if (!response || response->size()!=len+4 || !std::ranges::equal(std::span{*response}.subspan(4),expected_client)) return 3;
        auto digest=state.transcript_hash(); if (!digest || *digest!=expected_hash || state.make_client().error()!=t::FinishedError::invalid_state) return 4;
        auto bad=make(alg); wire.back()^=1; if (bad.verify_server(wire).error()!=t::FinishedError::verification_failed || bad.verify_server(wire).error()!=t::FinishedError::invalid_state || bad.transcript_hash().error()!=t::FinishedError::invalid_state) return 5;
        auto malformed=make(alg); wire.pop_back(); if (malformed.verify_server(wire).error()!=t::FinishedError::malformed_message || malformed.make_client().error()!=t::FinishedError::invalid_state) return 6;
        auto before=make(alg); auto after=std::move(before); if (before.transcript_hash().error()!=t::FinishedError::invalid_state || !after.transcript_hash()) return 7;
    }
    std::cout << "TLS Finished SHA-256/384 verification, ordering and transcript passed\n";
}
