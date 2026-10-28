import std;
import nexus.tls.certificate_verify;
import nexus.tls.transcript;
import nexus.tls.finished;
#include "support/rfc8448_server_flight.hpp"
namespace t=nexus::tls; namespace c=nexus::crypto;
auto hex(std::string_view s) -> c::Bytes { auto n=[](char x){return x<='9'?x-'0':x-'a'+10;}; c::Bytes b; for (std::size_t i=0;i<s.size();i+=2) b.push_back(static_cast<std::uint8_t>((n(s[i])<<4)|n(s[i+1]))); return b; }
int main() {
    auto client_wire=hex("010000c00303cb34ecb1e78163ba1c38c6dacb196a6dffa21a8d9912ec18a2ef6283024dece7000006130113031302010000910000000b0009000006736572766572ff01000100000a00140012001d0017001800190100010101020103010400230000003300260024001d002099381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c002b0003020304000d0020001e040305030603020308040805080604010501060102010402050206020202002d00020101001c00024001");
    auto server_wire=hex("020000560303a6af06a4121860dc5e6e60249cd34c95930c8ac5cb1434dac155772ed3e2692800130100002e00330024001d0020c9828876112095fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f002b00020304");
    auto flight=hex(rfc8448_server_flight); if (flight.size()!=657) return 1;
    auto transcript=t::Transcript::create(c::Hash::sha256);
    if (!transcript || !transcript->append(client_wire) || !transcript->append(server_wire) ||
        !transcript->append(std::span{flight}.first(40)) || !transcript->append(std::span{flight}.subspan(40,445))) return 2;
    auto hash=transcript->snapshot(); if (!hash) return 3;
    auto cert=std::span{flight}.subspan(51,432); auto message=std::span{flight}.subspan(485,136); std::array<std::uint16_t,1> offered{0x0804};
    if (!t::verify_server_certificate_signature(cert,c::Hash::sha256,*hash,offered,message)) return 4;
    if (!transcript->append(message)) return 13;
    t::ClientFinished finished(c::Hash::sha256,std::move(*transcript),
        t::Secret(hex("b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21")),
        t::Secret(hex("b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38")));
    if (!finished.verify_server(std::span{flight}.subspan(621,36))) return 14;
    auto client_finished=finished.make_client();
    if (!client_finished || *client_finished!=hex("14000020a8ec436d677634ae525ac1fcebe11a039ec17694fac6e98527b642f2edd5ce61")) return 15;
    auto bad=c::Bytes(message.begin(),message.end()); bad.back()^=1;
    if (t::verify_server_certificate_signature(cert,c::Hash::sha256,*hash,offered,bad).error()!=t::CertificateVerifyError::invalid_signature) return 5;
    auto altered=*hash; altered[0]^=1;
    if (t::verify_server_certificate_signature(cert,c::Hash::sha256,altered,offered,message).error()!=t::CertificateVerifyError::invalid_signature) return 6;
    if (t::verify_server_certificate_signature(cert,c::Hash::sha256,*hash,std::span<std::uint16_t const>{},message).error()!=t::CertificateVerifyError::unoffered_scheme) return 7;
    if (t::verify_server_certificate_signature(cert.first(cert.size()-1),c::Hash::sha256,*hash,offered,message).error()!=t::CertificateVerifyError::invalid_certificate) return 8;
    c::Bytes trailing(cert.begin(),cert.end()); trailing.push_back(0);
    if (t::verify_server_certificate_signature(trailing,c::Hash::sha256,*hash,offered,message).error()!=t::CertificateVerifyError::invalid_certificate) return 9;
    bad=c::Bytes(message.begin(),message.end()); bad[5]=5;
    if (t::verify_server_certificate_signature(cert,c::Hash::sha256,*hash,offered,bad).error()!=t::CertificateVerifyError::unsupported_scheme) return 10;
    if (t::verify_server_certificate_signature(cert,c::Hash::sha384,*hash,offered,message).error()!=t::CertificateVerifyError::invalid_transcript) return 11;
    if (t::verify_server_certificate_signature(cert,c::Hash::sha256,*hash,offered,message.first(message.size()-1)).error()!=t::CertificateVerifyError::invalid_message) return 12;
    std::cout << "TLS CertificateVerify RFC 8448 RSA-PSS signature passed\n";
}
