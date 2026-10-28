import std;
import nexus.tls.encrypted_extensions;
import nexus.tls.transcript;
#include "support/rfc8448_server_flight.hpp"
namespace t=nexus::tls; using Bytes=std::vector<std::uint8_t>;
auto hex(std::string_view s) -> Bytes { auto n=[](char c){return c<='9'?c-'0':c-'a'+10;}; Bytes b; for (std::size_t i=0;i<s.size();i+=2) b.push_back(static_cast<std::uint8_t>((n(s[i])<<4)|n(s[i+1]))); return b; }
auto message(Bytes const& ext) -> Bytes { auto len=ext.size(); Bytes b{8,0,static_cast<std::uint8_t>((len+2)>>8),static_cast<std::uint8_t>(len+2),static_cast<std::uint8_t>(len>>8),static_cast<std::uint8_t>(len)}; b.insert(b.end(),ext.begin(),ext.end()); return b; }
int main() {
    t::ClientHello c; c.extensions={{10,{0,2,0,29}},{28,{0x40,1}},{0,{0,0}},{16,{0,12,2,'h','2',8,'h','t','t','p','/','1','.','1'}}};
    auto flight=hex(rfc8448_server_flight); auto r=t::validate_encrypted_extensions(c,std::span{flight}.first(40));
    if (!r || r->peer_groups.size()!=9 || r->peer_record_size_limit!=16385) return 1;
    auto ext=Bytes{0,0,0,0,0,16,0,5,0,3,2,'h','2'}; auto wire=message(ext);
    auto a=t::validate_encrypted_extensions(c,wire);
    if (!a || !a->server_name_acknowledged || !a->alpn || *a->alpn!=Bytes{'h','2'}) return 2;
    auto tr=t::Transcript::create(nexus::crypto::Hash::sha256); if (!tr || !tr->append(wire)) return 3;
    auto bad=wire; bad.back()='3'; auto err=t::validate_encrypted_extensions(c,bad);
    if (err || err.error()!=t::EncryptedExtensionsError::invalid_selection) return 4;
    bad=message(Bytes{0,16,0,5,0,3,2,'h','2',0,16,0,5,0,3,2,'h','2'});
    if (t::validate_encrypted_extensions(c,bad).error()!=t::EncryptedExtensionsError::duplicate) return 5;
    t::ClientHello none; if (t::validate_encrypted_extensions(none,wire).error()!=t::EncryptedExtensionsError::unoffered) return 6;
    bad=message(Bytes{0,28,0,2,0,63}); if (t::validate_encrypted_extensions(c,bad).error()!=t::EncryptedExtensionsError::malformed) return 7;
    bad=message(Bytes{0,28,0,2,0x40,2}); if (t::validate_encrypted_extensions(c,bad).error()!=t::EncryptedExtensionsError::malformed) return 8;
    bad=message(Bytes{0,10,0,3,0,1,0}); if (t::validate_encrypted_extensions(c,bad).error()!=t::EncryptedExtensionsError::malformed) return 9;
    bad=wire; bad.pop_back(); if (t::validate_encrypted_extensions(c,bad).error()!=t::EncryptedExtensionsError::malformed) return 10;
    c.extensions.push_back({42,{}}); bad=message(Bytes{0,42,0,0}); if (t::validate_encrypted_extensions(c,bad).error()!=t::EncryptedExtensionsError::unsupported) return 11;
    if (!t::validate_encrypted_extensions(c,message({}))) return 12;
    std::cout << "TLS EncryptedExtensions negotiation passed\n";
}
