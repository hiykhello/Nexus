import std;
import nexus.tls.hello;
namespace t=nexus::tls;
auto hex(std::string_view s) -> std::vector<std::uint8_t> { auto n=[](char c){ return c<='9' ? c-'0' : c-'a'+10; }; std::vector<std::uint8_t> r; for (std::size_t i=0;i<s.size();i+=2) r.push_back(static_cast<std::uint8_t>((n(s[i])<<4)|n(s[i+1]))); return r; }
int main() {
    auto rfc = hex("0303cb34ecb1e78163ba1c38c6dacb196a6dffa21a8d9912ec18a2ef6283024dece7000006130113031302010000910000000b0009000006736572766572ff01000100000a00140012001d0017001800190100010101020103010400230000003300260024001d002099381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c002b0003020304000d0020001e040305030603020308040805080604010501060102010402050206020202002d00020101001c00024001");
    auto rfc_hello=t::ClientHello::parse(rfc); if (!rfc_hello || !rfc_hello->validate_tls13() || rfc_hello->cipher_suites.size()!=3 || !rfc_hello->extension(51)) return 1;
    t::ClientHello hello; hello.random.fill(0x42); hello.session_id={1,2,3}; hello.cipher_suites={0x1301,0x1302}; hello.compression_methods={0}; hello.extensions={{43,{2,3,4}},{16,{'h','2',' ', 'h','1'}}};
    auto encoded=hello.encode(); if (!encoded) return 1; auto parsed=t::ClientHello::parse(*encoded); if (!parsed || *parsed!=hello || !parsed->validate_tls13() || !parsed->extension(16) || parsed->extension(99)) return 2;
    auto reencoded=parsed->encode(); if (!reencoded || *reencoded!=*encoded) return 3;
    auto no_tls=hello; no_tls.extensions[0].data={2,3,3}; if (no_tls.validate_tls13() || t::ClientHello::parse(*no_tls.encode()).value().validate_tls13()) return 4;
    auto duplicate=hello; duplicate.extensions.push_back({43,{2,3,4}}); if (duplicate.encode().error()!=t::HelloError::duplicate_extension) return 5;
    auto bad_version=hello; bad_version.legacy_version=0x0301; if (bad_version.encode().error()!=t::HelloError::invalid_version) return 6;
    auto bad_sid=hello; bad_sid.session_id.resize(33); if (bad_sid.encode().error()!=t::HelloError::invalid_session_id) return 7;
    auto bad_suite=hello; bad_suite.cipher_suites.clear(); if (bad_suite.encode().error()!=t::HelloError::invalid_cipher_suites) return 8;
    auto extra_compression=hello; extra_compression.compression_methods={0,1}; if (extra_compression.validate_tls13().error()!=t::HelloError::invalid_compression) return 13;
    auto bad_compression=hello; bad_compression.compression_methods={1}; if (bad_compression.encode().error()!=t::HelloError::invalid_compression) return 9;
    auto truncated=*encoded; truncated.pop_back(); if (t::ClientHello::parse(truncated).error()!=t::HelloError::truncated) return 10;
    auto malformed=*encoded; malformed[34]=33; if (t::ClientHello::parse(malformed).error()!=t::HelloError::truncated) return 11;
    auto malformed_ext=*encoded; auto ext_len=static_cast<std::size_t>(malformed_ext[malformed_ext.size()-1]); (void)ext_len; malformed_ext.pop_back(); if (t::ClientHello::parse(malformed_ext).error()!=t::HelloError::truncated) return 12;
    std::cout << "TLS ClientHello encoding and validation passed\n";
}
