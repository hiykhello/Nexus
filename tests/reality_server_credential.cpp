import std;
import reality.auth;
import reality.server_credential;
import tls.server_credential;
import tls.certificate_verify;
namespace c = ::crypto; namespace r=reality; namespace t=tls;
auto read(char const* path) -> c::Bytes { std::ifstream file(path,std::ios::binary); return {std::istreambuf_iterator<char>(file),std::istreambuf_iterator<char>()}; }
int main(int argc,char** argv) {
    if (argc!=4) return 1;
    auto cert=read(argv[1]),key=read(argv[2]),wrong=read(argv[3]);
    std::array<std::uint8_t,32> a{},b{},random{}; a[0]=3; b[0]=4;
    auto one=c::X25519Private::from_bytes(a),two=c::X25519Private::from_bytes(b);
    if (!one || !two) return 2; auto peer=two->public_key(); if (!peer) return 3;
    auto auth=r::AuthKey::derive(*one,*peer,random); if (!auth) return 4;
    auto credential=r::make_server_credential(*auth,cert,key);
    if (!credential || !auth->verify_certificate(credential->certificate())) return 5;
    std::array<std::uint8_t,32> digest{}; digest[0]=42; auto signature=credential->sign(c::Hash::sha256,digest);
    constexpr std::array<std::uint16_t,1> schemes{0x0807};
    if (!signature || !t::verify_server_certificate_signature(credential->certificate(),c::Hash::sha256,digest,schemes,*signature)) return 6;
    auto clone=credential->clone(); if (!clone || !auth->verify_certificate(clone->certificate())) return 7;
    if (r::make_server_credential(*auth,cert,wrong)) return 8;
    cert.pop_back(); if (r::make_server_credential(*auth,cert,key)) return 9;
    auto generated=t::ServerCredential::generate_ed25519(),other=t::ServerCredential::generate_ed25519();
    if (!generated || !other || generated->scheme()!=0x0807 || generated->with_certificate(other->certificate())) return 11;
    auto dynamic=r::make_server_credential(*auth,*generated);
    if (!dynamic || !auth->verify_certificate(dynamic->certificate())) return 12;
    auto dynamic_signature=dynamic->sign(c::Hash::sha256,digest);
    if (!dynamic_signature || !t::verify_server_certificate_signature(dynamic->certificate(),c::Hash::sha256,digest,schemes,*dynamic_signature)) return 13;
    auto moved=std::move(*auth); if (r::make_server_credential(*auth,cert,key)) return 10;
    std::println("Reality certificate HMAC and TLS CertificateVerify passed");
}
