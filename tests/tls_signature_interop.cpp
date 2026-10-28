import std;
import nexus.tls.certificate_verify;
namespace t=nexus::tls; using Bytes=std::vector<std::uint8_t>;
auto read(char const* file) -> Bytes { std::ifstream f(file,std::ios::binary); return Bytes(std::istreambuf_iterator<char>(f),{}); }
int main(int argc,char** argv) {
    if (argc!=4) return 1; auto cert=read(argv[1]), sig=read(argv[2]); if (cert.empty() || sig.empty() || sig.size()>65535) return 2;
    auto scheme=std::string_view(argv[3])=="ecdsa" ? std::uint16_t{0x0403} : std::uint16_t{0x0807};
    Bytes message{15,0,0,0,static_cast<std::uint8_t>(scheme>>8),static_cast<std::uint8_t>(scheme),static_cast<std::uint8_t>(sig.size()>>8),static_cast<std::uint8_t>(sig.size())};
    message.insert(message.end(),sig.begin(),sig.end()); auto length=message.size()-4; message[1]=static_cast<std::uint8_t>(length>>16); message[2]=static_cast<std::uint8_t>(length>>8); message[3]=static_cast<std::uint8_t>(length);
    Bytes digest(32,0x42); std::array<std::uint16_t,1> offered{scheme};
    auto check=[&](auto hash,auto schemes,auto msg) { return t::verify_server_certificate_signature(cert,nexus::crypto::Hash::sha256,hash,schemes,msg); };
    if (!check(digest,offered,message)) return 3;
    auto altered=message; altered.back()^=1; if (check(digest,offered,altered).error()!=t::CertificateVerifyError::invalid_signature) return 4;
    auto wrong_hash=digest; wrong_hash[0]^=1; if (check(wrong_hash,offered,message).error()!=t::CertificateVerifyError::invalid_signature) return 5;
    if (check(digest,std::span<std::uint16_t const>{},message).error()!=t::CertificateVerifyError::unoffered_scheme) return 6;
    auto wrong_scheme=message; wrong_scheme[4]=scheme==0x0403 ? 8 : 4; wrong_scheme[5]=scheme==0x0403 ? 7 : 3;
    std::array<std::uint16_t,1> wrong_offer{static_cast<std::uint16_t>((wrong_scheme[4]<<8)|wrong_scheme[5])};
    if (check(digest,wrong_offer,wrong_scheme).error()!=t::CertificateVerifyError::invalid_certificate) return 7;
    std::cout << argv[3] << " signature verification and rejection passed\n";
}
