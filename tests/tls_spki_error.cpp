import std;
import nexus.thirdparty.boringssl;
namespace b=nex::boringssl;
auto read(char const* path) -> std::vector<std::uint8_t> {std::ifstream input(path,std::ios::binary);return {std::istreambuf_iterator<char>(input),{}};}
int main(int argc,char** argv) {
    if(argc!=2)return 1;
    auto der=read(argv[1]);
    constexpr std::array<std::uint8_t,11> rsa_oid{6,9,0x2a,0x86,0x48,0x86,0xf7,0x0d,1,1,1};
    auto found=std::search(der.begin(),der.end(),rsa_oid.begin(),rsa_oid.end());if(found==der.end())return 2;
    auto unknown=der;auto offset=static_cast<std::size_t>(found-der.begin());unknown[offset+10]=0x7f;
    for(bool unsupported:{false,true}) {
        auto const& bytes=unsupported ? unknown : der;auto cursor=static_cast<std::uint8_t const*>(bytes.data());
        b::ERR_clear_error();auto cert=std::unique_ptr<b::X509,decltype(&b::X509_free)>(b::d2i_X509(nullptr,&cursor,bytes.size()),&b::X509_free);
        if(!cert||cursor!=bytes.data()+bytes.size())return 3;
        auto key=std::unique_ptr<b::EVP_PKEY,decltype(&b::EVP_PKEY_free)>(b::X509_get_pubkey(cert.get()),&b::EVP_PKEY_free);
        if(bool(key)==unsupported)return 4;
        while(auto error=b::ERR_get_error())if(b::error_is_allocation_failure(error))return 5;
    }
    for(auto size:{0u,1u,2u,10u}) {
        auto bytes=std::span(der).first(std::min<std::size_t>(size,der.size()));auto cursor=static_cast<std::uint8_t const*>(bytes.data());
        b::ERR_clear_error();auto* cert=b::d2i_X509(nullptr,&cursor,bytes.size());if(cert){b::X509_free(cert);return 6;}
        while(auto error=b::ERR_get_error())if(b::error_is_allocation_failure(error))return 7;
    }
    std::println("valid RSA parsed; unknown SPKI still syntactically accepted with no EVP key; malformed DER rejected and no false native allocation errors passed");
}
