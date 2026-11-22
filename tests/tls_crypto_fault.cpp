import std;
import tls.certificate_trust;
import tls.server_credential;
import tls.certificate_verify;
namespace native {
    struct alignas(std::max_align_t) Header { std::size_t size; };
    bool enabled=false,denied=false,single=false;
    std::ptrdiff_t allowance=-1;
    std::size_t calls=0,live=0,bytes=0;
}
// Fixed BoringSSL mem.cc's native allocator hook, not a C++ allocation shim.
extern "C" auto OPENSSL_memory_alloc(std::size_t size) noexcept -> void* {
    if (native::enabled) { ++native::calls; if (!native::allowance) {native::denied=true;if(native::single)native::allowance=-1;return nullptr;} if(native::allowance>0)--native::allowance; }
    if(size>std::numeric_limits<std::size_t>::max()-sizeof(native::Header))return nullptr;
    auto* block=static_cast<native::Header*>(std::malloc(sizeof(native::Header)+size));if(!block)return nullptr;
    block->size=size;++native::live;native::bytes+=size;return block+1;
}
extern "C" auto OPENSSL_memory_free(void* pointer) noexcept -> void {
    if(!pointer)return;
    auto* block=static_cast<native::Header*>(pointer)-1;auto size=block->size;
    native::bytes-=size;--native::live;
    auto* byte=reinterpret_cast<volatile unsigned char*>(block);
    for(std::size_t i=0;i<sizeof(native::Header)+size;++i)byte[i]=0;
    std::free(block);
}
extern "C" auto OPENSSL_memory_get_size(void* pointer) noexcept -> std::size_t {
    return (static_cast<native::Header*>(pointer)-1)->size;
}

namespace t=tls; namespace c = ::crypto;
auto read(char const* path) -> c::Bytes {std::ifstream input(path,std::ios::binary);return {std::istreambuf_iterator<char>(input),{}};}
int main(int argc,char** argv) {
    if(argc!=6)return 1;
    auto cert=read(argv[1]),key=read(argv[2]),anchor=read(argv[3]);auto scheme=static_cast<std::uint16_t>(std::stoul(argv[4],nullptr,0));
    auto transcript=c::Bytes(32,0x42);c::Bytes signature;
    {auto credential=t::ServerCredential::create(cert,key);if(!credential)return 2;auto signed_message=credential->sign(scheme,c::Hash::sha256,transcript);if(!signed_message)return 3;signature=std::move(*signed_message);}
    c::cleanse(key);
    std::array<std::span<std::uint8_t const>,1> chain{cert},anchors{anchor};
    auto name=std::string_view("server.example");auto now=std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    std::array<std::uint16_t,1> offered{scheme};
    auto trust=[&] {return t::verify_server_certificate_chain(chain,anchors,t::PeerNameKind::dns,{reinterpret_cast<std::uint8_t const*>(name.data()),name.size()},now);};
    auto verify=[&] {return t::verify_server_certificate_signature(cert,c::Hash::sha256,transcript,offered,signature);};
    if(!trust()||!verify())return 4;
    std::array<unsigned,2> failures{},retained{};
    for(bool single:{false,true})for(unsigned stage:{0u,1u}) {
        auto before=native::live,bytes=native::bytes;native::calls=0;native::denied=false;native::allowance=-1;native::single=single;native::enabled=true;
        bool ok=stage==0 ? trust().has_value() : verify().has_value();native::enabled=false;auto count=native::calls;if(!ok||!count)return 5;
        for(std::size_t point=0;point<=count;++point) {
            native::calls=0;native::denied=false;native::allowance=point;native::enabled=true;bool complete=false,crypto_error=false;
            if(stage==0) {auto result=trust();complete=result.has_value();crypto_error=!result&&result.error()==t::CertificateTrustError::crypto_error;}
            else {auto result=verify();complete=result.has_value();crypto_error=!result&&result.error()==t::CertificateVerifyError::crypto_error;}
            native::enabled=false;
            if(native::live!=before||native::bytes!=bytes||(!complete&&!crypto_error)||(!native::denied&&!complete)) {
                std::println("local fault stage={} single={} point={}/{} ok={} crypto={} denied={} live={}/{} bytes={}/{}",stage,single,point,count,complete,crypto_error,native::denied,native::live,before,native::bytes,bytes);return 6;
            }
            if(native::denied) {++failures[single];if(crypto_error)++retained[single];}
            if(!trust()||!verify()||native::live!=before||native::bytes!=bytes)return 7;
        }
        std::println("stage={} single={} native faults={} passed",stage,single,count);
    }
    std::println("native crypto persistent={} single={} local errors={}/{} all owner/livebyte cleanup and next-owner auth recovery passed",failures[0],failures[1],retained[0],retained[1]);
}
