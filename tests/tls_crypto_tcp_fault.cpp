import std;
import tls.profiles;
import tls.fingerprint;
import tls.client_handshake_io;
import tls.server_handshake_io;
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


namespace t=tls;namespace c = ::crypto;
auto read(char const* path) -> c::Bytes {std::ifstream input(path,std::ios::binary);return {std::istreambuf_iterator<char>(input),{}};}
struct Trial {bool complete=false,clean=false,denied=false,local_error=true;std::size_t calls=0;};
auto attempt(c::Bytes const& cert,c::Bytes const& key,t::ClientProfile const& profile,std::uint16_t scheme,std::uint16_t group,bool retry,unsigned cipher,std::ptrdiff_t allowance,bool single) -> Trial {
    auto before=native::live,bytes=native::bytes;Trial result;
    {
        auto credential=t::ServerCredential::create(cert,key);if(!credential)return {};
        t::FingerprintConfig config;config.group_count=1;config.group_order[0]=group;config.key_share_groups[0]=group;config.key_share_count=retry ? 0 : 1;
        config.cipher_count=1;config.cipher_order[0]=cipher;config.signature_count=1;config.signature_order[0]=scheme;
        auto now=std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
        auto client=profile.handshake(0,1000,now,config);auto server=t::ServerHandshakeIo::create(std::move(*credential),0,1000,"h3");if(!client||!server)return {};
        native::enabled=true;native::single=single;native::denied=false;native::calls=0;native::allowance=allowance;
        bool failed=false;
        auto transfer=[&](auto& from,auto& to,bool to_server) {
            auto pending=from.pending_output();if(pending.empty())return true;
            auto data=pending.first(std::min<std::size_t>(13,pending.size()));auto received=to.feed(data,1);
            if(!received) {
                if constexpr (std::same_as<std::remove_cvref_t<decltype(to)>,t::ServerHandshakeIo>) result.local_error&=received.error()==t::ServerHandshakeIoError::crypto_error;
                else result.local_error&=received.error()==t::ClientHandshakeIoError::crypto_error;
                (void)to_server;failed=true;return false;
            }
            if(!received->consumed||!from.written(received->consumed,1)){failed=true;result.local_error=false;return false;}
            return true;
        };
        for(unsigned round=0;round<10000&&!failed&&(!client->complete()||!server->complete());++round) {
            if(!server->pending_output().empty())transfer(*server,*client,false);
            else if(!client->pending_output().empty())transfer(*client,*server,true);
            else {failed=true;result.local_error=false;}
        }
        result.complete=client->complete()&&server->complete();result.denied=native::denied;result.calls=native::calls;native::enabled=false;
    }
    nex::boringssl::ERR_clear_error();result.clean=native::live==before&&native::bytes==bytes;return result;
}
int main(int argc,char** argv) {
    if(argc!=6)return 1;
    auto cert=read(argv[1]),key=read(argv[2]);auto scheme=static_cast<std::uint16_t>(std::stoul(argv[4],nullptr,0));
    std::array<std::string_view,1> alpn{"h3"};auto profile=t::ClientProfile::load("server.example",argv[5],29,false,alpn);if(!profile)return 2;
    unsigned failures=0,recovered=0;
    for(auto group:{23,24,25,29,4588})for(bool retry:{false,true})for(auto cipher:{0x1301u,0x1302u,0x1303u})for(bool single:{false,true}) {
        auto baseline=attempt(cert,key,*profile,scheme,group,retry,cipher,-1,single);if(!baseline.complete||!baseline.clean)return 3;
        for(std::size_t point=0;point<=baseline.calls;++point) {
            auto result=attempt(cert,key,*profile,scheme,group,retry,cipher,point,single);
            if(!result.clean||(!result.complete&&!result.local_error)||(!result.denied&&!result.complete)) {
                std::println("TCP native error group={} retry={} cipher={:04x} single={} point={}/{} complete={} local={} clean={} denied={}",group,retry,cipher,single,point,baseline.calls,result.complete,result.local_error,result.clean,result.denied);return 4;
            }
            if(result.denied) {++failures;if(result.complete)++recovered;}
            auto next=attempt(cert,key,*profile,scheme,group,retry,cipher,-1,single);if(!next.complete||!next.clean)return 5;
        }
        std::println("TCP group={} retry={} cipher={:04x} single={} native={} crypto-error retention, livebyte cleanup and authenticated next-owner recovery passed",group,retry,cipher,single,baseline.calls);
    }
    c::cleanse(key);std::println("TCP real native failures={} recoveredoptional={} passed",failures,recovered);
}
