import std;
import tls.profiles;
import tls.fingerprint;
import tls.client_handshake_io;
import tls.server_handshake_io;
import tls.corosio_client;
import tls.corosio_server_handshake;
import capy;
import corosio;
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


namespace t=tls;namespace c = ::crypto;namespace io = ::corosio;
using namespace std::chrono_literals;
auto read(char const* path) -> c::Bytes {std::ifstream input(path,std::ios::binary);return {std::istreambuf_iterator<char>(input),{}};}
struct FaultSocket {
    io::local_stream_socket& socket;bool arm=false,single=false;
    auto read_some(capy::mutable_buffer buffer) -> capy::task<capy::results<std::size_t>> {
        auto result=co_await socket.read_some(buffer);
        if(arm&&!std::get<0>(result)&&std::get<1>(result)) {arm=false;native::enabled=true;native::single=single;native::allowance=0;native::denied=false;}
        co_return result;
    }
    auto write_some(capy::const_buffer buffer) {return socket.write_some(buffer);}
    auto cancel() {socket.cancel();}
};
struct Results {bool client=false,server=false,caught=false,denied=false;std::optional<t::detail::AsyncHandshakeError> ce;std::optional<t::detail::ServerAsyncError> se;};
auto client_run(FaultSocket& socket,t::ClientHandshakeIo& handshake,Results& result) -> capy::task<> {
    try {auto value=co_await t::detail::corosio_handshake(socket,handshake);result.client=bool(value);if(!value)result.ce=value.error();}
    catch(...) {result.caught=true;}
    result.denied|=native::denied;native::enabled=false;socket.socket.close();
}
auto server_run(FaultSocket& socket,t::ServerHandshakeIo& handshake,Results& result) -> capy::task<> {
    try {auto value=co_await t::detail::server_handshake(socket,handshake);result.server=bool(value);if(!value)result.se=value.error();}
    catch(...) {result.caught=true;}
    result.denied|=native::denied;native::enabled=false;socket.socket.close();
}
auto trial(io::io_context& context,c::Bytes const& cert,c::Bytes const& key,t::ClientProfile const& profile,int fail,bool single) -> bool {
    auto before=native::live,bytes=native::bytes;bool valid=false;
    {
        io::local_stream_socket client{context},server{context};if(io::connect_pair(client,server))return false;
        auto now=std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count();
        auto wall=std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
        auto ch=profile.handshake(now,now+5000,wall);auto credential=t::ServerCredential::create(cert,key);
        if(!ch||!credential)return false;
        auto sh=t::ServerHandshakeIo::create(std::move(*credential),now,now+5000,"h3");if(!sh)return false;
        FaultSocket cs{client,fail==1,single},ss{server,fail==2,single};Results result;native::denied=false;
        capy::run_async(context.get_executor())(client_run(cs,*ch,result));
        capy::run_async(context.get_executor())(server_run(ss,*sh,result));
        context.restart();context.run();
        valid=!result.caught&&context.stopped()&&
            (fail==0 ? result.client&&result.server : result.denied&&
                (fail==1 ? result.ce==t::detail::AsyncHandshakeError::crypto : result.se==t::detail::ServerAsyncError::crypto));
        if(!valid)std::println("async failure side={} single={} denied={} client={} server={} ce={} se={} caught={}",fail,single,result.denied,result.client,result.server,result.ce ? int(*result.ce) : -1,result.se ? int(*result.se) : -1,result.caught);
    }
    boringssl::ERR_clear_error();
    return valid&&native::live==before&&native::bytes==bytes;
}
int main(int argc,char** argv) {
    if(argc!=6)return 1;auto cert=read(argv[1]),key=read(argv[2]);std::array<std::string_view,1> alpn{"h3"};
    auto profile=t::ClientProfile::load("server.example",argv[5],29,false,alpn);if(!profile)return 2;
    unsigned count=0;
    for(bool uring:{false,true}) {
        auto execute=[&](io::io_context& context) {
            if(!trial(context,cert,key,*profile,0,false))return false;
            for(int side:{1,2})for(bool single:{false,true}) {
                if(!trial(context,cert,key,*profile,side,single)||!trial(context,cert,key,*profile,0,false))return false;
                ++count;
            }
            return true;
        };
        if(uring) {io::io_context context{io::uring};if(!execute(context))return 3;}
        else {io::io_context context{io::epoll};if(!execute(context))return 4;}
    }
    c::cleanse(key);std::println("TCP async crypto-error native client/server single+persistent dual-backend {} faults and authenticated same-context next-owner recovery passed",count);
}
