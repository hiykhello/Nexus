import std;
import crypto;
import net.datagram_driver;
import quic.tls_client;
import quic.tls_server;
import tls.server_credential;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;
import nexus.test.quic_tls_link;
import nexus.test.quic_datagram_link;
namespace io=nex::corosio;
namespace capy=nex::capy;
namespace q=quic;
namespace t=tls;
namespace support=nexus::test::quic_tls;
namespace app=nexus::test::quic_datagram_link;
using namespace std::chrono_literals;
namespace allocations {
    struct Header { void* raw; std::size_t size; };
    std::size_t live=0,bytes=0,calls=0;
    bool enabled=false,denied=false;
    std::ptrdiff_t allowance=-1;
    bool verify_exit=false;
    auto allocate(std::size_t size,std::size_t alignment=alignof(std::max_align_t)) -> void* {
        if (enabled) { ++calls; if (!allowance) { denied=true; throw std::bad_alloc(); } if (allowance>0) --allowance; }
        size=std::max<std::size_t>(size,1); alignment=std::max(alignment,alignof(Header));
        if (size>std::numeric_limits<std::size_t>::max()-alignment-sizeof(Header)) throw std::bad_alloc();
        auto* raw=std::malloc(size+alignment+sizeof(Header)); if (!raw) throw std::bad_alloc();
        auto address=(reinterpret_cast<std::uintptr_t>(raw)+sizeof(Header)+alignment-1)/alignment*alignment;
        auto* out=reinterpret_cast<Header*>(address); out[-1]={raw,size}; ++live; bytes+=size; return out;
    }
    auto release(void* pointer) noexcept -> void {
        if (!pointer) return;
        auto saved=static_cast<Header*>(pointer)[-1]; --live; bytes-=saved.size; std::free(saved.raw);
    }
    struct Final {
        ~Final() {
            if (!verify_exit) return;
            if (live || bytes) { std::println("driver process-exit allocation leak live={} bytes={}",live,bytes); std::fflush(nullptr); std::_Exit(91); }
            std::println("driver process-exit tracked ordinary/array/aligned allocations=0");
        }
    } final;
}
auto operator new(std::size_t size) -> void* { return allocations::allocate(size); }
auto operator new[](std::size_t size) -> void* { return allocations::allocate(size); }
auto operator new(std::size_t size,std::align_val_t alignment) -> void* { return allocations::allocate(size,static_cast<std::size_t>(alignment)); }
auto operator new[](std::size_t size,std::align_val_t alignment) -> void* { return allocations::allocate(size,static_cast<std::size_t>(alignment)); }
auto operator delete(void* pointer) noexcept -> void { allocations::release(pointer); }
auto operator delete[](void* pointer) noexcept -> void { allocations::release(pointer); }
auto operator delete(void* pointer,std::size_t) noexcept -> void { allocations::release(pointer); }
auto operator delete[](void* pointer,std::size_t) noexcept -> void { allocations::release(pointer); }
auto operator delete(void* pointer,std::align_val_t) noexcept -> void { allocations::release(pointer); }
auto operator delete[](void* pointer,std::align_val_t) noexcept -> void { allocations::release(pointer); }
auto operator delete(void* pointer,std::size_t,std::align_val_t) noexcept -> void { allocations::release(pointer); }
auto operator delete[](void* pointer,std::size_t,std::align_val_t) noexcept -> void { allocations::release(pointer); }

auto trial(t::ServerCredential const& credential,std::span<std::uint8_t const> anchor,bool uring,unsigned phase) -> bool {
    auto context=std::unique_ptr<io::io_context>(new io::io_context(io::make_io_context(uring)));
    q::TlsClient client_tls(support::hello(*credential.scheme()),29,support::Pki{anchor},"h3"); q::TlsServer server_tls(credential,"h3");
    using Client=app::Endpoint<decltype(client_tls)>;using Server=app::Endpoint<decltype(server_tls)>;
    std::optional<Client> client;std::optional<Server> server;
    std::optional<typename Client::Driver> client_driver;std::optional<typename Server::Driver> server_driver;
    bool ready=false,done=false,valid=true;
    auto monitor=[&]() -> capy::task<capy::results<>> {
        if (!phase) { auto [error]=co_await io::delay(0ms); if (error) co_return capy::results<>{error}; }
        else while (!server->app.authenticated) { server_driver->changed().clear(); auto [error]=co_await server_driver->changed().wait(); if (error) co_return capy::results<>{error}; }
        ready=true;context->stop(); co_return capy::results<>{};
    };
    auto root=[&]() -> capy::task<> {
        // Corosio I/O objects belong to this root frame and die while their
        // context services are still alive. Protocol owners outlive the root.
        io::udp_socket client_socket(*context),server_socket(*context);
        io::endpoint loopback(io::ipv4_address::loopback(),0);
        if (client_socket.open() || client_socket.bind(loopback) || server_socket.open() || server_socket.bind(loopback)) { valid=false;co_return; }
        client.emplace(client_socket,client_tls,false,server_socket.local_endpoint());server.emplace(server_socket,server_tls,true,client_socket.local_endpoint());
        client->wait_peer_close=true;
        if(client->initialize() || server->initialize()){valid=false;co_return;}
        auto deadline=app::Clock::now()+30s;
        client_driver.emplace(client_socket,*client,deadline);server_driver.emplace(server_socket,*server,deadline);
        client->driver=&*client_driver;server->driver=&*server_driver;
        auto [error,a,b,c]=co_await capy::when_all(client_driver->run(),server_driver->run(),monitor());(void)error;(void)a;(void)b;(void)c;done=true;
    };
    capy::run_async(context->get_executor())(root());context->run_for(2s);
    if (!valid || !ready || done || !client_driver->running() || !server_driver->running()) return false;
    bool authenticated=server->app.authenticated;
    context.reset();
    bool clean=client_driver->drained() && server_driver->drained() && client->clean() && server->clean() && client->app.quic_closed==1 && server->app.quic_closed<=1 && (!phase || server->app.http3_closed==1);
    std::println("driver actual native context abandon backend={} phase={} authenticated={} done={} clientdrained={} serverdrained={} clean={} close={}/{} H3={}/{} QUICbytes={}/{} H3bytes={}/{}",uring,phase,authenticated,done,client_driver->drained(),server_driver->drained(),clean,client->app.quic_closed,server->app.quic_closed,client->app.http3_closed,server->app.http3_closed,client->memory.used,server->memory.used,client->app.memory.used,server->app.memory.used);
    return !done && clean;
}
auto main(int argc,char** argv) -> int {
    if (argc!=3) return 1;
    auto cert=support::read(argv[1]),key=support::read(argv[2]);auto credential=t::ServerCredential::create(cert,key);::crypto::cleanse(key);if(!credential)return 2;
    for(bool uring:{false,true})for(unsigned phase=0;phase<2;++phase)if(!trial(*credential,cert,uring,phase))return 3;
    allocations::verify_exit=true;
}
