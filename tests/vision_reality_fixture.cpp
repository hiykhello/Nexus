#include <boost/corosio/backend.hpp>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
import std;
import tls.client_handshake_io;
import reality.client;
import tls.corosio_client;
import vless;
import vision;
import vless.vision_client;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;
namespace t=tls; namespace v=vless; namespace io=nex::corosio; namespace capy=nex::capy;
using namespace std::chrono_literals;
using Relay=v::detail::VisionRelay<io::tcp_socket,io::tcp_socket>;
struct RelayState { Relay& relay; capy::async_event done; unsigned pending=2; bool up=false,down=false;
    void finish(bool ok,bool upload) { if (upload) up=ok; else down=ok; if (--pending==0) done.set(); }
};
auto upload(RelayState& state) -> capy::task<> { auto ok=co_await state.relay.upload(); state.finish(ok,true); }
auto download(RelayState& state) -> capy::task<> { auto ok=co_await state.relay.download(); state.finish(ok,false); }
auto run(io::io_context& context,io::tcp_socket& socket,io::tcp_socket* local,t::ClientHandshakeIo handshake,std::uint16_t port,std::uint16_t target,int& result) -> capy::task<> {
    auto [error]=co_await socket.connect(io::endpoint(io::ipv4_address::loopback(),port)); if (error) { result=2; co_return; }
    t::detail::ClientConnection connection(socket,std::move(handshake)); auto ready=co_await connection.start(); if (!ready) { result=3; co_return; }
    v::TcpRequest request; std::iota(request.user.begin(),request.user.end(),std::uint8_t{0}); request.port=target; request.address={127,0,0,1};
    v::detail::VisionClient client(socket,*connection.application(),request.user);
    if (!co_await client.start(request)) { result=4; co_return; }
    if (local) {
        Relay relay(*local,client); RelayState state{relay};
        capy::run_async(context.get_executor())(upload(state)); capy::run_async(context.get_executor())(download(state));
        (void)co_await state.done.wait();
        std::cerr << "send_direct=" << (client.send_status()==vision::SendStatus::direct) << " receive_direct=" << client.receive_direct() << " up=" << state.up << " down=" << state.down << "\n";
        result=state.up && state.down ? 0 : 11; co_return;
    }
    std::string payload="Vision Reality bidirectional payload";
    auto bytes=std::span(reinterpret_cast<std::uint8_t const*>(payload.data()),payload.size());
    if (!co_await client.write(bytes)) { result=5; co_return; }
    std::vector<std::uint8_t> received; std::array<std::uint8_t,64> buffer{};
    while (received.size()<payload.size()) {
        auto n=co_await client.read(buffer); if (!n || !*n) { result=6; co_return; }
        received.insert(received.end(),buffer.begin(),buffer.begin()+*n);
    }
    if (!std::ranges::equal(received,bytes)) { result=7; co_return; }
    if (!co_await client.close_output()) { result=8; co_return; }
    result=0;
}
int main(int argc,char** argv) {
    if (argc!=4 && argc!=5) return 1; auto port=std::strtoul(argv[1],nullptr,10),target=std::strtoul(argv[3],nullptr,10); if (!port || port>65535 || !target || target>65535) return 1;
    std::string_view hex=argv[2]; if (hex.size()!=64) return 1; std::array<std::uint8_t,32> pub{};
    auto nib=[](char c)->int { if(c>='0'&&c<='9') return c-'0'; if(c>='a'&&c<='f') return c-'a'+10; return -1; };
    for (std::size_t i=0;i<32;++i) { auto a=nib(hex[i*2]),b=nib(hex[i*2+1]); if(a<0 || b<0) return 1; pub[i]=a*16+b; }
    std::array<std::uint16_t,1> groups{0x001d}; auto hello=t::make_client_hello("cover.example",{},groups); if (!hello) return 1;
    auto seconds=std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    reality::Identity identity{{1,8,24},static_cast<std::uint32_t>(seconds),{0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef}};
    auto session=reality::create_client_session(std::move(*hello),pub,identity); if (!session) return 1;
    auto now=std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count();
    auto handshake=t::ClientHandshakeIo::create(std::move(*session),now,now+10000); if (!handshake) return 1;
    io::io_context context(io::epoll); io::tcp_socket socket(context),local(context); int result=9;
    if (argc==5) { auto fd=::accept(std::atoi(argv[4]),nullptr,nullptr); if (fd<0 || fcntl(fd,F_SETFL,fcntl(fd,F_GETFL,0)|O_NONBLOCK)<0 || local.assign(fd)) return 1; }
    capy::run_async(context.get_executor())(run(context,socket,argc==5 ? &local : nullptr,std::move(*handshake),port,target,result)); context.restart(); (void)context.run_for(20s);
    if (!context.stopped()) { socket.cancel(); local.cancel(); context.restart(); (void)context.run_for(1s); if (!context.stopped()) std::_Exit(10); return 10; }
    return result;
}
