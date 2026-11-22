#include <boost/corosio/backend.hpp>
#include <cstdio>
#include <cstdlib>
import std;
import tls.client_handshake_io;
import reality.client;
import tls.corosio_client;
import tls.corosio_application;
import vless;
import vless.corosio_client;
import vless.vision_client;
import xudp;
import xudp.client_io;
import xudp.client_sessions;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;
namespace t=tls; namespace v=vless; namespace x=xudp; namespace io=nex::corosio; namespace capy=nex::capy;
using namespace std::chrono_literals;
using Bytes=std::vector<std::uint8_t>;
struct Stream {
    v::detail::DuplexRelay<io::tcp_socket,io::tcp_socket>& plain;
    v::detail::VisionClient<io::tcp_socket>& vision;
    bool use_vision;
    auto write(std::span<std::uint8_t const> bytes) -> capy::task<bool> {
        if (use_vision) co_return co_await vision.write(bytes);
        co_return co_await plain.write(bytes);
    }
    auto read(std::span<std::uint8_t> bytes) -> capy::task<std::expected<std::size_t,v::detail::ClientError>> {
        if (use_vision) {
            auto result=co_await vision.read(bytes);
            if (std::getenv("NEXUS_TEST_XUDP_TRACE") && result) {
                std::fputs("vision input:",stderr);
                for (auto byte : bytes.first(*result)) std::fprintf(stderr," %02x",byte);
                std::fputc('\n',stderr);
            }
            co_return result;
        }
        co_return co_await plain.read(bytes);
    }
    auto cancel() noexcept -> void { if (use_vision) vision.cancel(); else plain.cancel(); }
};
auto run(io::tcp_socket& socket,io::tcp_socket& local,t::ClientHandshakeIo handshake,std::uint16_t port,std::array<std::uint16_t,2> targets,bool vision,int& result) -> capy::task<> {
    auto [error]=co_await socket.connect(io::endpoint(io::ipv4_address::loopback(),port)); if (error) { result=2; co_return; }
    t::detail::ClientConnection connection(socket,std::move(handshake)); if (!co_await connection.start()) { result=3; co_return; }
    v::UserId user{}; std::iota(user.begin(),user.end(),std::uint8_t{0});
    v::detail::TcpClient plain(*connection.application()); v::detail::VisionClient framed(socket,*connection.application(),user);
    if (vision) { if (!co_await framed.start_mux()) { result=4; co_return; } }
    else if (!co_await plain.start_mux(user)) { result=4; co_return; }
    v::detail::DuplexRelay relay(local,*connection.application(),plain);
    Stream stream{relay,framed,vision}; x::ClientIo client(stream,2);
    std::array<std::array<Bytes,2>,2> payloads{{{Bytes{'f','i','r','s','t'},Bytes{'a','g','a','i','n','1'}},{Bytes{'s','e','c','o','n','d'},Bytes{'a','g','a','i','n','2'}}}};
    for (unsigned i=0;i<2;++i) {
        x::Address address; address.length=4; address.port=targets[i]; address.bytes[0]=127; address.bytes[3]=1;
        auto id=co_await client.open(address,payloads[i][0]); if (!id || *id!=i+1) { result=5; co_return; }
    }
    for (unsigned i=0;i<2;++i) if (!co_await client.send(i+1,{},payloads[i][1])) { result=6; co_return; }
    std::array<std::array<bool,2>,2> received{};
    while (!received[0][0] || !received[0][1] || !received[1][0] || !received[1][1]) {
        auto reply=co_await client.read();
        if (!reply) {
            std::cerr << "read error=" << static_cast<int>(reply.error()) << " received="
                      << received[0][0] << received[0][1] << received[1][0] << received[1][1] << "\n";
            result=9; co_return;
        }
        if (reply->action!=x::Incoming::datagram || reply->session<1 || reply->session>2 || !reply->source || reply->source->port!=targets[reply->session-1]) { std::cerr << "bad reply action=" << static_cast<int>(reply->action) << " session=" << reply->session << " port=" << (reply->source ? reply->source->port : 0) << "\n"; result=9; co_return; }
        auto i=reply->session-1; unsigned match=2;
        for (unsigned j=0;j<2;++j) if (std::ranges::equal(reply->payload,payloads[i][j])) match=j;
        if (match==2 || received[i][match]) { std::cerr << "bad payload session=" << reply->session << " size=" << reply->payload.size() << "\n"; result=9; co_return; }
        received[i][match]=true;
    }
    for (std::uint16_t id=1;id<=2;++id) if (!co_await client.end(id)) { result=10; co_return; }
    result=0;
}

int main(int argc,char** argv) {
    if (argc!=6) return 1; auto port=std::strtoul(argv[1],nullptr,10),a=std::strtoul(argv[3],nullptr,10),b=std::strtoul(argv[4],nullptr,10); if (!port || port>65535 || !a || a>65535 || !b || b>65535) return 1;
    std::string_view hex=argv[2]; if (hex.size()!=64) return 1; std::array<std::uint8_t,32> pub{};
    auto nib=[](char c)->int { if(c>='0'&&c<='9') return c-'0'; if(c>='a'&&c<='f') return c-'a'+10; return -1; };
    for (std::size_t i=0;i<32;++i) { auto x=nib(hex[i*2]),y=nib(hex[i*2+1]); if(x<0 || y<0) return 1; pub[i]=x*16+y; }
    bool vision=std::string_view(argv[5])=="vision"; if (!vision && std::string_view(argv[5])!="plain") return 1;
    std::array<std::uint16_t,1> groups{0x001d}; auto hello=t::make_client_hello("cover.example",{},groups); if (!hello) return 1;
    auto seconds=std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    reality::Identity identity{{1,8,24},static_cast<std::uint32_t>(seconds),{0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef}};
    auto session=reality::create_client_session(std::move(*hello),pub,identity); if (!session) return 1;
    auto now=std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count();
    auto handshake=t::ClientHandshakeIo::create(std::move(*session),now,now+10000); if (!handshake) return 1;
    io::io_context context(io::epoll); io::tcp_socket socket(context),local(context); int result=12;
    capy::run_async(context.get_executor())(run(socket,local,std::move(*handshake),port,{static_cast<std::uint16_t>(a),static_cast<std::uint16_t>(b)},vision,result));
    context.restart(); (void)context.run_for(15s);
    if (!context.stopped()) { socket.cancel(); context.restart(); (void)context.run_for(1s); if (!context.stopped()) std::_Exit(13); return 13; }
    return result;
}
