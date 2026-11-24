module test.hy2_production_resource_link;
import std;
import crypto;
import hysteria2.auth;
import hysteria2.credential;
import hysteria2.listener;
import hysteria2.stream_state;
import hysteria2.tcp_channel;
import hysteria2.wire;
import net.datagram_driver;
import quic.cid_registry;
import quic.tls_client;
import tls.server_credential;
import capy;
import corosio;
import test.quic_tls_link;
import test.hysteria2_application_link;

namespace test::hy2_production_resource {
namespace h=hysteria2;namespace io = ::corosio;namespace capy = ::capy;namespace support=test::quic_tls;namespace link=test::hysteria2_application_link;
using Clock=std::chrono::steady_clock;using namespace std::chrono_literals;

struct Hooks {
    h::Password const& password;bool completed=false;
    auto authenticate(h::ClientAuthView auth)noexcept->std::optional<std::size_t>{return h::authenticate({&password,1},auth.credential);}
    auto datagram(quic::SessionHandle,std::span<std::uint8_t const>)noexcept->int{return 0;}
    template<class Request>auto serve(Request& request)->capy::task<>{
        if(!request.respond(h::TcpStatus::success))co_return;std::array<std::uint8_t,1> bytes{};
        auto got=co_await request.channel.read(bytes);if(!got || *got!=1 || bytes[0]!=37)co_return;
        if(!co_await request.channel.send(bytes) || !co_await request.channel.close_output())co_return;
        auto eof=co_await request.channel.read(bytes);completed=eof && !*eof;
    }
};
template<class Endpoint>auto business(Endpoint& client,bool& success)->capy::task<capy::results<>>{
    auto until=Clock::now()+1s;
    while(!client.app.authenticated() && !Heap::denied && !cpp_denied && Clock::now()<until){auto [error]=co_await io::delay(1ms);if(error)co_return capy::results<>{error};}
    if(Heap::denied || cpp_denied || !client.app.authenticated())co_return capy::results<>{};
    auto stream=client.app.open("target.example:443");if(!stream)co_return capy::results<>{};client.driver->notify();
    h::TcpChannel channel(client.app,*client.driver,*stream,until);if(!co_await channel.ready())co_return capy::results<>{};
    std::array<std::uint8_t,1> bytes{37};if(!co_await channel.send(bytes) || !co_await channel.close_output())co_return capy::results<>{};
    auto got=co_await channel.read(bytes);if(!got || *got!=1 || bytes[0]!=37)co_return capy::results<>{};
    auto eof=co_await channel.read(bytes);success=eof && !*eof;co_return capy::results<>{};
}
auto phase(io::io_context& context,tls::ServerCredential const& credential,std::span<std::uint8_t const> cert,h::Password const& password,bool* clean)->bool{
    io::udp_socket socket(context);io::endpoint local(io::ipv4_address::loopback(),0);if(socket.open() || socket.bind(local))return false;
    Hooks hooks{password};h::Listener<Hooks,4,16,16384,Heap> listener(context,hooks,credential);auto bound=listener.prepare(local);if(!bound)return false;
    quic::TlsClient tls(support::hello(*credential.scheme()),29,support::Pki{cert},"h3");link::Endpoint client(socket,tls,false,*bound);if(client.initialize())return false;
    typename decltype(client)::Driver driver(socket,client,Clock::now()+2s);client.driver=&driver;bool success=false,done=false;
    auto supervise=[&]()->capy::task<capy::results<>>{
        auto deadline=Clock::now()+1500ms;while(!Heap::denied && !cpp_denied && !success && Clock::now()<deadline){auto [error]=co_await io::delay(1ms);if(error)break;}
        listener.stop();driver.finish();co_return capy::results<>{};
    };
    auto all=[&]()->capy::task<>{auto [error,a,b,c]=co_await capy::when_all(driver.run(),business(client,success),supervise());(void)error;(void)a;(void)b;(void)c;done=true;};
    std::exception_ptr async_error;
    try{listener.start();capy::run_async(context.get_executor(),[&]()noexcept{done=true;},[&](std::exception_ptr error)noexcept{async_error=std::move(error);done=true;listener.stop();driver.finish();})(all());context.restart();context.run_for(3s);listener.maintain();}
    catch(...){
        listener.stop();driver.finish();context.restart();context.run();listener.maintain();
        if(!driver.drained()){client.request_stop();client.stop();client.drain();}
        if(clean)*clean=listener.drained() && !Heap::blocks && client.app.clean() && !client.memory.used && !client.h3memory.used;
        throw;
    }
    if(!driver.drained() && !driver.running()){client.request_stop();client.stop();client.drain();}
    auto all_clean=listener.drained() && !driver.running() && !Heap::blocks && client.app.clean() && !client.memory.used && !client.h3memory.used;
    if(clean)*clean=all_clean;
    return done && (Heap::denied || cpp_denied || (success && hooks.completed)) && all_clean && (listener.clean() || cpp_denied);
}

}
