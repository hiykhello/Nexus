import std;
import crypto;
import hysteria2.credential;
import hysteria2.auth;
import hysteria2.listener;
import hysteria2.stream_state;
import hysteria2.tcp_channel;
import hysteria2.wire;
import net.datagram_driver;
import quic.cid_registry;
import quic.tls_client;
import tls.server_credential;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;
import nexus.test.quic_tls_link;
import nexus.test.hysteria2_application_link;
namespace h=hysteria2;namespace io=nex::corosio;namespace capy=nex::capy;namespace support=nexus::test::quic_tls;namespace link=nexus::test::hysteria2_application_link;
using Clock=std::chrono::steady_clock;using namespace std::chrono_literals;
struct Hooks {
    h::Password const& password;unsigned mode;bool entered=false,completed=false,valid=true;
    auto authenticate(h::ClientAuthView auth) noexcept->std::optional<std::size_t>{return h::authenticate({&password,1},auth.credential);}
    auto datagram(quic::SessionHandle,std::span<std::uint8_t const>) noexcept->int{return 0;}
    template<class Request>auto serve(Request& request)->capy::task<>{
        valid&=request.respond(h::TcpStatus::success);entered=true;
        if(mode==0){std::array<std::uint8_t,1> bytes{};(void)co_await request.channel.read(bytes);}
        else {std::array<std::uint8_t,131072> bytes{};(void)co_await request.channel.send(bytes);}
        completed=true;
    }
};
template<class Driver,class Predicate>auto wait(Driver& driver,Predicate predicate)->capy::task<bool>{
    auto deadline=Clock::now()+1s;while(!predicate()){driver.changed().clear();auto [error]=co_await io::timeout(driver.changed().wait(),deadline);if(error)co_return false;}co_return true;
}
template<class Endpoint,class Listener>auto business(io::io_context& context,Endpoint& client,Listener& listener,Hooks& hooks,unsigned mode,bool& observed)->capy::task<capy::results<>>{
    if(!co_await wait(*client.driver,[&]{return client.app.authenticated();}))co_return capy::results<>{std::make_error_code(std::errc::io_error)};
    auto stream=client.app.open("target.example:443");if(!stream)co_return capy::results<>{std::make_error_code(std::errc::io_error)};client.driver->notify();
    if(!co_await wait(*client.driver,[&]{return client.app.phase(*stream)==h::StreamPhase::ready;}))co_return capy::results<>{std::make_error_code(std::errc::io_error)};
    h::TcpChannel channel(client.app,*client.driver,*stream,Clock::now()+30s);bool entered=false,completed=false;
    auto operation=[&]()->capy::task<capy::results<>>{entered=true;if(mode==0){std::array<std::uint8_t,1> bytes{};(void)co_await channel.read(bytes);}else{std::array<std::uint8_t,131072> bytes{};(void)co_await channel.send(bytes);}completed=true;co_return capy::results<>{};};
    auto abandon=[&]()->capy::task<capy::results<>>{
        if(mode==1){if(!co_await wait(*client.driver,[&]{return client.app.buffered_input(*stream).value_or(0)>=16000;}))co_return capy::results<>{std::make_error_code(std::errc::io_error)};}
        else{auto [error]=co_await io::delay(1ms);if(error)co_return capy::results<>{error};}
        observed=entered && !completed && hooks.entered && !hooks.completed && listener.business()==1 && listener.size()==1;
        context.stop();auto [error]=co_await io::delay(60s);co_return capy::results<>{error};
    };
    auto [error,a,b]=co_await capy::when_all(operation(),abandon());(void)a;(void)b;co_return capy::results<>{error};
}
auto trial(tls::ServerCredential const& credential,std::span<std::uint8_t const> cert,h::Password const& password,bool uring,unsigned mode)->bool{
    auto context=std::unique_ptr<io::io_context>(new io::io_context(io::make_io_context(uring)));io::udp_socket socket(*context);io::endpoint local(io::ipv4_address::loopback(),0);if(socket.open() || socket.bind(local))return false;
    Hooks hooks{password,mode};h::Listener<Hooks,4,16,16384> listener(*context,hooks,credential);auto bound=listener.prepare(local);if(!bound)return false;
    quic::TlsClient tls(support::hello(*credential.scheme()),29,support::Pki{cert},"h3");link::Endpoint client(socket,tls,false,*bound);if(client.initialize())return false;
    typename decltype(client)::Driver driver(socket,client,Clock::now()+30s);client.driver=&driver;listener.start();bool observed=false,done=false;
    auto all=[&]()->capy::task<>{auto [error,a,b]=co_await capy::when_all(driver.run(),business(*context,client,listener,hooks,mode,observed));(void)error;(void)a;(void)b;done=true;};
    capy::run_async(context->get_executor())(all());context->run_for(2s);
    auto before=observed && !done && hooks.valid && !hooks.completed && driver.running() && listener.business()==1;
    {auto release_server=std::move(listener.transport_socket());auto release_client=std::move(socket);}
    context.reset();listener.maintain();
    auto clean=before && !done && listener.drained() && listener.clean() && driver.drained() && client.app.clean() && !client.memory.used && !client.h3memory.used && !client.connection.key_slots();
    std::println("production Hy2 natural context abandon backend={} mode={} observed={} done={} clean={} native_sessions={} business={}",uring,mode,observed,done,clean,listener.size(),listener.business());return clean;
}
auto main(int argc,char** argv)->int{
    if(argc!=3 && argc!=4)return 1;if(argc==4 && std::string_view(argv[3])!="0" && std::string_view(argv[3])!="1")return 1;auto cert=support::read(argv[1]),key=support::read(argv[2]);auto credential=tls::ServerCredential::create(cert,key);::crypto::cleanse(key);auto password=h::Password::create(support::bytes("test-password"));if(!credential || !password)return 2;
    for(bool backend:{false,true})for(unsigned mode=0;mode<2;++mode)if((argc==3 || backend==(std::string_view(argv[3])=="1")) && !trial(*credential,cert,*password,backend,mode))return 3;
}
