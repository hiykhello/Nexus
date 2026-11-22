import std;
import crypto;
import hysteria2.tcp_channel;
import hysteria2.stream_state;
import hysteria2.wire;
import net.datagram_driver;
import quic.tls_client;
import tls.server_credential;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;
import nexus.test.quic_tls_link;
import nexus.test.hysteria2_application_link;
import nexus.test.hy2_retry_port_link;
namespace io=nex::corosio;namespace capy=nex::capy;namespace h=hysteria2;namespace q=quic;namespace support=nexus::test::quic_tls;namespace clientlink=nexus::test::hysteria2_application_link;namespace portlink=nexus::test::hy2_retry_port;
using Clock=std::chrono::steady_clock;using namespace std::chrono_literals;
template<class Driver,class Predicate>auto wait(Driver& driver,Predicate predicate) -> capy::task<bool>{
    auto until=Clock::now()+1s;while(!predicate()){driver.changed().clear();auto [error]=co_await io::timeout(driver.changed().wait(),until);if(error)co_return false;}co_return true;
}
template<class Client>auto exercise(io::io_context& context,Client& client,portlink::Factory& factory,portlink::Port& port,portlink::Driver& server_driver,unsigned mode,bool& observed) -> capy::task<capy::results<>> {
    if(!co_await wait(*client.driver,[&]{return client.app.authenticated() && factory.bundles[0] && factory.bundles[0]->app.authenticated();}))co_return capy::results<>{std::make_error_code(std::errc::io_error)};
    auto opened=client.app.open("abandon.example:443");if(!opened)co_return capy::results<>{std::make_error_code(std::errc::io_error)};client.driver->notify();
    if(!co_await wait(server_driver,[&]{return factory.bundles[0]->app.pending().has_value();}))co_return capy::results<>{std::make_error_code(std::errc::io_error)};
    auto& bundle=*factory.bundles[0];bundle.launched=true;portlink::BusinessRoot root(bundle);auto remote=*bundle.app.pending();
    if(!bundle.app.respond(remote,h::TcpStatus::success))co_return capy::results<>{std::make_error_code(std::errc::io_error)};server_driver.notify();
    if(!co_await wait(*client.driver,[&]{return client.app.phase(*opened)==h::StreamPhase::ready;}))co_return capy::results<>{std::make_error_code(std::errc::io_error)};
    h::TcpChannel outgoing(client.app,*client.driver,*opened,Clock::now()+30s);h::TcpChannel incoming(bundle.app,server_driver,remote,Clock::now()+30s);
    bool client_entered=false,server_entered=false,client_completed=false,server_completed=false;
    auto client_operation=[&]() -> capy::task<capy::results<>>{
        client_entered=true;
        if(mode==0){std::array<std::uint8_t,1> byte{};(void)co_await outgoing.read(byte);}
        else {std::array<std::uint8_t,131072> bytes{};(void)co_await outgoing.send(bytes);}
        client_completed=true;co_return capy::results<>{};
    };
    auto server_operation=[&]() -> capy::task<capy::results<>>{
        server_entered=true;
        if(mode==0){std::array<std::uint8_t,1> byte{};(void)co_await incoming.read(byte);}
        else {std::array<std::uint8_t,131072> bytes{};(void)co_await incoming.send(bytes);}
        server_completed=true;co_return capy::results<>{};
    };
    auto abandon=[&]() -> capy::task<capy::results<>>{
        if(mode==1){if(!co_await wait(server_driver,[&]{return bundle.app.buffered_input(remote).value_or(0)>=16000 && client.app.buffered_input(*opened).value_or(0)>=16000;}))co_return capy::results<>{std::make_error_code(std::errc::io_error)};}
        else {auto [error]=co_await io::delay(1ms);if(error)co_return capy::results<>{error};}
        observed=client_entered && server_entered && !client_completed && !server_completed && !bundle.drained && port.live(bundle.owner);
        context.stop();auto [error]=co_await io::delay(60s);co_return capy::results<>{error};
    };
    auto [error,a,b,c]=co_await capy::when_all(client_operation(),server_operation(),abandon());(void)a;(void)b;(void)c;co_return capy::results<>{error};
}
auto trial(tls::ServerCredential const& credential,std::span<std::uint8_t const> cert,bool uring,unsigned mode) -> bool {
    auto context=std::unique_ptr<io::io_context>(new io::io_context(io::make_io_context(uring)));io::udp_socket client_socket(*context),server_socket(*context);io::endpoint local(io::ipv4_address::loopback(),0);
    if(client_socket.open() || client_socket.bind(local) || server_socket.open() || server_socket.bind(local))return false;local=server_socket.local_endpoint();
    q::TlsClient client_tls(support::hello(*credential.scheme()),29,support::Pki{cert},"h3");clientlink::Endpoint client(client_socket,client_tls,false,local);if(client.initialize())return false;
    portlink::Factory factory(credential,local);portlink::Port port(factory);portlink::Driver server_driver(server_socket,port,Clock::now()+30s);typename decltype(client)::Driver client_driver(client_socket,client,Clock::now()+30s);client.driver=&client_driver;
    bool done=false,observed=false;
    auto all=[&]() -> capy::task<>{auto [error,a,b,c]=co_await capy::when_all(client_driver.run(),server_driver.run(),exercise(*context,client,factory,port,server_driver,mode,observed));(void)error;(void)a;(void)b;(void)c;done=true;};
    capy::run_async(context->get_executor())(all());context->run_for(2s);
    bool before=observed && !done && client_driver.running() && server_driver.running() && factory.created==1 && factory.destroyed==0 && factory.bundles[0] && !factory.bundles[0]->drained;
    {auto released_client=std::move(client_socket);auto released_server=std::move(server_socket);}
    context.reset();port.drain();
    bool clean=before && !done && client_driver.drained() && server_driver.drained() && port.drained() && factory.destroyed==1 && factory.valid && client.app.clean() && !client.memory.used && !client.h3memory.used && !client.connection.key_slots();
    std::println("Hy2 native shared port natural context abandon backend={} mode={} observed={} done={} destroyed={} clean={}",uring,mode,observed,done,factory.destroyed,clean);return clean;
}
auto main(int argc,char** argv) -> int {
    if(argc!=3 && argc!=4)return 1;if(argc==4 && std::string_view(argv[3])!="0" && std::string_view(argv[3])!="1")return 1;auto cert=support::read(argv[1]),key=support::read(argv[2]);auto credential=tls::ServerCredential::create(cert,key);::crypto::cleanse(key);if(!credential)return 2;
    for(bool uring:{false,true})for(unsigned mode=0;mode<2;++mode){if(argc==4 && uring!=(std::string_view(argv[3])=="1"))continue;if(!trial(*credential,cert,uring,mode))return 3;}
}
