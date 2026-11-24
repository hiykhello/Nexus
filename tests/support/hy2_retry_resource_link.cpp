module test.hy2_retry_resource_link;
import std;
import crypto;
import hysteria2.stream_state;
import hysteria2.wire;
import net.datagram_driver;
import quic.tls_client;
import tls.server_credential;
import capy;
import corosio;
import test.quic_tls_link;
import test.hysteria2_application_link;
import test.hy2_retry_port_link;
import test.hy2_native_memory;

namespace test::hy2_retry_resource {
namespace io = ::corosio;namespace capy = ::capy;namespace h=hysteria2;namespace q=quic;namespace support=test::quic_tls;namespace clientlink=test::hysteria2_application_link;namespace portlink=test::hy2_retry_port;namespace mem=test::hy2_native_memory;
using Clock=std::chrono::steady_clock;using namespace std::chrono_literals;
template<class Driver,class Predicate>auto wait(Driver& driver,Predicate predicate) -> capy::task<bool>{
    auto until=Clock::now()+1s;while(!predicate()){driver.changed().clear();auto [error]=co_await io::timeout(driver.changed().wait(),until);if(error)co_return false;}co_return true;
}
template<class Client>auto exchange(Client& client,portlink::Factory& factory,portlink::Driver& driver) -> capy::task<bool> {
    if(!co_await wait(driver,[&]{return (mem::fault.denied || mem::cpp_denied) || (client.app.authenticated() && factory.bundles[0] && factory.bundles[0]->app.authenticated());}))co_return false;
    if((mem::fault.denied || mem::cpp_denied))co_return true;
    auto& protected_bundle=*factory.bundles[0];protected_bundle.launched=true;portlink::BusinessRoot root(protected_bundle);
    auto opened=client.app.open("recover.example:443");if(!opened)co_return false;client.driver->notify();
    if(!co_await wait(driver,[&]{return (mem::fault.denied || mem::cpp_denied) || (factory.bundles[0] && factory.bundles[0]->app.pending().has_value());}))co_return false;
    if((mem::fault.denied || mem::cpp_denied))co_return true;
    auto& server=*factory.bundles[0];auto remote=*server.app.pending();if(!server.app.respond(remote,h::TcpStatus::success))co_return false;driver.notify();
    if(!co_await wait(*client.driver,[&]{return (mem::fault.denied || mem::cpp_denied) || client.app.phase(*opened)==h::StreamPhase::ready;}))co_return false;
    if((mem::fault.denied || mem::cpp_denied))co_return true;
    std::array<std::uint8_t,4> payload{0,1,0xfe,0xff};auto sent=client.app.send(*opened,payload);if(!sent || *sent!=payload.size())co_return false;client.driver->notify();
    if(!co_await wait(driver,[&]{return (mem::fault.denied || mem::cpp_denied) || !factory.bundles[0] || factory.bundles[0]->app.buffered_input(remote)==payload.size();}))co_return false;
    if((mem::fault.denied || mem::cpp_denied))co_return true;
    if(!factory.bundles[0])co_return false;std::array<std::uint8_t,4> bytes{};auto result=server.app.read(remote,bytes);
    co_return result && result->size==bytes.size() && bytes==payload;
}
template<class Tls>struct ObservedClient:clientlink::Endpoint<Tls> {
    using Base=clientlink::Endpoint<Tls>;
    using Base::Base;
    ~ObservedClient(){
        this->stop();this->drain();
        mem::oracle.valid&=this->app.clean() && !this->memory.used && !this->h3memory.used && !this->connection.key_slots() &&
            this->memory.allocations==this->memory.frees && this->h3memory.allocations==this->h3memory.frees && !this->tls.pending_handshake_bytes();
    }
};
auto phase(io::io_context& context,tls::ServerCredential const& credential,std::span<std::uint8_t const> cert,bool* observed_clean) -> bool {
    io::udp_socket client_socket(context),server_socket(context);io::endpoint local(io::ipv4_address::loopback(),0);
    if(client_socket.open() || client_socket.bind(local) || server_socket.open() || server_socket.bind(local))return false;local=server_socket.local_endpoint();
    q::TlsClient client_tls(support::hello(*credential.scheme()),29,support::Pki{cert},"h3");ObservedClient<decltype(client_tls)> client(client_socket,client_tls,false,local);if(client.initialize())return false;
    portlink::Factory factory(credential,local);portlink::Port port(factory);portlink::Driver server_driver(server_socket,port,Clock::now()+1500ms);typename decltype(client)::Driver client_driver(client_socket,client,Clock::now()+1500ms);client.driver=&client_driver;
    bool done=false,passed=false;std::exception_ptr exception;
    auto control=[&]() -> capy::task<capy::results<>> {passed=co_await exchange(client,factory,server_driver);client_driver.finish();server_driver.finish();co_return capy::results<>{};};
    auto all=[&]() -> capy::task<>{auto [error,a,b,c]=co_await capy::when_all(client_driver.run(),server_driver.run(),control());(void)error;(void)a;(void)b;(void)c;done=true;};
    capy::run_async(context.get_executor(),[&]() noexcept{done=true;},[&](std::exception_ptr error) noexcept{exception=std::move(error);done=true;})(all());context.restart();context.run_for(2s);port.drain();
    bool clean=done && client_driver.drained() && server_driver.drained() && port.drained() && factory.created==factory.destroyed && factory.valid && client.app.clean() && !client.memory.used && !client.h3memory.used && !client.connection.key_slots();
    if(exception && !mem::cpp_denied)return false;
    if(!passed || !clean)std::println("resource phase passed={} clean={} denied={} calls={} done={} created={} destroyed={} failures={}",passed,clean,(mem::fault.denied || mem::cpp_denied),mem::fault.calls,done,factory.created,factory.destroyed,factory.failures);
    if(!clean)std::println("resource cleanup client_driver={} server_driver={} port={} valid={} client_app={} QUICused={} H3used={} keys={}",client_driver.drained(),server_driver.drained(),port.drained(),factory.valid,client.app.clean(),client.memory.used,client.h3memory.used,client.connection.key_slots());
    if(observed_clean)*observed_clean=clean;
    return (passed||(mem::fault.denied || mem::cpp_denied))&&clean;
}
}
