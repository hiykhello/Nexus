import std;
import crypto;
import hysteria2.application;
import hysteria2.tcp_channel;
import hysteria2.stream_state;
import hysteria2.wire;
import quic.tls_client;
import quic.tls_server;
import tls.server_credential;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;
import nexus.thirdparty.ngtcp2;
import nexus.test.quic_tls_link;
import nexus.test.hysteria2_application_link;
namespace io=nex::corosio;
namespace capy=nex::capy;
namespace h=hysteria2;
namespace q=quic;
namespace t=tls;
namespace support=nexus::test::quic_tls;
namespace link=nexus::test::hysteria2_application_link;
using namespace std::chrono_literals;
using Clock=std::chrono::steady_clock;
template<class Endpoint,class Condition>auto wait(Endpoint& endpoint,Condition condition) -> capy::task<bool>{
    auto deadline=Clock::now()+1s;
    while(!condition()){
        if(endpoint.driver->drained() || Clock::now()>=deadline)co_return false;
        endpoint.driver->changed().clear();auto [error]=co_await io::timeout(endpoint.driver->changed().wait(),deadline);if(error)co_return false;
    }co_return true;
}
template<class Client,class Server>auto recovery(Client& client,Server& server) -> capy::task<bool>{
    auto stream=client.app.open("recover.example:443");if(!stream){std::println("recovery open fail {}",static_cast<int>(stream.error()));co_return false;}client.driver->notify();
    if(!co_await wait(server,[&]{return server.app.pending().has_value();})){std::println("recovery server pending fail");co_return false;}
    auto remote=*server.app.pending();if(server.app.address(remote)!="recover.example:443" || !server.app.respond(remote,h::TcpStatus::success)){std::println("recovery response fail address={}",server.app.address(remote));co_return false;}server.driver->notify();
    if(!co_await wait(client,[&]{return client.app.phase(*stream)==h::StreamPhase::ready;}))co_return false;
    std::array<std::uint8_t,4> data{0,1,0xfe,0xff};auto sent=client.app.send(*stream,data);if(!sent || *sent!=data.size())co_return false;
    client.driver->notify();if(!co_await wait(server,[&]{return server.app.buffered_input(remote).value_or(0)==data.size();}))co_return false;
    std::array<std::uint8_t,4> read{};auto received=server.app.read(remote,read);if(!received || received->size!=4 || read!=data)co_return false;
    client.app.abandon(*stream);server.app.abandon(remote);client.driver->notify();server.driver->notify();co_return true;
}
template<class Client,class Server>auto exercise(Client& client,Server& server,unsigned mode) -> capy::task<bool>{
    if(mode==0){
        if(!co_await wait(client,[&]{return client.driver->drained();}))co_return false;
        co_return !client.app.authenticated() && !server.app.authenticated() && !server.app.pending() && client.driver->failure().has_value();
    }
    if(!co_await wait(client,[&]{return client.app.authenticated() && server.app.authenticated();}))co_return false;
    auto opened=client.app.open("blocked.example:443");if(!opened)co_return false;auto stream=*opened;client.driver->notify();
    if(!co_await wait(server,[&]{return server.app.pending().has_value();}))co_return false;
    auto remote=*server.app.pending();if(server.app.address(remote)!="blocked.example:443")co_return false;
    if(mode==1){
        if(!server.app.respond(remote,h::TcpStatus::error,"refused"))co_return false;server.driver->notify();
        {h::TcpChannel channel(client.app,*client.driver,stream,Clock::now()+500ms);
         auto ready=co_await channel.ready();auto failure=channel.failure();
         if(ready || !failure || failure->error!=h::StreamError::rejected){std::println("rejected channel ready={} failure={} expected={} compare={}",ready,failure?static_cast<int>(failure->error):-1,static_cast<int>(h::StreamError::rejected),failure && failure->error==h::StreamError::rejected);co_return false;}}
        server.app.abandon(remote);server.driver->notify();
        if(!co_await recovery(client,server))co_return false;
        co_return client.driver->running() && server.driver->running();
    }
    if(!server.app.respond(remote,h::TcpStatus::success))co_return false;server.driver->notify();
    if(!co_await wait(client,[&]{return client.app.phase(stream)==h::StreamPhase::ready;}))co_return false;
    auto initial_payload=16384-h::encode_tcp_request("blocked.example:443")->size();
    if(mode==2){
        std::array<std::uint8_t,16384> bytes{};std::fill(bytes.begin(),bytes.end(),0x71);std::size_t sent=0;
        while(server.app.buffered_input(remote).value_or(0)<initial_payload){
            auto result=client.app.send(stream,bytes);if(!result)co_return false;sent+=*result;client.driver->notify();
            if(!co_await wait(client,[&]{return server.app.buffered_input(remote).value_or(0)>=initial_payload || client.app.buffered_output(stream).value_or(0)<16384;}))co_return false;
        }
        auto before=server.app.buffered_input(remote);auto [error]=co_await io::delay(30ms);if(error || before!=initial_payload || server.app.buffered_input(remote)!=before)co_return false;
        auto written=client.app.send(stream,bytes);if(!written)co_return false;sent+=*written;client.driver->notify();
        std::array<std::uint8_t,8192> consumed{};auto read=server.app.read(remote,consumed);if(!read || read->size!=consumed.size() || std::ranges::any_of(consumed,[](auto byte){return byte!=0x71;}))co_return false;server.driver->notify();
        if(!co_await wait(server,[&]{return server.app.buffered_input(remote)==16384;}))co_return false;
        std::println("Hy2 actual backpressure initial_payload={} bounded_window=16384 admitted={} held30ms_no_credit=true consumed8192_resumes=true",initial_payload,sent);
        client.app.abandon(stream);server.app.abandon(remote);client.driver->notify();server.driver->notify();
        co_return co_await recovery(client,server);
    }
    if(mode==3 || mode==4){
        h::TcpChannel channel(client.app,*client.driver,stream,Clock::now()+(mode==3?60ms:1s));
        bool sent=false,read_done=false;
        std::array<std::uint8_t,131072> bytes{};
        auto upload=[&]() -> capy::task<capy::results<>>{sent=co_await channel.send(bytes);co_return capy::results<>{};};
        auto input=[&]() -> capy::task<capy::results<>>{std::array<std::uint8_t,1> byte{};auto result=co_await channel.read(byte);read_done=!result;co_return capy::results<>{};};
        auto cancel=[&]() -> capy::task<capy::results<>>{if(mode==4){if(!co_await wait(server,[&]{return server.app.buffered_input(remote).value_or(0)>=initial_payload;}))co_return capy::results<>{std::make_error_code(std::errc::io_error)};channel.cancel();}co_return capy::results<>{};};
        auto began=Clock::now();auto [error,a,b,c]=co_await capy::when_all(upload(),input(),cancel());(void)a;(void)b;(void)c;
        if(error || sent || !read_done || !channel.failure())co_return false;
        if(mode==3 && (channel.failure()->error!=h::StreamError::timeout || Clock::now()-began<50ms || Clock::now()-began>150ms))co_return false;
        server.app.abandon(remote);server.driver->notify();
        co_return co_await recovery(client,server);
    }
    if(mode==5){
        // Zero is an error code on RESET_STREAM, never a successful EOF.
        if(!server.app.reset(remote,0))co_return false;server.driver->notify();
        h::TcpChannel channel(client.app,*client.driver,stream,Clock::now()+500ms);std::array<std::uint8_t,1> byte{};
        auto read=co_await channel.read(byte);if(read || !channel.failure() || channel.failure()->error!=h::StreamError::reset || channel.failure()->code)co_return false;
        server.app.abandon(remote);co_return co_await recovery(client,server);
    }
    if(mode==7){
        // The authentication request uses client stream 0; this first
        // business request is stream 4. The peer aborts only its read side,
        // then sends a response after the client observes STOP_SENDING.
        if(nex::ngtcp2::ngtcp2_conn_shutdown_stream_read(server.connection.native(),0,4,0x123))co_return false;
        server.driver->notify();
        if(!co_await wait(client,[&]{return client.app.output_stopped(stream);}))co_return false;
        std::array<std::uint8_t,4> data{1,2,3,4};auto sent=server.app.send(remote,data);
        if(!sent || *sent!=data.size() || !server.app.close_output(remote))co_return false;
        server.driver->notify();
        {
            h::TcpChannel channel(client.app,*client.driver,stream,Clock::now()+500ms);
            std::array<std::uint8_t,4> received{};auto read=co_await channel.read(received);
            if(!read || *read!=data.size() || received!=data)co_return false;
            auto end=co_await channel.read(received);if(!end || *end)co_return false;
        }
        server.app.abandon(remote);server.driver->notify();
        co_return co_await recovery(client,server);
    }
    if(mode==6){
        // Fully close a stream, discard both channels, and reuse bounded
        // slots repeatedly; stale handles must never revive another owner.
        client.app.abandon(stream);server.app.abandon(remote);client.driver->notify();server.driver->notify();
        for(unsigned i=0;i<20;++i){
            if(!co_await recovery(client,server))co_return false;
            auto [error]=co_await io::delay(1ms);if(error)co_return false;
        }
        co_return !client.app.phase(stream).has_value();
    }
    co_return false;
}
auto pair(t::ServerCredential const& credential,std::span<std::uint8_t const> anchor,bool uring,unsigned mode) -> bool {
    io::io_context context=io::make_io_context(uring);io::udp_socket client_socket(context),server_socket(context);io::endpoint local(io::ipv4_address::loopback(),0);
    if(client_socket.open() || client_socket.bind(local) || server_socket.open() || server_socket.bind(local))return false;
    q::TlsClient client_tls(support::hello(*credential.scheme()),29,support::Pki{anchor},"h3");q::TlsServer server_tls(credential,"h3");
    link::Endpoint client(client_socket,client_tls,false,server_socket.local_endpoint());link::Endpoint server(server_socket,server_tls,true,client_socket.local_endpoint());
    if(client.initialize() || server.initialize())return false;server.hooks.allow=mode!=0;
    typename decltype(client)::Driver client_driver(client_socket,client,Clock::now()+1500ms);typename decltype(server)::Driver server_driver(server_socket,server,Clock::now()+1500ms);client.driver=&client_driver;server.driver=&server_driver;
    bool done=false,passed=false;
    auto control=[&]() -> capy::task<capy::results<>>{passed=co_await exercise(client,server,mode);client_driver.finish();server_driver.finish();co_return capy::results<>{};};
    auto root=[&]() -> capy::task<>{auto [error,a,b,c]=co_await capy::when_all(client_driver.run(),server_driver.run(),control());(void)error;(void)a;(void)b;(void)c;done=true;};
    capy::run_async(context.get_executor())(root());context.run_for(2s);
    bool clean=client_driver.drained()&&server_driver.drained()&&client.app.clean()&&server.app.clean()&&!client.memory.used&&!server.memory.used&&!client.h3memory.used&&!server.h3memory.used&&!client.connection.key_slots()&&!server.connection.key_slots();
    std::println("Hy2 application lifecycle backend={} mode={} passed={} done={} clean={} client_failure={} server_failure={}",uring,mode,passed,done,clean,client_driver.failure().has_value(),server_driver.failure().has_value());
    return passed&&done&&clean;
}
auto main(int argc,char** argv) -> int {
    if(argc!=3 && argc!=4)return 1;
    auto cert=support::read(argv[1]),key=support::read(argv[2]);auto credential=t::ServerCredential::create(cert,key);::crypto::cleanse(key);if(!credential)return 2;
    auto selected=argc==4 ? std::stoi(argv[3]) : -1;if(selected < -1 || selected>7)return 1;
    for(bool uring:{false,true})for(unsigned mode=0;mode<8;++mode)
        if((selected<0 || mode==static_cast<unsigned>(selected)) && !pair(*credential,cert,uring,mode))return 3;
}
