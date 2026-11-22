import std;
import crypto;
import hysteria2.application;
import hysteria2.auth;
import hysteria2.wire;
import hysteria2.tcp_channel;
import hysteria2.stream_state;
import quic.cid_registry;
import quic.datagram_port;
import quic.datagram_session;
import quic.tls_server;
import net.datagram_driver;
import net.stream_relay;
import tls.server_credential;
import nexus.thirdparty.ngtcp2;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;
import nexus.test.quic_tls_link;
import nexus.test.hy2_port_link;
namespace n=nex::ngtcp2;namespace q=quic;namespace h=hysteria2;namespace io=nex::corosio;namespace capy=nex::capy;namespace support=nexus::test::quic_tls;
using Clock=std::chrono::steady_clock;using namespace std::chrono_literals;
using namespace nexus::test::hy2_port;
auto transfer(capy::task<bool> operation) -> capy::task<capy::results<>> {co_return capy::results<>{co_await std::move(operation)?std::error_code{}:std::make_error_code(std::errc::io_error)};}
auto business(Bundle& bundle,Driver& driver,std::size_t total,io::io_context& context,unsigned upstream,BusinessRoot root) -> capy::task<capy::results<>> {
    auto active=std::move(root);auto& app=bundle.app;
    while(!app.pending() && !app.stopping()){
        driver.changed().clear();auto [error]=co_await io::timeout(driver.changed().wait(),Clock::now()+8s);if(error)co_return capy::results<>{std::make_error_code(std::errc::timed_out)};
    }
    auto stream=app.pending();if(!stream || app.address(*stream)!="target.example:443" || !app.respond(*stream,h::TcpStatus::success))co_return capy::results<>{std::make_error_code(std::errc::protocol_error)};
    h::TcpChannel channel(app,driver,*stream,Clock::now()+8s);driver.notify();
    if(upstream){
        io::tcp_socket target(context);auto [connected]=co_await io::timeout(target.connect(io::endpoint(io::ipv4_address::loopback(),upstream)),Clock::now()+8s);
        if(connected)co_return capy::results<>{connected};
        auto adapter=net::ByteRelayAdapter{target,channel,[] {},false};
        auto [error,a,b]=co_await capy::when_all(transfer(net::stream_relay::upload(adapter)),transfer(net::stream_relay::download(adapter)));(void)a;(void)b;
        bundle.passed=!error;std::println("shared actual relay slot={} generation={} passed={}",bundle.owner.slot,bundle.owner.generation,bundle.passed);
        co_return capy::results<>{error};
    }
    std::size_t incoming=0,outgoing=0;bool valid=true,eof=false;
    auto upload=[&]() -> capy::task<capy::results<>> {
        std::array<std::uint8_t,7000> bytes{};
        while(outgoing<total){auto size=std::min(bytes.size(),total-outgoing);for(std::size_t i=0;i<size;++i)bytes[i]=static_cast<std::uint8_t>((outgoing+i)*71+19);
            if(!co_await channel.send(std::span(bytes).first(size))){valid=false;break;}outgoing+=size;}
        if(valid && !co_await channel.close_output())valid=false;
        co_return capy::results<>{valid?std::error_code{}:std::make_error_code(std::errc::io_error)};
    };
    auto download=[&]() -> capy::task<capy::results<>> {
        std::array<std::uint8_t,7000> bytes{};while(!eof){auto read=co_await channel.read(bytes);if(!read){valid=false;break;}if(!*read){eof=true;break;}
            for(std::size_t i=0;i<*read;++i)if(bytes[i]!=static_cast<std::uint8_t>((incoming+i)*71+37))valid=false;incoming+=*read;}
        co_return capy::results<>{valid?std::error_code{}:std::make_error_code(std::errc::io_error)};
    };
    auto [error,up,down]=co_await capy::when_all(upload(),download());(void)up;(void)down;
    bundle.passed=!error && valid && eof && incoming==total && outgoing==total;
    std::println("shared business slot={} generation={} in={} out={} passed={}",bundle.owner.slot,bundle.owner.generation,incoming,outgoing,bundle.passed);
    co_return capy::results<>{bundle.passed?std::error_code{}:std::make_error_code(std::errc::io_error)};
}
auto supervise(io::io_context& context,Factory& factory,Port& port,Driver& driver,unsigned expected,std::size_t total,unsigned upstream) -> capy::task<capy::results<>> {
    while(factory.completed<expected && !factory.failures){
        factory.work.clear();port.maintain();
        for(auto& bundle:factory.bundles)if(bundle && !bundle->launched){
            bundle->launched=true;auto owner=bundle->owner;
            capy::run_async(context.get_executor(),[&,owner](auto result){
                auto& entry=factory.bundles[owner.slot];if(!entry || entry->owner!=owner){factory.valid=false;return;}
                if(std::get<0>(result) || !entry->passed)++factory.failures;
                entry->drained=true;++factory.completed;(void)port.request_retire(owner);factory.work.set();
            },[&,owner](std::exception_ptr){auto& entry=factory.bundles[owner.slot];if(entry && entry->owner==owner)entry->drained=true;++factory.completed;++factory.failures;(void)port.request_retire(owner);factory.work.set();})(business(*bundle,driver,total,context,upstream,BusinessRoot{*bundle}));
        }
        driver.notify();if(factory.completed>=expected || factory.failures)break;
        auto [error]=co_await io::timeout(factory.work.wait(),Clock::now()+10s);if(error){++factory.failures;break;}
    }
    if(factory.failures)driver.cancel();else driver.finish();
    co_return capy::results<>{};
}
auto run(tls::ServerCredential const& credential,bool ipv6,bool uring,unsigned expected,std::size_t total,unsigned upstream) -> int {
    io::io_context context=io::make_io_context(uring);io::udp_socket socket(context);io::endpoint local=ipv6?io::endpoint(io::ipv6_address::loopback(),0):io::endpoint(io::ipv4_address::loopback(),0);
    if(socket.open(local.address().family()) || socket.bind(local))return 1;local=socket.local_endpoint();Factory factory{credential,local};Port port(factory);Driver driver(socket,port,Clock::now()+20s);
    auto all=[&]() -> capy::task<capy::results<>> {auto [error,a,b]=co_await capy::when_all(driver.run(),supervise(context,factory,port,driver,expected,total,upstream));(void)a;(void)b;co_return capy::results<>{error};};
    bool done=false,failed=false;std::cout<<"READY "<<local.port()<<std::endl;
    capy::run_async(context.get_executor(),[&](auto result){done=true;failed=bool(std::get<0>(result));},[&](std::exception_ptr exception){try{std::rethrow_exception(exception);}catch(std::exception const& e){std::println("exception {}",e.what());}done=failed=true;})(all());
    context.run_for(22s);port.drain();
    std::println("shared done={} failed={} created={} destroyed={} completed={} failures={} valid={} drained={} session={} port={}",done,failed,factory.created,factory.destroyed,factory.completed,factory.failures,factory.valid,port.drained(),sizeof(Session),sizeof(Port));
    return done && !failed && factory.created==expected && factory.destroyed==expected && factory.completed==expected && !factory.failures && factory.valid && driver.drained() && port.drained()?0:3;
}
auto main(int argc,char** argv) -> int {
    if(argc!=7 && argc!=8)return 1;try{auto cert=support::read(argv[1]),key=support::read(argv[2]);auto credential=tls::ServerCredential::create(cert,key);::crypto::cleanse(key);if(!credential)return 2;
    return run(*credential,std::string_view(argv[3])=="6",std::string_view(argv[4])=="1",static_cast<unsigned>(std::stoul(argv[5])),std::stoull(argv[6]),argc==8?static_cast<unsigned>(std::stoul(argv[7])):0);}catch(std::exception const& e){std::println("exception {}",e.what());return 99;}
}
