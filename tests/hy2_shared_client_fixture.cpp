import std;
import crypto;
import hysteria2.application;
import hysteria2.tcp_channel;
import hysteria2.stream_state;
import net.datagram_driver;
import quic.cid_registry;
import quic.datagram_port;
import quic.datagram_session;
import quic.tls_client;
import nexus.thirdparty.ngtcp2;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;
import nexus.test.quic_tls_link;
import nexus.test.quic_datagram_link;
import nexus.test.hy2_port_link;
namespace n=nex::ngtcp2;namespace q=quic;namespace h=hysteria2;namespace io=nex::corosio;namespace capy=nex::capy;namespace support=nexus::test::quic_tls;namespace udp=nexus::test::quic_datagram_link;namespace link=nexus::test::hy2_port;
using Clock=std::chrono::steady_clock;using namespace std::chrono_literals;
using Tls=q::TlsClient<support::Pki>;using Registry=q::CidRegistry<4,8>;using App=h::Application<Tls,link::Hooks,4,16384>;using NativeSession=q::DatagramSession<Tls,App>;
struct Bundle {
    Tls tls;link::Hooks hooks;support::Memory memory,h3memory;App app;NativeSession session;q::SessionHandle owner;bool drained=false,passed=false;
    Bundle(std::span<std::uint8_t const> cert,std::uint16_t scheme,Registry& registry,q::SessionHandle owner,capy::async_event& work,io::endpoint const& local)
        :tls(support::hello(scheme),29,support::Pki{cert},"h3"),hooks{registry,owner,work},app(tls,hooks,false,h3memory.http3(),"test-password"),session(tls,app,local),owner(owner){}
};
struct Factory {
    using Session=NativeSession;
    std::span<std::uint8_t const> cert;std::uint16_t scheme;io::endpoint const& local;capy::async_event work;std::array<std::optional<Bundle>,4> bundles;
    unsigned created=0,destroyed=0,failures=0;bool valid=true;
    Factory(std::span<std::uint8_t const> cert,std::uint16_t scheme,io::endpoint const& local):cert(cert),scheme(scheme),local(local){}
    auto admit(n::ngtcp2_pkt_hd const&,io::endpoint const&,Clock::time_point) const noexcept -> bool {return false;}
    auto create(q::SessionHandle,Registry&,std::span<std::uint8_t const>,n::ngtcp2_pkt_hd const&,io::endpoint const&,Clock::time_point) noexcept -> std::expected<Session*,int> {return std::unexpected(n::err_callback_failure);}
    auto application_drained(q::SessionHandle owner,Session const&) const noexcept -> bool {return bundles[owner.slot] && bundles[owner.slot]->drained;}
    auto failed(q::SessionHandle owner,int error) noexcept -> void {++failures;std::println("shared client native failure generation={} code={}",owner.generation,error);}
    auto destroy(q::SessionHandle owner,Session&) noexcept -> void {
        auto& bundle=bundles[owner.slot];valid&=bundle && bundle->drained && bundle->app.clean() && !bundle->memory.used && !bundle->h3memory.used && !bundle->session.transport().key_slots();++destroyed;bundle.reset();
    }
};
using Port=q::DatagramPort<Factory,4,8>;using Driver=net::DatagramDriver<Port>;
struct Root {
    Bundle* bundle;explicit Root(Bundle& bundle):bundle(&bundle){}Root(Root const&)=delete;Root(Root&& other) noexcept:bundle(std::exchange(other.bundle,nullptr)){}~Root(){if(bundle)bundle->drained=true;}
};
auto business(Bundle& bundle,Driver& driver,std::size_t total,Root root) -> capy::task<capy::results<>> {
    auto active=std::move(root);
    while(!bundle.app.authenticated() && !bundle.app.stopping()){
        driver.changed().clear();auto [error]=co_await io::timeout(driver.changed().wait(),Clock::now()+8s);if(error)co_return capy::results<>{error};
    }
    auto stream=bundle.app.open("target.example:443");if(!stream)co_return capy::results<>{std::make_error_code(std::errc::io_error)};driver.notify();h::TcpChannel channel(bundle.app,driver,*stream,Clock::now()+8s);
    if(!co_await channel.ready())co_return capy::results<>{std::make_error_code(std::errc::io_error)};
    std::size_t sent=0,received=0;bool eof=false,valid=true;
    auto upload=[&]() -> capy::task<capy::results<>>{
        std::array<std::uint8_t,7000> bytes{};while(sent<total){auto size=std::min(bytes.size(),total-sent);for(std::size_t i=0;i<size;++i)bytes[i]=static_cast<std::uint8_t>((sent+i)*71+37);
            if(!co_await channel.send(std::span(bytes).first(size))){valid=false;break;}sent+=size;}
        if(valid && !co_await channel.close_output())valid=false;co_return capy::results<>{valid?std::error_code{}:std::make_error_code(std::errc::io_error)};
    };
    auto download=[&]() -> capy::task<capy::results<>>{
        std::array<std::uint8_t,7000> bytes{};while(!eof){auto read=co_await channel.read(bytes);if(!read){valid=false;break;}if(!*read){eof=true;break;}
            for(std::size_t i=0;i<*read;++i)if(bytes[i]!=static_cast<std::uint8_t>((received+i)*71+19))valid=false;received+=*read;}
        co_return capy::results<>{valid?std::error_code{}:std::make_error_code(std::errc::io_error)};
    };
    auto [error,a,b]=co_await capy::when_all(upload(),download());(void)a;(void)b;bundle.passed=!error&&valid&&eof&&sent==total&&received==total;
    std::println("same source client slot={} generation={} bytes={} passed={}",bundle.owner.slot,bundle.owner.generation,total,bundle.passed);
    co_return capy::results<>{bundle.passed?std::error_code{}:std::make_error_code(std::errc::io_error)};
}
auto sessions(Factory& factory,Port& port,Driver& driver,io::endpoint const& peer,std::size_t total,unsigned rounds) -> capy::task<capy::results<>> {
    for(unsigned round=0;round<rounds;++round){
        std::array<q::SessionHandle,2> owners{};
        for(auto& owner:owners){
            auto reserved=port.registry().reserve();if(!reserved)co_return capy::results<>{std::make_error_code(std::errc::no_buffer_space)};owner=*reserved;
            auto source=udp::random_cid(),destination=udp::random_cid();if(!port.registry().insert(owner,{source.data,source.datalen}))co_return capy::results<>{std::make_error_code(std::errc::io_error)};
            auto& bundle=factory.bundles[owner.slot];bundle.emplace(factory.cert,factory.scheme,port.registry(),owner,factory.work,factory.local);auto parameters=support::parameters(false);
            parameters.initial_max_stream_data_bidi_local=parameters.initial_max_stream_data_bidi_remote=16384;parameters.initial_max_streams_bidi=4;parameters.active_connection_id_limit=4;
            if(bundle->session.start(false,destination,source,peer,support::settings(),parameters,bundle->memory.transport(),Clock::now()) || !port.attach(owner,bundle->session))co_return capy::results<>{std::make_error_code(std::errc::io_error)};++factory.created;
        }
        driver.notify();auto& first=*factory.bundles[owners[0].slot];auto& second=*factory.bundles[owners[1].slot];
        auto [error,a,b]=co_await capy::when_all(business(first,driver,total,Root{first}),business(second,driver,total,Root{second}));(void)a;(void)b;
        bool passed=!error && first.passed && second.passed && first.drained && second.drained;
        std::println("same source joined passed={} drained0={} drained1={} pin0={} pin1={}",passed,first.drained,second.drained,port.pinned(owners[0]),port.pinned(owners[1]));
        for(auto owner:owners)(void)port.request_retire(owner);port.maintain();driver.notify();
        while(passed && port.size()){
            driver.changed().clear();auto [wait_error]=co_await io::timeout(driver.changed().wait(),Clock::now()+1s);if(wait_error){passed=false;break;}port.maintain();
        }
        if(!passed || port.size() || factory.failures){driver.cancel();co_return capy::results<>{std::make_error_code(std::errc::io_error)};}
    }
    driver.finish();co_return capy::results<>{};
}
auto run(std::span<std::uint8_t const> cert,std::uint16_t scheme,bool ipv6,bool uring,unsigned peer_port,std::size_t total,unsigned rounds) -> int {
    io::io_context context=io::make_io_context(uring);io::udp_socket socket(context);io::endpoint local=ipv6?io::endpoint(io::ipv6_address::loopback(),0):io::endpoint(io::ipv4_address::loopback(),0);
    io::endpoint peer=ipv6?io::endpoint(io::ipv6_address::loopback(),peer_port):io::endpoint(io::ipv4_address::loopback(),peer_port);
    if(socket.open(local.address().family()) || socket.bind(local))return 1;local=socket.local_endpoint();Factory factory(cert,scheme,local);Port port(factory);Driver driver(socket,port,Clock::now()+20s);bool done=false,failed=false;
    auto all=[&]() -> capy::task<capy::results<>>{auto [error,a,b]=co_await capy::when_all(driver.run(),sessions(factory,port,driver,peer,total,rounds));(void)a;(void)b;co_return capy::results<>{error};};
    std::cout<<"READY "<<local.port()<<std::endl;capy::run_async(context.get_executor(),[&](auto result){done=true;failed=bool(std::get<0>(result));},[&](std::exception_ptr exception){try{std::rethrow_exception(exception);}catch(std::exception const& e){std::println("exception {}",e.what());}done=failed=true;})(all());context.run_for(22s);port.drain();
    std::println("same source shared client done={} failed={} created={} destroyed={} failures={} valid={} drained={} source_port={}",done,failed,factory.created,factory.destroyed,factory.failures,factory.valid,port.drained(),local.port());
    return done&&!failed&&factory.created==2*rounds&&factory.destroyed==factory.created&&!factory.failures&&factory.valid&&driver.drained()&&port.drained()?0:3;
}
auto main(int argc,char** argv) -> int {if(argc!=8)return 1;auto cert=support::read(argv[1]);return run(cert,static_cast<std::uint16_t>(std::stoul(argv[2],nullptr,0)),std::string_view(argv[3])=="6",std::string_view(argv[4])=="1",static_cast<unsigned>(std::stoul(argv[5])),std::stoull(argv[6]),static_cast<unsigned>(std::stoul(argv[7])));}
