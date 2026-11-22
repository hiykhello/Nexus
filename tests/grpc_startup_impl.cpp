module proxy;
import std;
import proxy.v4;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;
namespace startupcapy=nex::capy;
namespace startupio=nex::corosio;
namespace {
    using namespace proxy;
    using namespace std::chrono_literals;
    struct StartupResult {
        Session* session=nullptr;
        bool done=false,passed=false;
        unsigned stage=0;
        TunnelConnectResult connected=TunnelConnectResult::failed;
    };
    auto startup_application(startupio::io_context& context,TunnelFactory const& factory,
        unsigned target,StartupResult& result,std::chrono::milliseconds budget,bool business=false)
        -> startupcapy::task<> {
        struct Done {StartupResult& result;~Done(){result.session=nullptr;result.done=true;}} done{result};
        try {
            Session session(context);result.session=&session;
            session.tunnel=factory(session,context,false);
            if(!session.tunnel)co_return;
            result.stage=1;
            result.connected=co_await session.tunnel->connect_until(
                startupio::endpoint(startupio::ipv4_address::loopback(),static_cast<std::uint16_t>(target)),Clock::now()+budget);
            if(result.connected!=TunnelConnectResult::connected)co_return;
            result.stage=2;
            if(!business)co_return;
            std::array<std::uint8_t,8192> bytes{};
            for(std::size_t i=0;i<bytes.size();++i)bytes[i]=static_cast<std::uint8_t>(i*37);
            if(!co_await session.tunnel->send(bytes)||!co_await session.tunnel->close_output())co_return;
            std::array<std::uint8_t,1031> receive{};std::size_t offset=0;
            for(;;){
                auto got=co_await session.tunnel->read(receive);
                if(!got||*got>bytes.size()-offset)co_return;
                if(!*got)break;
                if(!std::ranges::equal(std::span(receive).first(*got),std::span(bytes).subspan(offset,*got)))co_return;
                offset+=*got;
            }
            result.passed=offset==bytes.size();result.stage=3;
        }catch(...){}
    }
}
extern "C" int nexus_test_grpc_runtime(char const*,char const*,unsigned,unsigned,unsigned,unsigned,
    void (*)(bool,std::size_t) noexcept,bool (*)() noexcept);
extern "C" int nexus_test_grpc_startup(char const* uuid,char const* ca,unsigned remote,unsigned target,
    unsigned backend,unsigned mode,unsigned stalled,void (*inject)(bool,std::size_t) noexcept,bool (*fired)() noexcept){
    using namespace proxy;
    if(!remote||!target||!stalled||backend>1||mode>3)return 64;
    auto previous=startupcapy::get_current_frame_allocator();startupcapy::set_current_frame_allocator(std::pmr::new_delete_resource());
    struct Restore{std::pmr::memory_resource* value;~Restore(){startupcapy::set_current_frame_allocator(value);}} restore{previous};
    GrpcTransport transport;transport.service_name="nexus.Service";transport.authority="localhost";
    auto make=[&](unsigned port){return make_vless_factory("127.0.0.1",static_cast<std::uint16_t>(port),uuid,"localhost",ca,
        TlsKeyExchange::x25519,{}, {},false,4000,{},{},transport);};
    auto factory=make(stalled);if(!factory)return 2;
    auto owner=std::unique_ptr<startupio::io_context>(new startupio::io_context(startupio::make_io_context(backend!=0)));auto& context=*owner;
    context.set_frame_allocator(std::pmr::new_delete_resource());
    DnsRouting routing;routing.servers.emplace_back();SharedDnsGeneration generation(1,1);
    auto profile=generation.registry().register_profile(routing,0);if(!profile)return 2;generation.seal();
    DnsState dns(routing,generation.cache(),0,0);std::array profiles{*profile};
    dns.views.emplace(generation.registry(),profiles);dns.local_views.emplace(generation.local_registry());
    dns.coordinator.emplace(context,dns.cache,generation.coordinator(),30s);
    LocalDnsState local;TcpSocketOptions options;OutboundContext environment{context,&dns,&local,nullptr,&options};
    StartupResult first,second;inject(true,0);
    if(!factory->start_context(environment,nullptr,false))return 2;
    startupcapy::run_async(context.get_executor(),std::pmr::new_delete_resource())(startup_application(context,*factory,target,first,4s));
    context.run_for(20ms);
    startupcapy::run_async(context.get_executor(),std::pmr::new_delete_resource())(startup_application(context,*factory,target,second,mode==2?40ms:4s));
    context.restart();context.run_for(10ms);
    if(first.stage!=1||second.stage!=1||first.done||second.done||!second.session)return 3;
    if(mode==1||mode==2){
        if(mode==1)second.session->close();
        context.restart();context.run_for(120ms);
        if(!second.done||first.done||first.stage!=1||(mode==2&&second.connected!=TunnelConnectResult::timeout))return 4;
    }
    bool recovered=false;
    if(mode==3){
        context.stop();dns.coordinator.reset();owner.reset();factory=std::unexpected(std::string{});
        if(!first.done||!second.done)return 5;
        inject(false,0);recovered=nexus_test_grpc_runtime(uuid,ca,remote,target,backend,0,inject,fired)==0;
    }else{
        factory->stop_context(context);context.restart();context.run_for(1s);
        if(!first.done||!second.done||!context.stopped())return 6;
        factory->finish_context(context);factory=make(remote);if(!factory)return 7;
        StartupResult fresh;context.restart();if(!factory->start_context(environment,nullptr,false))return 7;
        startupcapy::run_async(context.get_executor(),std::pmr::new_delete_resource())(startup_application(context,*factory,target,fresh,4s,true));
        context.run_for(200ms);factory->stop_context(context);context.restart();context.run_for(1s);
        recovered=fresh.done&&fresh.passed&&context.stopped();factory->finish_context(context);inject(false,0);
    }
    std::println("startup mode={} first-done={} second-done={} recovered={}",mode,first.done,second.done,recovered);
    return recovered?0:8;
}
