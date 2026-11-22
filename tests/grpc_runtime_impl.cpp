module proxy;
import std;
import proxy.v4;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;
namespace rtcapy=nex::capy;namespace rtio=nex::corosio;
namespace {
    using namespace proxy;
    using namespace std::chrono_literals;
    struct Result {bool done=false,passed=false;unsigned stage=0;};
    auto application(rtio::io_context& context,TunnelFactory const& factory,unsigned target,Result& result) -> rtcapy::task<> {
        struct Done {Result& result;TunnelFactory const& factory;rtio::io_context& context;~Done() {result.done=true;factory.stop_context(context);}} done{result,factory,context};
        try {
            Session session(context);
            session.tunnel=factory(session,context,false);
            if (!session.tunnel) co_return;
            result.stage=1;
            if (co_await session.tunnel->connect_until(rtio::endpoint(rtio::ipv4_address::loopback(),static_cast<std::uint16_t>(target)),Clock::now()+4s)!=TunnelConnectResult::connected) co_return;
            result.stage=2;
            std::array<std::uint8_t,8192> bytes{};for (std::size_t i=0;i<bytes.size();++i) bytes[i]=static_cast<std::uint8_t>(i*37);
            if (!co_await session.tunnel->send(bytes) || !co_await session.tunnel->close_output()) co_return;
            result.stage=3;std::array<std::uint8_t,1031> receive{};std::size_t offset=0;
            for (;;) {
                auto got=co_await session.tunnel->read(receive);
                if (!got || *got>bytes.size()-offset) co_return;
                if (!*got) break;
                if (!std::ranges::equal(std::span(receive).first(*got),std::span(bytes).subspan(offset,*got))) co_return;
                offset+=*got;
            }
            result.stage=4;result.passed=offset==bytes.size();
        } catch (...) {}
    }
}
extern "C" int nexus_test_grpc_runtime(char const* uuid,char const* ca,unsigned remote,unsigned target,unsigned backend,unsigned fail,
    void (*inject)(bool,std::size_t) noexcept,bool (*fired)() noexcept) {
    using namespace proxy;
    if (!remote || remote>65535 || !target || target>65535 || backend>1 || (backend && !rtio::has_uring)) return 64;
    auto previous=rtcapy::get_current_frame_allocator();rtcapy::set_current_frame_allocator(std::pmr::new_delete_resource());
    struct Restore {std::pmr::memory_resource* value;~Restore() {rtcapy::set_current_frame_allocator(value);}} restore{previous};
    GrpcTransport transport;transport.service_name="nexus.Service";transport.authority="localhost";
    auto factory=make_vless_factory("127.0.0.1",static_cast<std::uint16_t>(remote),uuid,"localhost",ca,TlsKeyExchange::x25519,{}, {},false,4000,{},{},transport);
    if (!factory) return 2;
    auto context=rtio::make_io_context(backend!=0);context.set_frame_allocator(std::pmr::new_delete_resource());
    DnsRouting routing;routing.servers.emplace_back();
    SharedDnsGeneration generation(1,1);auto dns_profile=generation.registry().register_profile(routing,0);if (!dns_profile) return 2;
    generation.seal();DnsState dns_state(routing,generation.cache(),0,0);
    std::array profiles{*dns_profile};dns_state.views.emplace(generation.registry(),profiles);
    dns_state.local_views.emplace(generation.local_registry());dns_state.coordinator.emplace(context,dns_state.cache,generation.coordinator(),30s);
    LocalDnsState local_dns;
    TcpSocketOptions options;OutboundContext environment{context,&dns_state,&local_dns,nullptr,&options};Result result;
    inject(true,fail);
    try {
        if (factory->start_context(environment,nullptr,false)) {
            rtcapy::run_async(context.get_executor(),std::pmr::new_delete_resource())(application(context,*factory,target,result));
            context.run_for(6s);
        }
    } catch (std::bad_alloc const&) {}
    inject(false,0);
    factory->stop_context(context);context.restart();context.run_for(2s);
    if (!context.stopped()) {std::println("runtime not stopped done={} stage={}",result.done,result.stage);std::_Exit(67);}
    factory->finish_context(context);
    bool fault_drained=context.stopped();bool recovered=false;
    if (fired()) {
        result={};context.restart();
        if (factory->start_context(environment,nullptr,false)) {
            rtcapy::run_async(context.get_executor(),std::pmr::new_delete_resource())(application(context,*factory,target,result));context.run_for(6s);
        }
        factory->stop_context(context);context.restart();context.run_for(2s);
        if (!context.stopped()) std::_Exit(67);
        factory->finish_context(context);recovered=result.done && result.passed && context.stopped();
    }
    std::println("runtime done={} passed={} stage={} stopped={} fault-drained={} recovered={}",result.done,result.passed,result.stage,context.stopped(),fault_drained,recovered);
    return fired() ? (fault_drained && recovered ? 0 : 3) : (result.done && result.passed ? (fail ? 77 : 0) : 1);
}
