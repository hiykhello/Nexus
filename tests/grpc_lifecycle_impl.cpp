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
    auto application(rtio::io_context& context,TunnelFactory const& factory,unsigned target,Result& result,unsigned mode=0) -> rtcapy::task<> {
        struct Done {Result& result;~Done() {result.done=true;}} done{result};
        try {
            Session session(context);
            session.tunnel=factory(session,context,false);
            if (!session.tunnel) co_return;
            result.stage=1;
            if (co_await session.tunnel->connect_until(rtio::endpoint(rtio::ipv4_address::loopback(),static_cast<std::uint16_t>(target)),Clock::now()+4s)!=TunnelConnectResult::connected) co_return;
            result.stage=2;
            if (mode) {if (mode==4) context.stop();std::array<std::uint8_t,17> blocked{};(void)co_await session.tunnel->read(blocked);co_return;}
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
extern "C" int nexus_test_grpc_runtime(char const*,char const*,unsigned,unsigned,unsigned,unsigned,
    void (*)(bool,std::size_t) noexcept,bool (*)() noexcept);
extern "C" int nexus_test_grpc_lifecycle(char const* uuid,char const* ca,unsigned remote,unsigned target,unsigned backend,unsigned mode,
    void (*inject)(bool,std::size_t) noexcept,bool (*fired)() noexcept) {
    using namespace proxy;
    if (!remote || remote>65535 || !target || target>65535 || backend>1 || mode<1 || mode>4 || (backend && !rtio::has_uring)) return 64;
    auto previous=rtcapy::get_current_frame_allocator();rtcapy::set_current_frame_allocator(std::pmr::new_delete_resource());
    struct Restore {std::pmr::memory_resource* value;~Restore() {rtcapy::set_current_frame_allocator(value);}} restore{previous};
    GrpcTransport transport;transport.service_name="nexus.Service";transport.authority="localhost";
    auto factory=make_vless_factory("127.0.0.1",static_cast<std::uint16_t>(remote),uuid,"localhost",ca,TlsKeyExchange::x25519,{}, {},false,4000,{},{},transport);
    if (!factory) return 2;
    auto context_owner=std::unique_ptr<rtio::io_context>(new rtio::io_context(rtio::make_io_context(backend!=0)));auto& context=*context_owner;
    context.set_frame_allocator(std::pmr::new_delete_resource());
    DnsRouting routing;routing.servers.emplace_back();
    SharedDnsGeneration generation(1,1);auto dns_profile=generation.registry().register_profile(routing,0);if (!dns_profile) return 2;
    generation.seal();DnsState dns_state(routing,generation.cache(),0,0);
    std::array profiles{*dns_profile};dns_state.views.emplace(generation.registry(),profiles);
    dns_state.local_views.emplace(generation.local_registry());dns_state.coordinator.emplace(context,dns_state.cache,generation.coordinator(),30s);
    LocalDnsState local_dns;TcpSocketOptions options;OutboundContext environment{context,&dns_state,&local_dns,nullptr,&options};Result result;
    inject(true,0);
    if (!factory->start_context(environment,nullptr,false)) return 2;
    rtcapy::run_async(context.get_executor(),std::pmr::new_delete_resource())(application(context,*factory,target,result,mode));
    if (mode!=3) {
        context.run_for(80ms);
        if (result.stage!=2 || result.done || (context.stopped()!=(mode==4))) return 3;
    }
    factory->stop_context(context);
    if (mode==1) {
        context.restart();context.run_for(2s);
        if (!result.done || !context.stopped()) std::_Exit(67);
        factory->finish_context(context);
    } else {
        // Stop and destroy the real executor with queued/active roots retained.
        // It destroys those task frames before the worker profile is cleared.
        context.stop();dns_state.coordinator.reset();context_owner.reset();
        factory=std::unexpected(std::string{});
        if ((mode==2 || mode==4) && !result.done) return 4;
        if (mode==3 && result.done) return 4;
    }
    inject(false,0);
    auto recovered=nexus_test_grpc_runtime(uuid,ca,remote,target,backend,0,inject,fired)==0;
    std::println("lifecycle mode={} done={} stage={} recovered={}",mode,result.done,result.stage,recovered);
    return recovered ? 0 : 5;
}
