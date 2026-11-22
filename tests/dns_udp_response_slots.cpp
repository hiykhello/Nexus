import std;
import ss_udp.shared_coordinator;
import ss_udp.resolve;
import shadowsocks.udp_dispatch;
import proxy;
import rules;
import dns.response_cache;
import dns.local_config;
import dns.corosio_resolver;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;
namespace ss=shadowsocks;
namespace io=nex::corosio;
namespace capy=nex::capy;
using Setup=proxy::udp_runtime::CoordinatorCacheSetup;
using Parent=ss::detail::BasicUdpResolveOperation<Setup::Lookup>;
using Clock=std::chrono::steady_clock;
auto run(Parent::ResponseOperation& operation,bool& done,bool& ok,bool expect_cancel) -> capy::task<> {
    auto result=co_await operation.run();
    ok=expect_cancel ? !result && result.error()==dns::detail::ResolveError::canceled : bool(result);
    done=true;
}
auto main(int argc,char** argv) -> int {
    if(argc!=4 && argc!=5)return 2;
    auto port=[](char const* text) {return static_cast<std::uint16_t>(std::strtoul(text,nullptr,10));};
    bool uring=std::string_view(argv[3])=="uring";
    bool coalesce=argc==5 && std::string_view(argv[4])=="coalesce";
    if(argc==5 && !coalesce)return 2;
#if BOOST_COROSIO_HAVE_LIBURING
    io::io_context context=uring ? io::io_context(io::uring) : io::io_context(io::epoll);
#else
    if(uring)return 77;io::io_context context(io::epoll);
#endif
    std::array<std::size_t,1> capacities{1};
    dns_hp_experiment::GroupSnapshot group(capacities,dns_hp_experiment::GroupSnapshot::SharedCapacity{32},1);
    dns_hp_experiment::Coordinator coordinator(16,64);
    dns_hp_experiment::ViewRegistry views(4,65536,32);
    dns::ResponseCache responses(32);
    proxy::DnsRouting routing;
    proxy::DnsServer a;a.address[0]=127;a.address[3]=1;a.port=port(argv[1]);
    auto b=a;b.port=port(argv[2]);routing.servers={a,b};
    Setup setup;
    if(!setup.bind(group,0,0) || !setup.bind_coordinator(coordinator,views,routing) || !setup.bind_response_cache(responses))return 3;
    views.seal();if(setup.start(context,routing))return 4;
    auto policy=::rules::Matcher::compile({});if(!policy)return 5;
    ss::UdpDispatcher dispatcher(std::move(*policy),4,4,4,4096);
    ss::detail::UdpResponseRouting response_routing;
    response_routing.servers={{{io::ipv4_address::loopback(),a.port},false,{},{}},{{io::ipv4_address::loopback(),b.port},false,{},{}}};
    bool first_done=false,first_ok=false,second_done=false,second_ok=false,second_pending_at_cancel=false;
    {
        Parent parent(dispatcher,context,setup.cache(),{0,{}},false,dns::detail::AddressStrategy::ipv4_only,
            false,false,{}, {},nullptr,setup.reader(),setup.extra(),{}, {},&response_routing,{},{});
        Setup::Lookup base(setup.cache(),setup.reader(),setup.extra());
        auto deadline=Clock::now()+std::chrono::seconds(3);
        Parent::ResponseOperation first(parent,base,0,coalesce ? "shared.test" : "slow.test",1,deadline,!coalesce,{},{});
        Parent::ResponseOperation second(parent,base,coalesce ? 0 : 1,coalesce ? "shared.test" : "fast.test",1,deadline,!coalesce,{},{});
        capy::run_async(context.get_executor())(run(first,first_done,first_ok,true));
        capy::run_async(context.get_executor())(run(second,second_done,second_ok,false));
        auto stop=[&]() -> capy::task<> {io::steady_timer timer(context);timer.expires_at(Clock::now()+std::chrono::milliseconds(150));auto [error]=co_await timer.wait();if(!error){second_pending_at_cancel=!second_done;first.cancel();}};
        capy::run_async(context.get_executor())(stop());
        (void)context.run_for(std::chrono::seconds(4));
        if(!first_done || !first_ok || !second_done || !second_ok || !second_pending_at_cancel) {first.cancel();second.cancel();context.restart();(void)context.run();return 6;}
    }
    {
        auto local=std::make_shared<dns::LocalSnapshot>();dns::LocalServer address;address.address[0]=127;address.address[3]=1;
        local->hosts.push_back({"local.test",address});response_routing.servers.push_back({{},false,{},{}});
        Parent parent(dispatcher,context,setup.cache(),{0,{}},false,dns::detail::AddressStrategy::ipv4_only,
            false,false,{},local,nullptr,setup.reader(),setup.extra(),{}, {},&response_routing,{},{});
        Setup::Lookup base(setup.cache(),setup.reader(),setup.extra());
        Parent::ResponseOperation operation(parent,base,2,"local.test",1,Clock::now()+std::chrono::seconds(2),true,{},{});
        bool done=false,ok=false;
        auto local_task=[&]() -> capy::task<> {auto result=co_await operation.run();ok=result && result->local && !result->upstream.port() && result->question=="local.test";done=true;};
        capy::run_async(context.get_executor())(local_task());context.restart();(void)context.run_for(std::chrono::seconds(1));
        if(!done || !ok)return 8;
    }
    setup.stop_begin();context.restart();(void)context.run_for(std::chrono::seconds(2));
    if(!setup.drained())return 7;setup.stop_end();
    return 0;
}
