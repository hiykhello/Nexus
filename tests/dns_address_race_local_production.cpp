import std;
import proxy;
import proxy.dns_state;
import ss_udp.shared_coordinator;
import ss_udp.resolve;
import shadowsocks.udp_dispatch;
import rules;
import dns.response_race_walk;
import dns.response_cache;
import dns.local_config;
import dns.corosio_resolver;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;
namespace ss=shadowsocks;
namespace io=nex::corosio;
namespace capy=nex::capy;
using Clock=std::chrono::steady_clock;
using Setup=proxy::udp_runtime::CoordinatorCacheSetup;
using Parent=ss::detail::BasicUdpResolveOperation<Setup::Lookup>;
auto main(int argc,char** argv) -> int {
    if(argc!=5)return 2;
    bool uring=std::string_view(argv[1])=="uring",udp=std::string_view(argv[2])=="udp";
    if(!udp && std::string_view(argv[2])!="tcp")return 2;
#if BOOST_COROSIO_HAVE_LIBURING
    io::io_context context=uring ? io::io_context(io::uring) : io::io_context(io::epoll);
#else
    if(uring)return 77;io::io_context context(io::epoll);
#endif
    auto port=static_cast<std::uint16_t>(std::strtoul(argv[3],nullptr,10));
    auto snapshot=std::make_shared<dns::LocalSnapshot>();dns::LocalServer server;server.address[0]=127;server.address[3]=1;server.port=port;
    snapshot->config.servers.push_back(server);snapshot->config.search={"one.test","two.test"};snapshot->config.attempts=1;
    std::array<std::size_t,1> capacities{1};dns_hp_experiment::GroupSnapshot group(capacities,dns_hp_experiment::GroupSnapshot::SharedCapacity{32},1);
    dns_hp_experiment::Coordinator coordinator(16,64);dns_hp_experiment::ViewRegistry views(4,65536,32);dns::ResponseCache cache(32);
    proxy::DnsRouting routing;proxy::DnsServer local;routing.servers={local};
    ::policy::DnsRule first;first.match_all=true;first.action=::policy::DnsAction::evaluate;first.evaluate_tag="first";
    auto second=first;second.evaluate_tag="second";
    ::policy::DnsRule matched;matched.match_all=true;matched.match_response=true;matched.match_response_tag="second";matched.action=::policy::DnsAction::respond;
    routing.rules={first,second,matched};routing.strategy=proxy::DnsStrategy::prefer_ipv4;
    for(auto& rule:routing.rules)if(!::policy::normalize_dns_rule(rule,1))return 3;
    std::array modes{dns::ResponseRaceMode{},dns::ResponseRaceMode{},dns::ResponseRaceMode{true,false}};
    bool done=false,ok=false;
    if(!udp) {
        auto profile=views.register_profile(routing,0);if(!profile)return 4;views.seal();std::array profiles{*profile};
        proxy::DnsState state(std::move(routing),group,0,0);dns_hp_experiment::LocalViewRegistry local_registry;
        state.views.emplace(views,profiles);state.local_views.emplace(local_registry);state.coordinator.emplace(context,state.cache,coordinator);state.response_coordinator.emplace(context,cache,coordinator);
        // The fixture receives an isolated resolv/hosts pair; LocalSnapshotSource
        // keeps the same immutable generation throughout the request.
        dns::LocalSnapshotSource source(argv[4],"/etc/hosts");
        proxy::LocalDnsState local_state{source};proxy::Session session(context);session.dns=&state;session.local_dns=&local_state;
        auto work=[&]() -> capy::task<> {
            auto result=co_await proxy::resolve_destination_race(session,context,"short",443,Clock::now()+std::chrono::seconds(4),{},modes);
            ok=result && result->size()==2 && (*result)[0].address().is_v4() && (*result)[1].address().is_v6();done=true;
        };
        capy::run_async(context.get_executor())(work());(void)context.run_for(std::chrono::seconds(5));
        if(!done || !ok){if(session.cancel_dns)session.cancel_dns(session.dns_operation);context.restart();(void)context.run();return 5;}
        state.response_coordinator->stop();state.coordinator->stop();context.restart();(void)context.run_for(std::chrono::seconds(1));
        if(!state.response_coordinator->drained() || !state.coordinator->drained())return 6;
    } else {
        Setup setup;dns_hp_experiment::LocalViewRegistry local_registry;
        if(!setup.bind(group,0,0) || !setup.bind_coordinator(coordinator,views,routing) || !setup.bind_response_cache(cache) || !setup.bind_local(local_registry))return 7;
        views.seal();if(setup.start(context,routing))return 8;
        auto matcher=::rules::Matcher::compile({});if(!matcher)return 9;ss::UdpDispatcher dispatcher(std::move(*matcher),2,2,2,4096);
        ss::detail::UdpResponseRouting response;response.servers={{{},false,{},{}}};response.rules=routing.rules;
        Parent parent(dispatcher,context,setup.cache(),{0,{}},false,dns::detail::AddressStrategy::prefer_ipv4,false,false,{},snapshot,nullptr,setup.reader(),setup.extra(),{}, {},&response,{}, {},modes);
        auto work=[&]() -> capy::task<> {
            bool local_used=false;
            auto a=co_await parent.response_address("short",1,Clock::now()+std::chrono::seconds(4),{},local_used);
            auto b=co_await parent.response_address("short",28,Clock::now()+std::chrono::seconds(4),{},local_used);
            ok=a && b && a->canonical_name=="short.two.test" && b->canonical_name==a->canonical_name && local_used;done=true;
        };
        capy::run_async(context.get_executor())(work());(void)context.run_for(std::chrono::seconds(5));
        if(!done || !ok){parent.cancel();context.restart();(void)context.run();return 10;}
        setup.stop_begin();context.restart();(void)context.run_for(std::chrono::seconds(1));if(!setup.drained())return 11;setup.stop_end();
    }
    return 0;
}
