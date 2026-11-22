import std;
import ss_udp.shared_coordinator;
import ss_udp.resolve;
import shadowsocks.udp_dispatch;
import proxy;
import rules;
import dns.address_race_program;
import dns.response_race_walk;
import dns.response_program;
import dns.response_cache;
import dns.corosio_resolver;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;
namespace ss=shadowsocks;
namespace io=nex::corosio;
namespace capy=nex::capy;
using Clock=std::chrono::steady_clock;
using Setup=proxy::udp_runtime::CoordinatorCacheSetup;
using Parent=ss::detail::BasicUdpResolveOperation<Setup::Lookup>;
struct Operation {
    Parent::ResponseOperation operation;io::io_context& context;dns::ResponseStep step;Clock::time_point deadline;
    std::optional<dns::detail::AddressResolver> resolver;bool canceled=false;
    Operation(Parent& parent,Setup::Lookup const& prototype,io::io_context& context,dns::ResponseStep step,Clock::time_point deadline)
        :operation(parent,prototype,step.server,"alias.test",1,deadline,true,{},{}),context(context),step(step),deadline(deadline) {}
    auto cancel() noexcept -> void {canceled=true;operation.cancel();if(resolver)resolver->cancel();}
    auto run() -> capy::task<dns::AddressRaceResult> {
        auto response=co_await operation.run();if(!response)co_return std::unexpected(response.error());
        if(step.action==::policy::DnsAction::evaluate)co_return dns::AddressRaceValue{std::move(*response)};
        auto first=std::optional<dns::Response>{std::move(response->response)};
        resolver.emplace(context,response->tcp,false);
        auto generator=[] {return dns::detail::random_id();};
        auto answer=co_await resolver->resolve(response->upstream,{response->question,1},deadline,generator,&first);
        resolver.reset();if(canceled)co_return std::unexpected(dns::detail::ResolveError::canceled);
        if(!answer)co_return std::unexpected(answer.error());
        co_return dns::AddressRaceValue{std::move(*answer)};
    }
};
auto main(int argc,char** argv) -> int {
    if(argc!=5)return 2;
    auto port=[](char const* text){return static_cast<std::uint16_t>(std::strtoul(text,nullptr,10));};
    bool uring=std::string_view(argv[3])=="uring";auto scenario=std::string_view(argv[4]);
#if BOOST_COROSIO_HAVE_LIBURING
    io::io_context context=uring ? io::io_context(io::uring) : io::io_context(io::epoll);
#else
    if(uring)return 77;io::io_context context(io::epoll);
#endif
    std::array<std::size_t,1> capacities{1};dns_hp_experiment::GroupSnapshot group(capacities,dns_hp_experiment::GroupSnapshot::SharedCapacity{32},1);
    dns_hp_experiment::Coordinator coordinator(16,64);dns_hp_experiment::ViewRegistry views(4,65536,32);dns::ResponseCache cache(32);
    proxy::DnsRouting routing;proxy::DnsServer a;a.address[0]=127;a.address[3]=1;a.port=port(argv[1]);auto b=a;b.port=port(argv[2]);routing.servers={a,b};
    Setup setup;if(!setup.bind(group,0,0) || !setup.bind_coordinator(coordinator,views,routing) || !setup.bind_response_cache(cache))return 3;
    views.seal();if(setup.start(context,routing))return 4;
    auto policy=::rules::Matcher::compile({});if(!policy)return 5;ss::UdpDispatcher dispatcher(std::move(*policy),4,4,4,4096);
    ss::detail::UdpResponseRouting response_routing;
    response_routing.servers={{{io::ipv4_address::loopback(),a.port},false,{},{}},{{io::ipv4_address::loopback(),b.port},false,{},{}}};
    Parent parent(dispatcher,context,setup.cache(),{0,{}},false,dns::detail::AddressStrategy::ipv4_only,false,false,{}, {},nullptr,setup.reader(),setup.extra(),{}, {},&response_routing,{},{});
    Setup::Lookup prototype(setup.cache(),setup.reader(),setup.extra());
    ::policy::DnsRule evaluate;evaluate.match_all=true;evaluate.action=::policy::DnsAction::evaluate;evaluate.evaluate_tag="slow";
    ::policy::DnsRule match;match.match_all=true;match.match_response=true;match.match_response_tag="slow";match.response=::policy::ResponseCondition{.rcode=0};match.action=::policy::DnsAction::respond;
    auto fast=evaluate;fast.server=1;fast.evaluate_tag="fast";auto fast_match=match;fast_match.match_response_tag="fast";
    ::policy::DnsRule route;route.match_all=true;route.action=::policy::DnsAction::route;route.server=1;
    std::vector<::policy::DnsRule> rules{evaluate,match};std::vector<dns::ResponseRaceMode> modes{{},{true,false}};
    if(scenario=="race" || scenario=="cancel" || scenario=="ttl"){rules.push_back(fast);rules.push_back(fast_match);modes.push_back({false,true});modes.push_back({true,false});}
    else if(scenario=="route"){rules.push_back(route);modes.push_back({false,true});}else if(scenario!="timeout")return 2;
    if(scenario=="ttl")rules[2].timeout_ms=200;
    for(auto& rule:rules)if(!::policy::normalize_dns_rule(rule,2))return 6;
    dns::AddressRaceProgram<Operation> program(context,rules,modes,0);
    auto factory=[&](dns::ResponseStep step,Clock::time_point deadline){return std::make_unique<Operation>(parent,prototype,context,step,deadline);};
    bool done=false,ok=false,stop_done=scenario!="cancel";auto start=Clock::now();
    auto work=[&]() -> capy::task<> {
        auto result=co_await program.run(factory,"alias.test",1,{},start+std::chrono::milliseconds(scenario=="timeout" ? 200 : 3000));
        if(scenario=="cancel")ok=!result && result.error()==dns::detail::ResolveError::canceled;
        else if(scenario=="timeout")ok=!result && result.error()==dns::detail::ResolveError::timeout;
        else if(result && scenario=="route")ok=result->route && *result->route && std::holds_alternative<dns::AddressAnswer>(**result->route) && std::get<dns::AddressAnswer>(**result->route).addresses.size()==1;
        else if(result && result->response && result->metadata) {
            auto const& meta=*result->metadata;dns::detail::AddressResolver resolver(context,meta.tcp,false,meta.subnet);
            auto generator=[] {return dns::detail::random_id();};
            auto answer=co_await resolver.resolve(meta.upstream,{meta.question,1},meta.deadline,generator,&result->response);
            ok=meta.upstream.port()==port(argv[2]) && (scenario=="ttl" ? !answer && answer.error()==dns::detail::ResolveError::timeout :
                answer && answer->canonical_name=="target.test" && answer->addresses.size()==1);
        }
        done=true;
    };
    auto stop=[&]() -> capy::task<> {io::steady_timer timer(context);timer.expires_at(start+std::chrono::milliseconds(150));auto [error]=co_await timer.wait();if(!error)program.cancel();stop_done=true;};
    capy::run_async(context.get_executor())(work());if(scenario=="cancel")capy::run_async(context.get_executor())(stop());
    (void)context.run_for(std::chrono::seconds(5));
    if(!done || !stop_done){program.cancel();context.restart();(void)context.run();return 7;}
    setup.stop_begin();context.restart();(void)context.run_for(std::chrono::seconds(2));if(!setup.drained())return 8;setup.stop_end();
    return ok ? 0 : 9;
}
