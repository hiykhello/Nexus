import std;
import relay;
import relay.dns_state;
import dns.address_race_program;
import dns.response_race_walk;
import dns.response_program;
import dns.shared_coordinator;
import dns.response_cache;
import dns.local_response;
import dns.corosio_resolver;
import capy;
import corosio;
namespace io = ::corosio;
using Clock=std::chrono::steady_clock;
struct Operation {
    relay::Session& session;io::io_context& context;dns::ResponseStep step;Clock::time_point deadline;
    relay::DnsSlot slot;std::optional<dns::detail::AddressResolver> resolver;bool canceled=false;
    auto cancel() noexcept -> void {canceled=true;slot.cancel();if(resolver)resolver->cancel();}
    auto run() -> capy::task<dns::AddressRaceResult> {
        auto response=co_await relay::resolve_response_owned(session,context,slot,step.server,"alias.test",1,deadline,{},true);
        if(!response)co_return std::unexpected(response.error());
        if(step.action==::policy::DnsAction::evaluate)co_return dns::AddressRaceValue{std::move(*response)};
        auto first=std::optional<dns::Response>{std::move(response->response)};
        resolver.emplace(context,response->tcp,false);
        auto generator=[] {return dns::detail::random_id();};
        auto result=co_await resolver->resolve(response->upstream,{response->question,1},deadline,generator,&first);
        resolver.reset();if(canceled)co_return std::unexpected(dns::detail::ResolveError::canceled);
        if(!result)co_return std::unexpected(result.error());
        co_return dns::AddressRaceValue{std::move(*result)};
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
    relay::DnsRouting routing;relay::DnsServer a;a.address[0]=127;a.address[3]=1;a.port=port(argv[1]);auto b=a;b.port=port(argv[2]);routing.servers={a,b};
    auto pa=views.register_profile(routing,0),pb=views.register_profile(routing,1);if(!pa || !pb)return 3;
    views.seal();std::array profiles{*pa,*pb};relay::DnsState state(std::move(routing),group,0,0);
    state.views.emplace(views,profiles);state.coordinator.emplace(context,state.cache,coordinator);state.response_coordinator.emplace(context,cache,coordinator);
    relay::Session session(context);session.dns=&state;
    ::policy::DnsRule evaluate;evaluate.match_all=true;evaluate.action=::policy::DnsAction::evaluate;evaluate.evaluate_tag="slow";
    ::policy::DnsRule match;match.match_all=true;match.match_response=true;match.match_response_tag="slow";match.response=::policy::ResponseCondition{.rcode=0};match.action=::policy::DnsAction::respond;
    auto fast=evaluate;fast.server=1;fast.evaluate_tag="fast";auto fast_match=match;fast_match.match_response_tag="fast";
    ::policy::DnsRule route;route.match_all=true;route.action=::policy::DnsAction::route;route.server=1;
    std::vector<::policy::DnsRule> rules{evaluate,match};std::vector<dns::ResponseRaceMode> modes{{},{true,false}};
    if(scenario=="race" || scenario=="cancel" || scenario=="ttl") {rules.push_back(fast);rules.push_back(fast_match);modes.push_back({false,true});modes.push_back({true,false});}
    else if(scenario=="route") {rules.push_back(route);modes.push_back({false,true});}
    else if(scenario!="timeout")return 2;
    if(scenario=="ttl")rules[2].timeout_ms=200;
    for(auto& rule:rules)if(!::policy::normalize_dns_rule(rule,2))return 4;
    dns::AddressRaceProgram<Operation> program(context,rules,modes,0);
    auto factory=[&](dns::ResponseStep step,Clock::time_point deadline){return std::make_unique<Operation>(session,context,step,deadline);};
    bool done=false,ok=false,stop_done=scenario!="cancel";auto start=Clock::now();
    auto work=[&]() -> capy::task<> {
        auto result=co_await program.run(factory,"alias.test",1,{},start+std::chrono::milliseconds(scenario=="timeout" ? 200 : 3000));
        if(scenario=="cancel")ok=!result && result.error()==dns::detail::ResolveError::canceled;
        else if(scenario=="timeout")ok=!result && result.error()==dns::detail::ResolveError::timeout;
        else if(result && scenario=="route") {
            ok=result->route && *result->route && std::holds_alternative<dns::AddressAnswer>(**result->route) &&
                std::get<dns::AddressAnswer>(**result->route).addresses.size()==1;
        } else if(result && result->response && result->metadata) {
            auto const& meta=*result->metadata;
            dns::detail::AddressResolver resolver(context,meta.tcp,false,meta.subnet);
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
    if(!done || !stop_done){program.cancel();context.restart();(void)context.run();return 5;}
    state.response_coordinator->stop();state.coordinator->stop();context.restart();(void)context.run_for(std::chrono::seconds(2));
    if(!state.response_coordinator->drained() || !state.coordinator->drained())return 6;
    return ok ? 0 : 7;
}
