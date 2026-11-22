import std;
import proxy;
import proxy.dns_state;
import dns.address_race_program;
import dns.response_race_walk;
import dns.response_program;
import dns.shared_coordinator;
import dns.response_cache;
import dns.local_response;
import dns.corosio_resolver;
import dns.input_budget;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;
namespace io=nex::corosio;
namespace capy=nex::capy;
using Clock=std::chrono::steady_clock;
auto main(int argc,char** argv) -> int {
    if(argc!=5)return 2;
    auto port=[](char const* text){return static_cast<std::uint16_t>(std::strtoul(text,nullptr,10));};
    bool uring=std::string_view(argv[3])=="uring";auto scenario=std::string_view(argv[4]);
    auto& receive_budget=dns::default_upstream_receive_budget();
    auto& response_budget=dns::default_serial_response_budget();
    auto& race_result_budget=dns::default_address_race_result_budget();
    std::optional<dns::InputBudget::Lease> exhausted;
    if(scenario=="budget"){auto lease=receive_budget.acquire(receive_budget.limit());if(lease)exhausted.emplace(std::move(*lease));}
    if(scenario=="serial-budget"){auto lease=response_budget.acquire(response_budget.limit());if(lease)exhausted.emplace(std::move(*lease));}
    if(scenario=="race-result-budget"){auto lease=race_result_budget.acquire(race_result_budget.limit());if(lease)exhausted.emplace(std::move(*lease));}
    if((scenario=="budget" || scenario=="serial-budget" || scenario=="race-result-budget") && !exhausted)return 8;
#if BOOST_COROSIO_HAVE_LIBURING
    io::io_context context=uring ? io::io_context(io::uring) : io::io_context(io::epoll);
#else
    if(uring)return 77;io::io_context context(io::epoll);
#endif
    std::array<std::size_t,1> capacities{1};dns_hp_experiment::GroupSnapshot group(capacities,dns_hp_experiment::GroupSnapshot::SharedCapacity{32},1);
    dns_hp_experiment::Coordinator coordinator(16,64);dns_hp_experiment::ViewRegistry views(4,65536,32);dns::ResponseCache cache(32);
    proxy::DnsRouting routing;proxy::DnsServer a;a.address[0]=127;a.address[3]=1;a.port=port(argv[1]);auto b=a;b.port=port(argv[2]);routing.servers={a,b};
    auto pa=views.register_profile(routing,0),pb=views.register_profile(routing,1);if(!pa || !pb)return 3;
    views.seal();std::array profiles{*pa,*pb};proxy::DnsState state(std::move(routing),group,0,0);
    state.views.emplace(views,profiles);state.coordinator.emplace(context,state.cache,coordinator);state.response_coordinator.emplace(context,cache,coordinator);
    proxy::Session session(context);session.dns=&state;
    ::policy::DnsRule evaluate;evaluate.match_all=true;evaluate.action=::policy::DnsAction::evaluate;evaluate.evaluate_tag="slow";
    ::policy::DnsRule match;match.match_all=true;match.match_response=true;match.match_response_tag="slow";match.response=::policy::ResponseCondition{.rcode=0};match.action=::policy::DnsAction::respond;
    auto fast=evaluate;fast.server=1;fast.evaluate_tag="fast";auto fast_match=match;fast_match.match_response_tag="fast";
    if(scenario=="race") {fast.rewrite_ttl=7;fast_match.response->record_ttl_min=7;fast_match.response->record_ttl_max=7;}
    ::policy::DnsRule route;route.match_all=true;route.action=::policy::DnsAction::route;route.server=1;
    std::vector<::policy::DnsRule> rules{evaluate,match};std::vector<dns::ResponseRaceMode> modes{{},{true,false}};
    if(scenario=="race" || scenario=="cancel" || scenario=="ttl" || scenario=="dual" || scenario=="dual-mismatch") {rules.push_back(fast);rules.push_back(fast_match);modes.push_back({false,true});modes.push_back({true,false});}
    else if(scenario=="route") {rules.push_back(route);modes.push_back({false,true});}
    else if(scenario=="serial-cancel") {rules={evaluate,fast,route};modes.clear();}
    else if(scenario!="timeout" && scenario!="budget" && scenario!="serial-budget" && scenario!="race-result-budget")return 2;
    if(scenario=="ttl")rules[2].timeout_ms=200;
    for(auto& rule:rules)if(!::policy::normalize_dns_rule(rule,2))return 4;
    state.routing.rules=rules;state.has_response_program=true;state.routing.strategy=scenario.starts_with("dual") ? proxy::DnsStrategy::prefer_ipv4 : proxy::DnsStrategy::ipv4_only;
    bool done=false,ok=false,held_at_cancel=false,stop_done=scenario!="cancel" && scenario!="serial-cancel";auto start=Clock::now();
    auto work=[&]() -> capy::task<> {
        if(scenario=="race-result-budget") {
            auto result=co_await proxy::resolve_destination_race(session,context,"alias.test",443,Clock::now()+std::chrono::seconds(3),{},modes);
            if(result || result.error()!=dns::detail::ResolveError::limit){done=true;co_return;}
            exhausted.reset();if(race_result_budget.used()){done=true;co_return;}
            result=co_await proxy::resolve_destination_race(session,context,"alias.test",443,Clock::now()+std::chrono::seconds(3),{},modes);
            ok=result && result->size()==1 && race_result_budget.used()==0;done=true;co_return;
        }
        if(scenario=="serial-budget") {
            auto result=co_await proxy::resolve_destination_race(session,context,"alias.test",443,Clock::now()+std::chrono::seconds(3),{},{});
            if(result || result.error()!=dns::detail::ResolveError::limit){done=true;co_return;}
            exhausted.reset();
            if(response_budget.used()){done=true;co_return;}
            result=co_await proxy::resolve_destination_race(session,context,"alias.test",443,Clock::now()+std::chrono::seconds(3),{},{});
            ok=result && result->size()==1 && response_budget.used()==0;done=true;co_return;
        }
        if(scenario=="serial-cancel") {
            auto result=co_await proxy::resolve_destination_race(session,context,"alias.test",443,start+std::chrono::seconds(3),{},{});
            ok=!result && result.error()==dns::detail::ResolveError::canceled && response_budget.used()==0;done=true;co_return;
        }
        auto result=co_await proxy::resolve_destination_race(session,context,"alias.test",443,
            start+std::chrono::milliseconds(scenario=="timeout" ? 200 : 3000),{},modes);
        if(scenario=="cancel")ok=!result && result.error()==dns::detail::ResolveError::canceled;
        else if(scenario=="budget")ok=!result && result.error()==dns::detail::ResolveError::limit;
        else if(scenario=="timeout" || scenario=="ttl")ok=!result && result.error()==dns::detail::ResolveError::timeout;
        else if(scenario=="dual-mismatch")ok=!result && result.error()==dns::detail::ResolveError::protocol;
        else if(scenario=="dual")ok=result && result->size()==2 && (*result)[0].address().is_v4() && (*result)[1].address().is_v6();
        else ok=result && result->size()==1 && (*result)[0].port()==443 && (*result)[0].address().is_v4();
        done=true;
    };
    auto stop=[&]() -> capy::task<> {io::steady_timer timer(context);timer.expires_at(start+std::chrono::milliseconds(150));auto [error]=co_await timer.wait();if(!error && session.cancel_dns){held_at_cancel=response_budget.used()>0;session.cancel_dns(session.dns_operation);}stop_done=true;};
    capy::run_async(context.get_executor())(work());if(scenario=="cancel" || scenario=="serial-cancel")capy::run_async(context.get_executor())(stop());
    (void)context.run_for(std::chrono::seconds(5));
    if(!done || !stop_done){if(session.cancel_dns)session.cancel_dns(session.dns_operation);context.restart();(void)context.run();return 5;}
    state.response_coordinator->stop();state.coordinator->stop();context.restart();(void)context.run_for(std::chrono::seconds(2));
    if(!state.response_coordinator->drained() || !state.coordinator->drained())return 6;
    if(scenario=="serial-cancel" && !held_at_cancel)return 10;
    if(scenario=="budget"){exhausted.reset();if(receive_budget.used())return 9;}
    return ok ? 0 : 7;
}
