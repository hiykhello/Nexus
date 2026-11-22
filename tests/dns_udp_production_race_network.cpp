import std;
import ss_udp.shared_coordinator;
import ss_udp.resolve;
import shadowsocks.udp_dispatch;
import shadowsocks.udp_packet;
import proxy;
import rules;
import dns.address_race_program;
import dns.response_race_walk;
import dns.response_program;
import dns.response_cache;
import dns.corosio_resolver;
import dns.input_budget;
import dns.address_sequence;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;
namespace dns=dns;
namespace ss=shadowsocks;
namespace io=nex::corosio;
namespace capy=nex::capy;
using Clock=std::chrono::steady_clock;
using Setup=proxy::udp_runtime::CoordinatorCacheSetup;
using Parent=ss::detail::BasicUdpResolveOperation<Setup::Lookup>;
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
    if((scenario=="budget" || scenario=="serial-budget" || scenario=="race-result-budget") && !exhausted)return 12;
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
    ::policy::DnsRule evaluate;evaluate.match_all=true;evaluate.action=::policy::DnsAction::evaluate;evaluate.evaluate_tag="slow";
    ::policy::DnsRule match;match.match_all=true;match.match_response=true;match.match_response_tag="slow";match.response=::policy::ResponseCondition{.rcode=0};match.action=::policy::DnsAction::respond;
    auto fast=evaluate;fast.server=1;fast.evaluate_tag="fast";auto fast_match=match;fast_match.match_response_tag="fast";
    if(scenario=="race") {fast.rewrite_ttl=7;fast_match.response->record_ttl_min=7;fast_match.response->record_ttl_max=7;}
    ::policy::DnsRule route;route.match_all=true;route.action=::policy::DnsAction::route;route.server=1;
    std::vector<::policy::DnsRule> rules{evaluate,match};std::vector<dns::ResponseRaceMode> modes{{},{true,false}};
    if(scenario=="race" || scenario=="cancel" || scenario=="ttl" || scenario=="dual" || scenario=="dual-mismatch"){rules.push_back(fast);rules.push_back(fast_match);modes.push_back({false,true});modes.push_back({true,false});}
    else if(scenario=="route"){rules.push_back(route);modes.push_back({false,true});}
    else if(scenario=="serial-cancel"){rules={evaluate,fast,route};modes.clear();}
    else if(scenario!="timeout" && scenario!="budget" && scenario!="serial-budget" && scenario!="race-result-budget")return 2;
    if(scenario=="ttl")rules[2].timeout_ms=200;
    for(auto& rule:rules)if(!::policy::normalize_dns_rule(rule,2))return 6;
    response_routing.rules=rules;
    auto start=Clock::now();std::array<std::uint8_t,16> key{};
    ss::UdpPacket packet{{1},0,1000,{}, {3,10,'a','l','i','a','s','.','t','e','s','t',1,187}, {1,2,3}};
    auto wire=ss::encode_udp_packet(key,ss::UdpDirection::client,packet,{});if(!wire)return 10;
    auto pending=dispatcher.begin_ordered(key,*wire,{4,{127,0,0,1},2222},start,1000,start+std::chrono::seconds(4));if(!pending)return 11;
    bool handled=false;
    auto handler=[&](std::uint64_t token,std::span<ss::UdpPeer const> peers,
        std::chrono::steady_clock::time_point&) -> std::expected<ss::detail::UdpResolvedAction,ss::detail::UdpResolveError> {
        handled=peers.size()==2 && peers[0].family==4 && peers[1].family==6 && peers[0].port==443 && peers[1].port==443;
        (void)dispatcher.cancel(token);return ss::detail::UdpResolvedAction::complete;
    };
    auto active_modes=scenario=="serial-budget" || scenario=="serial-cancel" ? std::span<dns::ResponseRaceMode const>{} : std::span<dns::ResponseRaceMode const>{modes};
    Parent parent(dispatcher,context,setup.cache(),std::move(*pending),false,dns::detail::AddressStrategy::prefer_ipv4,false,false,{}, {},nullptr,setup.reader(),setup.extra(),{}, {},&response_routing,{},handler,active_modes);
    bool done=false,ok=false,held_at_cancel=false,stop_done=scenario!="cancel" && scenario!="serial-cancel";
    auto work=[&]() -> capy::task<> {
        if(scenario=="race-result-budget") {
            bool local=false;auto result=co_await parent.response_address("alias.test",1,Clock::now()+std::chrono::seconds(3),{},local);
            if(result || result.error()!=dns::detail::ResolveError::limit){done=true;co_return;}
            exhausted.reset();if(race_result_budget.used()){done=true;co_return;}
            result=co_await parent.response_address("alias.test",1,Clock::now()+std::chrono::seconds(3),{},local);
            ok=result && !result->addresses.empty() && race_result_budget.used()==0;done=true;co_return;
        }
        if(scenario=="serial-budget") {
            bool local=false;
            auto result=co_await parent.response_address("alias.test",1,Clock::now()+std::chrono::seconds(3),{},local);
            if(result || result.error()!=dns::detail::ResolveError::limit){done=true;co_return;}
            exhausted.reset();if(response_budget.used()){done=true;co_return;}
            result=co_await parent.response_address("alias.test",1,Clock::now()+std::chrono::seconds(3),{},local);
            ok=result && !result->addresses.empty() && response_budget.used()==0;done=true;co_return;
        }
        if(scenario=="serial-cancel") {
            bool local=false;auto result=co_await parent.response_address("alias.test",1,start+std::chrono::seconds(3),{},local);
            ok=!result && result.error()==dns::detail::ResolveError::canceled && response_budget.used()==0;done=true;co_return;
        }
        if(scenario.starts_with("dual")) {
            auto result=co_await parent.run({io::ipv4_address::loopback(),a.port},1,start+std::chrono::seconds(3));
            ok=scenario=="dual" ? result && handled : !result && result.error()==ss::detail::UdpResolveError::dns && !handled;
            done=true;co_return;
        }
        bool local=false;auto deadline=start+std::chrono::milliseconds(scenario=="timeout" ? 200 : 3000);
        auto result=co_await parent.response_address("alias.test",1,deadline,{},local);
        if(scenario=="cancel")ok=!result && result.error()==dns::detail::ResolveError::canceled;
        else if(scenario=="budget")ok=!result && result.error()==dns::detail::ResolveError::limit;
        else if(scenario=="timeout" || scenario=="ttl")ok=!result && result.error()==dns::detail::ResolveError::timeout;
        else ok=result && result->canonical_name=="target.test" && result->addresses.size()==1;
        done=true;
    };
    auto stop=[&]() -> capy::task<> {io::steady_timer timer(context);timer.expires_at(start+std::chrono::milliseconds(150));auto [error]=co_await timer.wait();if(!error){held_at_cancel=response_budget.used()>0;parent.cancel();}stop_done=true;};
    capy::run_async(context.get_executor())(work());if(scenario=="cancel" || scenario=="serial-cancel")capy::run_async(context.get_executor())(stop());
    (void)context.run_for(std::chrono::seconds(5));
    if(!done || !stop_done){parent.cancel();context.restart();(void)context.run();return 7;}
    setup.stop_begin();context.restart();(void)context.run_for(std::chrono::seconds(2));if(!setup.drained())return 8;setup.stop_end();
    if(scenario=="serial-cancel" && !held_at_cancel)return 14;
    if(scenario=="budget"){exhausted.reset();if(receive_budget.used())return 13;}
    return ok ? 0 : 9;
}
