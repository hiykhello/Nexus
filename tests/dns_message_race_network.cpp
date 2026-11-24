import std;
import dns.message;
import dns.message_exchange;
import dns.message_program;
import dns.response_race_walk;
import dns.policy;
import dns.corosio_resolver;
import capy;
import corosio;
namespace io = ::corosio;
auto main(int argc,char** argv) -> int {
    if(argc!=5)return 2;
    auto port=[](char const* text) {return static_cast<std::uint16_t>(std::strtoul(text,nullptr,10));};
    bool uring=std::string_view(argv[3])=="uring";auto scenario=std::string_view(argv[4]);
#if BOOST_COROSIO_HAVE_LIBURING
    io::io_context context=uring ? io::io_context(io::uring) : io::io_context(io::epoll);
#else
    if(uring)return 77;io::io_context context(io::epoll);
#endif
    std::array<dns::MessageUpstream,2> upstreams{{{{io::ipv4_address::loopback(),port(argv[1])},false,nullptr},
                                                 {{io::ipv4_address::loopback(),port(argv[2])},false,nullptr}}};
    ::policy::DnsRule a;a.match_all=true;a.action=::policy::DnsAction::evaluate;a.evaluate_tag="a";
    ::policy::DnsRule b=a;b.evaluate_tag="b";b.server=1;
    ::policy::DnsRule response;response.match_all=true;response.match_response=true;response.match_response_tag="a";
    response.response=::policy::ResponseCondition{.rcode=0};response.action=::policy::DnsAction::respond;
    auto second=response;second.match_response_tag="b";
    if(scenario=="race") {b.rewrite_ttl=7;second.response->record_ttl_min=7;second.response->record_ttl_max=7;}
    ::policy::DnsRule route;route.match_all=true;route.action=::policy::DnsAction::route;route.server=1;
    std::vector<::policy::DnsRule> rules{a,response};
    std::vector<dns::ResponseRaceMode> modes{{},{true,false}};
    if(scenario=="race-route") {rules[1].action=::policy::DnsAction::route;rules[1].server=1;}
    else if(scenario=="race" || scenario=="miss" || scenario=="fail" || scenario=="ecs" || scenario=="cancel") {
        if(scenario=="ecs") {::policy::ResponsePrefix prefix{};prefix.size=4;prefix.bits=24;prefix.address[0]=198;prefix.address[1]=51;prefix.address[2]=100;b.client_subnet=prefix;}
        rules.push_back(b);rules.push_back(second);modes.push_back({false,true});modes.push_back({true,false});
    } else if(scenario=="route" || scenario=="route-ready") {rules.push_back(route);modes.push_back({false,true});}
    else if(scenario!="timeout")return 2;
    for(auto& rule:rules)if(!::policy::normalize_dns_rule(rule,2))return 3;
    dns::MessageProgram program(context,rules,upstreams,0,nullptr,false,modes);
    bool done=false,ok=false,cancel_done=scenario!="cancel";auto start=std::chrono::steady_clock::now();
    auto deadline=start+std::chrono::milliseconds(scenario=="timeout" ? 200 : 3000);
    dns::QueryMessage query{42,0x0100,{"owner.test",1},{}};
    if(scenario=="ecs") {
        query.edns=dns::QueryEdns{1232,0,false,{}};
        dns::ClientSubnet subnet{1,24,{192,0,2}};
        if(!dns::set_query_client_subnet(query,subnet))return 6;
        query.edns->options.push_back({65001,dns::Bytes(2048,0x5a)});
    }
    auto task=[&]() -> capy::task<> {
        auto result=co_await program.run(query,deadline,{});
        if(scenario=="timeout")ok=!result && result.error()==dns::detail::ResolveError::timeout;
        else if(scenario=="cancel")ok=!result && result.error()==dns::detail::ResolveError::canceled;
        else if(result) {
            if(scenario=="ecs") {
                auto response=dns::parse_response(*result,42,query.question);
                std::array<std::uint8_t,11> expected{0,8,0,7,0,1,24,24,192,0,2};
                ok=response && bool(dns::validate_response_ecs(query,*response)) &&
                    std::ranges::search(*result,expected).begin()!=result->end();
            } else {
                auto answer=dns::parse_addresses(*result,42,{"owner.test",1});
                ok=answer && answer->addresses.size()==1 && answer->addresses[0].bytes[0]==127;
            }
        }
        done=true;
    };
    capy::run_async(context.get_executor(),[]() noexcept {},[&](std::exception_ptr) noexcept {done=true;})(task());
    auto stop=[&]() -> capy::task<> {io::steady_timer timer(context);timer.expires_at(start+std::chrono::milliseconds(150));auto [error]=co_await timer.wait();if(!error)program.cancel();cancel_done=true;};
    if(scenario=="cancel") {
        capy::run_async(context.get_executor(),[]() noexcept {},[&](std::exception_ptr) noexcept {cancel_done=true;})(stop());
    }
    (void)context.run_for(std::chrono::seconds(5));
    if(!done || !cancel_done){program.cancel();context.restart();(void)context.run();return 4;}
    return ok ? 0 : 5;
}
