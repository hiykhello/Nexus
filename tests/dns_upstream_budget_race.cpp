import std;
import dns.input_budget;
import dns.message;
import dns.message_program;
import dns.message_race_program;
import dns.response_race_walk;
import dns.policy;
import dns.corosio_resolver;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;
namespace dns=dns;namespace io=nex::corosio;namespace capy=nex::capy;
using namespace std::chrono_literals;
auto work(io::io_context& context,std::uint16_t port,bool& ok) -> capy::task<> {
    auto& budget=dns::default_upstream_receive_budget();auto all=budget.acquire(budget.limit());if(!all)co_return;
    ::policy::DnsRule a;a.match_all=true;a.action=::policy::DnsAction::evaluate;a.evaluate_tag="a";
    ::policy::DnsRule judge;judge.match_all=true;judge.match_response=true;judge.match_response_tag="a";judge.action=::policy::DnsAction::respond;
    auto b=a;b.evaluate_tag="b";
    ::policy::DnsRule route;route.match_all=true;route.action=::policy::DnsAction::route;
    std::array<dns::MessageUpstream,1> upstreams{{{{io::ipv4_address::loopback(),port},false,nullptr}}};
    auto deadline=std::chrono::steady_clock::now()+2s;
    dns::QueryMessage query{42,0x0100,{"budget.test",1},{}};
    {
        std::array rules{a,route};dns::MessageProgram program(context,rules,upstreams,0,nullptr,true);
        auto result=co_await program.run(query,deadline,{});
        if(result || result.error()!=dns::detail::ResolveError::limit)co_return;
    }
    {
        std::array rules{a,judge,b,route};std::array modes{dns::ResponseRaceMode{},dns::ResponseRaceMode{true,false},dns::ResponseRaceMode{false,true},dns::ResponseRaceMode{}};
        dns::MessageRaceProgram program(context,rules,modes,upstreams,0,nullptr,true);
        auto result=co_await program.run(query,deadline,{});
        if(result || result.error()!=dns::detail::ResolveError::limit)co_return;
    }
    all.reset();if(budget.used()!=0)co_return;
    auto& saved_budget=dns::default_serial_response_budget();
    auto reserved=saved_budget.acquire(saved_budget.limit());if(!reserved)co_return;
    {
        std::array rules{a,route};dns::MessageProgram program(context,rules,upstreams,0,nullptr,true);
        auto result=co_await program.run(query,std::chrono::steady_clock::now()+2s,{});
        if(result || result.error()!=dns::detail::ResolveError::limit)co_return;
    }
    reserved.reset();if(saved_budget.used()!=0)co_return;
    {
        std::array rules{a,route};dns::MessageProgram program(context,rules,upstreams,0,nullptr,true);
        auto result=co_await program.run(query,std::chrono::steady_clock::now()+2s,{});
        if(!result || saved_budget.used()!=0)co_return;
    }
    auto& race_budget=dns::default_message_race_result_budget();
    auto race_reserved=race_budget.acquire(race_budget.limit());if(!race_reserved)co_return;
    {
        std::array rules{a,judge};std::array modes{dns::ResponseRaceMode{},dns::ResponseRaceMode{}};
        dns::MessageRaceProgram program(context,rules,modes,upstreams,0,nullptr,true);
        auto result=co_await program.run(query,std::chrono::steady_clock::now()+2s,{});
        if(result || result.error()!=dns::detail::ResolveError::limit)co_return;
    }
    race_reserved.reset();if(race_budget.used())co_return;
    {
        std::array rules{a,judge};std::array modes{dns::ResponseRaceMode{},dns::ResponseRaceMode{}};
        dns::MessageRaceProgram program(context,rules,modes,upstreams,0,nullptr,true);
        auto result=co_await program.run(query,std::chrono::steady_clock::now()+2s,{});
        if(!result || race_budget.used())co_return;
    }
    ok=budget.used()==0 && saved_budget.used()==0 && race_budget.used()==0;
}
auto main(int argc,char** argv) -> int {
    if(argc!=3)return 2;bool uring=std::string_view(argv[1])=="uring";
#if BOOST_COROSIO_HAVE_LIBURING
    io::io_context context=uring ? io::io_context(io::uring) : io::io_context(io::epoll);
#else
    if(uring)return 77;io::io_context context(io::epoll);
#endif
    bool done=false,ok=false;auto port=static_cast<std::uint16_t>(std::strtoul(argv[2],nullptr,10));
    capy::run_async(context.get_executor(),[&]() noexcept {done=true;},[&](std::exception_ptr) noexcept {done=true;})(work(context,port,ok));
    (void)context.run_for(4s);if(!done || !ok)return 3;
    std::cout<<"receive, serial and message-race result budget exhaustion, recovery and drain passed\n";
}
