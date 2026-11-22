import std;
import dns.input_budget;
import dns.message;
import dns.message_program;
import dns.message_race_program;
import dns.response_program;
import dns.response_race_walk;
import dns.policy;
import dns.corosio_resolver;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;
namespace dns=dns;
namespace io=nex::corosio;
namespace capy=nex::capy;
using namespace std::chrono_literals;

auto work(io::io_context& context,std::uint16_t port,bool& ok) -> capy::task<> {
    dns::QueryMessage query{42,0x0100,{"owner.test",1},dns::QueryEdns{1232,0,false,{{65001,dns::Bytes(8192,0x5a)}}}};
    ::policy::ResponsePrefix subnet{};subnet.size=4;subnet.bits=24;subnet.address[0]=192;subnet.address[2]=2;
    ::policy::DnsRule a;a.match_all=true;a.action=::policy::DnsAction::evaluate;a.evaluate_tag="a";a.client_subnet=subnet;
    ::policy::DnsRule judge;judge.match_all=true;judge.match_response=true;judge.match_response_tag="a";judge.action=::policy::DnsAction::respond;
    auto b=a;b.evaluate_tag="b";
    ::policy::DnsRule route;route.match_all=true;route.action=::policy::DnsAction::route;
    std::array<dns::MessageUpstream,1> upstreams{{{{io::ipv4_address::loopback(),port},false,nullptr}}};
    auto deadline=std::chrono::steady_clock::now()+2s;
    {
        dns::InputBudget denied(0);std::array rules{a,route};
        dns::MessageProgram serial(context,rules,upstreams,0,nullptr,true,{},&denied);
        auto result=co_await serial.run(query,deadline,{});
        if(result || result.error()!=dns::detail::ResolveError::limit || denied.used())co_return;
    }
    {
        dns::InputBudget budget(24000);std::array rules{a,judge,b,route};
        std::array modes{dns::ResponseRaceMode{},dns::ResponseRaceMode{true,false},dns::ResponseRaceMode{false,true},dns::ResponseRaceMode{}};
        dns::MessageRaceProgram program(context,rules,modes,upstreams,0,nullptr,true,&budget);
        auto result=co_await program.run(query,deadline,{});
        if(result || result.error()!=dns::detail::ResolveError::limit || budget.used())co_return;
    }
    // No override consumes no override budget and must preserve the original.
    {
        dns::InputBudget denied(0);
        dns::ResponseStep step{.action=dns::ResponseAction::evaluate,.server=0};
        dns::MessageExchange exchange(context,upstreams,nullptr,query,step,deadline,&denied);
        if(&exchange.upstream_query()!=&query || denied.used())co_return;
    }
    {
        dns::InputBudget budget(24000);bool observed=false,driver_done=false;capy::async_event finished;
        {
            dns::ResponseStep step{.action=dns::ResponseAction::evaluate,.server=0};
            step.subnet.emplace(dns::ClientSubnet{1,24,{192,0,2}});
            dns::MessageExchange exchange(context,upstreams,nullptr,query,step,deadline,&budget);
            auto cancel=[&]() -> capy::task<> {
                struct Signal {capy::async_event& event;~Signal(){event.set();}} signal{finished};
                io::steady_timer timer(context);timer.expires_at(std::chrono::steady_clock::now()+20ms);
                auto [error]=co_await timer.wait();
                if(!error){observed=budget.used()>8192 && &exchange.upstream_query()!=&query;driver_done=true;exchange.cancel();}
            };
            capy::run_async(context.get_executor())(cancel());
            auto result=co_await exchange.run();
            auto [error]=co_await finished.wait();
            if(error || !driver_done || !observed || result || result.error()!=dns::detail::ResolveError::canceled || !budget.used())co_return;
        }
        if(budget.used())co_return;
    }
    ok=true;
}
auto main(int argc,char** argv) -> int {
    if(argc!=3)return 2;
    bool uring=std::string_view(argv[1])=="uring";
#if BOOST_COROSIO_HAVE_LIBURING
    io::io_context context=uring ? io::io_context(io::uring) : io::io_context(io::epoll);
#else
    if(uring)return 77;io::io_context context(io::epoll);
#endif
    auto port=static_cast<std::uint16_t>(std::strtoul(argv[2],nullptr,10));
    bool done=false,ok=false;
    capy::run_async(context.get_executor(),[&]() noexcept {done=true;},[&](std::exception_ptr) noexcept {done=true;})(work(context,port,ok));
    (void)context.run_for(4s);if(!done || !ok)return 3;
    std::cout<<"override budget: explicit limit, cancellation and drain passed\n";
}
