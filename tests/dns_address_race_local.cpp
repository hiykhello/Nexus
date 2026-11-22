import std;
import dns.address_race_program;
import dns.response_program;
import dns.response_race_walk;
import dns.policy;
import dns.local_response;
import dns.message;
import dns.input_budget;
import dns.corosio_resolver;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;
namespace capy=nex::capy;
namespace io=nex::corosio;
using Clock=std::chrono::steady_clock;
struct Operation {
    dns::ResponseStep step;std::uint16_t type;std::vector<std::string>& calls;
    auto cancel() noexcept -> void {}
    auto run() -> capy::task<dns::AddressRaceResult> {
        calls.push_back(std::to_string(step.server)+":"+std::to_string(type));
        dns::Response response{};response.rcode=0;
        co_return dns::AddressRaceValue{dns::detail::LocalResponseSelection{std::move(response),{},false,"short.search.test",true}};
    }
};
struct Factory {
    std::optional<std::pair<std::size_t,std::string>>& candidate;
    std::vector<std::string>& calls;std::uint16_t type;
    auto operator()(dns::ResponseStep step,Clock::time_point) -> std::unique_ptr<Operation> {
        if(candidate)calls.push_back("candidate:"+candidate->second);
        return std::make_unique<Operation>(step,type,calls);
    }
    auto completed(dns::ResponseStep const& step,dns::detail::EvaluatedResponseMeta const& meta) -> void {
        dns::AddressRaceLocalCandidate{candidate}.completed(step,meta);
    }
};
auto run(io::io_context& context,bool& ok) -> capy::task<> {
    ::policy::DnsRule first;first.match_all=true;first.action=::policy::DnsAction::evaluate;first.evaluate_tag="a";
    auto second=first;second.evaluate_tag="b";
    ::policy::DnsRule respond;respond.match_all=true;respond.match_response=true;respond.match_response_tag="b";respond.action=::policy::DnsAction::respond;
    std::array rules{first,second,respond};std::array modes{dns::ResponseRaceMode{},dns::ResponseRaceMode{},dns::ResponseRaceMode{}};
    std::optional<std::pair<std::size_t,std::string>> candidate;std::vector<std::string> calls;
    dns::AddressRaceProgram<Operation> first_walk(context,rules,modes,0);Factory a{candidate,calls,1};
    auto first_result=co_await first_walk.run(a,"short",1,{},Clock::now()+std::chrono::seconds(2));
    if(!first_result || !first_result->metadata || first_result->metadata->question!="short.search.test" ||
       !candidate || candidate->first!=0 || candidate->second!="short.search.test" ||
       calls!=std::vector<std::string>{"0:1","candidate:short.search.test","0:1"})co_return;
    auto& budget=dns::default_address_race_result_budget();auto first_used=budget.used();if(!first_used)co_return;
    calls.clear();dns::AddressRaceProgram<Operation> second_walk(context,rules,modes,0);Factory b{candidate,calls,28};
    auto second_result=co_await second_walk.run(b,"short",28,{},Clock::now()+std::chrono::seconds(2));
    ok=second_result && second_result->metadata && second_result->metadata->question==candidate->second && budget.used()>first_used &&
       calls==std::vector<std::string>{"candidate:short.search.test","0:28","candidate:short.search.test","0:28"};
}
auto main() -> int {
    io::io_context context;bool done=false,ok=false;
    capy::run_async(context.get_executor(),[&]() noexcept {done=true;},[&](std::exception_ptr) noexcept {done=true;})(run(context,ok));
    (void)context.run_for(std::chrono::seconds(3));return done && ok && dns::default_address_race_result_budget().used()==0 ? 0 : 1;
}
