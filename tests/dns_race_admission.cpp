import std;
import dns.race_admission;
import dns.address_race_program;
import dns.message_race_program;
import dns.message_exchange;
import dns.response_race_walk;
import dns.response_program;
import dns.policy;
import dns.corosio_resolver;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;
namespace io=nex::corosio;
namespace capy=nex::capy;
struct Never {
    auto cancel() noexcept -> void {}
    auto run() -> capy::task<dns::AddressRaceResult> {co_return std::unexpected(dns::detail::ResolveError::state);}
};
auto check(io::io_context& context,bool& ok) -> capy::task<> {
    std::vector<std::unique_ptr<dns::RaceAdmission>> leases;
    for(std::size_t i=0;i<dns::RaceAdmission::maximum;++i) {
        auto lease=std::make_unique<dns::RaceAdmission>();if(!lease->acquired())co_return;
        leases.push_back(std::move(lease));
    }
    ::policy::DnsRule reject;reject.match_all=true;reject.action=::policy::DnsAction::reject;
    std::array rules{reject};std::array modes{dns::ResponseRaceMode{}};
    std::array<dns::MessageUpstream,1> upstreams{{{{io::ipv4_address::loopback(),53},false,nullptr}}};
    auto factory=[](dns::ResponseStep,std::chrono::steady_clock::time_point){return std::make_unique<Never>();};
    auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(3);
    dns::MessageRaceProgram message(context,rules,modes,upstreams,0);
    auto denied=co_await message.run({42,0x100,{"test",1},{}},deadline,{});
    if(denied || denied.error()!=dns::detail::ResolveError::limit)co_return;
    dns::AddressRaceProgram<Never> address(context,rules,modes,0);
    auto denied_address=co_await address.run(factory,"test",1,{},deadline);
    if(denied_address || denied_address.error()!=dns::detail::ResolveError::limit)co_return;
    leases.pop_back();
    dns::AddressRaceProgram<Never> resumed(context,rules,modes,0);
    auto permitted=co_await resumed.run(factory,"test",1,{},deadline);
    if(!permitted || permitted->step.action!=::policy::DnsAction::reject)co_return;
    dns::MessageRaceProgram resumed_message(context,rules,modes,upstreams,0);
    auto rejected=co_await resumed_message.run({42,0x100,{"test",1},{}},deadline,{});
    ok=!rejected && rejected.error()==dns::detail::ResolveError::policy_rejected;
}
auto main() -> int {
    io::io_context context;bool done=false,ok=false;
    capy::run_async(context.get_executor(),[&]() noexcept {done=true;},[&](std::exception_ptr) noexcept {done=true;})(check(context,ok));
    (void)context.run_for(std::chrono::seconds(4));return done && ok ? 0 : 1;
}
