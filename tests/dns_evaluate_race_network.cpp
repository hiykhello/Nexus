import std;
import dns.evaluate_owner;
import dns.message_exchange;
import dns.message;
import dns.input_budget;
import dns.response_program;
import dns.response_race_walk;
import dns.policy;
import dns.corosio_resolver;
import rules;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;

namespace capy=nex::capy;
namespace io=nex::corosio;
namespace dns=dns;
using Result=std::expected<dns::EvaluatedMessage,dns::detail::ResolveError>;
using Owner=dns::EvaluateOwner<dns::EvaluatedMessageExchange,Result,2>;
using Walk=dns::ResponseRaceWalk;
auto run(Owner& owner,Owner::Handle slow,Owner::Handle fast,bool fallback,bool& ok) -> capy::task<> {
    ::policy::DnsRule evaluate;evaluate.match_all=true;evaluate.action=::policy::DnsAction::evaluate;evaluate.evaluate_tag="slow";
    ::policy::DnsRule rule;rule.has_rule_set=true;rule.match_response=true;rule.action=::policy::DnsAction::respond;rule.match_response_tag="slow";
    if(!::policy::bind_dns_rule_set(rule,{{{"ip-cidr","127.0.0.0/8",{}}},2}) || !dns::normalize_response_rule(rule,2))co_return;
    auto fast_evaluate=evaluate;fast_evaluate.server=1;fast_evaluate.evaluate_tag="fast";
    auto fast_rule=rule;fast_rule.match_response_tag="fast";
    std::array rules{evaluate,rule,fast_evaluate,fast_rule};
    std::array modes{dns::ResponseRaceMode{},dns::ResponseRaceMode{true,false},dns::ResponseRaceMode{false,true},dns::ResponseRaceMode{true,false}};
    Walk walk(rules,modes,0);
    auto first=walk.next("owner.test",1),second=walk.next("owner.test",1);
    if(!first || !second || first->kind!=Walk::Kind::start || second->kind!=Walk::Kind::start || !first->ticket || !second->ticket)co_return;
    bool published[2]{},fast_missed=false;
    for(;;) {
        auto epoch=owner.epoch();
        auto a=published[0] ? std::optional<Owner::View>{} : owner.inspect(slow);
        auto b=published[1] ? std::optional<Owner::View>{} : owner.inspect(fast);
        if((!published[0] && !a) || (!published[1] && !b))co_return;
        // Publish the complete observed batch before judging ready rules.
        for(unsigned i=0;i<2;++i) {
            bool choose_a=a && a->ready && !published[0] && (!b || !b->ready || published[1] || a->completion<b->completion);
            bool choose_b=b && b->ready && !published[1] && !choose_a;
            auto publish=[&](Owner::Handle handle,Owner::View const& view,Walk::Ticket ticket,std::uint8_t expected_network) {
                std::optional<dns::Response> response;
                if(!view.result)return false;
                auto taken=owner.take_result(handle);if(!taken)return false;
                if(*taken) {
                    auto const& result=**taken;
                    if(!result.lease || dns::default_message_race_result_budget().used()<result.wire.capacity())return false;
                    if(result.local_synthetic)return false;
                    auto const& subnet=result.upstream_ecs.subnet;
                    if(!subnet || subnet->family!=1 || subnet->prefix!=24 ||
                       subnet->address[0]!=(expected_network==2 ? 192 : 198) ||
                       subnet->address[1]!=(expected_network==2 ? 0 : 51) || subnet->address[2]!=expected_network)return false;
                    auto parsed=dns::parse_response(result.wire,42,{"owner.test",1});
                    if(!parsed)return false;response=std::move(*parsed);
                }
                if(!walk.complete(ticket,std::move(response)) || !owner.release(handle))return false;
                return !*taken || dns::default_message_race_result_budget().used()>=(**taken).wire.capacity();
            };
            if(choose_a) {if(!publish(slow,*a,*first->ticket,100))co_return;published[0]=true;}
            else if(choose_b) {if(!publish(fast,*b,*second->ticket,2))co_return;published[1]=true;}
            else break;
        }
        auto event=walk.next("owner.test",1);if(!event)co_return;
        if(event->kind==Walk::Kind::commit) {
            if(event->step.rule!=(fallback ? 1u : 3u) || (fallback && !fast_missed) || !event->ticket || !walk.take_response(*event->ticket))co_return;
            if(!fallback && !owner.cancel(slow))co_return;
            while(!owner.drained()) {
                auto observed=owner.epoch();if(owner.drained())break;
                auto [error]=co_await owner.wait(observed);if(error)co_return;
            }
            if(fallback)ok=published[0] && published[1];
            else {
                auto canceled=owner.inspect(slow);
                ok=canceled && canceled->result && !*canceled->result &&
                    canceled->result->error()==dns::detail::ResolveError::canceled && owner.release(slow);
            }
            co_return;
        }
        if(event->kind!=Walk::Kind::wait)co_return;
        if(published[1] && !published[0])fast_missed=true;
        auto [error]=co_await owner.wait(epoch);if(error)co_return;
    }
}
auto main(int argc,char** argv) -> int {
    if(argc!=4 && argc!=5)return 2;
    bool fallback=argc==5 && std::string_view(argv[4])=="fallback";
    if(argc==5 && !fallback)return 2;
    auto port=[](char const* text)->std::uint16_t {return static_cast<std::uint16_t>(std::strtoul(text,nullptr,10));};
    bool uring=std::string_view(argv[3])=="uring";
#if BOOST_COROSIO_HAVE_LIBURING
    io::io_context context=uring ? io::io_context(io::uring) : io::io_context(io::epoll);
#else
    if(uring)return 77;io::io_context context(io::epoll);
#endif
    std::array<dns::MessageUpstream,2> upstreams{{
        {{io::ipv4_address::loopback(),port(argv[1])},false,nullptr},
        {{io::ipv4_address::loopback(),port(argv[2])},false,nullptr}}};
    dns::QueryMessage query{42,0x0100,{"owner.test",1},{}};
    auto make=[&](std::size_t index) {
        dns::ResponseStep step{.action=dns::ResponseAction::evaluate,.server=index};
        dns::ClientSubnet subnet{1,24,{}};
        subnet.address[0]=index ? 192 : 198;subnet.address[1]=index ? 0 : 51;subnet.address[2]=index ? 2 : 100;
        step.subnet.emplace(subnet);
        return std::make_unique<dns::EvaluatedMessageExchange>(context,upstreams,nullptr,
            query,step,std::chrono::steady_clock::now()+std::chrono::seconds(3));
    };
    Owner owner(context);auto slow=owner.start(make(0)),fast=owner.start(make(1));if(!slow || !fast)return 3;
    bool ok=false,done=false;
    capy::run_async(context.get_executor(),[&]() noexcept {done=true;},[&](std::exception_ptr) noexcept {done=true;})(run(owner,*slow,*fast,fallback,ok));
    (void)context.run_for(std::chrono::seconds(5));
    if(!done || !owner.drained()){owner.stop();context.restart();(void)context.run();return 4;}
    return ok && dns::default_message_race_result_budget().used()==0 ? 0 : 5;
}
