import std;
import dns.message;
import dns.response_program;
import dns.response_race_walk;
import dns.policy;

namespace dns=dns;
namespace policy = ::policy;
using Walk=dns::ResponseRaceWalk;
auto evaluate(std::optional<std::string> tag={}) -> policy::DnsRule {
    policy::DnsRule rule;rule.match_all=true;rule.action=policy::DnsAction::evaluate;rule.evaluate_tag=std::move(tag);return rule;
}
auto race_response(policy::DnsAction action,std::optional<std::string> tag={}) -> policy::DnsRule {
    policy::DnsRule rule;rule.match_all=true;rule.action=action;rule.match_response=true;rule.match_response_tag=std::move(tag);
    rule.response=policy::ResponseCondition{.rcode=0};return rule;
}
auto answer(unsigned rcode=0) -> dns::Response {dns::Response response{};response.rcode=rcode;return response;}
auto main() -> int {
    {
        // A speculative evaluate starts behind a pending race. The second
        // race can win with its own tagged response before the first settles.
        auto a=evaluate("a"),b=evaluate("b");auto first=race_response(policy::DnsAction::respond,"a"),second=race_response(policy::DnsAction::respond,"b");
        std::array rules{a,first,b,second};std::array modes{dns::ResponseRaceMode{},dns::ResponseRaceMode{true,false},dns::ResponseRaceMode{false,true},dns::ResponseRaceMode{true,false}};
        Walk walk(rules,modes,0);auto start_a=walk.next("test",1);if(!start_a || start_a->kind!=Walk::Kind::start || !start_a->ticket)return 1;
        auto start_b=walk.next("test",1);if(!start_b || start_b->kind!=Walk::Kind::start || start_b->step.rule!=2 || !start_b->ticket)return 2;
        auto wait=walk.next("test",1);if(!wait || wait->kind!=Walk::Kind::wait)return 3;
        if(!walk.complete(*start_b->ticket,answer()))return 4;
        auto result=walk.next("test",1);if(!result || result->kind!=Walk::Kind::commit || result->step.rule!=3 || result->ticket!=start_b->ticket || !walk.response(*result->ticket))return 5;
        if(walk.take_response(*start_a->ticket) || !walk.take_response(*start_b->ticket) || walk.take_response(*start_b->ticket))return 26;
        if(walk.complete(*start_a->ticket,answer()))return 6;
    }
    {
        // Ordinary evaluate waits behind the first race; its failure leaves
        // the generation unknown and allows the later evaluate to start.
        auto first=race_response(policy::DnsAction::reject,"a");
        std::array rules{evaluate("a"),first,evaluate("b")};std::array modes{dns::ResponseRaceMode{},dns::ResponseRaceMode{true,false},dns::ResponseRaceMode{}};
        Walk walk(rules,modes,7);auto a=walk.next("test",1);if(!a || !a->ticket)return 7;
        auto wait=walk.next("test",1);if(!wait || wait->kind!=Walk::Kind::wait)return 8;
        if(!walk.complete(*a->ticket,{}))return 9;
        auto b=walk.next("test",1);if(!b || b->kind!=Walk::Kind::start || b->step.rule!=2 || !b->ticket)return 10;
        auto fallback=walk.next("test",1);if(!fallback || fallback->kind!=Walk::Kind::commit || fallback->step.server!=7)return 11;
    }
    {
        // A pending race keeps its options even when subsequent options apply
        // to a speculative query launched before the race settles.
        auto set100=policy::DnsRule{};set100.match_all=true;set100.action=policy::DnsAction::route_options;set100.timeout_ms=100;
        auto set200=set100;set200.timeout_ms=200;
        auto first=race_response(policy::DnsAction::route,"a");first.server=3;
        std::array rules{set100,evaluate("a"),first,set200,evaluate("b")};
        std::array modes{dns::ResponseRaceMode{},dns::ResponseRaceMode{},dns::ResponseRaceMode{true,false},dns::ResponseRaceMode{},dns::ResponseRaceMode{false,true}};
        Walk walk(rules,modes,0);auto a=walk.next("test",1);if(!a || a->step.timeout_ms!=100 || !a->ticket)return 12;
        auto b=walk.next("test",1);if(!b || b->step.timeout_ms!=200 || !b->ticket)return 13;
        if(!walk.complete(*a->ticket,answer()))return 14;
        auto result=walk.next("test",1);if(!result || result->kind!=Walk::Kind::commit || result->step.rule!=2 || result->step.timeout_ms!=100)return 15;
    }
    {
        // A race binds the anonymous generation at arm time, not whichever
        // anonymous query happens to be latest when it is judged.
        auto first=race_response(policy::DnsAction::respond),second=race_response(policy::DnsAction::respond);
        std::array rules{evaluate(),first,evaluate(),second};
        std::array modes{dns::ResponseRaceMode{},dns::ResponseRaceMode{true,false},dns::ResponseRaceMode{false,true},dns::ResponseRaceMode{true,false}};
        Walk walk(rules,modes,0);auto old=walk.next("test",1),newer=walk.next("test",1);if(!old || !newer || !old->ticket || !newer->ticket)return 16;
        auto wait=walk.next("test",1);if(!wait || wait->kind!=Walk::Kind::wait)return 17;
        if(!walk.complete(*newer->ticket,answer(3)))return 18;
        wait=walk.next("test",1);if(!wait || wait->kind!=Walk::Kind::wait)return 19;
        if(!walk.complete(*old->ticket,answer()))return 20;
        auto result=walk.next("test",1);if(!result || result->step.rule!=1 || result->ticket!=old->ticket)return 21;
    }
    {
        // A non-race response rule waits for its referenced query, then
        // takes effect before later rules.
        auto response=race_response(policy::DnsAction::respond,"a");
        std::array rules{evaluate("a"),response};std::array modes{dns::ResponseRaceMode{},dns::ResponseRaceMode{}};
        Walk walk(rules,modes,0);auto a=walk.next("test",1);if(!a || !a->ticket)return 22;
        auto wait=walk.next("test",1);if(!wait || wait->kind!=Walk::Kind::wait)return 23;
        if(!walk.complete(*a->ticket,answer()))return 24;
        auto result=walk.next("test",1);if(!result || result->step.rule!=1 || result->ticket!=a->ticket)return 25;
    }
    {
        // A speculative route starts before an earlier race settles, but is
        // only committed when that race fails to match.
        auto reject=race_response(policy::DnsAction::reject,"a");
        policy::DnsRule route;route.match_all=true;route.action=policy::DnsAction::route;route.server=2;
        std::array rules{evaluate("a"),reject,route};
        std::array modes{dns::ResponseRaceMode{},dns::ResponseRaceMode{true,false},dns::ResponseRaceMode{false,true}};
        Walk walk(rules,modes,0);auto a=walk.next("test",1),spec=walk.next("test",1);
        if(!a || !spec || !a->ticket || !spec->ticket || spec->step.rule!=2)return 27;
        auto wait=walk.next("test",1);if(!wait || wait->kind!=Walk::Kind::wait)return 28;
        if(!walk.complete(*a->ticket,answer(3)))return 29;
        auto result=walk.next("test",1);if(!result || result->kind!=Walk::Kind::commit || result->step.rule!=2 || result->ticket!=spec->ticket)return 30;
    }
    {
        std::array rules{evaluate()};std::array modes{dns::ResponseRaceMode{}};
        Walk walk(rules,modes,0);auto start=walk.next("test",1);if(!start || !start->ticket)return 31;
        auto excessive=answer();excessive.wire.resize(65536);
        auto rejected=walk.complete(*start->ticket,std::move(excessive));
        if(rejected || rejected.error()!=dns::ResponseProgramError::resource_limit)return 32;
        auto reserved=answer();reserved.wire.reserve(2*1024*1024);
        rejected=walk.complete(*start->ticket,std::move(reserved));
        if(rejected || rejected.error()!=dns::ResponseProgramError::resource_limit)return 33;
        if(!walk.complete(*start->ticket,answer()))return 34;
    }
    std::cout<<"DNS concurrent response walk: races, barriers, options and response generations passed\n";
}
