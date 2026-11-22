import std;
import dns.evaluate_race;

using Walk=dns::EvaluateRace<4,4>;
auto main() -> int {
    {
        Walk walk;auto slow=walk.start(),fast=walk.start();if(!slow || !fast)return 1;
        if(!walk.arm(2,*slow) || !walk.arm(3,*fast))return 2;
        auto scan=walk.poll();if(!scan || scan->kind!=Walk::Kind::scan)return 3;
        auto speculative=walk.start();if(!speculative || !walk.hold(4,*speculative))return 4;
        auto wait=walk.poll();if(!wait || wait->kind!=Walk::Kind::wait)return 5;
        if(!walk.complete(*fast))return 6;
        auto judge=walk.poll();if(!judge || judge->kind!=Walk::Kind::judge || judge->rule!=3 || judge->response!=*fast)return 7;
        if(!walk.judged(true))return 8;
        auto winner=walk.poll();if(!winner || winner->kind!=Walk::Kind::commit || winner->rule!=3 || walk.poll())return 9;
    }
    {
        Walk walk;auto a=walk.start(),b=walk.start(),speculative=walk.start();if(!a || !b || !speculative)return 10;
        if(!walk.arm(4,*a) || !walk.arm(5,*b) || !walk.hold(6,*speculative))return 11;
        if(!walk.complete(*b,true))return 12;
        auto judge=walk.poll();if(!judge || judge->kind!=Walk::Kind::judge || judge->rule!=5 || !judge->failed)return 13;
        if(!walk.judged(false))return 14;
        auto wait=walk.poll();if(!wait || wait->kind!=Walk::Kind::wait)return 15;
        if(!walk.complete(*a))return 16;
        judge=walk.poll();if(!judge || judge->rule!=4 || judge->failed || !walk.judged(false))return 17;
        auto commit=walk.poll();if(!commit || commit->kind!=Walk::Kind::commit || commit->rule!=6 || commit->response!=*speculative)return 18;
    }
    {
        Walk walk;auto old=walk.start(),newer=walk.start();if(!old || !newer || !walk.arm(8,*old))return 19;
        if(!walk.complete(*newer))return 20;
        auto event=walk.poll();if(!event || event->kind!=Walk::Kind::scan)return 21;
        if(!walk.complete(*old))return 22;
        event=walk.poll();if(!event || event->kind!=Walk::Kind::judge || event->response!=*old || !walk.judged(false))return 23;
        if(!walk.arm(9,*newer) || !walk.arm(10,*newer))return 24;
        event=walk.poll();if(!event || event->rule!=9 || !walk.judged(false))return 25;
        event=walk.poll();if(!event || event->rule!=10 || !walk.judged(false))return 26;
        if(!walk.arm(11,{}))return 27;
        event=walk.poll();if(!event || event->rule!=11 || !event->failed || !walk.judged(false))return 28;
    }
    {
        dns::EvaluateRace<1,1> walk;auto ticket=walk.start();if(!ticket || walk.start())return 29;
        if(!walk.arm(1,*ticket) || walk.arm(2,*ticket))return 30;
        if(!walk.complete(*ticket) || walk.complete(*ticket))return 31;
        auto stale=*ticket;++stale.generation;if(walk.complete(stale))return 32;
        if(!walk.poll() || walk.poll() || !walk.judged(false) || walk.judged(false))return 33;
    }
    {
        Walk walk;auto pending=walk.start(),speculative=walk.start();if(!pending || !speculative)return 34;
        if(!walk.arm(1,*pending) || !walk.hold(2,*speculative,false) || !walk.complete(*speculative))return 35;
        auto event=walk.poll();if(!event || event->kind!=Walk::Kind::wait)return 36;
        if(!walk.complete(*pending,true))return 37;
        event=walk.poll();if(!event || event->kind!=Walk::Kind::judge || !event->failed || !walk.judged(false))return 38;
        event=walk.poll();if(!event || event->kind!=Walk::Kind::proceed || event->response!=*speculative)return 39;
        event=walk.poll();if(!event || event->kind!=Walk::Kind::scan || !walk.hold(3))return 40;
        event=walk.poll();if(!event || event->kind!=Walk::Kind::commit || event->rule!=3)return 41;
    }
    {
        // A speculative evaluate continues scanning while an earlier race
        // remains armed; a later race can bind its independent generation.
        Walk walk;auto first=walk.start();if(!first || !walk.arm(1,*first))return 42;
        auto speculative=walk.start();if(!speculative)return 43;
        auto event=walk.poll();if(!event || event->kind!=Walk::Kind::scan || !walk.arm(3,*speculative))return 44;
        if(!walk.complete(*speculative))return 45;
        event=walk.poll();if(!event || event->kind!=Walk::Kind::judge || event->rule!=3 || !walk.judged(true))return 46;
        event=walk.poll();if(!event || event->kind!=Walk::Kind::commit || event->rule!=3)return 47;
    }
    {
        // One wake can observe multiple completions. The first listed ready
        // rule is judged first, even when its query completed second.
        Walk walk;auto first=walk.start(),second=walk.start();if(!first || !second)return 48;
        if(!walk.arm(1,*first) || !walk.arm(2,*second) || !walk.complete(*second) || !walk.complete(*first))return 49;
        auto event=walk.poll();if(!event || event->kind!=Walk::Kind::judge || event->rule!=1 || !walk.judged(true))return 50;
        event=walk.poll();if(!event || event->kind!=Walk::Kind::commit || event->rule!=1)return 51;
    }
    std::cout<<"DNS race scheduling: completion order, barriers, speculation, generations and limits passed\n";
}
