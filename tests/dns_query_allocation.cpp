import std;
import dns.message;
import dns.message_exchange;
import dns.message_cache;
import dns.response_program;
import dns.response_race_walk;
import dns.response_addresses;
import dns.input_budget;
import dns.policy;
import rules;
import corosio;

static bool observing=false;
static std::size_t large_allocations=0;
static std::size_t allocations=0;
auto operator new(std::size_t size) -> void* {
    if(observing)++allocations;
    if(observing && size>=60000)++large_allocations;
    if(auto* p=std::malloc(size ? size : 1))return p;
    throw std::bad_alloc();
}
auto operator new[](std::size_t size) -> void* {return ::operator new(size);}
void operator delete(void* p) noexcept {std::free(p);}
void operator delete(void* p,std::size_t) noexcept {std::free(p);}
void operator delete[](void* p) noexcept {std::free(p);}
void operator delete[](void* p,std::size_t) noexcept {std::free(p);}

auto main() -> int {
    namespace dns=dns;
    {
        dns::InputBudget budget(100);
        {
            auto one=budget.acquire(20),two=budget.acquire(30);if(!one || !two)return 26;
            dns::EvaluatedMessage first(dns::Bytes(20),{},false,std::move(one));
            dns::EvaluatedMessage second(dns::Bytes(30),{},false,std::move(two));
            first=std::move(second);
            if(budget.used()!=30 || first.wire.size()!=30)return 27;
            first=std::move(first);if(budget.used()!=30)return 28;
        }
        if(budget.used())return 29;
    }
    dns::QueryMessage query{42,0x0100,{"large.test",1},dns::QueryEdns{1232,0,false,{{65001,dns::Bytes(60000,0x5a)}}}};
    auto wire=dns::encode_query(query);if(!wire)return 1;
    observing=true;auto parsed=dns::parse_query(*wire);observing=false;
    if(!parsed || !parsed->edns || parsed->edns->options.size()!=1 || parsed->edns->options[0].data.size()!=60000)return 2;
    // One large allocation is the retained option, not a second temporary
    // compression table sized to the whole request.
    if(large_allocations!=1)return 3;
    corosio::io_context context;
    std::array<dns::MessageUpstream,1> upstreams{{{{corosio::ipv4_address::loopback(),53},false,nullptr}}};
    dns::ResponseStep step{.action=dns::ResponseAction::route,.server=0};
    large_allocations=0;observing=true;
    dns::MessageExchange exchange(context,upstreams,nullptr,*parsed,step,std::chrono::steady_clock::now()+std::chrono::seconds(1));
    observing=false;
    if(large_allocations || &exchange.upstream_query()!=&*parsed || !exchange.upstream_query().edns || exchange.upstream_query().edns->options[0].data.size()!=60000)return 4;
    dns::MessageCache cache;
    dns::MessageCache::View view(0,{corosio::ipv4_address::loopback(),53},false,{});
    large_allocations=0;observing=true;
    auto hit=cache.lookup(view,*parsed,std::chrono::steady_clock::now());
    auto ticket=cache.begin(view,*parsed);
    observing=false;
    if(hit || ticket || large_allocations)return 7;
    auto source=dns::make_query(42,{"large.test",1});if(!source)return 5;
    (*source)[2]=0x81;(*source)[3]=0x80;(*source)[7]=1;
    auto payload=std::size_t{60000};
    source->insert(source->end(),{0xc0,0x0c,0xfd,0xe8,0,1,0,0,0,60,static_cast<std::uint8_t>(payload>>8),static_cast<std::uint8_t>(payload)});
    source->resize(source->size()+payload,0x5a);auto* original=source->data();
    large_allocations=0;observing=true;
    auto response=dns::parse_owned_response(std::move(*source),42,{"large.test",1});
    observing=false;
    // A packed fixed-size boundary table and moved wire require no large
    // allocation while parsing this owned response.
    if(!response || response->wire.data()!=original || response->records.size()!=1 || large_allocations!=0)return 6;
    large_allocations=0;observing=true;auto rewritten=dns::rewrite_response(*response,7,11);observing=false;
    if(!rewritten || large_allocations || response->wire.data()!=original || response->records[0].ttl!=11 || response->wire[1]!=7)return 30;
    // A cache hit with many long decoded owner names should allocate only the
    // key and returned wire, independent of the number of stored records.
    auto name=std::string(60,'a')+".test";
    dns::QueryMessage cached_query{42,0x0100,{name,1},{}};
    auto cached_wire=dns::encode_query(cached_query);if(!cached_wire)return 8;
    (*cached_wire)[2]=0x81;(*cached_wire)[3]=0x80;(*cached_wire)[7]=100;
    for(unsigned i=0;i<100;++i)cached_wire->insert(cached_wire->end(),{0xc0,0x0c,0,1,0,1,0,0,0,60,0,4,192,0,2,1});
    auto cached_response=dns::parse_owned_response(std::move(*cached_wire),42,cached_query.question);
    auto now=std::chrono::steady_clock::now();auto cached_ticket=cache.begin(view,cached_query);
    if(!cached_response || !cached_ticket)return 9;
    cache.publish(*cached_ticket,cached_query,std::move(*cached_response),now);
    auto missing_query=cached_query;missing_query.question.name[0]='b';
    allocations=0;observing=true;auto miss=cache.lookup(view,missing_query,now);observing=false;auto miss_allocations=allocations;
    allocations=0;observing=true;auto cached=cache.lookup(view,cached_query,now);observing=false;
    if(miss || !cached || allocations>miss_allocations+1)return 10;
#ifdef NEXUS_DNS_RESPONSE
    dns::Question hint_question{"large.test",65};
    auto hint_wire=dns::make_query(42,hint_question);if(!hint_wire)return 11;
    (*hint_wire)[2]=0x81;(*hint_wire)[3]=0x80;(*hint_wire)[7]=1;
    hint_wire->insert(hint_wire->end(),{0xc0,0x0c,0,65,0,1,0,0,0,60,0xea,0x67,0,1,0,0,4,0xea,0x60});
    hint_wire->resize(hint_wire->size()+60000,127);
    auto hints=dns::parse_owned_response(std::move(*hint_wire),42,hint_question);if(!hints)return 12;
    large_allocations=0;observing=true;auto count=dns::response_address_count(*hints);observing=false;
    if(!count || *count!=15000 || large_allocations)return 13;
    ::policy::DnsRule evaluate;evaluate.match_all=true;evaluate.action=::policy::DnsAction::evaluate;
    ::policy::DnsRule match;match.has_rule_set=true;match.match_response=true;match.action=::policy::DnsAction::respond;
    ::rules::RuleSet set{{{"ip-cidr","127.0.0.0/8",{}}},2};
    if(!::policy::bind_dns_rule_set(match,std::move(set)))return 14;
    std::array rules{evaluate,match};std::size_t held;
    {
        dns::InputBudget measure(1024*1024);dns::ResponseWalk walk(rules,0,false,&measure);
        if(!walk.next("large.test",65) || !walk.evaluated(*hints))return 15;
        held=measure.used();
    }
    dns::InputBudget tight(held);dns::ResponseWalk limited(rules,0,false,&tight);
    if(!limited.next("large.test",65) || !limited.evaluated(*hints))return 16;
    large_allocations=0;observing=true;auto denied=limited.next("large.test",65);observing=false;
    if(denied || denied.error()!=dns::ResponseProgramError::resource_limit || large_allocations || tight.used()!=held)return 17;
    dns::InputBudget enough(1024*1024);
    {
        dns::ResponseWalk allowed(rules,0,false,&enough);
        if(!allowed.next("large.test",65) || !allowed.evaluated(*hints))return 18;
        auto before=enough.used();auto accepted=allowed.next("large.test",65);
        if(!accepted || accepted->action!=dns::ResponseAction::respond ||
           enough.used()!=before+*count*sizeof(::rules::ProgramAddress))return 19;
        auto result=allowed.take_response();if(!result || enough.used()!=before)return 20;
    }
    if(enough.used())return 21;
    {
        auto nearly_full=*hints;nearly_full.wire.reserve(2*1024*1024-100000);
        dns::ResponseRaceWalk walk(rules,{},0);
        auto start=walk.next("large.test",65);
        if(!start || !start->ticket || !walk.complete(*start->ticket,std::move(nearly_full)))return 22;
        large_allocations=0;observing=true;auto rejected=walk.next("large.test",65);observing=false;
        if(rejected || rejected.error()!=dns::ResponseProgramError::resource_limit || large_allocations)return 23;
    }
    {
        dns::ResponseRaceWalk walk(rules,{},0);
        auto start=walk.next("large.test",65);
        if(!start || !start->ticket || !walk.complete(*start->ticket,*hints))return 24;
        auto accepted=walk.next("large.test",65);
        if(!accepted || accepted->kind!=dns::ResponseRaceWalk::Kind::commit || accepted->step.action!=dns::ResponseAction::respond)return 25;
    }
#endif
    std::cout<<"large query: one retained option allocation, no duplicate exchange copy\n";
}
