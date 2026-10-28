import std;
import nexus.dns.fakeip_response;
import nexus.dns.fakeip;
import nexus.dns.message;
using namespace std::chrono_literals;
namespace d=nexus::dns;
int main() {
    auto t=std::chrono::steady_clock::time_point{};
    auto pool=d::FakeIpPool::create(0xc6120001,0xc6120001,60s,5s);
    if (!pool) return 1;
    d::Question q{"www.Example.com",1};
    auto query=d::make_query(0x1234,q);
    if (!query) return 2;
    auto response=d::fakeip_response(**pool,*query,42,t);
    if (!response) return 3;
    auto decoded=d::parse_addresses((*response)->wire(),0x1234,q);
    if (!decoded || decoded->ttl!=60 || decoded->addresses.size()!=1 ||
        decoded->addresses[0].bytes[0]!=198 || decoded->addresses[0].bytes[1]!=18 ||
        decoded->addresses[0].bytes[2]!=0 || decoded->addresses[0].bytes[3]!=1) return 4;
    auto mapping=(**pool).lookup(0xc6120001,t);
    if (!mapping || !*mapping || (*mapping)->domain!="www.example.com" || (*mapping)->view!=42) return 5;
    auto again=d::fakeip_response(**pool,*query,42,t+10s);
    if (!again || !std::ranges::equal((*again)->wire(),(*response)->wire())) return 6;
    if (!(*response)->finish(true,t+10s) || !(*again)->finish(false,t+10s) ||
        !(*response)->wire().empty() || (*response)->finish(true,t+10s).error()!=d::FakeIpError::stale) return 17;
    auto different=*d::make_query(5,{"other.example",1});
    if (d::fakeip_response(**pool,different,42,t+74s).error()!=d::FakeIpDnsError::full) return 7;
    auto after=d::fakeip_response(**pool,different,42,t+75s);
    if (!after || (**pool).lookup(0xc6120001,t+75s)->value().domain!="other.example") return 8;
    if (!(*after)->finish(true,t+75s)) return 18;
    auto empty=d::FakeIpPool::create(10,10,1s,0s);
    if (!empty) return 9;
    for (std::size_t n=0;n<query->size();++n)
        if (d::fakeip_response(**empty,std::span(*query).first(n),0,t)) return 10;
    auto bad=*query; bad[2]=0x81;
    if (d::fakeip_response(**empty,bad,0,t).error()!=d::FakeIpDnsError::unsupported) return 11;
    bad=*query; bad[12]=0xc0;
    if (d::fakeip_response(**empty,bad,0,t).error()!=d::FakeIpDnsError::unsupported) return 12;
    bad=*query; bad.back()=2;
    if (d::fakeip_response(**empty,bad,0,t).error()!=d::FakeIpDnsError::unsupported) return 13;
    bad=*query; bad.push_back(0);
    if (d::fakeip_response(**empty,bad,0,t).error()!=d::FakeIpDnsError::malformed) return 14;
    auto edns=d::make_edns_query(1,q,4096);
    auto edns_pool=d::FakeIpPool::create(10,10,1s,0s);
    if (!edns || !edns_pool) return 15;
    auto edns_answer=d::fakeip_response(**edns_pool,*edns,0,t);
    if (!edns_answer) return 25;
    auto edns_parsed=d::parse_response((*edns_answer)->wire(),1,q);
    auto edns_addresses=d::parse_addresses((*edns_answer)->wire(),1,q,true);
    if (!edns_parsed || !edns_parsed->edns || edns_parsed->edns->udp_payload_size!=1232 ||
        !edns_addresses || edns_addresses->addresses.size()!=1 || edns_addresses->addresses[0].bytes[3]!=10 ||
        !(*edns_answer)->finish(true,t)) return 26;
    auto bad_edns=*edns; bad_edns[bad_edns.size()-4]=0x80;
    if (d::validate_fakeip_query(bad_edns).error()!=d::FakeIpDnsError::unsupported) return 27;
    bad_edns=*edns; bad_edns.pop_back();
    if (d::validate_fakeip_query(bad_edns).error()!=d::FakeIpDnsError::malformed) return 28;
    bad_edns=*edns; bad_edns[bad_edns.size()-1]=1;
    if (d::validate_fakeip_query(bad_edns).error()!=d::FakeIpDnsError::unsupported) return 29;
    auto available=d::fakeip_response(**empty,*query,0,t);
    if (!available) return 16;
    // Delayed or ambiguous completion holds the address and extends its TTL.
    if (d::fakeip_response(**empty,different,0,t+100s).error()!=d::FakeIpDnsError::full ||
        !(*available)->finish(true,t+100s) ||
        d::fakeip_response(**empty,different,0,t+100s).error()!=d::FakeIpDnsError::full) return 19;
    auto last=d::fakeip_response(**empty,different,0,t+101s);
    if (!last || !(*last)->finish(false,t+101s)) return 20;
    auto pinned=d::fakeip_response(**empty,*query,0,t+102s);
    if (!pinned || (*pinned)->finish(true,t+101s).error()!=d::FakeIpError::time_reversed ||
        d::fakeip_response(**empty,different,0,t+104s).error()!=d::FakeIpDnsError::full ||
        !(*pinned)->finish(true,t+104s)) return 21;
    auto abandoned=d::FakeIpPool::create(20,20,1s,0s);
    if (!abandoned) return 22;
    {
        auto pending=d::fakeip_response(**abandoned,*query,0,t);
        if (!pending) return 23;
    }
    if (d::fakeip_response(**abandoned,different,0,t+100s).error()!=d::FakeIpDnsError::full) return 24;
    std::println("FakeIP DNS response integration passed");
}
