// Instantiate the experimental registry with the actual proxy routing API.
#include <boost/corosio/endpoint.hpp>
#include <boost/corosio/ipv4_address.hpp>
import std;
import dns.message;
import dns.cache;
import proxy;
#include "../../src/dns-shared/group_snapshot.hpp"
#include "../../src/dns-shared/group_view_registry.hpp"

int main() {
    using namespace std;
    namespace p=proxy;
    namespace d=dns;
    namespace hp=dns_hp_experiment;
    namespace io=boost::corosio;
    try {
        p::DnsServer root; root.address[0]=127; root.address[3]=1; root.port=5301;
        p::DnsServer leaf; leaf.host="Dns.Example.Test."; leaf.port=5302; leaf.resolver=0;
        p::DnsRouting first{{root,leaf},{},1},second=first;
        second.servers[0].port=5303;
        hp::ViewRegistry registry(8,65536,16);
        auto a=registry.register_profile(first,1),b=registry.register_profile(second,1);
        if (!a || !b) throw runtime_error("real proxy profile registration failed");
        registry.seal();
        auto server=io::endpoint(io::ipv4_address::loopback(),5302);
        auto view_a=registry.view(*a,server),view_b=registry.view(*b,server);
        if (!view_a || !view_b || *view_a==*view_b) throw runtime_error("different proxy resolver chains shared a view");
        array<size_t,2> capacities{8,8}; hp::GroupSnapshot cache(capacities,2,0,65536);
        auto reader=cache.reader(1);
        d::CacheKey key{*view_a,"name.example.test",1};
        d::Address address{}; address.size=4; address.bytes[0]=127; address.bytes[3]=91;
        d::AddressAnswer answer{key.name,{key.name},{address},30};
        auto token=cache.begin_query(0,key);
        if (!token || !cache.publish(0,key,std::move(answer),1000,*token)) throw runtime_error("real proxy view cache seed failed");
        auto hit=cache.lookup(1,key,1001,reader); key.view=*view_b;
        auto isolated=cache.lookup(1,key,1001,reader);
        if (!hit || !*hit || !isolated || *isolated) throw runtime_error("different proxy chains shared a cached answer");
        puts("proxy DNS routing: incompatible chains use isolated experimental views");
    } catch (exception const& error) { println(stderr,"proxy view registry: {}",error.what()); return 1; }
}
