// Isolated view identity tests; no production path uses the registry.
#include <boost/corosio/endpoint.hpp>
#include <boost/corosio/ipv4_address.hpp>
#include <boost/corosio/ipv6_address.hpp>
import std;
import dns.message;
import dns.cache;
namespace nex { namespace corosio=boost::corosio; }
#include "../../src/dns-shared/group_snapshot.hpp"
#include "../../src/dns-shared/group_view_registry.hpp"

namespace hp=dns_hp_experiment;
namespace d=dns;
namespace io=boost::corosio;
namespace {
thread_local int fail_after=-1;
}
void* operator new(std::size_t size) {
    if (fail_after>=0 && fail_after--==0) { fail_after=-1; throw std::bad_alloc(); }
    if (auto* value=std::malloc(size ? size : 1)) return value;
    throw std::bad_alloc();
}
void operator delete(void* value) noexcept { std::free(value); }
void operator delete(void* value,std::size_t) noexcept { std::free(value); }

namespace {
auto require(bool value,char const* message) -> void { if (!value) throw std::runtime_error(message); }
struct Server {
    std::array<std::uint8_t,16> address{};
    bool ipv6=false;
    std::uint16_t port=0;
    bool tcp=false;
    std::string host;
    std::optional<std::size_t> resolver;
};
enum class Strategy { automatic,prefer_ipv4,prefer_ipv6,ipv4_only,ipv6_only };
struct Routing {
    std::vector<Server> servers;
    Strategy strategy=Strategy::automatic;
    bool disable_cache=false,edns=false;
};
auto routing() -> Routing {
    Server root; root.address[0]=127; root.address[3]=1; root.port=5301;
    Server leaf; leaf.host="Dns.Example.Test."; leaf.port=5302; leaf.resolver=0;
    return {{std::move(root),std::move(leaf)}};
}
auto endpoint(std::uint16_t port,std::uint8_t address=1) -> io::endpoint {
    return {io::ipv4_address({127,0,0,address}),port};
}
auto identity() -> void {
    using Registry=hp::ViewRegistry; using Error=Registry::Error;
    Registry registry(64,1024*1024,128),other(1,4096,1);
    auto original=routing(); auto base=registry.register_profile(original,1);
    require(base.has_value(),"base profile registration failed");
    auto reversed=original;
    std::swap(reversed.servers[0],reversed.servers[1]); reversed.servers[0].host="dns.example.test."; reversed.servers[0].resolver=1;
    auto equivalent=registry.register_profile(reversed,0);
    require(equivalent && registry.counts().first==1,"equivalent reordered resolver chain was not shared");
    auto other_profile=other.register_profile(original,1); require(other_profile.has_value(),"second registry profile failed");
    auto matched=registry.matches(*base,reversed,0);
    auto mismatch=registry.matches(*base,original,0);
    auto wrong_match=registry.matches(*other_profile,original,1);
    require(matched && *matched && mismatch && !*mismatch && !wrong_match && wrong_match.error()==Error::wrong_owner &&
            !registry.sealed(),"profile matching failed before seal");
    require(!registry.view(*base,endpoint(5302)) && registry.view(*base,endpoint(5302)).error()==Error::not_sealed,
            "view was issued before configuration sealed");
    std::array local_profiles{*base,*other_profile}; hp::ViewBinding local(registry,local_profiles);
    auto unsealed=local.view(0,endpoint(5302));
    require(!unsealed && unsealed.error()==Error::not_sealed,"local binding cached an unsealed view");

    std::vector<Registry::Profile> variants;
    auto add=[&](Routing value) {
        auto profile=registry.register_profile(value,1);
        require(profile.has_value(),"different profile registration failed"); variants.push_back(*profile);
    };
    auto different=original; different.servers[0].address[3]=2; add(different);
    different=original; different.servers[0].port++; add(different);
    different=original; different.servers[0].tcp=true; add(different);
    different=original; different.servers[1].host="other.example.test"; add(different);
    different=original; different.servers[1].host="dns.example.test"; add(different);
    different=original; different.servers[1].port++; add(different);
    different=original; different.servers[1].tcp=true; add(different);
    different=original; different.edns=true; add(different);
    different=original; different.disable_cache=true; add(different);
    different=original; different.strategy=Strategy::prefer_ipv6; add(different);
    different=original; different.servers[0].ipv6=true; add(different);
    require(registry.counts().first==variants.size()+1,"distinct policies reused a profile");
    auto charged=registry.policy_bytes();
    auto duplicate=registry.register_profile(original,1);
    require(duplicate && registry.policy_bytes()==charged,"duplicate profile consumed policy budget");
    registry.seal(); other.seal();
    require(registry.sealed() && registry.matches(*base,original,1).value_or(false),"sealed profile did not match");
    auto sealed=registry.register_profile(original,1);
    require(!sealed && sealed.error()==Error::sealed,"sealed registry accepted configuration");
    auto foreign=registry.view(*other_profile,endpoint(5302));
    require(!foreign && foreign.error()==Error::wrong_owner,"registry accepted a foreign profile");
    auto bad_endpoint=registry.view(*base,endpoint(0));
    require(!bad_endpoint && bad_endpoint.error()==Error::invalid,"registry accepted a zero port");
    auto first=registry.view(*base,endpoint(5302)); auto shared=registry.view(*equivalent,endpoint(5302));
    require(first && shared && *first==*shared,"equivalent profiles produced different views");
    require(local.view(0,endpoint(5302))==first && local.view(0,endpoint(5302))==first,
            "local binding did not reuse its issued view");
    auto wrong_local=local.view(1,endpoint(5302)),bad_local=local.view(2,endpoint(5302));
    require(!wrong_local && wrong_local.error()==Error::wrong_owner && !bad_local && bad_local.error()==Error::invalid,
            "local binding accepted an invalid profile or index");
    std::set<std::uint64_t> ids{*first};
    d::ClientSubnet subnet{1,24,{192,0,2}};
    auto subnet_view=registry.view(*base,endpoint(5302),subnet);
    require(subnet_view && ids.insert(*subnet_view).second && local.view(0,endpoint(5302),subnet)==subnet_view,
            "ECS view was not isolated or reused");
    subnet.address[2]=3;
    auto other_subnet=registry.view(*base,endpoint(5302),subnet);
    require(other_subnet && ids.insert(*other_subnet).second,"different ECS prefixes reused a view");
    subnet.address[3]=1;
    auto invalid_subnet=registry.view(*base,endpoint(5302),subnet);
    require(!invalid_subnet && invalid_subnet.error()==Error::invalid,"invalid ECS prefix accepted");
    for (auto profile:variants) {
        auto view=registry.view(profile,endpoint(5302)); require(view && ids.insert(*view).second,"distinct policy reused a view");
    }
    for (auto target:{endpoint(5302,2),endpoint(5303)}) {
        auto view=registry.view(*base,target); require(view && ids.insert(*view).second,"distinct upstream reused a view");
    }
    io::ipv6_address::bytes_type bytes{}; bytes[0]=0xfe; bytes[1]=0x80; bytes[15]=1;
    for (std::uint32_t scope:{1u,2u}) {
        auto view=registry.view(*base,io::endpoint(io::ipv6_address(bytes,scope),5302));
        require(view && ids.insert(*view).second,"IPv6 scope reused a view");
    }
    require(registry.counts().second==ids.size(),"unexpected number of unique views");
    // A prior view remains stable even after other views were inserted.
    require(registry.view(*base,endpoint(5302))==first,"view changed during registry lifetime");
}
auto invalid_and_limits() -> void {
    using Registry=hp::ViewRegistry; using Error=Registry::Error;
    Registry registry(1,4096,2);
    auto route=routing(),invalid=route;
    invalid.servers[0].host="root.example.test"; invalid.servers[0].resolver=1;
    auto cycle=registry.register_profile(invalid,1); require(!cycle && cycle.error()==Error::invalid,"resolver cycle accepted");
    invalid=route; invalid.servers[1].resolver=100;
    auto missing=registry.register_profile(invalid,1); require(!missing && missing.error()==Error::invalid,"missing resolver accepted");
    invalid=route; invalid.servers[1].host=std::string(10000,'a');
    auto long_name=registry.register_profile(invalid,1); require(!long_name && long_name.error()==Error::invalid,"oversized name accepted");
    require(registry.counts()==std::pair<std::size_t,std::size_t>{0,0} && registry.policy_bytes()==0,
            "invalid profile changed accounting");
    auto profile=registry.register_profile(route,1); require(profile.has_value(),"limited profile registration failed");
    auto duplicate=registry.register_profile(route,1); require(duplicate.has_value(),"full profile set rejected a duplicate");
    route.edns=true; auto excess=registry.register_profile(route,1);
    require(!excess && excess.error()==Error::limit && registry.counts().first==1,"profile count limit failed");
    registry.seal();
    auto first=registry.view(*profile,endpoint(5301)),second=registry.view(*profile,endpoint(5302));
    auto third=registry.view(*profile,endpoint(5303));
    require(first && second && !third && third.error()==Error::limit && registry.counts().second==2 &&
            registry.view(*profile,endpoint(5301))==first,"view limit or existing-view lookup failed");
    std::array profiles{*profile}; hp::ViewBinding local(registry,profiles);
    require(local.view(0,endpoint(5301))==first,"local limited binding failed");
    auto local_excess=local.view(0,endpoint(5303));
    require(!local_excess && local_excess.error()==Error::limit && local.view(0,endpoint(5301))==first,
            "failed endpoint change damaged local binding");
    Registry no_bytes(2,0,2); auto no_profile=no_bytes.register_profile(route,1);
    require(!no_profile && no_profile.error()==Error::limit && no_bytes.policy_bytes()==0,"policy byte limit failed");
}
auto allocation_failures() -> void {
    using Registry=hp::ViewRegistry; using Error=Registry::Error;
    auto route=routing(); unsigned failures=0; bool success=false;
    for (int position=0;position<64;++position) {
        Registry registry(2,4096,2);
        fail_after=position; auto profile=registry.register_profile(route,1); fail_after=-1;
        if (!profile) {
            require(profile.error()==Error::allocation && registry.counts().first==0 && registry.policy_bytes()==0,
                    "profile allocation failure damaged registry state");
            ++failures;
            require(registry.register_profile(route,1).has_value(),"profile did not recover after allocation failure");
        } else { success=true; break; }
    }
    require(success && failures>0,"profile allocation sweep missed failures");
    Registry registry(2,4096,2); auto profile=registry.register_profile(route,1); require(profile.has_value(),"view fault profile failed");
    fail_after=0; auto failed_match=registry.matches(*profile,route,1); fail_after=-1;
    require(!failed_match && failed_match.error()==Error::allocation && registry.matches(*profile,route,1).value_or(false),
            "profile match allocation failure did not recover");
    registry.seal(); fail_after=0; auto failed=registry.view(*profile,endpoint(5301)); fail_after=-1;
    require(!failed && failed.error()==Error::allocation && registry.counts().second==0,"view allocation failure changed accounting");
    auto recovered=registry.view(*profile,endpoint(5301)); require(recovered && *recovered==1,"view allocation retry did not recover");
    fail_after=0; auto existing=registry.view(*profile,endpoint(5301)); fail_after=-1;
    require(existing && *existing==*recovered,"existing view lookup allocated");
}
auto parallel_and_cache() -> void {
    using Registry=hp::ViewRegistry;
    Registry registry(8,65536,64); auto first_route=routing(),second_route=first_route;
    second_route.servers[0].address[3]=2;
    auto first=registry.register_profile(first_route,1),second=registry.register_profile(second_route,1);
    require(first && second,"parallel profiles failed"); registry.seal();
    auto a=registry.view(*first,endpoint(5302)),b=registry.view(*second,endpoint(5302));
    auto c=registry.view(*first,endpoint(5302,2)); require(a && b && c && *a!=*b && *a!=*c && *b!=*c,"view isolation failed");
    std::atomic<bool> failed=false; std::vector<std::jthread> threads;
    for (unsigned thread=0;thread<8;++thread) threads.emplace_back([&] {
        std::array profiles{*first,*second}; hp::ViewBinding local(registry,profiles);
        for (unsigned i=0;i<5000;++i) {
            auto one=registry.view(*first,endpoint(5302)),two=registry.view(*second,endpoint(5302)),three=registry.view(*first,endpoint(5302,2));
            auto local_one=local.view(0,endpoint(5302)),local_two=local.view(1,endpoint(5302));
            if (!one || !two || !three || !local_one || !local_two || *one!=*a || *two!=*b || *three!=*c ||
                *local_one!=*a || *local_two!=*b) failed=true;
        }
        auto changed=local.view(0,endpoint(5302,2)),restored=local.view(0,endpoint(5302));
        if (!changed || !restored || *changed!=*c || *restored!=*a) failed=true;
    });
    threads.clear(); require(!failed && registry.counts().second==3,"concurrent view lookups changed identity");
    std::array<std::atomic<std::uint64_t>,32> concurrent_ids{};
    std::barrier gate(8);
    for (unsigned thread=0;thread<8;++thread) threads.emplace_back([&] {
        gate.arrive_and_wait();
        for (unsigned i=0;i<32;++i) {
            auto view=registry.view(i<16 ? *first : *second,endpoint(static_cast<std::uint16_t>(5400+i%16)));
            if (!view) { failed=true; continue; }
            std::uint64_t empty=0;
            if (!concurrent_ids[i].compare_exchange_strong(empty,*view) && empty!=*view) failed=true;
        }
    });
    threads.clear();
    std::set<std::uint64_t> unique{*a,*b,*c};
    for (auto const& id:concurrent_ids) if (!id.load() || !unique.insert(id.load()).second) failed=true;
    require(!failed && registry.counts().second==35,"concurrent view insertion duplicated or merged identities");
    std::array<std::size_t,2> capacities{8,8}; hp::GroupSnapshot cache(capacities,2,0,65536);
    auto reader=cache.reader(1); d::CacheKey key{*a,"same.example.test",1};
    d::Address address{}; address.size=4; address.bytes[0]=127; address.bytes[3]=81;
    d::AddressAnswer answer{key.name,{key.name},{address},30};
    auto token=cache.begin_query(0,key);
    require(token && cache.publish(0,key,std::move(answer),1000,*token),"view cache seed failed");
    auto same=cache.lookup(1,key,1001,reader); key.view=*b;
    auto other_policy=cache.lookup(1,key,1001,reader); key.view=*c;
    auto other_endpoint=cache.lookup(1,key,1001,reader);
    require(same && *same && (**same).addresses[0].bytes[3]==81 && other_policy && !*other_policy &&
            other_endpoint && !*other_endpoint,"different policy or endpoint adopted the cached answer");
}
}
int main() {
    try {
        identity(); invalid_and_limits(); allocation_failures(); parallel_and_cache();
        std::puts("DNS views: full policy/endpoint identity, bounds, failures and concurrent lookup passed");
    } catch (std::exception const& error) { std::println(stderr,"view registry: {}",error.what()); return 1; }
}
