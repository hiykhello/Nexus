// Exercise exported view identities with the real proxy routing type.
import std;
import dns.message;
import dns.corosio_query;
import dns.cache;
import dns.shared_cache;
import dns.shared_coordinator;
import capy;
import corosio;
import relay;
import dns.corosio_cached;

int main() {
    namespace p = relay;
    namespace d=dns;
    namespace hp=dns_hp_experiment;
    namespace io = ::corosio;
    try {
        p::DnsServer root; root.address[0]=127; root.address[3]=1; root.port=5301;
        p::DnsServer leaf; leaf.host="DNS.Example.Test."; leaf.port=5302; leaf.resolver=0;
        p::DnsRouting first{{root,leaf},{},1},second=first,equivalent=first;
        second.servers[0].port=5303;
        equivalent.servers[1].host="dns.example.test.";
        hp::ViewRegistry registry(8,65536,16);
        auto a=registry.register_profile(first,1),b=registry.register_profile(second,1),c=registry.register_profile(equivalent,1);
        if (!a || !b || !c) throw std::runtime_error("proxy profiles could not be registered");
        registry.seal();
        std::array profiles{*a,*b,*c}; hp::ViewBinding binding(registry,profiles);
        auto endpoint=io::endpoint(io::ipv4_address::loopback(),5302);
        auto view_a=binding.view(0,endpoint),view_b=binding.view(1,endpoint),view_c=binding.view(2,endpoint);
        if (!view_a || !view_b || !view_c || *view_a==*view_b || *view_a!=*view_c)
            throw std::runtime_error("exported proxy views did not preserve policy identity");
        std::array<std::size_t,2> groups{1,1};
        hp::GroupSnapshot cache(groups,hp::GroupSnapshot::SharedCapacity{8},2,0,65536);
        auto reader=cache.reader(1);
        hp::GroupBinding local(cache,1);
        auto context=io::make_io_context(false);
        hp::Coordinator coordinator(2,4); hp::CoordinatorOwner owner(context,local,coordinator);
        d::detail::BasicDualAddressResolver<hp::GroupBinding> existing(context,local,false,
            d::detail::AddressStrategy::ipv4_only,false,false,nullptr,&reader);
        hp::CoordinatorQuery coordinated(owner,&reader,hp::CoordinatedStrategy::ipv4_only);
        existing.cancel(); coordinated.cancel(); owner.stop();
        d::CacheKey key{*view_a,"name.example.test",1};
        d::Address address{}; address.size=4; address.bytes[0]=127; address.bytes[3]=91;
        d::AddressAnswer answer{key.name,{key.name},{address},30};
        auto token=cache.begin_query(0,key);
        if (!token || !cache.publish(0,key,std::move(answer),1000,*token)) throw std::runtime_error("view cache seed failed");
        auto shared=cache.lookup(1,key,1001,reader); key.view=*view_b;
        auto isolated=cache.lookup(1,key,1001,reader);
        if (!shared || !*shared || !isolated || *isolated) throw std::runtime_error("exported views shared incompatible answers");
        std::println("exported view registry: real proxy routing and cache isolation passed");
    } catch (std::exception const& error) { std::cerr << "coordinator proxy view: " << error.what() << '\n'; return 1; }
}
