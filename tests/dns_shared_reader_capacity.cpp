import std;
import config;
import dns.cache;
import dns.message;
import relay;

namespace {
    auto require(bool condition,std::string_view message) -> void {
        if(!condition)throw std::runtime_error(std::string(message));
    }
    auto maximum_config() -> config::Config {
        std::string text="schema-version 1\nrole \"server\"\nworkers 16\ninbounds {\n";
        for(unsigned i=0;i<16;++i)
            text+=std::format("inbound \"ss{}\" type=\"shadowsocks\" {{ listen host=\"127.0.0.1\" port={}; method \"2022-blake3-aes-128-gcm\"; key-file \"/unused-reader-capacity.key\"; }}\n",i,20000+i);
        text+="}\noutbound \"direct\" type=\"direct\"\nrouting { default-outbound \"direct\"; tcp-program sniff-timeout-ms=500 unknown=\"skip\" udp=#true { rule action=\"route\" outbound=\"direct\"; }; }\n";
        auto parsed=config::parse_kdl(text);
        if(!parsed)throw std::runtime_error(parsed.error());
        return std::move(*parsed);
    }
}

auto main() -> int {
    try {
        auto config=maximum_config();
        auto listeners=config.inbounds.size();
        require(listeners==16 && config.workers==16 && config.ordered_tcp && config.ordered_tcp->udp,
                "maximum configuration did not retain its resource plan");
        auto workers=listeners*config.workers;
        auto readers=workers+2; // SS UDP lookup and its ordered routing context.
        relay::SharedDnsGeneration generation(listeners+1,readers);
        auto& cache=generation.cache();
        for(std::size_t group=0;group<listeners;++group)
            require(cache.supports_binding(group,group*config.workers,config.workers),"worker binding rejected");
        require(cache.supports_binding(listeners,workers,1) && cache.supports_binding(listeners,workers+1,1),
                "SS UDP lookup or ordered routing reader unavailable");
        require(!cache.supports_binding(listeners,workers+1,2),"binding crossed reader limit");
        std::vector<decltype(cache.reader(0))> claimed;
        claimed.reserve(readers);
        for(std::size_t i=0;i<readers;++i)claimed.push_back(cache.reader(i));

        dns::CacheKey key{1,"reader-boundary.example",1};
        dns::Address address{};address.size=4;address.bytes[0]=127;address.bytes[3]=1;
        auto token=cache.begin_query(listeners,key);
        require(token.has_value(),"UDP cache query registration failed");
        dns::AddressAnswer answer{key.name,{key.name},{address},60};
        require(cache.publish(listeners,key,std::move(answer),1000,*token).has_value(),"UDP cache publication failed");
        for(auto index:{workers,workers+1}) {
            auto found=cache.lookup(listeners,key,1000,claimed[index]);
            require(found && *found && (**found).addresses.size()==1 && (**found).addresses[0].bytes==address.bytes,
                    "last UDP reader could not read published answer");
        }
        claimed.pop_back();claimed.push_back(cache.reader(readers-1));
        bool overflow=false;
        try {auto invalid=cache.reader(readers);}
        catch(std::out_of_range const&) {overflow=true;}
        require(overflow,"out-of-range reader accepted");
        overflow=false;
        try {relay::SharedDnsGeneration invalid(listeners+1,readers+1);}
        catch(std::out_of_range const&) {overflow=true;}
        require(overflow,"reader allocation ceiling not enforced");

        // All consumers register the same global DNS plan. Its profiles are
        // deduplicated before the 64-profile bound, independent of reader count.
        relay::DnsRouting routing;
        for(unsigned i=0;i<64;++i) {
            relay::DnsServer server{};server.address[0]=127;server.address[3]=1;server.port=10000+i;
            routing.servers.push_back(std::move(server));
        }
        for(std::size_t consumer=0;consumer<listeners+2;++consumer)
            for(std::size_t server=0;server<routing.servers.size();++server)
                require(generation.registry().register_profile(routing,server).has_value(),"shared profile registration exceeded limit");
        generation.seal();
        require(generation.coordinator().counts()==std::pair<std::size_t,std::size_t>{0,0},"reader allocation created flights");
        std::println("16 listeners x 16 workers plus SS UDP lookup and ordered routing: {} readers passed",readers);
    } catch(std::exception const& error) {
        std::cerr<<error.what()<<'\n';return 1;
    }
}
