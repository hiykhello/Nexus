// Two real SOCKS inbounds with distinct DNS strategies share one generation.
import std;
import dns.message;
import dns.cache;
import dns.shared_cache;
import dns.shared_coordinator;
import relay;

extern "C" void nexus_test_dns_shared_access(void const*) noexcept {}

int main(int argc,char** argv) {
    namespace p = relay;
    namespace hp=dns_hp_experiment;
    if (argc!=3) return 2;
    try {
        std::array<std::size_t,2> groups{1,1};
        hp::GroupSnapshot cache(groups,hp::GroupSnapshot::SharedCapacity{64},4,0,1024*1024);
        hp::Coordinator coordinator(8,32);
        hp::ViewRegistry views(8,65536,32);
        std::array<std::unique_ptr<p::Server>,2> servers;
        for (std::size_t i=0;i<servers.size();++i) {
            auto port=std::stoi(argv[i+1]);
            if (port<1 || port>65535) return 2;
            auto server=p::Server::create(); if (!server) return 3;
            servers[i]=std::move(*server);
            p::DnsServer root; root.address[0]=127; root.address[3]=1; root.port=static_cast<std::uint16_t>(port);
            p::DnsRouting routing; routing.servers.push_back(root); routing.strategy=p::DnsStrategy::ipv4_only;
            if (!servers[i]->set_dns_routing(std::move(routing)) || !servers[i]->set_dns_group_for_test(cache,i,2*i) ||
                !servers[i]->set_dns_coordinator_for_test(coordinator,views)) return 4;
        }
        views.seal();
        std::array<std::uint16_t,2> ports{};
        for (std::size_t i=0;i<servers.size();++i) {
            auto port=servers[i]->start(0,p::Inbound::socks5,2); if (!port) return 5;
            ports[i]=*port;
        }
        std::cout<<ports[0]<<' '<<ports[1]<<std::endl;
        std::string line; if (!std::getline(std::cin,line) || line!="stop") return 6;
        for (auto& server:servers) server->stop();
        if (coordinator.counts()!=std::pair<std::size_t,std::size_t>{0,0} || coordinator.direct_active()) return 7;
    } catch (std::exception const& error) { std::cerr << "isolation fixture: " << error.what() << '\n'; return 1; }
}
