import std;
import nexus.proxy;
import nexus.dns.fakeip_shared;
import nexus.dns.fakeip_registry;
import nexus.dns.fakeip_response;
import nexus.dns.message;
using namespace std::chrono_literals;
namespace d=nexus::dns;
namespace p=nexus::proxy;
std::atomic<unsigned> blocked_candidates=0;
std::atomic<unsigned> watcher_done=0, pin_release_after_watcher=0, pin_release_before_watcher=0;
extern "C" auto nexus_test_fakeip_blocked() -> void { ++blocked_candidates; }
extern "C" void nexus_test_fakeip_watcher_done() { ++watcher_done; }
extern "C" void nexus_test_fakeip_session_release(bool pinned) {
    if (pinned && std::getenv("NEXUS_TEST_FAKEIP_DNS_THROW")) {
        if (watcher_done) ++pin_release_after_watcher;
        else ++pin_release_before_watcher;
    }
}
extern "C" void nexus_test_fakeip_dns_received() {
    if (std::getenv("NEXUS_TEST_FAKEIP_DNS_THROW")) throw std::runtime_error("injected DNS receive failure");
}
auto main(int argc,char** argv) -> int {
    if (argc<3) return 2;
    auto dns_port=std::stoi(argv[1]);
    auto workers=std::stoi(argv[2]);
    if (dns_port<1 || dns_port>65535 || workers<1 || workers>16) return 2;
    constexpr std::uint32_t base=0xc6120000;
    auto owner=std::make_shared<d::FakeIpShared>(1);
    if (!owner->add(base,base+3,base+1,base+1,1s,0s) || !owner->seal()) return 3;
    auto query=d::make_query(1,{"example.test",1});
    auto other=d::make_query(2,{"other.test",1});
    if (!query || !other) return 3;
    auto response=owner->respond(base,*query,7);
    if (!response || !(*response)->finish(true)) return 3;
    p::Server server;
    p::DnsRouting routing;
    p::DnsServer upstream; upstream.address[0]=127; upstream.address[3]=1; upstream.port=dns_port;
    routing.servers.push_back(upstream); routing.strategy=p::DnsStrategy::ipv4_only; routing.disable_cache=true;
    if (!server.set_fakeip(owner,7) || !server.set_dns_routing(std::move(routing))) return 4;
    auto inbound=p::Inbound::mixed;
    bool block=argc>3 && std::string_view(argv[argc-1])=="block";
    if (block) {
        if (!server.set_block_rules("schema-version 1\nkind \"predicate\"\nrule type=\"domain-suffix\" value=\"example.test\"\n",p::RuleFormat::kdl)) return 4;
        --argc;
    }
    if (argc==7 && std::string_view(argv[3])=="vless") {
        std::array<std::string,1> users{argv[6]};
        if (!server.prepare_vless_inbound(argv[4],argv[5],users)) return 4;
        inbound=p::Inbound::vless;
    } else if (argc==4 && std::string_view(argv[3])=="ss") {
        std::array<std::uint8_t,16> key{};
        std::iota(key.begin(),key.end(),std::uint8_t{0});
        if (!server.prepare_shadowsocks_inbound(key)) return 4;
        inbound=p::Inbound::shadowsocks;
    } else if (argc!=3) return 2;
    auto port=server.start(0,inbound,workers);
    if (!port) return 5;
    std::atomic<bool> stopping=false;
    std::thread poller([&] { while (!stopping) server.poll(10ms); });
    std::cout << *port << std::endl;
    std::string line;
    while (std::getline(std::cin,line) && line!="stop") {
        if (line=="halt") {
            stopping=true; if (poller.joinable()) poller.join(); server.stop();
            std::cout << "halted" << std::endl;
            continue;
        }
        if (line=="blocked") { std::cout << blocked_candidates.load() << std::endl; continue; }
        if (line=="order") { std::cout << pin_release_after_watcher.load() << ' ' << pin_release_before_watcher.load() << std::endl; continue; }
        if (line!="probe") break;
        auto probe=owner->respond(base,*other,7);
        if (probe) {
            bool finished=(*probe)->finish(false).has_value();
            std::cout << (finished ? "free" : "error") << std::endl;
        } else {
            auto expected=std::variant<d::FakeIpRegistryError,d::FakeIpDnsError>{d::FakeIpDnsError::full};
            std::cout << (probe.error()==expected ? "full" : "error") << std::endl;
        }
    }
    stopping=true; if (poller.joinable()) poller.join(); server.stop();
}
