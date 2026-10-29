#include <boost/capy/buffers.hpp>
#include <boost/capy/ex/run_async.hpp>
#include <boost/capy/task.hpp>
#include <boost/corosio/backend.hpp>
#include <boost/corosio/endpoint.hpp>
#include <boost/corosio/io_context.hpp>
#include <boost/corosio/ipv4_address.hpp>
#include <boost/corosio/udp_socket.hpp>
import std;
import nexus.proxy;
import nexus.dns.fakeip_history_store;
import nexus.dns.fakeip_shared;
import nexus.dns.fakeip_registry;
import nexus.dns.fakeip_response;
import nexus.dns.message;
#include "../src/dns/corosio_fakeip_listener.hpp"
using namespace std::chrono_literals;
namespace d=nexus::dns;
namespace p=nexus::proxy;
namespace capy=boost::capy;
namespace io=boost::corosio;
std::atomic<unsigned> blocked=0;
extern "C" auto nexus_test_fakeip_blocked() -> void { ++blocked; }
extern "C" void nexus_test_fakeip_dns_received() {}
extern "C" void nexus_test_fakeip_watcher_done() {}
extern "C" void nexus_test_fakeip_session_release(bool) {}
auto run_dns(d::detail::FakeIpListener& listener,
             std::optional<std::expected<void,d::detail::FakeIpListenerError>>& result) -> capy::task<> {
    result=co_await listener.run();
}

auto main(int argc,char** argv) -> int {
    if (argc!=6) return 2;
    auto port=std::stoi(argv[2]), workers=std::stoi(argv[3]);
    auto mode=std::string_view(argv[4]);
    auto pool=std::string_view(argv[5]);
    if (port<1 || port>65535 || workers<1 || workers>2 || (mode!="new" && mode!="existing") ||
        (pool!="old" && pool!="new")) return 2;
    auto base=pool=="old" ? 0xc6120000u : 0xc6130000u;
    auto store=d::FakeIpHistoryStore::open_with_credentials(argv[1],mode=="new" ?
        d::FakeIpHistoryStoreMode::create_new : d::FakeIpHistoryStoreMode::open_existing);
    if (!store) return 3;
    auto owner=d::start_fakeip(std::move(*store),{base,base+3,base+1,base+1,1s,0s},1s);
    if (!owner) return 4;
    auto query=d::make_query(1,{"example.test",1});
    auto other=d::make_query(2,{"other.test",1});
    if (!query || !other) return 5;
    p::Server server;
    p::DnsRouting routing; p::DnsServer upstream;
    upstream.address[0]=127; upstream.address[3]=1; upstream.port=port;
    routing.servers.push_back(upstream); routing.strategy=p::DnsStrategy::ipv4_only; routing.disable_cache=true;
    if (!server.set_fakeip(*owner,7) || !server.set_dns_routing(std::move(routing))) return 6;
#if BOOST_COROSIO_HAVE_LIBURING
    io::io_context dns_context{io::uring};
#else
    io::io_context dns_context;
#endif
    d::detail::FakeIpListener dns_listener{dns_context,**owner,base,7};
    if (!dns_listener.open(0)) return 8;
    auto dns_port=dns_listener.local_endpoint().port();
    auto listen=server.start(0,p::Inbound::mixed,workers); if (!listen) return 7;
    std::atomic<bool> stopping=false, dns_failed=false, proxy_stopped=false;
    std::optional<std::expected<void,d::detail::FakeIpListenerError>> dns_result;
    capy::run_async(dns_context.get_executor())(run_dns(dns_listener,dns_result));
    std::thread dns_poller([&] {
        while (!stopping) {
            dns_context.restart(); (void)dns_context.run_for(10ms);
            if (dns_result && !*dns_result) { dns_failed=true; break; }
        }
        dns_listener.stop(); dns_context.restart(); (void)dns_context.run();
    });
    std::thread poller([&] {
        while (!stopping && !dns_failed) server.poll(10ms);
        server.stop(); proxy_stopped=true;
    });
    std::cout << *listen << std::endl;
    std::string line;
    while (std::getline(std::cin,line) && line!="stop") {
        if (line=="publish") {
            auto response=(*owner)->respond(base,*query,7);
            auto ok=response && (*response)->finish(true);
            std::cout << (ok ? "published" : "quarantined") << std::endl;
        } else if (line=="dns-port") {
            std::cout << dns_port << std::endl;
        } else if (line=="proxy-status") {
            std::cout << (proxy_stopped ? "stopped" : "running") << std::endl;
        } else if (line=="other") {
            auto response=(*owner)->respond(base,*other,7);
            if (response) std::cout << ((*response)->finish(false) ? "free" : "error") << std::endl;
            else {
                auto full=std::variant<d::FakeIpRegistryError,d::FakeIpDnsError>{d::FakeIpDnsError::full};
                std::cout << (response.error()==full ? "full" : "error") << std::endl;
            }
        } else if (line=="blocked") {
            std::cout << blocked.load() << std::endl;
        } else if (line=="old") {
            auto result=(*owner)->contains(0xc6120001);
            std::cout << (result && *result ? "protected" : "unprotected") << std::endl;
        } else if (line=="new") {
            auto result=(*owner)->contains(0xc6130001);
            std::cout << (result && *result ? "protected" : "unprotected") << std::endl;
        } else break;
    }
    stopping=true; poller.join(); dns_poller.join();
    if (!dns_result || !*dns_result) return 9;
}
