#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
import std;
import nexus.proxy;
import nexus.dns.fakeip_shared;
using namespace std::chrono_literals;
namespace d=nexus::dns; namespace p=nexus::proxy;
std::weak_ptr<d::FakeIpShared> owner;
bool skip=false, destroyed=false, alive=false; long owners=0;
extern "C" bool nexus_test_skip_server_stop() { return skip; }
extern "C" void nexus_test_fakeip_owner_check(bool valid) { destroyed=true; alive=valid; owners=owner.use_count(); }
extern "C" void nexus_test_fakeip_blocked() {}
extern "C" void nexus_test_fakeip_dns_received() {}
extern "C" void nexus_test_fakeip_watcher_done() {}
extern "C" void nexus_test_fakeip_session_release(bool) {}
int main() {
    int fd=-1;
    {
        auto shared=std::make_shared<d::FakeIpShared>(1);
        if (!shared->add(0xc6120000,0xc6120003,0xc6120001,0xc6120001,1s,0s) || !shared->seal()) return 1;
        owner=shared;
        p::Server server;
        if (!server.set_fakeip(shared,7)) return 2;
        shared.reset();
        auto port=server.start(0); if (!port) return 3;
        fd=::socket(AF_INET,SOCK_STREAM,0); if (fd<0) return 4;
        sockaddr_in address{}; address.sin_family=AF_INET; address.sin_addr.s_addr=htonl(INADDR_LOOPBACK); address.sin_port=htons(*port);
        if (::connect(fd,reinterpret_cast<sockaddr*>(&address),sizeof(address))) return 5;
        for (int i=0;i<10;++i) server.poll(10ms);
        if (destroyed || owner.use_count()!=1) return 6;
        skip=true;
    }
    ::close(fd);
    if (!destroyed || !alive || owners!=1 || !owner.expired()) return 7;
    std::println("suspended session borrows fake-IP owner through context destruction");
}
