#include <arpa/inet.h>
#include <cerrno>
#include <sys/socket.h>
#include <unistd.h>
import std;
import nexus.proxy;
import nexus.dns.fakeip_shared;
import nexus.dns.message;
import nexus.dns.fakeip_registry;
import nexus.dns.fakeip_response;
using namespace std::chrono_literals;
namespace d=nexus::dns; namespace p=nexus::proxy;
std::weak_ptr<d::FakeIpShared> owner;
bool skip=false, destroyed=false, alive=false, pinned_on_release=false; long owners=0;
extern "C" bool nexus_test_skip_server_stop() { return skip; }
extern "C" void nexus_test_fakeip_owner_check(bool valid) { destroyed=true; alive=valid; owners=owner.use_count(); }
extern "C" void nexus_test_fakeip_blocked() {}
extern "C" void nexus_test_fakeip_dns_received() {}
extern "C" void nexus_test_fakeip_watcher_done() {}
extern "C" void nexus_test_fakeip_session_release(bool pinned) { pinned_on_release=pinned; }
int handshake() {
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
    return 0;
}

auto read_exact(p::Server& server,int fd,std::span<unsigned char> bytes) -> bool {
    auto until=std::chrono::steady_clock::now()+3s;
    while (!bytes.empty() && std::chrono::steady_clock::now()<until) {
        server.poll(10ms);
        auto n=::recv(fd,bytes.data(),bytes.size(),MSG_DONTWAIT);
        if (n>0) bytes=bytes.subspan(static_cast<std::size_t>(n));
        else if (!n || (errno!=EAGAIN && errno!=EWOULDBLOCK && errno!=EINTR)) return false;
    }
    return bytes.empty();
}
auto dial(bool tcp) -> int {
    constexpr std::uint32_t base=0xc6120000;
    auto shared=std::make_shared<d::FakeIpShared>(1);
    if (!shared->add(base,base+3,base+1,base+1,1s,0s) || !shared->seal()) return 10;
    auto query=d::make_query(1,{"example.test",1}), other=d::make_query(2,{"other.test",1});
    if (!query || !other) return 11;
    { auto response=shared->respond(base,*query,7); if (!response || !(*response)->finish(true)) return 12; }
    owner=shared; skip=false; destroyed=false; alive=false; pinned_on_release=false; owners=0;
    int dns=::socket(AF_INET,(tcp ? SOCK_STREAM : SOCK_DGRAM)|SOCK_NONBLOCK|SOCK_CLOEXEC,0);
    if (dns<0) return 13;
    sockaddr_in addr{}; addr.sin_family=AF_INET; addr.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    if (::bind(dns,reinterpret_cast<sockaddr*>(&addr),sizeof(addr)) || (tcp && ::listen(dns,1))) return 14;
    socklen_t size=sizeof(addr); if (::getsockname(dns,reinterpret_cast<sockaddr*>(&addr),&size)) return 15;
    int client=-1, peer=-1;
    {
        p::Server server; p::DnsRouting routing; p::DnsServer upstream;
        upstream.address[0]=127; upstream.address[3]=1; upstream.port=ntohs(addr.sin_port); upstream.tcp=tcp;
        routing.servers.push_back(upstream); routing.strategy=p::DnsStrategy::ipv4_only; routing.disable_cache=true;
        if (!server.set_fakeip(shared,7) || !server.set_dns_routing(std::move(routing))) return 16;
        auto port=server.start(0); if (!port) return 17;
        client=::socket(AF_INET,SOCK_STREAM|SOCK_CLOEXEC,0); if (client<0) return 18;
        addr.sin_port=htons(*port); if (::connect(client,reinterpret_cast<sockaddr*>(&addr),sizeof(addr))) return 19;
        std::array<unsigned char,3> greeting{5,1,0}; std::array<unsigned char,2> method{};
        if (::send(client,greeting.data(),greeting.size(),MSG_NOSIGNAL)!=3 || !read_exact(server,client,method) ||
            method!=std::array<unsigned char,2>{5,0}) return 20;
        std::array<unsigned char,10> request{5,1,0,1,198,18,0,1,0,80};
        if (::send(client,request.data(),request.size(),MSG_NOSIGNAL)!=10) return 21;
        if (tcp) {
            for (int i=0;i<300 && peer<0;++i) { server.poll(10ms); peer=::accept4(dns,nullptr,nullptr,SOCK_NONBLOCK|SOCK_CLOEXEC); }
            if (peer<0) return 22;
        }
        std::array<unsigned char,512> wire{}; ssize_t received=-1;
        for (int i=0;i<300 && received<0;++i) { server.poll(10ms); received=::recv(tcp ? peer : dns,wire.data(),wire.size(),0); }
        if (received<static_cast<ssize_t>(tcp ? 3 : 1) || owner.use_count()!=2 || destroyed) return 23;
        auto until=std::chrono::steady_clock::now()+1200ms;
        while (std::chrono::steady_clock::now()<until) server.poll(10ms);
        auto blocked=shared->respond(base,*other,7);
        if (blocked || blocked.error()!=std::variant<d::FakeIpRegistryError,d::FakeIpDnsError>{d::FakeIpDnsError::full}) return 24;
        skip=true;
    }
    if (client>=0) ::close(client); if (peer>=0) ::close(peer); ::close(dns);
    if (!destroyed || !alive || !pinned_on_release || owners!=2 || owner.use_count()!=1) return 25;
    { auto free=shared->respond(base,*other,7);
      if (!free || !(*free)->finish(false)) return 26; }
    shared.reset();
    if (!owner.expired()) return 27;
    std::println("pending {} DNS dial releases pin before borrowed Fake-IP owner",tcp ? "TCP" : "UDP");
    return 0;
}
int main() {
    if (auto result=handshake()) return result;
    if (auto result=dial(false)) return result;
    return dial(true);
}
