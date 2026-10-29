#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cerrno>
#include <memory_resource>
import std;
import nexus.proxy;
using namespace std::chrono_literals;
unsigned launches=0;
extern "C" void nexus_test_root_launch(unsigned stage) {
    if (stage==0 && ++launches==2) throw std::bad_alloc();
}
extern "C" std::pmr::memory_resource* nexus_test_root_resource() { return std::pmr::get_default_resource(); }
auto connect_to(std::uint16_t port) -> int {
    int fd=socket(AF_INET,SOCK_STREAM,0); if (fd<0) return -1;
    sockaddr_in address{}; address.sin_family=AF_INET; address.sin_addr.s_addr=htonl(INADDR_LOOPBACK); address.sin_port=htons(port);
    if (connect(fd,reinterpret_cast<sockaddr*>(&address),sizeof(address))) { close(fd); return -1; }
    return fd;
}
auto read_exact(nexus::proxy::Server& server,int fd,std::span<unsigned char> bytes) -> bool {
    auto deadline=std::chrono::steady_clock::now()+3s;
    while (!bytes.empty() && std::chrono::steady_clock::now()<deadline) {
        server.poll(10ms);
        auto n=recv(fd,bytes.data(),bytes.size(),MSG_DONTWAIT);
        if (n>0) bytes=bytes.subspan(static_cast<std::size_t>(n));
        else if (n==0 || (errno!=EAGAIN && errno!=EWOULDBLOCK && errno!=EINTR)) return false;
    }
    return bytes.empty();
}
int main() {
    nexus::proxy::Server server;
    constexpr auto rules="schema-version 1\nkind \"predicate\"\nrule type=\"ip-cidr\" value=\"127.0.0.0/8\"\n";
    if (!server.set_block_rules(rules,nexus::proxy::RuleFormat::kdl) || !server.set_socks5_credentials("user","password")) return 1;
    auto port=server.start(0); if (!port) return 2;
    auto first=connect_to(*port); if (first<0) return 3;
    for (int i=0;i<100 && launches!=1;++i) server.poll(10ms);
    if (launches!=1) return 4;
    auto second=connect_to(*port); if (second<0) return 5;
    for (int i=0;i<100 && server.healthy();++i) server.poll(10ms);
    auto failure=server.failure();
    if (server.healthy() || !failure || failure->kind!=nexus::proxy::FailureKind::accept_task || launches!=2) return 6;
    if (server.clear_socks5_credentials() || server.set_socks5_credentials("new","secret") ||
        server.set_route({},nexus::proxy::RuleFormat::kdl,nexus::proxy::RouteAction::direct,nexus::proxy::RouteAction::direct)) return 7;
    std::array<unsigned char,3> hello{5,1,2}; std::array<unsigned char,2> method{};
    if (send(first,hello.data(),hello.size(),MSG_NOSIGNAL)!=static_cast<ssize_t>(hello.size()) || !read_exact(server,first,method) || method!=std::array<unsigned char,2>{5,2}) return 8;
    std::array<unsigned char,15> auth{1,4,'u','s','e','r',8,'p','a','s','s','w','o','r','d'}, result{};
    if (send(first,auth.data(),auth.size(),MSG_NOSIGNAL)!=static_cast<ssize_t>(auth.size()) || !read_exact(server,first,std::span(result).first(2)) || result[1]!=0) return 9;
    std::array<unsigned char,10> request{5,1,0,1,127,0,0,1,0,80}, reply{};
    if (send(first,request.data(),request.size(),MSG_NOSIGNAL)!=static_cast<ssize_t>(request.size()) || !read_exact(server,first,reply) || reply[1]!=2) return 10;
    server.stop(); close(first); close(second);
    if (!server.clear_socks5_credentials() || !server.set_route({},nexus::proxy::RuleFormat::kdl,nexus::proxy::RouteAction::direct,nexus::proxy::RouteAction::direct)) return 11;
    auto again=server.start(0); if (!again) return 12;
    server.stop();
    std::println("Pending SOCKS session keeps its credentials and route after accept task failure");
}
