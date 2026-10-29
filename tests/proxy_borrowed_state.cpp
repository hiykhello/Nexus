#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
import std;
import nexus.proxy;
using namespace std::chrono_literals;
bool skip_stop=false, destroyed=false, valid=false;
extern "C" bool nexus_test_skip_server_stop() { return skip_stop; }
extern "C" void nexus_test_dns_owner_destroy() {}
extern "C" void nexus_test_dns_registration_destroy() {}
extern "C" void nexus_test_handshake_borrowed_state(bool result) { destroyed=true; valid=result; }
int main() {
    int fd=-1;
    {
        nexus::proxy::Server server;
        constexpr auto rules="schema-version 1\nkind \"predicate\"\nrule type=\"ip-cidr\" value=\"127.0.0.0/8\"\n";
        if (!server.set_block_rules(rules,nexus::proxy::RuleFormat::kdl) || !server.set_socks5_credentials("user","password")) return 1;
        auto port=server.start(0); if (!port) return 2;
        fd=socket(AF_INET,SOCK_STREAM,0); if (fd<0) return 3;
        sockaddr_in address{}; address.sin_family=AF_INET; address.sin_addr.s_addr=htonl(INADDR_LOOPBACK); address.sin_port=htons(*port);
        if (connect(fd,reinterpret_cast<sockaddr*>(&address),sizeof(address))) return 4;
        for (int i=0;i<10;++i) server.poll(10ms);
        if (destroyed) return 5;
        skip_stop=true;
    }
    close(fd);
    if (!destroyed || !valid) return 6;
    std::println("Suspended handshake retains its borrowed policy and credentials through context destruction");
}
