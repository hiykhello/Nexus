#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <iostream>
#include <sys/socket.h>
#include <unistd.h>
import shadowsocks.probe_close;

namespace s=shadowsocks::detail;
auto scenario(bool unread) -> bool {
    int listener=::socket(AF_INET,SOCK_STREAM|SOCK_CLOEXEC,0);
    if (listener<0) return false;
    sockaddr_in address{}; address.sin_family=AF_INET; address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    bool ok=::bind(listener,reinterpret_cast<sockaddr*>(&address),sizeof(address))==0 && ::listen(listener,1)==0;
    socklen_t length=sizeof(address);
    ok=ok && ::getsockname(listener,reinterpret_cast<sockaddr*>(&address),&length)==0;
    int client=::socket(AF_INET,SOCK_STREAM|SOCK_CLOEXEC,0);
    ok=ok && client>=0 && ::connect(client,reinterpret_cast<sockaddr*>(&address),sizeof(address))==0;
    int server=ok ? ::accept(listener,nullptr,nullptr) : -1;
    if (server<0) ok=false;
    timeval timeout{2,0};
    if (ok) ok=::setsockopt(client,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout))==0;
    if (ok && unread) {
        char bytes[2]={'a','b'}, consumed=0;
        ok=::send(client,bytes,sizeof(bytes),MSG_NOSIGNAL)==sizeof(bytes) && ::recv(server,&consumed,1,0)==1 && consumed=='a';
    }
    if (ok) ok=!s::prepare_probe_reset(server);
    if (server>=0) ::close(server);
    if (ok) {
        char byte=0; errno=0;
        auto n=::recv(client,&byte,1,0);
        ok=n==-1 && errno==ECONNRESET;
    }
    if (client>=0) ::close(client);
    ::close(listener); return ok;
}
auto main() -> int {
    if (!s::prepare_probe_reset(-1) || !scenario(false) || !scenario(true)) return 1;
    std::cout << "SS-2022 probe reset with empty and unread TCP receive queues passed\n";
}
