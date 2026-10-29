#include <fcntl.h>
#include <net/if.h>
#include <unistd.h>
import std;
import nexus.packet.tun_linux;
import nexus.packet.fd;
namespace p=nexus::packet;
int main() {
    for (auto name : {std::string_view("abcdefghijklmnop"),std::string_view("tun%d"),std::string_view("bad\0name",8)}) {
        auto invalid=p::LinuxTun::create(name);
        if (invalid || !std::holds_alternative<p::TunError>(invalid.error())) return 1;
    }
    auto first=p::LinuxTun::create("nx-owned");
    if (!first || first->name()!="nx-owned" || !if_nametoindex("nx-owned")) return 2;
    int fd=first->native_handle();
    if (fd<0 || !(fcntl(fd,F_GETFL)&O_NONBLOCK) || !(fcntl(fd,F_GETFD)&FD_CLOEXEC)) return 3;
    p::MemoryLink link;
    auto pump=p::FdPump::create(fd,link,1500); if (!pump) return 4;
    auto duplicate=p::LinuxTun::create("nx-owned");
    if (duplicate || !std::holds_alternative<std::error_code>(duplicate.error()) || !if_nametoindex("nx-owned")) return 5;
    auto moved=std::move(*first);
    if (first->native_handle()!=-1 || !first->name().empty() || moved.native_handle()!=fd || moved.name()!="nx-owned") return 6;
    moved=std::move(moved);
    if (moved.native_handle()!=fd || !if_nametoindex("nx-owned")) return 7;
    auto second=p::LinuxTun::create();
    if (!second || second->name().empty() || second->native_handle()==fd) return 8;
    moved=std::move(*second);
    if (if_nametoindex("nx-owned") || second->native_handle()!=-1 || moved.name().empty()) return 9;
    auto generated=std::string(moved.name());
    if (!if_nametoindex(generated.c_str())) return 10;
    moved.close(); moved.close();
    if (moved.native_handle()!=-1 || !moved.name().empty() || if_nametoindex(generated.c_str())) return 11;
    { auto scoped=p::LinuxTun::create("nx-scoped"); if (!scoped || !if_nametoindex("nx-scoped")) return 12; }
    if (if_nametoindex("nx-scoped")) return 13;
    std::println("exclusive nonblocking Linux TUN ownership and teardown passed");
}
