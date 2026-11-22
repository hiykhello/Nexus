#include <arpa/inet.h>
#include <cerrno>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
import std;
import udp.direct;
import rules;
namespace u = udp;
namespace p = ::packet;

static int inject_after = -1;
static int inject_errno = EIO;
extern "C" auto __real_recvfrom(int, void*, size_t, int, sockaddr*, socklen_t*) -> ssize_t;
extern "C" auto __wrap_recvfrom(int fd, void* data, size_t len, int flags, sockaddr* addr, socklen_t* addrlen) -> ssize_t {
    if (inject_after == 0) { inject_after = -1; errno = inject_errno; return -1; }
    if (inject_after > 0) --inject_after;
    return __real_recvfrom(fd, data, len, flags, addr, addrlen);
}
struct Socket {
    int fd;
    explicit Socket(int family) : fd(::socket(family, SOCK_DGRAM | SOCK_CLOEXEC, 0)) {}
    ~Socket() { if (fd >= 0) ::close(fd); }
};

template <typename Direct, typename Address, typename Sockaddr>
auto scenario(int family, Address client, Address loop, Sockaddr bind_address, bool stop_before_error) -> bool {
    Socket server(family);
    if (server.fd < 0 || ::bind(server.fd, reinterpret_cast<sockaddr*>(&bind_address), sizeof(bind_address))) return false;
    socklen_t len = sizeof(bind_address);
    if (::getsockname(server.fd, reinterpret_cast<sockaddr*>(&bind_address), &len)) return false;
    auto policy = ::rules::Matcher::compile({});
    if (!policy) return false;
    Direct direct(std::move(*policy), u::Mapping::endpoint_independent, u::Filtering::address_port_dependent, {2, 1, 100});
    std::uint16_t target_port;
    if constexpr (std::is_same_v<Sockaddr, sockaddr_in>) target_port = ntohs(bind_address.sin_port);
    else target_port = ntohs(bind_address.sin6_port);
    p::Bytes payload{'o','k'};
    auto packet = [&](int source_port) {
        if constexpr (std::is_same_v<Address, p::Address4>) return p::make_udp4(client, loop, source_port, target_port, payload);
        else return p::make_udp6(client, loop, source_port, target_port, payload);
    };
    auto one = packet(1001), two = packet(1002);
    if (!one || !two || !direct.submit(*one, 0) || !direct.submit(*two, 0)) return false;
    std::array<char, 16> data{}; sockaddr_storage origin{}; socklen_t origin_len = sizeof(origin);
    pollfd ready{server.fd, POLLIN, 0};
    if (::poll(&ready, 1, 2000) != 1) return false;
    auto n = ::recvfrom(server.fd, data.data(), data.size(), 0, reinterpret_cast<sockaddr*>(&origin), &origin_len);
    if (n != 2 || ::sendto(server.fd, data.data(), n, 0, reinterpret_cast<sockaddr*>(&origin), origin_len) != n) return false;
    inject_after = 2;
    auto first = direct.poll(1);
    if (!first || first->size() != 1 || direct.size() != 1 || inject_after != -1) return false;
    if (stop_before_error) {
        if (!direct.stop(2) || direct.size() != 0) return false;
        auto after_stop = direct.poll(2);
        return after_stop && after_stop->empty();
    }
    auto error = direct.poll(2);
    if (error || !std::holds_alternative<std::error_code>(error.error()) ||
        std::get<std::error_code>(error.error()) != std::error_code(EIO, std::generic_category())) return false;
    auto next = direct.poll(3);
    if (!next || !next->empty()) return false;
    return direct.stop(4).has_value() && direct.size() == 0;
}

template <typename Direct, typename Address, typename Sockaddr>
auto consume_fault(int family, Address client, Address loop, Sockaddr address, int error) -> bool {
    Socket server(family);
    if (server.fd < 0 || ::bind(server.fd, reinterpret_cast<sockaddr*>(&address), sizeof(address))) return false;
    socklen_t length=sizeof(address);
    if (::getsockname(server.fd,reinterpret_cast<sockaddr*>(&address),&length)) return false;
    std::uint16_t port;
    if constexpr (std::is_same_v<Sockaddr,sockaddr_in>) port=ntohs(address.sin_port);
    else port=ntohs(address.sin6_port);
    Direct direct(::rules::Matcher{},u::Mapping::endpoint_independent,u::Filtering::address_port_dependent,{2,1,100});
    p::Bytes payload{'o','k'};
    auto packet=[&](int local_port) {
        if constexpr (std::is_same_v<Address,p::Address4>) return p::make_udp4(client,loop,local_port,port,payload);
        else return p::make_udp6(client,loop,local_port,port,payload);
    };
    auto first=packet(1001), second=packet(1002);
    if (!first || !second || !direct.submit(*first,0) || !direct.submit(*second,0)) return false;
    for (int i=0;i<2;++i) {
        std::array<char,16> data{}; sockaddr_storage origin{}; socklen_t origin_len=sizeof(origin);
        auto n=::recvfrom(server.fd,data.data(),data.size(),0,reinterpret_cast<sockaddr*>(&origin),&origin_len);
        if (n!=2 || ::sendto(server.fd,data.data(),n,0,reinterpret_cast<sockaddr*>(&origin),origin_len)!=n) return false;
    }
    inject_errno=error; inject_after=3; // Peek and consume first; peek second, then fail consumption.
    auto batch=direct.poll(1); inject_errno=EIO;
    if (!batch || batch->size()!=1 || inject_after!=-1) return false;
    auto next=direct.poll(2);
    if (error==EIO) {
        if (direct.size()!=1 || next || !std::holds_alternative<std::error_code>(next.error()) ||
            std::get<std::error_code>(next.error())!=std::error_code(EIO,std::generic_category())) return false;
    } else if (!next || next->size()!=1 || direct.size()!=2) return false;
    auto empty=direct.poll(3);
    return empty && empty->empty() && direct.stop(4).has_value();
}
int main() {
    sockaddr_in a{}; a.sin_family = AF_INET; a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sockaddr_in6 b{}; b.sin6_family = AF_INET6; b.sin6_addr = in6addr_loopback;
    for (bool stop : {false, true}) {
        if (!scenario<u::Direct4>(AF_INET, p::Address4{10,0,0,1}, p::Address4{127,0,0,1}, a, stop) ||
            !scenario<u::Direct6>(AF_INET6, p::Address6{0x20,1,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,1},
                                  p::Address6{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1}, b, stop)) return 1;
    }
    for (int error : {EAGAIN, EINTR, EIO}) {
        if (!consume_fault<u::Direct4>(AF_INET,p::Address4{10,0,0,1},p::Address4{127,0,0,1},a,error) ||
            !consume_fault<u::Direct6>(AF_INET6,p::Address6{0x20,1,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,1},
                                       p::Address6{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1},b,error)) return 1;
    }
    std::cout << "UDP direct deferred receive errors preserve earlier packets\n";
}
