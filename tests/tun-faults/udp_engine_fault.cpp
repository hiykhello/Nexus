#include <arpa/inet.h>
#include <cerrno>
#include <new>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
import std;
import udp.engine;
import rules;
namespace u = udp;
namespace p = ::packet;
static int inject_after = -1;
static int throw_after = -1;
extern "C" auto __real_recvfrom(int, void*, size_t, int, sockaddr*, socklen_t*) -> ssize_t;
extern "C" auto __wrap_recvfrom(int fd, void* data, size_t size, int flags, sockaddr* from, socklen_t* length) -> ssize_t {
    if (throw_after == 0) { throw_after = -1; throw std::bad_alloc(); }
    if (throw_after > 0) --throw_after;
    if (inject_after == 0) { inject_after = -1; errno = EIO; return -1; }
    if (inject_after > 0) --inject_after;
    return __real_recvfrom(fd, data, size, flags, from, length);
}
struct Socket { int fd; explicit Socket(int family) : fd(::socket(family, SOCK_DGRAM | SOCK_CLOEXEC, 0)) {} ~Socket() { if (fd >= 0) ::close(fd); } };
int main() {
    Socket four(AF_INET), six(AF_INET6);
    sockaddr_in a{}; a.sin_family = AF_INET; a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sockaddr_in6 b{}; b.sin6_family = AF_INET6; b.sin6_addr = in6addr_loopback;
    if (four.fd < 0 || six.fd < 0 || ::bind(four.fd, reinterpret_cast<sockaddr*>(&a), sizeof(a)) ||
        ::bind(six.fd, reinterpret_cast<sockaddr*>(&b), sizeof(b))) return 1;
    socklen_t alen = sizeof(a), blen = sizeof(b);
    if (::getsockname(four.fd, reinterpret_cast<sockaddr*>(&a), &alen) ||
        ::getsockname(six.fd, reinterpret_cast<sockaddr*>(&b), &blen)) return 1;
    auto policy = ::rules::Matcher::compile({{{"ip-cidr", "192.0.2.0/24"}}});
    if (!policy) return 1;
    p::MemoryLink link;
    u::MemoryEngine engine(link, std::move(*policy), u::Mapping::endpoint_independent,
                           u::Filtering::address_port_dependent, {2, 2, 100});
    p::Bytes body{1,2,3};
    auto v4 = p::make_udp4({10,0,0,1}, {127,0,0,1}, 1000, ntohs(a.sin_port), body);
    auto v6 = p::make_udp6({0x20,1,0xd,0xb8,0,0,0,0,0,0,0,0,0,0,0,1},
                           {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1}, 1000, ntohs(b.sin6_port), body);
    if (!v4 || !v6 || !link.send(p::Side::first, *v4) || !engine.step(0) ||
        !link.send(p::Side::first, *v6) || !engine.step(1)) return 1;
    pollfd ready{four.fd, POLLIN, 0};
    if (::poll(&ready, 1, 2000) != 1) return 1;
    std::array<char, 16> buffer{}; sockaddr_in from{}; socklen_t nfrom = sizeof(from);
    auto n = ::recvfrom(four.fd, buffer.data(), buffer.size(), 0, reinterpret_cast<sockaddr*>(&from), &nfrom);
    if (n != 3 || ::sendto(four.fd, buffer.data(), n, 0, reinterpret_cast<sockaddr*>(&from), nfrom) != n) return 1;
    auto blocked = p::make_udp4({10,0,0,1}, {192,0,2,1}, 1000, 53, body);
    if (!blocked || !link.send(p::Side::first, *blocked)) return 1;
    throw_after = 2; // IPv4 reply is collected; IPv6 polling then throws before receiving.
    auto retained = engine.step(2);
    auto retained_packet = link.receive(p::Side::first);
    if (!retained || !retained->input || !retained->rejected || !retained->ipv6_allocation_failed ||
        retained->ipv4_allocation_failed || !retained->delivered || !retained_packet || !*retained_packet || !p::parse_udp4(**retained_packet)) return 1;
    if (::sendto(four.fd, buffer.data(), n, 0, reinterpret_cast<sockaddr*>(&from), nfrom) != n) return 1;
    if (!blocked || !link.send(p::Side::first, *blocked)) return 1;
    inject_after = 2; // IPv4 receives a packet; IPv6 then fails.
    auto report = engine.step(2);
    if (!report || !report->input || !report->rejected || !report->delivered || report->ipv4_error ||
        !report->ipv6_error || !std::holds_alternative<std::error_code>(*report->ipv6_error) ||
        std::get<std::error_code>(*report->ipv6_error) != std::error_code(EIO, std::generic_category())) return 1;
    auto packet = link.receive(p::Side::first);
    if (!packet || !*packet || !p::parse_udp4(**packet)) return 1;
    auto next = engine.step(3);
    if (!next || next->ipv6_error || !engine.stop(3)) return 1;
    std::cout << "UDP engine preserves input rejection, reply and per-family receive error\n";
}
