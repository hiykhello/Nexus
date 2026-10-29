#include <arpa/inet.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
import std;
import nexus.udp.engine;
import nexus.rules;
namespace u = nexus::udp;
namespace p = nexus::packet;

struct Socket {
    int fd;
    explicit Socket(int family) : fd(::socket(family, SOCK_DGRAM | SOCK_CLOEXEC, 0)) {}
    ~Socket() { if (fd >= 0) ::close(fd); }
};
int main() {
    Socket server(AF_INET);
    if (server.fd < 0) return 1;
    sockaddr_in address{}; address.sin_family = AF_INET; address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (::bind(server.fd, reinterpret_cast<sockaddr*>(&address), sizeof(address))) return 1;
    socklen_t size = sizeof(address);
    if (::getsockname(server.fd, reinterpret_cast<sockaddr*>(&address), &size)) return 1;
    auto policy = nexus::rules::Matcher::compile({{{"ip-cidr", "192.0.2.0/24"}}});
    if (!policy) return 1;
    p::MemoryLink link({1500, 1, 1500});
    u::MemoryEngine engine(link, std::move(*policy), u::Mapping::endpoint_independent,
                           u::Filtering::address_port_dependent, {2, 2, 100});
    p::Bytes payload{'t','e','s','t'};
    auto denied = p::make_udp4({10,0,0,1}, {192,0,2,1}, 1234, 53, payload);
    if (!denied || !link.send(p::Side::first, *denied)) return 1;
    auto blocked = engine.step(0);
    if (!blocked || !blocked->input || !blocked->rejected) return 1;
    auto request = p::make_udp4({10,0,0,1}, {127,0,0,1}, 1234, ntohs(address.sin_port), payload);
    if (!request) return 1;
    auto padded=*request;
    padded.insert(padded.begin()+20,{1,1,0,0}); padded[0]=0x46;
    padded[3]=static_cast<std::uint8_t>(padded.size()); padded[10]=padded[11]=0;
    auto checksum=p::internet_checksum(std::span(padded).first(24));
    padded[10]=static_cast<std::uint8_t>(checksum>>8); padded[11]=static_cast<std::uint8_t>(checksum);
    if (!link.send(p::Side::first, padded)) return 1;
    auto forwarded = engine.step(1);
    if (!forwarded || !forwarded->input || forwarded->rejected) return 1;
    pollfd ready{server.fd, POLLIN, 0};
    if (::poll(&ready, 1, 2000) != 1) return 1;
    std::array<char, 64> bytes{}; sockaddr_in source{}; socklen_t source_size = sizeof(source);
    auto n = ::recvfrom(server.fd, bytes.data(), bytes.size(), 0, reinterpret_cast<sockaddr*>(&source), &source_size);
    if (n != 4) return 1;
    // Saturate the device output before the real reply arrives.
    p::Bytes sentinel{42};
    if (!link.send(p::Side::second, sentinel)) return 1;
    if (::sendto(server.fd, bytes.data(), n, 0, reinterpret_cast<sockaddr*>(&source), source_size) != n) return 1;
    auto full = engine.step(2);
    if (!full || !full->backpressured || full->delivered) return 1;
    auto rejected_time = engine.step(1);
    if (rejected_time || std::get<u::Error>(rejected_time.error()) != u::Error::time_reversed) return 1;
    auto still_full = engine.step(102);
    if (!still_full || !still_full->backpressured || still_full->expired != 1) return 1;
    auto first = link.receive(p::Side::first);
    if (!first || !*first || **first != sentinel) return 1;
    auto drained = engine.step(103);
    if (!drained || !drained->delivered || drained->backpressured) return 1;
    auto reply = link.receive(p::Side::first);
    if (!reply || !*reply) return 1;
    auto decoded = p::parse_udp4(**reply);
    if (!decoded || decoded->destination != p::Address4{10,0,0,1} ||
        decoded->source_port != ntohs(address.sin_port) || !std::ranges::equal(decoded->payload, payload)) return 1;
    // A reply larger than the device's permanent byte budget must not block
    // later replies that fit, even when the configured MTU is larger.
    auto policy2 = nexus::rules::Matcher::compile({{{"ip-cidr", "192.0.2.0/24"}}});
    if (!policy2) return 1;
    p::MemoryLink small({1500, 1, 32});
    u::MemoryEngine small_engine(small, std::move(*policy2), u::Mapping::endpoint_independent,
                                 u::Filtering::address_port_dependent, {1, 1, 100});
    if (!small.send(p::Side::first, *request) || !small_engine.step(0)) return 1;
    source_size = sizeof(source);
    n = ::recvfrom(server.fd, bytes.data(), bytes.size(), 0, reinterpret_cast<sockaddr*>(&source), &source_size);
    if (n != 4) return 1;
    std::array<char, 5> big{'a','b','c','d','e'};
    if (::sendto(server.fd, big.data(), big.size(), 0, reinterpret_cast<sockaddr*>(&source), source_size) != 5) return 1;
    if (!small.send(p::Side::first, *denied)) return 1;
    auto impossible = small_engine.step(1);
    if (!impossible || !impossible->input || !impossible->rejected ||
        impossible->output_error != p::DeviceError::packet_too_large) return 1;
    if (::sendto(server.fd, bytes.data(), 4, 0, reinterpret_cast<sockaddr*>(&source), source_size) != 4) return 1;
    auto fits = small_engine.step(2);
    auto small_reply = small.receive(p::Side::first);
    if (!fits || !fits->delivered || !small_reply || !*small_reply || !p::parse_udp4(**small_reply) || !small_engine.stop(2)) return 1;
    Socket server6(AF_INET6);
    if (server6.fd < 0) return 1;
    sockaddr_in6 address6{}; address6.sin6_family = AF_INET6; address6.sin6_addr = in6addr_loopback;
    if (::bind(server6.fd, reinterpret_cast<sockaddr*>(&address6), sizeof(address6))) return 1;
    socklen_t size6 = sizeof(address6);
    if (::getsockname(server6.fd, reinterpret_cast<sockaddr*>(&address6), &size6)) return 1;
    constexpr p::Address6 client6{0x20,1,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,1};
    constexpr p::Address6 loop6{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
    auto request6 = p::make_udp6(client6, loop6, 1234, ntohs(address6.sin6_port), payload);
    if (!request6 || !link.send(p::Side::first, *request6)) return 1;
    auto forwarded6 = engine.step(104);
    if (!forwarded6 || !forwarded6->input || forwarded6->rejected) return 1;
    pollfd ready6{server6.fd, POLLIN, 0};
    if (::poll(&ready6, 1, 2000) != 1) return 1;
    sockaddr_in6 source6{}; socklen_t source_size6 = sizeof(source6);
    auto n6 = ::recvfrom(server6.fd, bytes.data(), bytes.size(), 0, reinterpret_cast<sockaddr*>(&source6), &source_size6);
    if (n6 != 4 || ::sendto(server6.fd, bytes.data(), n6, 0, reinterpret_cast<sockaddr*>(&source6), source_size6) != n6) return 1;
    auto delivered6 = engine.step(105);
    if (!delivered6 || !delivered6->delivered) return 1;
    auto reply6 = link.receive(p::Side::first);
    if (!reply6 || !*reply6) return 1;
    auto decoded6 = p::parse_udp6(**reply6);
    if (!decoded6 || decoded6->source != loop6 || decoded6->destination != client6 ||
        decoded6->source_port != ntohs(address6.sin6_port) || !std::ranges::equal(decoded6->payload, payload)) return 1;
    link.close(p::Side::first);
    auto closed = engine.step(106);
    if (closed || std::get<p::DeviceError>(closed.error()) != p::DeviceError::peer_closed || !engine.stop(106)) return 1;
    std::cout << "Memory UDP engine routing, real roundtrip and device backpressure passed\n";
}
