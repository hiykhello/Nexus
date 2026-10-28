#include <arpa/inet.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
import std;
import nexus.udp.direct;
import nexus.rules;
namespace u = nexus::udp;
namespace p = nexus::packet;

struct Socket {
    int fd = ::socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    ~Socket() { if (fd >= 0) ::close(fd); }
    auto bind() -> std::optional<sockaddr_in6> {
        sockaddr_in6 a{}; a.sin6_family = AF_INET6; a.sin6_addr = in6addr_loopback;
        if (fd < 0 || ::bind(fd, reinterpret_cast<sockaddr*>(&a), sizeof(a))) return {};
        socklen_t n = sizeof(a);
        if (::getsockname(fd, reinterpret_cast<sockaddr*>(&a), &n)) return {};
        return a;
    }
};
int main() {
    Socket server, attacker;
    auto server_addr = server.bind(), attacker_addr = attacker.bind();
    if (!server_addr || !attacker_addr) return 1;
    auto policy = nexus::rules::Matcher::compile({{{"ip-cidr", "192.0.2.0/24"}, {"ip-cidr", "2001:db8:1::/48"}}});
    if (!policy) return 1;
    u::Direct6 direct(std::move(*policy), u::Mapping::endpoint_independent,
                      u::Filtering::address_port_dependent, {2, 2, 100});
    constexpr p::Address6 client{0x20,1,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,1};
    constexpr p::Address6 local{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
    constexpr p::Address6 blocked6{0x20,1,0x0d,0xb8,0,1,0,0,0,0,0,0,0,0,0,1};
    constexpr p::Address6 blocked4{0,0,0,0,0,0,0,0,0,0,0xff,0xff,192,0,2,1};
    p::Bytes body{'p','i','n','g'};
    auto blocked = p::make_udp6(client, blocked4, 1234, 53, body);
    if (!blocked) return 1;
    auto denied = direct.submit(*blocked, 0);
    if (denied || !std::holds_alternative<u::RoutedError>(denied.error()) || direct.size() != 0) return 1;
    auto blocked_ipv6 = p::make_udp6(client, blocked6, 1234, 53, body);
    if (!blocked_ipv6 || direct.submit(*blocked_ipv6, 0) || direct.size()) return 1;
    auto request = p::make_udp6(client, local, 1234, ntohs(server_addr->sin6_port), body);
    if (!request) return 1;
    auto malformed = *request; malformed.back() ^= 1;
    if (direct.submit(malformed, 0) || direct.size() != 0) return 1;
    if (!request || !direct.submit(*request, 1) || direct.size() != 1) return 1;
    pollfd ready{server.fd, POLLIN, 0};
    if (::poll(&ready, 1, 2000) != 1) return 1;
    std::array<char, 32> data{}; sockaddr_in6 outbound{}; socklen_t n = sizeof(outbound);
    auto length = ::recvfrom(server.fd, data.data(), data.size(), 0, reinterpret_cast<sockaddr*>(&outbound), &n);
    if (length != 4 || std::string_view(data.data(), 4) != "ping") return 1;
    if (::sendto(attacker.fd, data.data(), 4, 0, reinterpret_cast<sockaddr*>(&outbound), n) != 4) return 1;
    auto forged = direct.poll(2);
    if (!forged || !forged->empty()) return 1;
    if (::sendto(server.fd, data.data(), 4, 0, reinterpret_cast<sockaddr*>(&outbound), n) != 4) return 1;
    auto reply = direct.poll(3);
    if (!reply || reply->size() != 1) return 1;
    auto decoded = p::parse_udp6(reply->front());
    if (!decoded || decoded->source != local || decoded->destination != client ||
        decoded->source_port != ntohs(server_addr->sin6_port) || decoded->destination_port != 1234 ||
        !std::ranges::equal(decoded->payload, body)) return 1;
    // An oversized upstream datagram is dropped without refreshing idle time.
    std::array<char, 1453> oversized{};
    if (::sendto(server.fd, oversized.data(), oversized.size(), 0, reinterpret_cast<sockaddr*>(&outbound), n) !=
        static_cast<ssize_t>(oversized.size())) return 1;
    auto dropped = direct.poll(102);
    if (!dropped || !dropped->empty()) return 1;
    auto reversed = direct.stop(2);
    if (reversed || reversed.error() != u::Error::time_reversed || direct.size() != 1) return 1;
    auto expired = direct.poll(103);
    if (!expired || direct.size() != 0) return 1;
    if (!direct.submit(*request, 104) || direct.size() != 1 || !direct.stop(105) || direct.size()) return 1;
    // An allowed IPv4-mapped destination must reach an IPv4 UDP peer and the
    // reply must retain its mapped address in the reconstructed IPv6 packet.
    int ipv4 = ::socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (ipv4 < 0) return 1;
    struct Close { int fd; ~Close() { ::close(fd); } } cleanup{ipv4};
    sockaddr_in peer{}; peer.sin_family = AF_INET; peer.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (::bind(ipv4, reinterpret_cast<sockaddr*>(&peer), sizeof(peer))) return 1;
    socklen_t peer_length = sizeof(peer);
    if (::getsockname(ipv4, reinterpret_cast<sockaddr*>(&peer), &peer_length)) return 1;
    constexpr p::Address6 mapped{0,0,0,0,0,0,0,0,0,0,0xff,0xff,127,0,0,1};
    auto mapped_request = p::make_udp6(client, mapped, 1234, ntohs(peer.sin_port), body);
    if (!mapped_request || !direct.submit(*mapped_request, 106)) return 1;
    pollfd ready4{ipv4, POLLIN, 0};
    if (::poll(&ready4, 1, 2000) != 1) return 1;
    sockaddr_in outbound4{}; socklen_t outbound_length = sizeof(outbound4);
    auto got = ::recvfrom(ipv4, data.data(), data.size(), 0, reinterpret_cast<sockaddr*>(&outbound4), &outbound_length);
    if (got != 4 || ::sendto(ipv4, data.data(), 4, 0, reinterpret_cast<sockaddr*>(&outbound4), outbound_length) != 4) return 1;
    auto mapped_reply = direct.poll(107);
    if (!mapped_reply || mapped_reply->size() != 1) return 1;
    auto mapped_decoded = p::parse_udp6(mapped_reply->front());
    if (!mapped_decoded || mapped_decoded->source != mapped || mapped_decoded->destination != client ||
        mapped_decoded->source_port != ntohs(peer.sin_port) || !std::ranges::equal(mapped_decoded->payload, body)) return 1;
    if (!direct.stop(108)) return 1;
    std::cout << "IPv6 UDP direct routing, roundtrip, source filtering and cleanup passed\n";
}
