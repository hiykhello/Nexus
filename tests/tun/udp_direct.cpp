#include <arpa/inet.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
import std;
import udp.direct;
import rules;
namespace u = udp;
namespace p = ::packet;

struct Socket {
    int fd = ::socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    ~Socket() { if (fd >= 0) ::close(fd); }
    auto bind() -> std::optional<sockaddr_in> {
        sockaddr_in a{}; a.sin_family = AF_INET; a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
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
    auto policy = ::rules::Matcher::compile({{{"ip-cidr", "192.0.2.0/24"}}});
    if (!policy) return 1;
    u::Direct4 direct(std::move(*policy), u::Mapping::endpoint_independent,
                      u::Filtering::address_port_dependent, {2, 2, 100});
    p::Bytes body{'p','i','n','g'};
    auto blocked = p::make_udp4({10,0,0,2}, {192,0,2,1}, 1234, 53, body);
    if (!blocked) return 1;
    auto denied = direct.submit(*blocked, 0);
    if (denied || !std::holds_alternative<u::RoutedError>(denied.error()) || direct.size() != 0) return 1;
    auto unspecified = p::make_udp4({10,0,0,2}, {0,0,0,0}, 1234, ntohs(server_addr->sin_port), body);
    if (!unspecified || direct.submit(*unspecified, 0) || direct.size() != 0) return 1;
    pollfd no_packet{server.fd, POLLIN, 0};
    if (::poll(&no_packet, 1, 50) != 0) return 1;
    auto request = p::make_udp4({10,0,0,2}, {127,0,0,1}, 1234, ntohs(server_addr->sin_port), body);
    if (!request) return 1;
    auto malformed = *request; malformed.back() ^= 1;
    if (direct.submit(malformed, 0) || direct.size() != 0) return 1;
    if (!request || !direct.submit(*request, 1) || direct.size() != 1) return 1;
    pollfd ready{server.fd, POLLIN, 0};
    if (::poll(&ready, 1, 2000) != 1) return 1;
    std::array<char, 32> data{}; sockaddr_in outbound{}; socklen_t n = sizeof(outbound);
    auto length = ::recvfrom(server.fd, data.data(), data.size(), 0, reinterpret_cast<sockaddr*>(&outbound), &n);
    if (length != 4 || std::string_view(data.data(), 4) != "ping") return 1;
    if (::sendto(attacker.fd, data.data(), 4, 0, reinterpret_cast<sockaddr*>(&outbound), n) != 4) return 1;
    auto forged = direct.poll(2);
    if (!forged || !forged->empty()) return 1;
    if (::sendto(server.fd, data.data(), 4, 0, reinterpret_cast<sockaddr*>(&outbound), n) != 4) return 1;
    auto reply = direct.poll(3);
    if (!reply || reply->size() != 1) return 1;
    auto decoded = p::parse_udp4(reply->front());
    if (!decoded || decoded->source != p::Address4{127,0,0,1} || decoded->destination != p::Address4{10,0,0,2} ||
        decoded->source_port != ntohs(server_addr->sin_port) || decoded->destination_port != 1234 ||
        !std::ranges::equal(decoded->payload, body)) return 1;
    // An oversized upstream datagram is dropped without refreshing idle time.
    std::array<char, 1473> oversized{};
    if (::sendto(server.fd, oversized.data(), oversized.size(), 0, reinterpret_cast<sockaddr*>(&outbound), n) !=
        static_cast<ssize_t>(oversized.size())) return 1;
    auto dropped = direct.poll(102);
    if (!dropped || !dropped->empty()) return 1;
    auto reversed = direct.stop(2);
    if (reversed || reversed.error() != u::Error::time_reversed || direct.size() != 1) return 1;
    auto expired = direct.poll(103);
    if (!expired || direct.size() != 0) return 1;
    if (!direct.submit(*request, 104) || direct.size() != 1 || !direct.stop(105) || direct.size()) return 1;
    std::cout << "UDP direct routing, roundtrip, source filtering and cleanup passed\n";
}
