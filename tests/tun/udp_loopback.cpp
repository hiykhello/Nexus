#include <arpa/inet.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
import std;
import udp.route;
import rules;

namespace u = udp;
namespace p = ::packet;

namespace {
    struct Socket {
        int fd = ::socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
        ~Socket() { if (fd >= 0) ::close(fd); }
    };
    auto bind_local(int fd) -> std::optional<sockaddr_in> {
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) return {};
        socklen_t length = sizeof(addr);
        if (::getsockname(fd, reinterpret_cast<sockaddr*>(&addr), &length) != 0) return {};
        return addr;
    }
    auto endpoint(sockaddr_in const& addr) -> u::Endpoint4 {
        auto const n = ntohl(addr.sin_addr.s_addr);
        return {{static_cast<std::uint8_t>(n >> 24), static_cast<std::uint8_t>(n >> 16),
                 static_cast<std::uint8_t>(n >> 8), static_cast<std::uint8_t>(n)}, ntohs(addr.sin_port)};
    }
    auto send(int fd, sockaddr_in const& to, std::span<std::uint8_t const> data) -> bool {
        return ::sendto(fd, data.data(), data.size(), 0, reinterpret_cast<sockaddr const*>(&to), sizeof(to)) ==
               static_cast<ssize_t>(data.size());
    }
    auto receive(int fd) -> std::optional<std::pair<sockaddr_in, p::Bytes>> {
        pollfd ready{fd, POLLIN, 0};
        if (::poll(&ready, 1, 2000) != 1 || !(ready.revents & POLLIN)) return {};
        std::array<std::uint8_t, 1500> buffer{};
        sockaddr_in from{};
        socklen_t size = sizeof(from);
        auto n = ::recvfrom(fd, buffer.data(), buffer.size(), 0, reinterpret_cast<sockaddr*>(&from), &size);
        if (n < 0) return {};
        return std::pair{from, p::Bytes(buffer.begin(), buffer.begin() + n)};
    }
    struct Socket6 {
        int fd = ::socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, 0);
        ~Socket6() { if (fd >= 0) ::close(fd); }
    };
    auto bind_local6(int fd) -> std::optional<sockaddr_in6> {
        sockaddr_in6 addr{};
        addr.sin6_family = AF_INET6;
        addr.sin6_addr = in6addr_loopback;
        if (::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) return {};
        socklen_t length = sizeof(addr);
        if (::getsockname(fd, reinterpret_cast<sockaddr*>(&addr), &length) != 0) return {};
        return addr;
    }
    auto endpoint6(sockaddr_in6 const& addr) -> u::Endpoint6 {
        u::Endpoint6 result{};
        std::ranges::copy(addr.sin6_addr.s6_addr, result.address.begin());
        result.port = ntohs(addr.sin6_port);
        return result;
    }
    auto send6(int fd, sockaddr_in6 const& to, std::span<std::uint8_t const> data) -> bool {
        return ::sendto(fd, data.data(), data.size(), 0, reinterpret_cast<sockaddr const*>(&to), sizeof(to)) ==
               static_cast<ssize_t>(data.size());
    }
    auto receive6(int fd) -> std::optional<std::pair<sockaddr_in6, p::Bytes>> {
        pollfd ready{fd, POLLIN, 0};
        if (::poll(&ready, 1, 2000) != 1 || !(ready.revents & POLLIN)) return {};
        std::array<std::uint8_t, 1500> buffer{};
        sockaddr_in6 from{};
        socklen_t size = sizeof(from);
        auto n = ::recvfrom(fd, buffer.data(), buffer.size(), 0, reinterpret_cast<sockaddr*>(&from), &size);
        if (n < 0) return {};
        return std::pair{from, p::Bytes(buffer.begin(), buffer.begin() + n)};
    }
    auto ipv6_roundtrip() -> bool {
        Socket6 outbound, origin, attacker;
        if (outbound.fd < 0 || origin.fd < 0 || attacker.fd < 0) return false;
        auto local = bind_local6(outbound.fd), server = bind_local6(origin.fd), fake = bind_local6(attacker.fd);
        if (!local || !server || !fake) return false;
        u::Endpoint6 client{{0x20,1,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,1}, 40000};
        auto remote = endpoint6(*server);
        p::Bytes payload{'h', 'e', 'l', 'l', 'o'};
        p::MemoryLink link;
        auto rules = ::rules::Matcher::compile({{{"ip-cidr", "2001:db8:1::/48"}}});
        if (!rules) return false;
        u::RoutedBridge6 bridge(std::move(*rules), u::Mapping::endpoint_independent,
                                u::Filtering::address_port_dependent, {1, 1, 100});
        auto packet = p::make_udp6(client.address, remote.address, client.port, remote.port, payload);
        if (!packet || !link.send(p::Side::first, *packet)) return false;
        auto queued = link.receive(p::Side::second);
        if (!queued || !*queued) return false;
        auto outgoing = bridge.prepare(**queued, 0);
        if (!outgoing || outgoing->remote != remote || outgoing->payload != payload) return false;
        if (!send6(outbound.fd, *server, outgoing->payload) ||
            !bridge.complete(outgoing->flow, outgoing->token, true, 1)) return false;
        auto upstream = receive6(origin.fd);
        if (!upstream || upstream->second != payload || endpoint6(upstream->first) != endpoint6(*local)) return false;
        if (!send6(attacker.fd, *local, payload)) return false;
        auto forged = receive6(outbound.fd);
        if (!forged) return false;
        auto rejected = bridge.reply(outgoing->flow, endpoint6(forged->first), forged->second, 2);
        if (rejected || std::get<u::Error>(rejected.error()) != u::Error::forbidden) return false;
        if (!send6(origin.fd, upstream->first, payload)) return false;
        auto response = receive6(outbound.fd);
        if (!response) return false;
        auto reply = bridge.reply(outgoing->flow, endpoint6(response->first), response->second, 3);
        if (!reply || !link.send(p::Side::second, *reply)) return false;
        auto delivered = link.receive(p::Side::first);
        if (!delivered || !*delivered) return false;
        auto parsed = p::parse_udp6(**delivered);
        if (!parsed || parsed->source != remote.address || parsed->destination != client.address ||
            parsed->source_port != remote.port || parsed->destination_port != client.port ||
            !std::ranges::equal(parsed->payload, payload)) return false;
        auto expired = bridge.expire(103);
        return expired && *expired == 1 && !bridge.reply(outgoing->flow, remote, payload, 103);
    }
}

int main() {
    Socket outbound, origin, attacker;
    if (outbound.fd < 0 || origin.fd < 0 || attacker.fd < 0) return 1;
    auto local_socket = bind_local(outbound.fd), origin_socket = bind_local(origin.fd), attacker_socket = bind_local(attacker.fd);
    if (!local_socket || !origin_socket || !attacker_socket) return 1;
    constexpr u::Endpoint4 client{{10, 0, 0, 2}, 40000};
    auto remote = endpoint(*origin_socket);
    p::Bytes payload{'h', 'e', 'l', 'l', 'o'};
    p::MemoryLink link;
    auto rules = ::rules::Matcher::compile({{{"ip-cidr", "192.0.2.0/24"}}});
    if (!rules) return 1;
    u::RetirementHandler retire{&outbound, [](void* context, u::FlowId) noexcept {
        auto& socket = *static_cast<Socket*>(context);
        if (socket.fd >= 0) { ::close(socket.fd); socket.fd = -1; }
    }};
    u::RoutedBridge4 bridge(std::move(*rules), u::Mapping::endpoint_independent,
                            u::Filtering::address_port_dependent, {1, 1, 100}, 1500, retire);
    auto blocked_packet = p::make_udp4(client.address, {192, 0, 2, 1}, client.port, 53, payload);
    if (!blocked_packet) return 1;
    auto denied = bridge.prepare(*blocked_packet, 0);
    if (denied || std::get<u::RouteError>(denied.error()) != u::RouteError::blocked || bridge.size() != 0) return 1;
    auto request = p::make_udp4(client.address, remote.address, client.port, remote.port, payload);
    if (!request || !link.send(p::Side::first, *request)) return 1;
    auto queued = link.receive(p::Side::second);
    if (!queued || !*queued) return 1;
    auto outgoing = bridge.prepare(**queued, 0);
    if (!outgoing || outgoing->remote != remote || outgoing->payload != payload) return 1;
    auto failed = bridge.complete(outgoing->flow, outgoing->token, false, 1);
    if (failed || failed.error() != u::Error::send_failed || bridge.reply(outgoing->flow, remote, payload, 2)) return 1;
    auto retry = bridge.prepare(**queued, 3);
    if (!retry || !send(outbound.fd, *origin_socket, retry->payload) ||
        !bridge.complete(retry->flow, retry->token, true, 3)) return 1;
    auto upstream = receive(origin.fd);
    if (!upstream || upstream->second != payload || endpoint(upstream->first) != endpoint(*local_socket)) return 1;
    if (!send(attacker.fd, *local_socket, payload)) return 1;
    auto forged = receive(outbound.fd);
    if (!forged) return 1;
    auto blocked = bridge.reply(retry->flow, endpoint(forged->first), forged->second, 5);
    if (blocked || std::get<u::Error>(blocked.error()) != u::Error::forbidden) return 1;
    if (!send(origin.fd, upstream->first, payload)) return 1;
    auto response = receive(outbound.fd);
    if (!response) return 1;
    auto packet = bridge.reply(retry->flow, endpoint(response->first), response->second, 6);
    if (!packet || !link.send(p::Side::second, *packet)) return 1;
    auto delivered = link.receive(p::Side::first);
    if (!delivered || !*delivered) return 1;
    auto decoded = p::parse_udp4(**delivered);
    if (!decoded || decoded->source != remote.address || decoded->destination != client.address ||
        !std::ranges::equal(decoded->payload, payload)) return 1;
    auto expired = bridge.expire(106);
    if (!expired || *expired != 1 || outbound.fd != -1 || bridge.reply(retry->flow, remote, payload, 106)) return 1;
    if (!ipv6_roundtrip()) { std::cerr << "IPv6 UDP loopback bridge failed\n"; return 1; }
    std::cout << "UDP loopback flow, failed send, peer filtering and packet return passed\n";
}
