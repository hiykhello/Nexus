#include <errno.h>
#include <arpa/inet.h>
#include <poll.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

import std;
import relay;
import rules;
import rulefile;
import platform.stream_peer;

static_assert(sizeof(::platform::stream_peer_abi::Descriptor)==sizeof(pollfd));
static_assert(alignof(::platform::stream_peer_abi::Descriptor)==alignof(pollfd));
static_assert(__builtin_offsetof(::platform::stream_peer_abi::Descriptor,events)==__builtin_offsetof(pollfd,events));
static_assert(__builtin_offsetof(::platform::stream_peer_abi::Descriptor,revents)==__builtin_offsetof(pollfd,revents));
static_assert(std::is_same_v<::platform::stream_peer_abi::Count,nfds_t>);
static_assert(::platform::stream_peer_abi::read_hangup==POLLRDHUP && ::platform::stream_peer_abi::hangup==POLLHUP &&
    ::platform::stream_peer_abi::error==POLLERR && ::platform::stream_peer_abi::invalid==POLLNVAL);

using namespace std::chrono_literals;

struct Fd {
    int fd = -1;
    explicit Fd(int value = -1) : fd(value) {}
    Fd(Fd const&) = delete;
    auto operator=(Fd const&) -> Fd& = delete;
    ~Fd() { if (fd >= 0) ::close(fd); }
};

static auto timeout(int fd) -> void {
    timeval limit{3, 0};
    (void)::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &limit, sizeof(limit));
    (void)::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &limit, sizeof(limit));
}

static auto connect_to(std::uint16_t port) -> int {
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    timeout(fd);
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons(port);
    if (::connect(fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0) {
        if (errno != EINTR) { ::close(fd); return -1; }
        pollfd event{fd, POLLOUT, 0};
        int ready;
        do { ready = ::poll(&event, 1, 3000); } while (ready < 0 && errno == EINTR);
        int error = 0; socklen_t length = sizeof(error);
        if (ready <= 0 || ::getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &length) != 0 || error != 0) {
            ::close(fd); return -1;
        }
    }
    return fd;
}

static auto send_all(int fd, std::span<std::uint8_t const> data, bool fragmented = false) -> bool {
    while (!data.empty()) {
        auto n = ::send(fd, data.data(), fragmented ? 1 : data.size(), MSG_NOSIGNAL);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return false;
        data = data.subspan(static_cast<std::size_t>(n));
    }
    return true;
}

static auto read_all(int fd, std::span<std::uint8_t> data) -> bool {
    while (!data.empty()) {
        auto n = ::recv(fd, data.data(), data.size(), 0);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return false;
        data = data.subspan(static_cast<std::size_t>(n));
    }
    return true;
}

static auto greet(int fd) -> bool {
    std::array<std::uint8_t, 3> hello{5, 1, 0};
    std::array<std::uint8_t, 2> reply{};
    return send_all(fd, hello, true) && read_all(fd, reply) && reply == std::array<std::uint8_t, 2>{5, 0};
}

static auto request(int fd, std::span<std::uint8_t const> bytes, std::uint8_t expected) -> bool {
    std::array<std::uint8_t, 10> reply{};
    bool sent = send_all(fd, bytes, true);
    bool read = sent && read_all(fd, reply);
    if (!read || reply[1] != expected) std::cerr << "request sent=" << sent << " read=" << read << " reply=" << int(reply[0]) << "," << int(reply[1]) << " errno=" << errno << "\n";
    return read && reply[0] == 5 && reply[1] == expected && reply[2] == 0 && reply[3] == 1;
}

static auto failures(std::uint16_t proxy_port) -> bool {
    {
        Fd client(connect_to(proxy_port));
        std::array<std::uint8_t, 3> hello{5, 1, 2};
        std::array<std::uint8_t, 2> reply{};
        if (client.fd < 0 || !send_all(client.fd, hello) || !read_all(client.fd, reply) ||
            reply != std::array<std::uint8_t, 2>{5, 255}) { std::cerr << "no acceptable method failed, fd=" << client.fd << " reply=" << int(reply[0]) << "," << int(reply[1]) << " errno=" << errno << "\n"; return false; }
    }
    for (auto const& [bytes, code] : std::vector<std::pair<std::vector<std::uint8_t>, std::uint8_t>>{
        {{5, 2, 0, 1}, 7}, {{5, 1, 0, 9}, 8}}) {
        Fd client(connect_to(proxy_port));
        if (client.fd < 0 || !greet(client.fd) || !request(client.fd, bytes, code)) { std::cerr << "invalid request failed, code=" << int(code) << " errno=" << errno << "\n"; return false; }
    }
    Fd reserved(::socket(AF_INET, SOCK_STREAM, 0));
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (reserved.fd < 0 || ::bind(reserved.fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0) return false;
    socklen_t size = sizeof(address);
    if (::getsockname(reserved.fd, reinterpret_cast<sockaddr*>(&address), &size) != 0) return false;
    auto port = ntohs(address.sin_port);
    std::array<std::uint8_t, 10> destination{5, 1, 0, 1, 127, 0, 0, 1,
        static_cast<std::uint8_t>(port >> 8), static_cast<std::uint8_t>(port)};
    Fd client(connect_to(proxy_port));
    bool ok = client.fd >= 0 && greet(client.fd) && request(client.fd, destination, 5);
    if (!ok) std::cerr << "connection refusal failed, errno=" << errno << "\n";
    return ok;
}

static auto transfer(std::uint16_t proxy_port, bool domain = false) -> bool {
    Fd listener(::socket(AF_INET, SOCK_STREAM, 0));
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (listener.fd < 0 || ::bind(listener.fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0 ||
        ::listen(listener.fd, 1) != 0) return false;
    socklen_t size = sizeof(address);
    if (::getsockname(listener.fd, reinterpret_cast<sockaddr*>(&address), &size) != 0) return false;
    auto const port = ntohs(address.sin_port);
    std::vector<std::uint8_t> payload(131072);
    for (std::size_t n = 0; n < payload.size(); ++n) payload[n] = static_cast<std::uint8_t>(n);
    std::atomic_bool target_ok{false};
    std::jthread target([&] {
        pollfd pending{listener.fd, POLLIN, 0};
        if (::poll(&pending, 1, 3000) <= 0) return;
        Fd socket(::accept(listener.fd, nullptr, nullptr));
        if (socket.fd < 0) return;
        timeout(socket.fd);
        std::vector<std::uint8_t> received(payload.size());
        if (!read_all(socket.fd, received) || received != payload) return;
        std::uint8_t extra{};
        if (::recv(socket.fd, &extra, 1, 0) != 0) return;
        std::array<std::uint8_t, 5> response{'r','e','p','l','y'};
        target_ok = send_all(socket.fd, response);
    });
    Fd client(connect_to(proxy_port));
    if (client.fd < 0 || !greet(client.fd)) return false;
    std::vector<std::uint8_t> data = domain ?
        std::vector<std::uint8_t>{5, 1, 0, 3, 9, 'l','o','c','a','l','h','o','s','t'} :
        std::vector<std::uint8_t>{5, 1, 0, 1, 127, 0, 0, 1};
    data.push_back(static_cast<std::uint8_t>(port >> 8));
    data.push_back(static_cast<std::uint8_t>(port));
    data.insert(data.end(), payload.begin(), payload.end());
    if (!send_all(client.fd, data) || ::shutdown(client.fd, SHUT_WR) != 0) return false;
    std::array<std::uint8_t, 10> reply{};
    std::array<std::uint8_t, 5> response{};
    if (!read_all(client.fd, reply) || reply[0] != 5 || reply[1] != 0 || reply[3] != 1 ||
        reply[4] != 127 || reply[5] != 0 || reply[6] != 0 || reply[7] != 1 ||
        (reply[8] == 0 && reply[9] == 0) ||
        !read_all(client.fd, response) || response != std::array<std::uint8_t, 5>{'r','e','p','l','y'}) return false;
    std::uint8_t extra{};
    if (::recv(client.fd, &extra, 1, 0) != 0) return false;
    target.join();
    return target_ok;
}

static auto transfer_ipv6(std::uint16_t proxy_port) -> bool {
    Fd listener(::socket(AF_INET6, SOCK_STREAM, 0));
    sockaddr_in6 address{};
    address.sin6_family = AF_INET6;
    address.sin6_addr = in6addr_loopback;
    if (listener.fd < 0 || ::bind(listener.fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0) {
        std::cout << "IPv6 loopback unavailable; IPv6 transfer skipped\n";
        return true;
    }
    if (::listen(listener.fd, 1) != 0) return false;
    socklen_t size = sizeof(address);
    if (::getsockname(listener.fd, reinterpret_cast<sockaddr*>(&address), &size) != 0) return false;
    auto const port = ntohs(address.sin6_port);
    std::atomic_bool target_ok{false};
    std::jthread target([&] {
        pollfd pending{listener.fd, POLLIN, 0};
        if (::poll(&pending, 1, 3000) <= 0) return;
        Fd socket(::accept(listener.fd, nullptr, nullptr));
        if (socket.fd < 0) return;
        timeout(socket.fd);
        std::array<std::uint8_t, 1> byte{};
        if (!read_all(socket.fd, byte)) return;
        target_ok = send_all(socket.fd, byte);
    });
    Fd client(connect_to(proxy_port));
    if (client.fd < 0 || !greet(client.fd)) return false;
    std::array<std::uint8_t, 22> request{5, 1, 0, 4};
    request[19] = 1;
    request[20] = static_cast<std::uint8_t>(port >> 8);
    request[21] = static_cast<std::uint8_t>(port);
    std::array<std::uint8_t, 22> reply{};
    std::array<std::uint8_t, 1> byte{42}, received{};
    if (!send_all(client.fd, request, true) || !read_all(client.fd, reply) ||
        reply[0] != 5 || reply[1] != 0 || reply[3] != 4 ||
        !send_all(client.fd, byte) || !read_all(client.fd, received) || received != byte) return false;
    target.join();
    return target_ok;
}

static auto policy_test(relay::RuleFormat format) -> bool {
    constexpr std::string_view kdl = R"(schema-version 2
kind "predicate"
rule type="ip-cidr" value="127.0.0.0/8"
rule type="ip-cidr" value="::1/128"
rule type="domain-suffix" value="blocked.test"
)";
    std::string data(kdl);
    if (format == relay::RuleFormat::beve) {
        auto rules = ::rules::parse_kdl(kdl);
        if (!rules) return false;
        auto encoded = ::rules::write_beve(*rules);
        if (!encoded) return false;
        data = std::move(*encoded);
    }
    auto path = std::filesystem::temp_directory_path() /
                ("nexus-policy-" + std::to_string(::getpid()) +
                 (format == relay::RuleFormat::kdl ? ".kdl" : ".beve"));
    auto published = ::rulefile::publish_new_file(path.string(), data);
    if (!published) return false;
    auto input = ::rulefile::read_regular_file(path.string());
    std::filesystem::remove(path);
    if (!input) return false;
    relay::Server server;
    if (!server.set_block_rules(*input, format)) return false;
    if (server.set_block_rules("invalid", format)) return false;
    auto port = server.start(0);
    if (!port || server.set_block_rules(data, format)) return false;
    std::atomic_bool stop{false};
    std::jthread loop([&] { while (!stop) server.poll(20ms); server.stop(); });
    Fd blocked_ip(connect_to(*port));
    std::array<std::uint8_t, 10> ip{5, 1, 0, 1, 127, 0, 0, 1, 0, 80};
    Fd blocked_domain(connect_to(*port));
    std::vector<std::uint8_t> domain{5, 1, 0, 3, 14, 'a','.','b','l','o','c','k','e','d','.','t','e','s','t', 0, 80};
    Fd resolved_domain(connect_to(*port));
    std::vector<std::uint8_t> local{5, 1, 0, 3, 9, 'l','o','c','a','l','h','o','s','t', 0, 80};
    Fd invalid_domain(connect_to(*port));
    std::vector<std::uint8_t> invalid{5, 1, 0, 3, 3, 'a', 0, 'b', 0, 80};
    bool ok = blocked_ip.fd >= 0 && greet(blocked_ip.fd) && request(blocked_ip.fd, ip, 2) &&
              blocked_domain.fd >= 0 && greet(blocked_domain.fd) && request(blocked_domain.fd, domain, 2) &&
              resolved_domain.fd >= 0 && greet(resolved_domain.fd) && request(resolved_domain.fd, local, 2) &&
              invalid_domain.fd >= 0 && greet(invalid_domain.fd) && request(invalid_domain.fd, invalid, 1);
    stop = true;
    loop.join();
    auto replaced = server.set_block_rules(data, format);
    auto restarted = server.start(0);
    if (restarted) server.stop();
    return ok && replaced.has_value() && restarted.has_value();
}

#ifdef NEXUS_TEST_SOURCE_ROUTE
static auto source_policy_test() -> bool {
    namespace r = ::rules;
    r::RuleSet source{{{"and","",{{"source-ip-cidr","127.0.0.0/8",{}},
        {"source-port-range","1-65535",{}},{"network","tcp",{}}}}},2};
    auto policy=r::RouteMatcher::compile(std::array{r::RouteRule{source,1}},0,2,r::SourceMetadata::provided);
    if (!policy || !policy->needs_source()) return false;
    relay::Server server;
    if (!server.set_source_policy_for_test(std::move(*policy))) return false;
    auto port=server.start(0);
    if (!port) return false;
    std::atomic_bool stop{false};
    std::jthread loop([&] { while (!stop) server.poll(20ms); server.stop(); });
    Fd ip_client(connect_to(*port));
    std::array<std::uint8_t,10> ip{5,1,0,1,127,0,0,1,0,80};
    Fd domain_client(connect_to(*port));
    std::array<std::uint8_t,16> domain{5,1,0,3,9,'l','o','c','a','l','h','o','s','t',0,80};
    bool ok=ip_client.fd>=0 && greet(ip_client.fd) && request(ip_client.fd,ip,2) &&
        domain_client.fd>=0 && greet(domain_client.fd) && request(domain_client.fd,domain,2);
    stop=true;
    loop.join();
    return ok;
}
#endif

static auto credential_lifecycle() -> bool {
    relay::Server server;
    if (server.set_socks5_credentials("", "password") || server.set_socks5_credentials("user", "") ||
        server.set_socks5_credentials(std::string(256, 'x'), "password")) return false;
    if (!server.set_socks5_credentials("user:colon", "password")) return false;
    if (server.start(0, relay::Inbound::mixed)) return false;
    if (!server.set_socks5_credentials("user", "password")) return false;
    if (server.start(0, relay::Inbound::redirect)) return false;
    auto mixed_auth = server.start(0, relay::Inbound::mixed);
    if (!mixed_auth) return false;
    server.stop();
    auto port = server.start(0);
    if (!port || server.clear_socks5_credentials() || server.set_socks5_credentials("user", "other")) return false;
    server.stop();
    if (!server.clear_socks5_credentials()) return false;
    auto mixed = server.start(0, relay::Inbound::mixed);
    if (!mixed) return false;
    server.stop();
    return true;
}

static auto active_relay_stop(unsigned workers) -> bool {
    Fd listener(::socket(AF_INET, SOCK_STREAM, 0));
    sockaddr_in address{}; address.sin_family=AF_INET; address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    if (listener.fd<0 || ::bind(listener.fd,reinterpret_cast<sockaddr*>(&address),sizeof(address)) ||
        ::listen(listener.fd,1)) return false;
    socklen_t size=sizeof(address);
    if (::getsockname(listener.fd,reinterpret_cast<sockaddr*>(&address),&size)) return false;
    auto target=ntohs(address.sin_port);
    relay::Server server;
    auto port=server.start(0,relay::Inbound::socks5,workers);
    if (!port) return false;
    std::atomic_bool stop{false};
    std::jthread loop([&] { while (!stop) server.poll(20ms); server.stop(); });
    Fd client(connect_to(*port));
    std::array<std::uint8_t,10> destination{5,1,0,1,127,0,0,1,
        static_cast<std::uint8_t>(target>>8),static_cast<std::uint8_t>(target)};
    bool ok=client.fd>=0 && greet(client.fd) && request(client.fd,destination,0);
    pollfd pending{listener.fd,POLLIN,0};
    Fd peer(ok && ::poll(&pending,1,3000)>0 ? ::accept(listener.fd,nullptr,nullptr) : -1);
    if (peer.fd>=0) timeout(peer.fd);
    std::array<std::uint8_t,1> ping{'x'}, received{};
    ok=ok && peer.fd>=0 && send_all(client.fd,ping) && read_all(peer.fd,received) && received==ping;
    stop=true; loop.join();
    std::uint8_t byte{};
    auto client_end=::recv(client.fd,&byte,1,0);
    auto peer_end=peer.fd>=0 ? ::recv(peer.fd,&byte,1,0) : -2;
    if (!ok || client_end!=0 || peer_end!=0)
        std::cerr << "active relay stop: transfer=" << ok << " client=" << client_end << " peer=" << peer_end << '\n';
    ok=ok && client_end==0 && peer_end==0;
    auto restarted=server.start(0,relay::Inbound::socks5,workers);
    if (restarted) server.stop();
    else std::cerr << "active relay restart failed: " << restarted.error().message() << '\n';
    return ok && restarted.has_value();
}

static auto slow_resolver_test(unsigned workers) -> bool {
    if (!std::getenv("NEXUS_TEST_SLOW_RESOLVER")) return true;
    int ready_pipe[2], gate_pipe[2];
    if (::pipe(ready_pipe) != 0) return false;
    Fd ready_read(ready_pipe[0]), ready_write(ready_pipe[1]);
    if (::pipe(gate_pipe) != 0) return false;
    Fd gate_read(gate_pipe[0]), gate_write(gate_pipe[1]);
    auto ready = std::to_string(ready_write.fd);
    auto gate = std::to_string(gate_read.fd);
    if (::setenv("NEXUS_TEST_RESOLVER_READY_FD", ready.c_str(), 1) != 0 ||
        ::setenv("NEXUS_TEST_RESOLVER_GATE_FD", gate.c_str(), 1) != 0) return false;
    relay::Server server;
    auto port = server.start(0,relay::Inbound::socks5,workers);
    if (!port) return false;
    std::atomic_bool stop{false}, stopped{false};
    std::jthread loop([&] { while (!stop) server.poll(20ms); server.stop(); stopped = true; });
    Fd missing(connect_to(*port));
    std::vector<std::uint8_t> missing_request{5, 1, 0, 3, 18,
        'n','e','x','u','s','-','m','i','s','s','i','n','g','.','t','e','s','t', 0, 80};
    bool ok = missing.fd >= 0 && greet(missing.fd) && request(missing.fd, missing_request, 4);
    Fd client(connect_to(*port));
    std::vector<std::uint8_t> request{5, 1, 0, 3, 16, 'n','e','x','u','s','-','d','e','l','a','y','.','t','e','s','t', 0, 80};
    ok = ok && client.fd >= 0 && greet(client.fd) && send_all(client.fd, request);
    pollfd ready_event{ready_read.fd, POLLIN, 0};
    int ready_result;
    do { ready_result=::poll(&ready_event,1,3000); } while (ready_result<0 && errno==EINTR);
    ok = ok && ready_result==1;
    Fd during_resolution(connect_to(*port));
    ok = ok && during_resolution.fd>=0 && greet(during_resolution.fd);
    pollfd client_event{client.fd, POLLIN | POLLHUP, 0};
    int client_result;
    do { client_result=::poll(&client_event,1,12000); } while (client_result<0 && errno==EINTR);
    ok = ok && client_result==1;
    std::uint8_t closed_byte{};
    ssize_t received;
    do { received=::recv(client.fd,&closed_byte,1,0); } while (received<0 && errno==EINTR);
    ok = ok && received==0;
    Fd concurrent(connect_to(*port));
    ok = ok && concurrent.fd >= 0 && greet(concurrent.fd);
    stop = true;
    std::this_thread::sleep_for(100ms);
    ok = ok && !stopped;
    char byte = 'x';
    (void)::write(gate_write.fd, &byte, 1);
    loop.join();
    ok = ok && stopped;
    ::unsetenv("NEXUS_TEST_RESOLVER_READY_FD");
    ::unsetenv("NEXUS_TEST_RESOLVER_GATE_FD");
    return ok;
}

int main(int argc, char** argv) {
    unsigned workers=argc==2 ? static_cast<unsigned>(std::stoul(argv[1])) : 1;
    relay::Server server;
    auto port = server.start(0);
    if (!port) { std::cerr << "proxy start failed: " << port.error() << '\n'; return 1; }
    std::atomic_bool stop{false};
    std::jthread loop([&] { while (!stop) server.poll(20ms); server.stop(); });
    auto check = [](bool value, char const* label) { if (!value) std::cerr << label << " failed\n"; return value; };
    bool ok = check(failures(*port), "failures") && check(transfer(*port), "IPv4 transfer") && check(transfer(*port, true), "DNS transfer") && check(transfer_ipv6(*port), "IPv6 transfer");
    Fd stalled(connect_to(*port));
    std::array<std::uint8_t, 1> partial{5};
    ok = ok && check(stalled.fd >= 0, "stalled connect") && check(greet(stalled.fd), "stalled greet") && check(send_all(stalled.fd, partial), "stalled send");
    stop = true;
    loop.join();
    if (stalled.fd >= 0) {
        std::uint8_t byte{};
        auto n = ::recv(stalled.fd, &byte, 1, 0);
        ok = ok && check(n == 0, "stalled close");
    }
    ok = ok && check(policy_test(relay::RuleFormat::kdl), "KDL policy") && check(policy_test(relay::RuleFormat::beve), "BEVE policy") &&
         check(slow_resolver_test(workers), "slow resolver") && check(credential_lifecycle(), "credential lifecycle") &&
         check(active_relay_stop(workers), "active relay stop");
#ifdef NEXUS_TEST_SOURCE_ROUTE
    ok = ok && check(source_policy_test(), "source policy");
#endif
    if (!ok) { std::cerr << "proxy end-to-end test failed\n"; return 1; }
    std::cout << "SOCKS5 direct TCP, DNS, block rules, pipelining, half-close and stop passed\n";
}
