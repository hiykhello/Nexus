#include <arpa/inet.h>
#include <cerrno>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

import std;
import relay;

using namespace std::chrono_literals;

struct Socket {
    int fd = -1;
    Socket() = default;
    explicit Socket(int value) : fd(value) {}
    Socket(Socket const&) = delete;
    auto operator=(Socket const&) -> Socket& = delete;
    Socket(Socket&& other) noexcept : fd(std::exchange(other.fd, -1)) {}
    ~Socket() { if (fd >= 0) ::close(fd); }
    auto close() -> void { if (fd >= 0) ::close(std::exchange(fd, -1)); }
};

static auto connect_to(std::uint16_t port) -> Socket {
    Socket socket(::socket(AF_INET, SOCK_STREAM, 0));
    if (socket.fd < 0) return socket;
    timeval limit{3, 0};
    (void)::setsockopt(socket.fd, SOL_SOCKET, SO_RCVTIMEO, &limit, sizeof(limit));
    (void)::setsockopt(socket.fd, SOL_SOCKET, SO_SNDTIMEO, &limit, sizeof(limit));
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (::connect(socket.fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0) {
        if (errno!=EINTR) { socket.close(); return socket; }
        pollfd pending{socket.fd,POLLOUT,0};
        int result;
        do { result=::poll(&pending,1,3000); } while (result<0 && errno==EINTR);
        int error=0; socklen_t size=sizeof(error);
        if (result<=0 || ::getsockopt(socket.fd,SOL_SOCKET,SO_ERROR,&error,&size)!=0 || error) socket.close();
    }
    return socket;
}

static auto send_all(int fd, std::span<unsigned char const> data) -> bool {
    while (!data.empty()) {
        auto sent=::send(fd,data.data(),data.size(),MSG_NOSIGNAL);
        if (sent<0 && errno==EINTR) continue;
        if (sent<=0) return false;
        data=data.subspan(static_cast<std::size_t>(sent));
    }
    return true;
}

static auto receive_all(int fd, std::span<unsigned char> data) -> bool {
    while (!data.empty()) {
        auto received=::recv(fd,data.data(),data.size(),0);
        if (received<0 && errno==EINTR) continue;
        if (received<=0) return false;
        data=data.subspan(static_cast<std::size_t>(received));
    }
    return true;
}

static auto greet(int fd) -> bool {
    std::array<unsigned char,3> greeting{5,1,0};
    std::array<unsigned char,2> reply{};
    return send_all(fd,greeting) && receive_all(fd,reply) && reply==std::array<unsigned char,2>{5,0};
}

static auto closed(int fd, int timeout_ms) -> bool {
    pollfd pending{fd,POLLIN|POLLHUP,0};
    int result;
    do { result=::poll(&pending,1,timeout_ms); } while (result<0 && errno==EINTR);
    if (result<=0) return false;
    unsigned char byte{};
    ssize_t count;
    do { count=::recv(fd,&byte,1,0); } while (count<0 && errno==EINTR);
    return count==0 || (count<0 && (errno==ECONNRESET || errno==ENOTCONN));
}

static auto concurrent_transfer(std::uint16_t proxy_port) -> bool {
    constexpr int count = 12;
    Socket listener(::socket(AF_INET, SOCK_STREAM, 0));
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (listener.fd < 0 || ::bind(listener.fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0 ||
        ::listen(listener.fd, count) != 0) return false;
    socklen_t length = sizeof(address);
    if (::getsockname(listener.fd, reinterpret_cast<sockaddr*>(&address), &length) != 0) return false;
    auto port = ntohs(address.sin_port);
    std::atomic_bool target_ok{true};
    std::jthread target([&] {
        std::vector<std::jthread> workers;
        for (int n = 0; n < count; ++n) {
            pollfd pending{listener.fd, POLLIN, 0};
            int result;
            do { result=::poll(&pending,1,5000); } while (result<0 && errno==EINTR);
            if (result<=0) { target_ok = false; break; }
            Socket peer(::accept(listener.fd, nullptr, nullptr));
            if (peer.fd < 0) { target_ok = false; break; }
            timeval limit{5, 0};
            (void)::setsockopt(peer.fd, SOL_SOCKET, SO_RCVTIMEO, &limit, sizeof(limit));
            (void)::setsockopt(peer.fd, SOL_SOCKET, SO_SNDTIMEO, &limit, sizeof(limit));
            workers.emplace_back([peer = std::move(peer), &target_ok] {
                std::array<unsigned char, 4096> data{};
                if (!receive_all(peer.fd,data)) {
                    target_ok = false; return;
                }
                if (!send_all(peer.fd,data)) target_ok=false;
            });
        }
    });
    std::atomic_bool clients_ok{true};
    std::vector<std::jthread> clients;
    for (int n = 0; n < count; ++n) {
        clients.emplace_back([=, &clients_ok] {
            auto socket = connect_to(proxy_port);
            std::array<unsigned char, 10> request{5, 1, 0, 1, 127, 0, 0, 1,
                static_cast<unsigned char>(port >> 8), static_cast<unsigned char>(port)};
            std::array<unsigned char, 10> reply{};
            std::array<unsigned char, 4096> data{}, received{};
            data.fill(static_cast<unsigned char>(n));
            if (socket.fd < 0 || !greet(socket.fd) ||
                !send_all(socket.fd, request) ||
                !receive_all(socket.fd,reply) ||
                reply[0] != 5 || reply[1] != 0 ||
                !send_all(socket.fd, data) ||
                !receive_all(socket.fd,received) ||
                received != data) clients_ok = false;
        });
    }
    for (auto& client : clients) client.join();
    target.join();
    if (!clients_ok || !target_ok) std::cerr << "concurrent transfers failed\n";
    return clients_ok && target_ok;
}

static auto capacity(std::uint16_t port) -> bool {
    std::vector<Socket> clients;
    for (int i = 0; i < 64; ++i) {
        auto socket = connect_to(port);
        if (socket.fd < 0 || !greet(socket.fd)) {
            std::cerr << "could not establish session " << i << '\n';
            return false;
        }
        clients.push_back(std::move(socket));
    }
    auto overflow = connect_to(port);
    if (overflow.fd < 0 || !closed(overflow.fd, 3000)) {
        std::cerr << "65th session was not rejected\n";
        return false;
    }
    clients.back().close();
    auto deadline = std::chrono::steady_clock::now() + 3s;
    while (std::chrono::steady_clock::now() < deadline) {
        auto next = connect_to(port);
        if (next.fd >= 0 && greet(next.fd)) return true;
        std::this_thread::sleep_for(20ms);
    }
    std::cerr << "session slot was not reclaimed\n";
    return false;
}

static auto handshake_deadline(std::uint16_t port) -> bool {
    Socket socket;
    auto ready_deadline = std::chrono::steady_clock::now() + 3s;
    while (std::chrono::steady_clock::now() < ready_deadline) {
        auto candidate = connect_to(port);
        if (candidate.fd >= 0 && greet(candidate.fd)) {
            socket.fd = std::exchange(candidate.fd, -1);
            break;
        }
        std::this_thread::sleep_for(20ms);
    }
    unsigned char partial[]{5, 1, 0};
    auto started = std::chrono::steady_clock::now();
    if (socket.fd < 0 || !send_all(socket.fd,std::span(partial).first(2))) {
        std::cerr << "could not start incomplete request\n";
        return false;
    }
    std::this_thread::sleep_for(6s);
    if (!send_all(socket.fd,std::span(partial).subspan(2))) {
        std::cerr << "request closed before handshake deadline\n";
        return false;
    }
    if (!closed(socket.fd, 6000)) {
        std::cerr << "incomplete greeting did not expire\n";
        return false;
    }
    auto elapsed = std::chrono::steady_clock::now() - started;
    if (elapsed < 9s || elapsed > 12s) {
        std::cerr << "handshake timeout was not measured from acceptance\n";
        return false;
    }
    auto next = connect_to(port);
    return next.fd >= 0 && greet(next.fd);
}

static auto run_test(std::function<bool(std::uint16_t)> const& test, unsigned workers) -> bool {
    relay::Server server;
    auto port = server.start(0,relay::Inbound::socks5,workers);
    if (!port) { std::cerr << "proxy start failed: " << port.error() << '\n'; return false; }
    std::atomic_bool stop{false};
    std::jthread loop([&] { while (!stop) server.poll(20ms); server.stop(); });
    bool ok = test(*port);
    stop = true;
    loop.join();
    return ok;
}

static auto start_rollback() -> bool {
    Socket occupied(::socket(AF_INET,SOCK_STREAM,0));
    sockaddr_in address{};
    address.sin_family=AF_INET;
    address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    if (occupied.fd<0 || ::bind(occupied.fd,reinterpret_cast<sockaddr*>(&address),sizeof(address))!=0 ||
        ::listen(occupied.fd,1)!=0) return false;
    socklen_t size=sizeof(address);
    if (::getsockname(occupied.fd,reinterpret_cast<sockaddr*>(&address),&size)!=0) return false;
    relay::Server server;
    if (server.start(ntohs(address.sin_port),relay::Inbound::socks5,2)) return false;
    occupied.close();
    auto retry=server.start(ntohs(address.sin_port),relay::Inbound::socks5,2);
    if (!retry || !server.healthy()) return false;
    server.stop();
    return !server.healthy();
}

int main(int argc, char** argv) {
    auto workers=argc==2 ? static_cast<unsigned>(std::stoul(argv[1])) : 1;
    if (workers>1 && !start_rollback()) return 1;
    if (!run_test(concurrent_transfer,workers) || !run_test(capacity,workers) || !run_test(handshake_deadline,workers)) return 1;
    std::cout << "SOCKS5 concurrent transfers, session limit, recovery and handshake deadline passed\n";
}
