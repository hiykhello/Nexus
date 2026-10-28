#include <arpa/inet.h>
#include <cerrno>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
import std;
import nexus.proxy;

namespace {
    int throw_on = 0;
    int calls = 0;
    struct LaunchFailure {};
    auto count(std::string_view path) -> std::size_t {
        return std::ranges::distance(std::filesystem::directory_iterator(path), std::filesystem::directory_iterator{});
    }
    auto handshake(sockaddr_in address) -> bool {
        int fd = ::socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) return false;
        timeval limit{3, 0};
        (void)::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &limit, sizeof(limit));
        int connected = ::connect(fd, reinterpret_cast<sockaddr*>(&address), sizeof(address));
        if (connected != 0 && errno == EINTR) {
            pollfd event{fd, POLLOUT, 0};
            int ready;
            do { ready = ::poll(&event, 1, 3000); } while (ready < 0 && errno == EINTR);
            int error = 0; socklen_t length = sizeof(error);
            connected = ready > 0 && ::getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &length) == 0 && !error ? 0 : -1;
        }
        unsigned char greeting[]{5, 1, 0}, reply[2]{};
        std::size_t sent = 0, received = 0;
        while (connected == 0 && sent < sizeof(greeting)) {
            auto n = ::send(fd, greeting + sent, sizeof(greeting) - sent, MSG_NOSIGNAL);
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) break;
            sent += static_cast<std::size_t>(n);
        }
        while (sent == sizeof(greeting) && received < sizeof(reply)) {
            auto n = ::recv(fd, reply + received, sizeof(reply) - received, 0);
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) break;
            received += static_cast<std::size_t>(n);
        }
        ::close(fd);
        return received == 2 && reply[0] == 5 && reply[1] == 0;
    }
}

extern "C" void nexus_test_vless_relay_throw(unsigned) {}
extern "C" void nexus_test_start_throw() {
    if (++calls == throw_on) throw LaunchFailure{};
}
extern "C" void nexus_test_session_throw(std::uint8_t) {}

auto main() -> int {
    using namespace std::chrono_literals;
    for (unsigned workers : {1u, 2u}) {
        int fd = ::socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) return 1;
        sockaddr_in address{};
        address.sin_family = AF_INET; address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        socklen_t size = sizeof(address);
        if (::bind(fd, reinterpret_cast<sockaddr*>(&address), size) ||
            ::getsockname(fd, reinterpret_cast<sockaddr*>(&address), &size)) return 2;
        ::close(fd);
        nexus::proxy::Server server;
        auto fds = count("/proc/self/fd"), threads = count("/proc/self/task");
        calls = 0; throw_on = static_cast<int>(workers);
        bool caught = false;
        try { (void)server.start(ntohs(address.sin_port), nexus::proxy::Inbound::socks5, workers); }
        catch (LaunchFailure const&) { caught = true; }
        if (!caught || calls != throw_on || server.healthy() ||
            count("/proc/self/fd") != fds || count("/proc/self/task") != threads) return 3;
        throw_on = 0;
        auto retry = server.start(ntohs(address.sin_port), nexus::proxy::Inbound::socks5, workers);
        if (!retry || *retry != ntohs(address.sin_port) || !server.healthy()) return 4;
        auto client = std::async(std::launch::async, handshake, address);
        auto deadline = std::chrono::steady_clock::now() + 4s;
        while (client.wait_for(0ms) != std::future_status::ready && std::chrono::steady_clock::now() < deadline)
            server.poll(10ms);
        if (!client.get()) return 5;
        server.stop();
        if (server.healthy() || count("/proc/self/fd") != fds || count("/proc/self/task") != threads) return 6;
        std::println("{} worker(s): launch exception rolled back and handshake succeeded after restart", workers);
    }
}
