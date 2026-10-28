#include <arpa/inet.h>
#include <cerrno>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
import std;
import nexus.proxy;
using namespace std::chrono_literals;

namespace {
    std::atomic<unsigned> injected{0};
    std::atomic_bool survivor_started{false};
    struct SessionFailure {};
    struct Socket {
        int fd = -1;
        explicit Socket(int value) : fd(value) {}
        Socket(Socket const&) = delete;
        ~Socket() { if (fd >= 0) ::close(fd); }
    };
    auto connect_to(std::uint16_t port) -> int {
        int fd = ::socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) return -1;
        timeval limit{3, 0};
        (void)::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &limit, sizeof(limit));
        sockaddr_in address{};
        address.sin_family = AF_INET; address.sin_addr.s_addr = htonl(INADDR_LOOPBACK); address.sin_port = htons(port);
        if (::connect(fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0) return fd;
        if (errno == EINTR) {
            pollfd event{fd, POLLOUT, 0};
            int ready;
            do { ready = ::poll(&event, 1, 3000); } while (ready < 0 && errno == EINTR);
            int error = 0; socklen_t length = sizeof(error);
            if (ready > 0 && ::getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &length) == 0 && !error) return fd;
        }
        ::close(fd); return -1;
    }
    auto send_all(int fd, std::span<unsigned char const> bytes) -> bool {
        while (!bytes.empty()) {
            auto n = ::send(fd, bytes.data(), bytes.size(), MSG_NOSIGNAL);
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) return false;
            bytes = bytes.subspan(static_cast<std::size_t>(n));
        }
        return true;
    }
    auto receive(int fd, std::span<unsigned char> bytes) -> bool {
        while (!bytes.empty()) {
            auto n = ::recv(fd, bytes.data(), bytes.size(), 0);
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) return false;
            bytes = bytes.subspan(static_cast<std::size_t>(n));
        }
        return true;
    }
    auto exercise(std::uint16_t port) -> bool {
        Socket survivor(connect_to(port));
        if (survivor.fd < 0 || !send_all(survivor.fd, std::array<unsigned char, 1>{5})) return false;
        auto deadline = std::chrono::steady_clock::now() + 3s;
        while (!survivor_started && std::chrono::steady_clock::now() < deadline) std::this_thread::sleep_for(1ms);
        if (!survivor_started) return false;
        for (unsigned i = 0; i < 70; ++i) {
            Socket failed(connect_to(port));
            if (failed.fd < 0 || !send_all(failed.fd, std::array<unsigned char, 1>{0x7f})) return false;
            unsigned char byte{};
            ssize_t n;
            do { n = ::recv(failed.fd, &byte, 1, 0); } while (n < 0 && errno == EINTR);
            if (n != 0 && !(n < 0 && (errno == ECONNRESET || errno == ENOTCONN))) return false;
        }
        std::array<unsigned char, 2> reply{};
        return send_all(survivor.fd, std::array<unsigned char, 2>{1, 0}) &&
               receive(survivor.fd, reply) && reply == std::array<unsigned char, 2>{5, 0};
    }
    auto count(std::string_view path) -> std::size_t {
        return std::ranges::distance(std::filesystem::directory_iterator(path), std::filesystem::directory_iterator{});
    }
}
extern "C" void nexus_test_vless_relay_throw(unsigned) {}
extern "C" void nexus_test_start_throw() {}
extern "C" void nexus_test_session_throw(std::uint8_t first) {
    if (first == 0x7f) { ++injected; throw SessionFailure{}; }
    if (first == 5) survivor_started = true;
}
auto main() -> int {
    for (unsigned workers : {1u, 2u}) {
        nexus::proxy::Server server;
        auto fds = count("/proc/self/fd"), threads = count("/proc/self/task");
        auto port = server.start(0, nexus::proxy::Inbound::socks5, workers);
        if (!port) return 1;
        injected = 0; survivor_started = false;
        auto client = std::async(std::launch::async, exercise, *port);
        auto deadline = std::chrono::steady_clock::now() + 15s;
        while (client.wait_for(0ms) != std::future_status::ready && std::chrono::steady_clock::now() < deadline && server.healthy())
            server.poll(10ms);
        if (!client.get() || injected != 70 || !server.healthy()) return 2;
        server.stop();
        if (count("/proc/self/fd") != fds || count("/proc/self/task") != threads) return 3;
        std::println("{} worker(s): 70 session exceptions closed, quota recovered and existing session survived", workers);
    }
}
