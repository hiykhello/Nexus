#include <arpa/inet.h>
#include <cassert>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

import std;
import nexus.compat;
import platform.ip_address;
import platform.os_fs;
import platform.process_owner;

namespace {
    struct Tracked {
        inline static int live = 0;
        std::string label;
        explicit Tracked(std::string s = "default") : label(std::move(s)) { ++live; }
        Tracked(Tracked const& o) : label(o.label) { ++live; }
        Tracked(Tracked&& o) noexcept : label(std::move(o.label)) { ++live; }
        auto operator=(Tracked const& o) -> Tracked& { label = o.label; return *this; }
        auto operator=(Tracked&& o) noexcept -> Tracked& { label = std::move(o.label); return *this; }
        ~Tracked() { --live; }
        auto operator==(Tracked const& o) const -> bool { return label == o.label; }
    };

    auto sum_via_ref(int a, int b) noexcept -> int { return a + b; }
}

int main() {
    {
        nexus::inplace_vector<Tracked, 4> vec;
        assert(vec.empty() && vec.max_size() == 4 && vec.capacity() == 4);
        assert(vec.try_emplace_back("a") != nullptr);
        assert(vec.try_emplace_back("b") != nullptr);
        assert(vec.try_emplace_back("c") != nullptr);
        assert(vec.try_emplace_back("d") != nullptr);
        assert(vec.try_emplace_back("overflow") == nullptr);
        assert(vec.size() == 4);

        auto copy = vec;
        assert(copy == vec && Tracked::live == 8);
        nexus::erase_if(copy, [](Tracked const& t) { return t.label == "b" || t.label == "c"; });
        assert(copy.size() == 2 && copy[0].label == "a" && copy[1].label == "d");
        copy.resize(3);
        assert(copy.size() == 3 && copy[2].label == "default");
        auto moved = std::move(copy);
        assert(moved.size() == 3);
    }
    assert(Tracked::live == 0);

    {
        int factor = 3;
        nexus::function_ref<int(int)> mul = [&](int x) { return x * factor; };
        assert(mul(7) == 21);
        nexus::function_ref<int(int, int) noexcept> add = &sum_via_ref;
        assert(add(19, 23) == 42);
    }

    assert(platform::normalize_windows_pipe_name("nexus-ctrl") == "\\\\.\\pipe\\nexus-ctrl");
    assert(platform::normalize_windows_pipe_name("\\\\.\\PIPE\\my_pipe") == "\\\\.\\pipe\\my_pipe");
    assert(!platform::normalize_windows_pipe_name("bad/name").has_value());
    assert(!platform::normalize_windows_pipe_name("\\\\server\\pipe\\x").has_value());

    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    assert(fd >= 0);
    sockaddr_in sin{};
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = ::htonl(INADDR_LOOPBACK);
    sin.sin_port = 0;
    assert(::bind(fd, reinterpret_cast<sockaddr*>(&sin), sizeof(sin)) == 0);
    assert(::listen(fd, 1) == 0);
    socklen_t slen = sizeof(sin);
    assert(::getsockname(fd, reinterpret_cast<sockaddr*>(&sin), &slen) == 0);
    auto port = ntohs(sin.sin_port);
    auto ip = *platform::parse_ip_address("127.0.0.1");
    auto owner = platform::lookup_socket_owner({.is_udp = false, .local_ip = ip, .local_port = port});
    ::close(fd);
    assert(owner.has_value());
    assert(owner->pid == static_cast<std::uint32_t>(::getpid()));
    assert(owner->uid == static_cast<std::uint32_t>(::geteuid()));
    assert(!owner->executable.empty());

    std::println("batch153 Phase B unit passed (pid={}, exe={})", owner->pid, owner->executable);
    return 0;
}
