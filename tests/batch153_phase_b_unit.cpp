#include <arpa/inet.h>
#include <cassert>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

import std;
import containers.inplace_vector;
import functional;
import utility;
import platform.ip_address;
import platform.os_fs;
import platform.process_owner;

static_assert(sizeof(functional::function_ref<void()>) == 2 * sizeof(void*));
static_assert(std::is_trivially_copyable_v<functional::function_ref<int(int)>>);
static_assert(std::is_trivially_destructible_v<functional::function_ref<int(int)>>);
static_assert(std::default_initializable<containers::inplace_vector<int, 4>>);
static_assert(std::default_initializable<utility::atomic_shared_ptr<int>>);

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
        containers::inplace_vector<Tracked, 4> vec;
        assert(vec.empty() && vec.max_size() == 4 && vec.capacity() == 4);
        assert(vec.try_emplace_back("a") != nullptr);
        assert(vec.try_emplace_back("b") != nullptr);
        assert(vec.try_emplace_back("c") != nullptr);
        assert(vec.try_emplace_back("d") != nullptr);
        assert(vec.try_emplace_back("overflow") == nullptr);
        assert(vec.size() == 4);

        auto copy = vec;
        assert(copy == vec && Tracked::live == 8);
        containers::erase_if(copy, [](Tracked const& t) { return t.label == "b" || t.label == "c"; });
        assert(copy.size() == 2 && copy[0].label == "a" && copy[1].label == "d");
        copy.resize(3);
        assert(copy.size() == 3 && copy[2].label == "default");
        auto moved = std::move(copy);
        assert(moved.size() == 3);
    }
    assert(Tracked::live == 0);

    {
        int factor = 3;
        functional::function_ref<int(int)> mul = [&](int x) { return x * factor; };
        assert(mul(7) == 21);
        functional::function_ref<int(int) const> cmul = [&](int x) { return x * factor; };
        assert(cmul(5) == 15);
        int accum = 10;
        functional::function_ref<int(int)> mut = [&](int x) mutable { accum += x; return accum; };
        assert(mut(4) == 14 && accum == 14);
        functional::function_ref<int(int, int) noexcept> add = &sum_via_ref;
        assert(add(19, 23) == 42);
    }

    {
        functional::move_only_function<int(int)> empty_mv;
        assert(!empty_mv && empty_mv == nullptr);

        auto up = std::make_unique<int>(10);
        functional::move_only_function<int(int) const> sbo_mv = [p = std::move(up)](int x) { return *p + x; };
        assert(static_cast<bool>(sbo_mv) && sbo_mv(5) == 15);
        auto moved_sbo = std::move(sbo_mv);
        assert(!sbo_mv && moved_sbo(7) == 17);

        struct BigMove {
            std::array<std::uint64_t, 8> pad{};
            std::unique_ptr<int> ptr;
            auto operator()(int x) const noexcept -> int { return *ptr + x; }
        };
        functional::move_only_function<int(int) const noexcept> big_mv = BigMove{{}, std::make_unique<int>(30)};
        assert(big_mv(12) == 42);
        big_mv.reset();
        assert(big_mv == nullptr);

        functional::copyable_function<int(int)> empty_cp = nullptr;
        assert(!empty_cp);
        int (*null_fn)(int) = nullptr;
        functional::copyable_function<int(int)> null_target_cp = null_fn;
        assert(!null_target_cp);

        functional::copyable_function<int(int) const> sbo_cp = [base = 100](int x) { return base + x; };
        auto sbo_cp2 = sbo_cp;
        assert(sbo_cp(1) == 101 && sbo_cp2(2) == 102);

        struct BigCopy {
            std::array<std::uint64_t, 8> pad{};
            int acc = 0;
            auto operator()(int delta) -> int { acc += delta; return acc; }
        };
        functional::copyable_function<int(int)> big_cp = BigCopy{{}, 50};
        auto big_cp2 = big_cp;
        assert(big_cp(5) == 55);
        assert(big_cp2(10) == 60);
        assert(big_cp(1) == 56);
    }

    {
        utility::atomic_shared_ptr<int> ptr(std::make_shared<int>(42));
        auto loaded = ptr.load();
        assert(loaded && *loaded == 42);
        auto prev = ptr.exchange(std::make_shared<int>(99));
        assert(prev && *prev == 42);
        assert(*ptr.load() == 99);

        auto expected = std::make_shared<int>(10);
        auto desired = std::make_shared<int>(77);
        assert(!ptr.compare_exchange_strong(expected, desired));
        assert(expected && *expected == 99);
        assert(ptr.compare_exchange_strong(expected, desired));
        assert(*ptr.load() == 77);
        ptr.store(nullptr);
        assert(!ptr.load());
    }

    {
        int calls = 0;
        {
            utility::scope_exit guard([&]() { ++calls; });
            auto moved = std::move(guard);
            (void)moved;
        }
        assert(calls == 1);
        {
            utility::scope_exit dismissed([&]() { ++calls; });
            dismissed.release();
        }
        assert(calls == 1);
    }

    {
        std::array<std::uint8_t, 32> secret{};
        secret.fill(0xA5);
        utility::secure_zero(std::span(secret));
        assert(std::ranges::all_of(secret, [](std::uint8_t b) { return b == 0; }));
        std::string pw = "super-secret-password";
        utility::secure_zero(pw.data(), pw.size());
        assert(std::ranges::all_of(pw, [](char c) { return c == '\0'; }));
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
