import std;
import platform.linux_random;
import test.random_fault;

auto main() -> int {
    std::array<std::byte,4> bytes{};
#ifdef NEXUS_TEST_LINUX_RANDOM
    using namespace test;
    for (auto [selected,error]:std::array{
            std::pair{RandomFault::unavailable,std::errc::resource_unavailable_try_again},
            std::pair{RandomFault::permission,std::errc::operation_not_permitted},
            std::pair{RandomFault::zero,std::errc::io_error}}) {
        set_random_fault(selected);
        auto result=::platform::secure_random(bytes);
        if (result || result.error()!=error || random_calls()!=1 || random_bad_flag()) return 1;
    }
    set_random_fault(RandomFault::interrupted_short);
    if (!::platform::secure_random(bytes) || random_calls()!=5 || random_bad_flag() ||
        bytes!=std::array{std::byte{0x5a},std::byte{0x5b},std::byte{0x5c},std::byte{0x5d}}) return 2;
    set_random_fault(RandomFault::interrupted_short);
    if (!::platform::secure_random(std::span<std::byte>{}) || random_calls()) return 3;
    set_random_fault(RandomFault::disabled);
    std::println("Linux entropy retries EINTR and short reads and reports nonblocking errors");
#endif
    if (!::platform::secure_random(bytes)) return 4;
}
