export module test.random_fault;
import std;

extern "C" int* __errno_location() noexcept;

export namespace test {
    enum class RandomFault { disabled, unavailable, permission, interrupted_short, zero };
    auto set_random_fault(RandomFault mode) noexcept -> void;
    [[nodiscard]] auto random_calls() noexcept -> int;
    [[nodiscard]] auto random_bad_flag() noexcept -> bool;
}

namespace {
    thread_local test::RandomFault mode=test::RandomFault::disabled;
    thread_local int calls=0;
    thread_local bool bad_flag=false;
}

namespace test {
    auto set_random_fault(RandomFault value) noexcept -> void { mode=value; calls=0; bad_flag=false; }
    auto random_calls() noexcept -> int { return calls; }
    auto random_bad_flag() noexcept -> bool { return bad_flag; }
}

extern "C" bool nexus_test_linux_random(void* data,std::size_t size,unsigned int flags,std::ptrdiff_t* result) noexcept {
    using test::RandomFault;
    if (mode==RandomFault::disabled) return false;
    ++calls;
    bad_flag |= flags!=1u;
    if (mode==RandomFault::unavailable || mode==RandomFault::permission ||
        (mode==RandomFault::interrupted_short && calls==1)) {
        *::__errno_location()=std::to_underlying(mode==RandomFault::unavailable ? std::errc::resource_unavailable_try_again :
                                                mode==RandomFault::permission ? std::errc::operation_not_permitted : std::errc::interrupted);
        *result=-1;
    } else if (mode==RandomFault::zero) *result=0;
    else {
        auto count=std::min<std::size_t>(size,1);
        std::fill_n(static_cast<std::byte*>(data),count,static_cast<std::byte>(0x58+calls));
        *result=static_cast<std::ptrdiff_t>(count);
    }
    return true;
}
