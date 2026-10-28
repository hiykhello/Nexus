#include <AK/Vector.h>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#ifndef NEXUS_AK_REAL_ASSERT
extern "C" [[noreturn]] void ak_verification_failed(char const*) { std::_Exit(90); }
#endif
static bool fail_next = false;
extern "C" void* __real_malloc(size_t);
extern "C" void* __wrap_malloc(size_t n) {
    if (fail_next) { fail_next = false; return nullptr; }
    return __real_malloc(n);
}
struct Item {
    static inline int live = 0, moves = 0;
    int value;
    explicit Item(int v) noexcept : value(v) { ++live; }
    Item(Item const&) = delete;
    Item(Item&& other) noexcept : value(other.value) { other.value = -1; ++live; ++moves; }
    ~Item() { --live; }
};
int main() {
    {
        AK::Vector<Item> v;
        if (v.try_empend(7).is_error()) return 1;
        while (v.size() < v.capacity()) if (v.try_empend(42).is_error()) return 2;
        auto n = v.size(); auto capacity = v.capacity(); auto moves = Item::moves;
        fail_next = true;
        auto failure = v.try_append(AK::move(v[0]));
        if (!failure.is_error() || failure.error().code() != ENOMEM || fail_next) return 3;
        if (v.size() != n || v.capacity() != capacity || v[0].value != 7 || Item::moves != moves || Item::live != static_cast<int>(n)) return 4;
        if (v.try_append(AK::move(v[0])).is_error()) return 5;
        if (v.size() != n + 1 || v[0].value != -1 || v[n].value != 7 || Item::live != static_cast<int>(n + 1)) return 6;
    }
    if (Item::live) return 7;
    std::puts("AK rvalue alias allocation failure, retry and lifetime passed");
}
