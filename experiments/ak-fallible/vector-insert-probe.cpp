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
    static inline int live = 0;
    int value;
    explicit Item(int n) noexcept : value(n) { ++live; }
    Item(Item const& x) noexcept : value(x.value) { ++live; }
    Item(Item&& x) noexcept : value(x.value) { x.value = -1; ++live; }
    ~Item() { --live; }
};
int main() {
    {
        AK::Vector<Item> v;
        for (int i = 0; i < 3; ++i) if (v.try_empend(10 + i).is_error()) return 1;
        while (v.size() < v.capacity()) if (v.try_empend(99).is_error()) return 2;
        auto n = v.size(); auto initial = Item::live;
        auto bad = v.try_insert(n + 1, v[0]);
        if (!bad.is_error() || bad.error().code() != EINVAL || Item::live != initial) return 3;
        fail_next = true;
        auto fail = v.try_insert(1, v[2]);
        if (!fail.is_error() || fail.error().code() != ENOMEM || fail_next || v.size() != n || v[2].value != 12 || Item::live != initial) return 4;
        if (v.try_insert(1, v[2]).is_error() || v[1].value != 12 || v[3].value != 12 || Item::live != initial + 1) return 5;
        if (v.try_prepend(AK::move(v[3])).is_error() || v[0].value != 12 || v[4].value != -1 || Item::live != initial + 2) return 6;
        while (v.size() < v.capacity()) if (v.try_empend(88).is_error()) return 7;
        n = v.size(); initial = Item::live;
        fail_next = true;
        auto rejected = v.try_prepend(v.data() + 1, 2);
        if (!rejected.is_error() || rejected.error().code() != ENOMEM || fail_next || v.size() != n || Item::live != initial || v[1].value != 10) return 8;
        if (v.try_prepend(v.data() + 1, 2).is_error() || v[0].value != 10 || v[1].value != 12 || v[2].value != 12 || Item::live != initial + 2) return 9;
        auto outside = v.try_prepend(v.data() + v.size() - 1, 2);
        if (!outside.is_error() || outside.error().code() != EINVAL) return 10;
    }
    if (Item::live) return 11;
    {
        AK::Vector<int> v;
        if (v.try_ensure_capacity(16).is_error()) return 12;
        for (int i = 1; i <= 3; ++i) if (v.try_append(i).is_error()) return 13;
        if (v.try_insert(2, v[0]).is_error() || v.size() != 4 || v[0] != 1 || v[1] != 2 || v[2] != 1 || v[3] != 3) return 14;
        if (v.try_insert(0, v[3]).is_error() || v[0] != 3 || v[4] != 3) return 15;
        if (v.try_prepend(v.data() + 1, 3).is_error() || v[0] != 1 || v[1] != 2 || v[2] != 1 || v[3] != 3) return 16;
    }
    {
        int a = 1, b = 2, c = 3;
        AK::Vector<int&> refs;
        if (refs.try_append(a).is_error() || refs.try_append(c).is_error() || refs.try_insert(1, b).is_error()) return 17;
        if (&refs[0] != &a || &refs[1] != &b || &refs[2] != &c) return 18;
    }
    std::puts("AK insert and prepend alias, failures and lifetimes passed");
}
