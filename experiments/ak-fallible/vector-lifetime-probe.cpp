#include <AK/Vector.h>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
extern "C" [[noreturn]] void ak_verification_failed(char const*) { std::_Exit(90); }
static bool fail_next = false;
extern "C" void* __real_malloc(size_t);
extern "C" void* __wrap_malloc(size_t n) {
    if (fail_next) { fail_next = false; return nullptr; }
    return __real_malloc(n);
}
struct Item {
    static inline int live = 0, moves = 0;
    int value;
    explicit Item(int n) noexcept : value(n) { ++live; }
    Item(Item const&) = delete;
    Item& operator=(Item const&) = delete;
    Item(Item&& o) noexcept : value(o.value) { o.value = -1; ++live; ++moves; }
    ~Item() { --live; }
};
int main() {
    {
        AK::Vector<Item> target, source;
        if (target.try_empend(1).is_error() || source.try_empend(7).is_error()) return 1;
        while (target.size() < target.capacity()) if (target.try_empend(2).is_error()) return 2;
        auto n = target.size(); int before = Item::live, moves = Item::moves;
        fail_next = true;
        auto failed = target.try_extend(AK::move(source));
        if (!failed.is_error() || failed.error().code() != ENOMEM || fail_next) return 3;
        if (target.size() != n || target[0].value != 1 || source.size() != 1 || source[0].value != 7 || Item::live != before || Item::moves != moves) return 4;
        if (target.try_extend(AK::move(source)).is_error()) return 5;
        if (target.size() != n + 1 || target[0].value != 1 || target[n].value != 7 || !source.is_empty() || Item::live != before) return 6;
    }
    if (Item::live != 0) return 7;
    std::puts("nontrivial elements survive failure, retry and destruction");
}
