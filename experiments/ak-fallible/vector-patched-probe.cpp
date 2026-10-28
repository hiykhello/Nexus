#include <AK/Vector.h>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <limits>
#ifndef NEXUS_AK_REAL_ASSERT
extern "C" [[noreturn]] void ak_verification_failed(char const*) { std::_Exit(90); }
#endif
static bool fail_next = false;
static int allocations = 0;
extern "C" void* __real_malloc(size_t);
extern "C" void* __wrap_malloc(size_t n) {
    ++allocations;
    if (fail_next) { fail_next = false; return nullptr; }
    return __real_malloc(n);
}
int main() {
    AK::Vector<int> v;
    if (v.try_append(3).is_error()) return 1;
    auto initial = v.capacity(); auto calls = allocations;
    auto huge = std::numeric_limits<size_t>::max() / sizeof(int) + 1;
    auto oversized = v.try_ensure_capacity(huge);
    if (!oversized.is_error() || oversized.error().code() != EOVERFLOW || allocations != calls) return 2;
    auto overflow = v.try_append(v.data(), std::numeric_limits<size_t>::max());
    if (!overflow.is_error() || overflow.error().code() != EOVERFLOW || allocations != calls) return 3;
    auto grow = v.try_grow_capacity(std::numeric_limits<size_t>::max());
    if (!grow.is_error() || grow.error().code() != EOVERFLOW || allocations != calls) return 4;
    auto prepend = v.try_prepend(v.data(), std::numeric_limits<size_t>::max());
    if (!prepend.is_error() || prepend.error().code() != EOVERFLOW || allocations != calls) return 11;
    if (v.size() != 1 || v[0] != 3 || v.capacity() != initial) return 5;
    AK::Vector<char> chars;
    fail_next = true;
    auto padded = chars.try_grow_capacity(std::numeric_limits<size_t>::max() - 1);
    if (!padded.is_error() || padded.error().code() != ENOMEM || fail_next || !chars.is_empty()) return 12;
    AK::Vector<int> source;
    if (source.try_append(9).is_error()) return 6;
    while (v.size() < v.capacity()) if (v.try_append(4).is_error()) return 7;
    auto size = v.size(); fail_next = true;
    auto failed = v.try_extend(AK::move(source));
    if (!failed.is_error() || failed.error().code() != ENOMEM || fail_next) return 8;
    if (source.size() != 1 || source[0] != 9 || v.size() != size || v[0] != 3) return 9;
    if (v.try_extend(AK::move(source)).is_error() || v.size() != size + 1 || v[size] != 9) return 10;
    std::puts("patched AK vector overflow and move failure recovery passed");
}
