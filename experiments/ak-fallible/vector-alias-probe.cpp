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
int main() {
    AK::Vector<int> v;
    for (int i = 0; i < 3; ++i) if (v.try_append(i + 10).is_error()) return 1;
    while (v.size() < v.capacity()) if (v.try_append(99).is_error()) return 2;
    auto n = v.size(); auto old = v.capacity();
    fail_next = true;
    auto error = v.try_append(v.data() + 1, 2);
    if (!error.is_error() || error.error().code() != ENOMEM || fail_next) return 3;
    if (v.size() != n || v.capacity() != old || v[1] != 11 || v[2] != 12) return 4;
    if (v.try_append(v.data() + 1, 2).is_error() || v[n] != 11 || v[n+1] != 12) return 5;
    auto invalid = v.try_append(v.data() + v.size() - 1, 2);
    if (!invalid.is_error() || invalid.error().code() != EINVAL || v.size() != n + 2) return 6;
    while (v.size() < v.capacity()) if (v.try_append(88).is_error()) return 8;
    n = v.size();
    auto span = v.span().slice(1, 2);
    if (v.try_extend(span).is_error() || v[n] != 11 || v[n+1] != 12) return 7;
    std::puts("AK alias append and span, failure and retry passed");
}
