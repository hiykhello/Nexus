#include <AK/Vector.h>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <limits>
extern "C" [[noreturn]] void ak_verification_failed(char const*) { std::_Exit(90); }
static bool fail_allocation = false;
static size_t failed_size = 0;
extern "C" void* __real_malloc(size_t);
extern "C" void* __wrap_malloc(size_t size) {
    if (fail_allocation) { fail_allocation = false; failed_size = size; return nullptr; }
    return __real_malloc(size);
}
int main() {
    AK::Vector<int> empty;
    fail_allocation = true;
    auto first = empty.try_append(12);
    if (!first.is_error() || first.error().code() != ENOMEM || fail_allocation || !empty.is_empty()) return 7;
    if (empty.try_append(12).is_error() || empty[0] != 12) return 8;
    AK::Vector<int> values;
    for (int i = 0; i < 4; ++i) if (values.try_append(i).is_error()) return 1;
    auto old_size = values.size(); auto old_capacity = values.capacity();
    fail_allocation = true;
    auto failure = values.try_ensure_capacity(old_capacity + 1);
    if (!failure.is_error() || failure.error().code() != ENOMEM || fail_allocation) return 2;
    if (values.size() != old_size || values.capacity() != old_capacity) return 3;
    for (int i = 0; i < 4; ++i) if (values[i] != i) return 4;
    if (values.try_ensure_capacity(old_capacity + 1).is_error()) return 5;
    if (values.try_append(4).is_error() || values[4] != 4) return 6;
    while (values.size() < values.capacity())
        if (values.try_append(42).is_error()) return 9;
    old_size = values.size(); old_capacity = values.capacity();
    fail_allocation = true;
    auto append_failure = values.try_append(99);
    if (!append_failure.is_error() || append_failure.error().code() != ENOMEM || fail_allocation) return 10;
    if (values.size() != old_size || values.capacity() != old_capacity || values[0] != 0 || values[4] != 4) return 11;
    if (values.try_append(99).is_error() || values.size() != old_size + 1 || values[old_size] != 99) return 12;
    // Avoid writing to an undersized allocation: force this allocation to fail.
    AK::Vector<int> overflow;
    fail_allocation = true; failed_size = 1;
    auto huge = std::numeric_limits<size_t>::max() / sizeof(int) + 1;
    auto result = overflow.try_ensure_capacity(huge);
#ifdef NEXUS_AK_PATCHED
    if (!result.is_error() || result.error().code() != EOVERFLOW || !fail_allocation) return 13;
    fail_allocation = false;
    std::puts("AK allocation and checked capacity recovery passed");
#else
    if (!result.is_error() || fail_allocation || failed_size != 0) return 13;
    std::puts("AK allocation recovery passed; capacity multiplication wrapped to zero");
#endif
}
