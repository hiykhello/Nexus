#include <cerrno>
#include <cstdio>
#include <cstdlib>
import ak_probe;
extern "C" [[noreturn]] void ak_verification_failed(char const*) { std::_Exit(90); }
static bool fail = false;
extern "C" void* __real_malloc(size_t);
extern "C" void* __wrap_malloc(size_t size) {
    if (fail) { fail = false; return nullptr; }
    return __real_malloc(size);
}
int main() {
    fail = true;
    if (append_result() != ENOMEM || fail) return 1;
    if (append_result() != 0) return 2;
    std::puts("module AK allocation error and retry passed");
}
