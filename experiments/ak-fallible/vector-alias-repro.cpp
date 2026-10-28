#include <AK/Vector.h>
#include <cstdlib>
extern "C" [[noreturn]] void ak_verification_failed(char const*) { std::_Exit(90); }
int main() {
    AK::Vector<int> v;
    if (v.try_append(123).is_error()) return 1;
    while (v.size() < v.capacity()) if (v.try_append(9).is_error()) return 2;
    if (v.try_append(v.data(), 1).is_error()) return 3;
    return v.last() == 123 ? 0 : 4;
}
