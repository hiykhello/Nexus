module;
#include <AK/Vector.h>
export module ak_probe;
import std;
export int append_result() {
    AK::Vector<int> values;
    auto result = values.try_append(42);
    if (result.is_error()) return result.error().code();
    return values.size() == 1 && values[0] == 42 ? 0 : -1;
}
