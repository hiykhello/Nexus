#include <proxy/proxy_macros.h>

import std;
import proxy.v4;

PRO_DEF_MEM_DISPATCH(ReadValue, value);

struct ValueFacade : pro::facade_builder
    ::add_convention<ReadValue, int() const>
    ::build {};

struct Value {
    int stored;
    auto value() const -> int { return stored; }
};

auto main() -> int {
    auto proxy = pro::make_proxy<ValueFacade, Value>(42);
    if (!proxy || proxy->value() != 42) return 1;
    proxy = pro::make_proxy<ValueFacade, Value>(73);
    return proxy->value() == 73 ? 0 : 1;
}
