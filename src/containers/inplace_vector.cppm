module;
#include <beman/inplace_vector/inplace_vector.hpp>

export module containers.inplace_vector;

export namespace containers {
    using ::beman::inplace_vector::inplace_vector;
    using ::beman::inplace_vector::erase;
    using ::beman::inplace_vector::erase_if;
    using ::beman::inplace_vector::has_constexpr_support;
}
