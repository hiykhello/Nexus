#include <boost/capy/buffers.hpp>
#include <boost/capy/buffers/buffer_copy.hpp>
#include <boost/capy/buffers/front.hpp>

extern "C" auto cpo_header_address(unsigned i) -> void const* {
    switch (i) {
    case 0: return &boost::capy::begin;
    case 1: return &boost::capy::end;
    case 2: return &boost::capy::buffer_size;
    case 3: return &boost::capy::buffer_empty;
    case 4: return &boost::capy::buffer_copy;
    case 5: return &boost::capy::front;
    default: return nullptr;
    }
}
