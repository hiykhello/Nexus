#include <boost/capy/buffers.hpp>
#include <boost/capy/buffers/buffer_copy.hpp>
#include <boost/capy/buffers/buffers_front.hpp>

extern "C" auto cpo_header_address(unsigned i) -> void const* {
    switch (i) {
    case 0: return &boost::capy::buffer_sequence_begin;
    case 1: return &boost::capy::buffer_sequence_end;
    case 2: return &boost::capy::buffer_size;
    case 3: return &boost::capy::buffers_empty;
    case 4: return &boost::capy::buffer_copy;
    case 5: return &boost::capy::buffers_front;
    default: return nullptr;
    }
}
