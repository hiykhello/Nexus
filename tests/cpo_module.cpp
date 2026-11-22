#include <boost/capy/buffers.hpp>
#include <boost/capy/buffers/buffer_copy.hpp>
#include <boost/capy/buffers/buffers_front.hpp>
#include <type_traits>

import probe;
extern "C" auto cpo_header_address(unsigned) -> void const*;

static_assert(std::is_same_v<decltype(probe::buffer_sequence_begin), decltype(boost::capy::buffer_sequence_begin)>);
static_assert(std::is_same_v<decltype(probe::buffer_sequence_end), decltype(boost::capy::buffer_sequence_end)>);
static_assert(std::is_same_v<decltype(probe::buffer_size), decltype(boost::capy::buffer_size)>);
static_assert(std::is_same_v<decltype(probe::buffers_empty), decltype(boost::capy::buffers_empty)>);
static_assert(std::is_same_v<decltype(probe::buffer_copy), decltype(boost::capy::buffer_copy)>);
static_assert(std::is_same_v<decltype(probe::buffers_front), decltype(boost::capy::buffers_front)>);

int main() {
    void const* addresses[]{&probe::buffer_sequence_begin, &probe::buffer_sequence_end, &probe::buffer_size,
                            &probe::buffers_empty, &probe::buffer_copy, &probe::buffers_front};
    for (unsigned i = 0; i < 6; ++i) if (addresses[i] != cpo_header_address(i)) return 1;
    probe::io_context ctx;
    probe::tcp_socket socket(ctx);
    char source[] = "hello", destination[5]{};
    probe::const_buffer src(source, 5);
    probe::mutable_buffer dst(destination, 5);
    if (probe::buffer_size(src) != 5 || probe::buffers_empty(src) ||
        probe::buffer_sequence_end(src) - probe::buffer_sequence_begin(src) != 1 || probe::buffers_front(src).size() != 5 ||
        probe::buffer_copy(dst, src) != 5 || destination[4] != 'o') return 1;
    socket.close();
}
