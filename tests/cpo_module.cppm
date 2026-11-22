module;
#include <boost/corosio/tcp_socket.hpp>
#include <boost/corosio/io_context.hpp>
#include <boost/capy/buffers.hpp>
#include <boost/capy/buffers/buffer_copy.hpp>
#include <boost/capy/buffers/buffers_front.hpp>
export module probe;
export namespace probe {
    using ::boost::corosio::tcp_socket;
    using ::boost::corosio::io_context;
    using ::boost::capy::const_buffer;
    using ::boost::capy::mutable_buffer;
    using ::boost::capy::buffer_sequence_begin;
    using ::boost::capy::buffer_sequence_end;
    using ::boost::capy::buffer_size;
    using ::boost::capy::buffers_empty;
    using ::boost::capy::buffer_copy;
    using ::boost::capy::buffers_front;
}
