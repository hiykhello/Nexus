module;
#include <boost/capy/results.hpp>
#include <boost/capy/task.hpp>
#include <boost/corosio/backend.hpp>
#include <boost/corosio/connect.hpp>
#include <boost/corosio/io_context.hpp>
#include <boost/corosio/local_stream_socket.hpp>
#include <boost/corosio/local_connect_pair.hpp>
#include <boost/corosio/tcp_socket.hpp>
#include <boost/corosio/tcp_acceptor.hpp>
#include <boost/corosio/socket_option.hpp>
#include <boost/corosio/udp_socket.hpp>
#include <boost/corosio/posix_stream_descriptor.hpp>
#include <boost/corosio/resolver.hpp>
#include <boost/corosio/endpoint.hpp>
#include <boost/corosio/local_endpoint.hpp>
#include <boost/corosio/ipv4_address.hpp>
#include <boost/corosio/ipv6_address.hpp>
#include <boost/corosio/delay.hpp>
#include <boost/corosio/shutdown_type.hpp>
#include <boost/corosio/timeout.hpp>

#include <tuple>
#include <vector>

export module corosio;
export namespace corosio {
    using ::boost::corosio::io_context;
    using ::boost::corosio::io_context_options;
    using ::boost::corosio::local_stream_socket;
    using ::boost::corosio::connect_pair;
    using ::boost::corosio::connect;
    using ::boost::corosio::tcp_socket;
    using ::boost::corosio::tcp_acceptor;
    using ::boost::corosio::family;
    using ::boost::corosio::udp_socket;
#if BOOST_COROSIO_POSIX || defined(BOOST_COROSIO_MRDOCS)
    using ::boost::corosio::posix_stream_descriptor;
#endif
    using ::boost::corosio::resolver;
    using ::boost::corosio::endpoint;
    using ::boost::corosio::endpoint_format;
    using ::boost::corosio::detect_endpoint_format;
    using ::boost::corosio::make_endpoint;
    using ::boost::corosio::local_endpoint;
    using ::boost::corosio::make_local_endpoint;
    using connect_result = ::boost::capy::results<endpoint>;
    using connect_task = ::boost::capy::task<connect_result>;
    // Instantiate the upstream range-connect template inside this module,
    // where Capy's condition specialization is visible to the compiler.
    auto connect_candidates(tcp_socket&, std::vector<endpoint>)
        -> connect_task;
    using ::boost::corosio::ipv4_address;
    using ::boost::corosio::ipv6_address;
    using ::boost::corosio::delay;
    using steady_timer = ::boost::corosio::detail::timer;
    using ::boost::corosio::shutdown_send;
    using ::boost::corosio::wait_type;
    using ::boost::corosio::timeout;
#if BOOST_COROSIO_HAS_EPOLL
    using ::boost::corosio::epoll;
#endif
#if BOOST_COROSIO_HAS_KQUEUE
    using ::boost::corosio::kqueue;
#endif
#if BOOST_COROSIO_HAS_IOCP
    using ::boost::corosio::iocp;
#endif
    namespace socket_option {
        using ::boost::corosio::socket_option::keep_alive;
        using ::boost::corosio::socket_option::send_buffer_size;
        using ::boost::corosio::socket_option::receive_buffer_size;
        using ::boost::corosio::socket_option::reuse_port;
        using ::boost::corosio::socket_option::v6_only;
    }
#if BOOST_COROSIO_HAVE_LIBURING
    using ::boost::corosio::uring;
    inline constexpr bool has_uring=true;
#else
    inline constexpr bool has_uring=false;
#endif
    inline auto make_io_context(bool use_uring) -> io_context {
#if BOOST_COROSIO_HAVE_LIBURING
        return use_uring ? io_context(uring) : io_context(epoll);
#elif BOOST_COROSIO_HAS_EPOLL
        (void)use_uring;
        return io_context(epoll);
#elif BOOST_COROSIO_HAS_KQUEUE
        (void)use_uring;
        return io_context(kqueue);
#elif BOOST_COROSIO_HAS_IOCP
        (void)use_uring;
        return io_context(iocp);
#else
        (void)use_uring;
        return io_context();
#endif
    }
}
