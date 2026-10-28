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

export module nexus.thirdparty.corosio;
export namespace nex::corosio {
    using ::boost::corosio::io_context;
    using ::boost::corosio::local_stream_socket;
    using ::boost::corosio::connect_pair;
    using ::boost::corosio::tcp_socket;
    using ::boost::corosio::tcp_acceptor;
    using ::boost::corosio::resolver;
    using ::boost::corosio::endpoint;
    using ::boost::corosio::endpoint_format;
    using ::boost::corosio::detect_endpoint_format;
    using ::boost::corosio::make_endpoint;
    using ::boost::corosio::local_endpoint;
    using ::boost::corosio::make_local_endpoint;
    using connect_result = ::boost::capy::results<endpoint>;
    // Instantiate the upstream range-connect template inside this module,
    // where Capy's condition specialization is visible to the compiler.
    auto connect_candidates(tcp_socket&, std::vector<endpoint>)
        -> ::boost::capy::task<connect_result>;
    using ::boost::corosio::ipv4_address;
    using ::boost::corosio::ipv6_address;
    using ::boost::corosio::delay;
    using ::boost::corosio::shutdown_send;
    using ::boost::corosio::timeout;
    using ::boost::corosio::epoll;
#if BOOST_COROSIO_HAVE_LIBURING
    using ::boost::corosio::uring;
#endif
}

namespace nex::corosio {
    auto connect_candidates(tcp_socket& socket, std::vector<endpoint> endpoints)
        -> ::boost::capy::task<connect_result> {
        auto result = co_await ::boost::corosio::connect(socket, std::move(endpoints));
        // Keep the ownership contract stable for callers: a failed or
        // canceled candidate sequence never leaves its last socket open.
        if (std::get<0>(result)) socket.close();
        co_return result;
    }
}
