#include <boost/capy/cond.hpp>
#include <boost/capy/ex/run_async.hpp>
#include <boost/capy/task.hpp>

import std;
import nexus.thirdparty.corosio;

namespace capy = boost::capy;
namespace io = nex::corosio;
using namespace std::chrono_literals;

static auto make_context(bool use_uring) -> io::io_context {
#if BOOST_COROSIO_HAVE_LIBURING
    return use_uring ? io::io_context(io::uring) : io::io_context();
#else
    (void)use_uring;
    return io::io_context();
#endif
}

struct Fixture {
    io::io_context context;
    io::tcp_acceptor rejected{context};
    io::tcp_acceptor listener{context};
    io::tcp_socket client{context};
    io::tcp_socket peer{context};

    explicit Fixture(bool use_uring) : context(make_context(use_uring)) {}

    ~Fixture() {
        client.close();
        peer.close();
        listener.close();
        rejected.close();
        context.restart();
        (void)context.run_for(1s);
    }
};

static auto accept_one(io::tcp_acceptor& listener, io::tcp_socket& peer,
                       std::error_code& error) -> capy::task<> {
    auto [accept_error, accepted] = co_await listener.accept();
    error = accept_error;
    if (!error) peer = std::move(accepted);
}

static auto try_candidates(io::tcp_socket& socket, std::vector<io::endpoint> endpoints,
                          std::error_code& error, io::endpoint& connected)
    -> capy::task<> {
    auto [connect_error, result] = co_await io::connect_candidates(socket, std::move(endpoints));
    error = connect_error;
    connected = result;
}

static auto run(io::io_context& context) -> void {
    context.restart();
    (void)context.run_for(1s);
}

static auto retry_test(bool use_uring) -> bool {
    Fixture f(use_uring);
    if (f.rejected.open() || f.rejected.bind(io::endpoint(io::ipv4_address::loopback(), 0))) return false;
    if (f.listener.open() || f.listener.bind(io::endpoint(io::ipv4_address::loopback(), 0)) ||
        f.listener.listen() || f.client.open()) return false;

    std::error_code accept_error, connect_error;
    io::endpoint connected;
    capy::run_async(f.context.get_executor())(accept_one(f.listener, f.peer, accept_error));
    std::vector<io::endpoint> candidates{
        f.rejected.local_endpoint(),
        f.listener.local_endpoint()};
    capy::run_async(f.context.get_executor())(
        try_candidates(f.client, std::move(candidates), connect_error, connected));
    run(f.context);
    if (connect_error || accept_error || !(connected == f.listener.local_endpoint()) || !f.peer.is_open()) {
        std::cerr << "retry failed: connect=" << connect_error.message()
                  << " accept=" << accept_error.message() << " peer=" << f.peer.is_open() << '\n';
        return false;
    }
    return true;
}

static auto canceled_test(bool use_uring) -> bool {
    Fixture f(use_uring);
    if (f.listener.open() || f.listener.bind(io::endpoint(io::ipv4_address::loopback(), 0)) ||
        f.listener.listen() || f.client.open()) return false;

    std::error_code connect_error;
    io::endpoint connected;
    std::stop_source stopped;
    stopped.request_stop();
    capy::run_async(f.context.get_executor(), stopped.get_token())(
        try_candidates(f.client, {f.listener.local_endpoint()}, connect_error, connected));
    run(f.context);
    if (!(connect_error == capy::cond::canceled) || f.client.is_open()) {
        std::cerr << "cancel failed: connect=" << connect_error.message()
                  << " open=" << f.client.is_open() << '\n';
        return false;
    }
    return true;
}

static auto failure_cleanup_test(bool use_uring) -> bool {
    Fixture f(use_uring);
    if (f.rejected.open() || f.rejected.bind(io::endpoint(io::ipv4_address::loopback(), 0)) ||
        f.client.open()) return false;

    std::error_code connect_error;
    io::endpoint connected;
    capy::run_async(f.context.get_executor())(
        try_candidates(f.client, {f.rejected.local_endpoint()}, connect_error, connected));
    run(f.context);
    if (!connect_error || f.client.is_open()) {
        std::cerr << "failure cleanup failed: connect=" << connect_error.message()
                  << " open=" << f.client.is_open() << '\n';
        return false;
    }
    return true;
}

static auto deadline_test(bool use_uring) -> bool {
    Fixture f(use_uring);
    if (f.listener.open() || f.listener.bind(io::endpoint(io::ipv4_address::loopback(), 0)) ||
        f.listener.listen() || f.client.open()) return false;
    std::error_code connect_error;
    io::endpoint connected;
    // A timed candidate connect must cancel the pending operation and close
    // its socket when the absolute deadline has already expired.
    f.context.restart();
    capy::run_async(f.context.get_executor())([&]() -> capy::task<> {
        auto operation = io::connect(f.client, std::vector<io::endpoint>{f.listener.local_endpoint()},
            [](std::error_code const&, io::endpoint const&) { return true; });
        auto [error, result] = co_await io::timeout(std::move(operation),
            std::chrono::steady_clock::now() - 1ms);
        connect_error = error;
        connected = result;
        if (error) f.client.close();
        co_return;
    }());
    run(f.context);
    if (connect_error != capy::make_error_condition(capy::cond::timeout) || f.client.is_open()) return false;
    return true;
}

int main() {
    if (!retry_test(false) || !canceled_test(false) || !failure_cleanup_test(false) || !deadline_test(false)) return 1;
    std::cout << "epoll: Corosio candidate retry, failure cleanup, cancellation and timeout passed\n";
#if BOOST_COROSIO_HAVE_LIBURING
    if (!retry_test(true) || !canceled_test(true) || !failure_cleanup_test(true) || !deadline_test(true)) return 1;
    std::cout << "io_uring: Corosio candidate retry, failure cleanup, cancellation and timeout passed\n";
#endif
}
