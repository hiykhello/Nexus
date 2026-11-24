#include <boost/capy/cond.hpp>
#include <boost/capy/ex/run_async.hpp>
#include <boost/capy/task.hpp>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

import std;
import corosio;

namespace capy = boost::capy;
namespace io = ::corosio;
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

static auto timed_candidates(io::tcp_socket& socket, std::vector<io::endpoint> endpoints,
                             std::chrono::steady_clock::time_point deadline, std::error_code& error,
                             unsigned& attempts, bool& done) -> capy::task<> {
    auto operation = io::connect(socket, std::move(endpoints),
        [&](std::error_code const&, io::endpoint const&) { ++attempts; return true; });
    auto [result, endpoint] = co_await io::timeout(std::move(operation), deadline);
    (void)endpoint;
    error = result;
    if (error) socket.close();
    done=true;
}

static auto deadline_test(bool use_uring) -> bool {
    Fixture f(use_uring);
    if (f.listener.open() || f.listener.bind(io::endpoint(io::ipv4_address::loopback(), 0)) ||
        f.listener.listen() || f.client.open()) return false;
    std::error_code connect_error;
    unsigned attempts=0; bool done=false;
    // A timed candidate connect must cancel the pending operation and close
    // its socket when the absolute deadline has already expired.
    f.context.restart();
    capy::run_async(f.context.get_executor())(timed_candidates(f.client, {f.listener.local_endpoint()},
        std::chrono::steady_clock::now() - 1ms, connect_error, attempts, done));
    run(f.context);
    if (!done || connect_error != capy::make_error_condition(capy::cond::timeout) || f.client.is_open()) return false;
    return true;
}

static auto pending_timeout_test(bool use_uring) -> bool {
    Fixture f(use_uring);
    if (f.rejected.open() ||
        f.rejected.bind(io::endpoint(io::ipv4_address::loopback(), 0)) || f.rejected.listen()) return false;
    // A native listener keeps the backlog full: the Corosio io_uring
    // acceptor pre-arms multishot accept and may drain its kernel queue.
    struct Fds { int listener=-1, a=-1, b=-1; ~Fds() { if (listener>=0) ::close(listener); if (a>=0) ::close(a); if (b>=0) ::close(b); } } fds;
    sockaddr_in address{}; address.sin_family=AF_INET; address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    fds.listener=::socket(AF_INET, SOCK_STREAM, 0);
    socklen_t length=sizeof(address);
    if (fds.listener<0 || ::bind(fds.listener,reinterpret_cast<sockaddr*>(&address),sizeof(address)) ||
        ::listen(fds.listener,1) || ::getsockname(fds.listener,reinterpret_cast<sockaddr*>(&address),&length)) return false;
    fds.a=::socket(AF_INET, SOCK_STREAM, 0); fds.b=::socket(AF_INET, SOCK_STREAM, 0);
    if (fds.a<0 || fds.b<0 || ::connect(fds.a,reinterpret_cast<sockaddr*>(&address),sizeof(address)) ||
        ::connect(fds.b,reinterpret_cast<sockaddr*>(&address),sizeof(address))) return false;
    std::error_code error; unsigned attempts=0; bool done=false;
    auto start=std::chrono::steady_clock::now();
    capy::run_async(f.context.get_executor())(timed_candidates(f.client,
        {io::endpoint(io::ipv4_address::loopback(),ntohs(address.sin_port)),f.rejected.local_endpoint()}, start+100ms, error, attempts, done));
    auto until=std::chrono::steady_clock::now()+2s;
    while (!done && std::chrono::steady_clock::now()<until) run(f.context);
    if (!done || error != capy::make_error_condition(capy::cond::timeout) || attempts!=1 || f.client.is_open()) {
        std::cerr << "pending timeout: " << error.message() << " attempts=" << attempts << " done=" << done
                  << " elapsed=" << std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now()-start).count() << "ms\n";
        f.client.close();
        ::close(std::exchange(fds.a,-1)); ::close(std::exchange(fds.b,-1));
        f.listener.close(); f.rejected.close();
        auto drain_until=std::chrono::steady_clock::now()+2s;
        while (!done && std::chrono::steady_clock::now()<drain_until) run(f.context);
        if (!done) std::abort(); // Do not destroy state still borrowed by the coroutine.
        return false;
    }
    return true;
}

int main() {
    if (!retry_test(false) || !canceled_test(false) || !failure_cleanup_test(false) || !deadline_test(false) || !pending_timeout_test(false)) return 1;
    std::cout << "epoll: Corosio candidate retry, failure cleanup, cancellation and timeout passed\n";
#if BOOST_COROSIO_HAVE_LIBURING
    if (!retry_test(true) || !canceled_test(true) || !failure_cleanup_test(true) || !deadline_test(true) || !pending_timeout_test(true)) return 1;
    std::cout << "io_uring: Corosio candidate retry, failure cleanup, cancellation and timeout passed\n";
#endif
}
