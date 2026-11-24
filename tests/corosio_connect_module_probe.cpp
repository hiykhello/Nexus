import std;
import capy;
import corosio;

static_assert(std::is_error_condition_enum_v<capy::cond>);
static_assert(std::is_convertible_v<capy::cond, std::error_condition>);
namespace io = ::corosio;
using namespace std::chrono_literals;

static auto make_context(bool use_uring) -> io::io_context {
    return io::make_io_context(use_uring);
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
    auto [connect_error, result] = co_await io::connect(socket, std::move(endpoints),
        [](std::error_code const&, io::endpoint const&) { return true; });
    error = connect_error;
    if (error) socket.close();
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

int main() {
    if (!retry_test(false) || !canceled_test(false) || !failure_cleanup_test(false)) return 1;
    std::cout << "epoll: Corosio exported connect retry, caller cleanup and cancellation passed\n";
    if (io::has_uring) {
        if (!retry_test(true) || !canceled_test(true) || !failure_cleanup_test(true)) return 1;
        std::cout << "io_uring: Corosio exported connect retry, caller cleanup and cancellation passed\n";
    }
}
