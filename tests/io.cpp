#include <boost/capy/buffers.hpp>
#include <boost/capy/task.hpp>
#include <boost/capy/error.hpp>
#include <boost/capy/cond.hpp>
#include <boost/capy/ex/run_async.hpp>
#include <boost/corosio/io_context.hpp>
#include <boost/corosio/backend.hpp>
#include <boost/corosio/local_stream_socket.hpp>
#include <boost/corosio/local_connect_pair.hpp>
#include <boost/corosio/tcp_socket.hpp>
#include <boost/corosio/tcp_acceptor.hpp>
#include <boost/corosio/endpoint.hpp>
#include <boost/corosio/ipv4_address.hpp>

import std;

namespace capy = boost::capy;
namespace corosio = boost::corosio;
using namespace std::chrono_literals;

static auto make_context(bool use_uring) -> corosio::io_context {
#if BOOST_COROSIO_HAVE_LIBURING
    return use_uring ? corosio::io_context(corosio::uring) : corosio::io_context();
#else
    (void)use_uring;
    return corosio::io_context();
#endif
}

struct Result {
    std::error_code error;
    std::size_t bytes = 0;
    bool started = false;
    bool done = false;
};

static auto check(bool ok, char const* message) -> bool {
    if (!ok) std::cerr << message << '\n';
    return ok;
}

// All operations are bounded. Even on failure, keep their objects alive until
// cancellation has drained the context. An undrainable failure terminates.
static auto drain(corosio::io_context& ctx) -> void {
    ctx.restart();
    (void)ctx.run_for(1s);
    if (!ctx.stopped()) {
        std::cerr << "pending operations did not drain\n";
        std::_Exit(1);
    }
}

struct LocalFixture {
    char buffer[4]{};
    Result sent, received, primed, precanceled, after_precancel;
    Result canceled, token_canceled, stopped, eof;
    corosio::io_context ctx;
    corosio::local_stream_socket a{ctx}, b{ctx};
    explicit LocalFixture(bool use_uring) : ctx(make_context(use_uring)) {}
    ~LocalFixture() {
        a.close();
        b.close();
        drain(ctx);
    }
};

struct TcpFixture {
    char buffer[4]{};
    Result connected, accepted, sent, received;
    corosio::io_context ctx;
    corosio::tcp_acceptor listener{ctx};
    corosio::tcp_socket client{ctx}, peer{ctx};
    explicit TcpFixture(bool use_uring) : ctx(make_context(use_uring)) {}
    ~TcpFixture() {
        client.close();
        peer.close();
        listener.close();
        drain(ctx);
    }
};

template <typename Socket>
static auto send_all(Socket& socket, Result& result) -> capy::task<> {
    result.started = true;
    while (result.bytes < 4) {
        auto [error, count] = co_await socket.write_some(
            capy::const_buffer(&"ping"[result.bytes], 4 - result.bytes));
        result.error = error;
        result.bytes += count;
        if (error || count == 0) break;
    }
    result.done = true;
}

template <typename Socket>
static auto receive_all(Socket& socket, char* buffer, Result& result) -> capy::task<> {
    result.started = true;
    while (result.bytes < 4) {
        auto [error, count] = co_await socket.read_some(
            capy::mutable_buffer(buffer + result.bytes, 4 - result.bytes));
        result.error = error;
        result.bytes += count;
        if (error || count == 0) break;
    }
    result.done = true;
}

static auto connect(corosio::tcp_socket& socket, corosio::endpoint endpoint, Result& result) -> capy::task<> {
    result.started = true;
    auto [error] = co_await socket.connect(endpoint);
    result.error = error;
    result.done = true;
}

static auto accept(corosio::tcp_acceptor& listener, corosio::tcp_socket& peer, Result& result) -> capy::task<> {
    result.started = true;
    auto [error, accepted] = co_await listener.accept();
    if (!error) peer = std::move(accepted);
    result.error = error;
    result.done = true;
}

static auto run(corosio::io_context& ctx, std::chrono::milliseconds bound = 1s) -> void {
    ctx.restart();
    (void)ctx.run_for(bound);
}

static auto parked(corosio::io_context& ctx, Result const& result) -> bool {
    run(ctx, 20ms);
    return result.started && !result.done && !ctx.stopped();
}

static auto local_test(bool use_uring) -> bool {
    LocalFixture f(use_uring);
    if (!check(!corosio::connect_pair(f.a, f.b), "local socket pair failed")) return false;
    auto ex = f.ctx.get_executor();
    capy::run_async(ex)(send_all(f.a, f.sent));
    capy::run_async(ex)(receive_all(f.b, f.buffer, f.received));
    run(f.ctx);
    if (!check(f.sent.done && f.received.done && !f.sent.error && !f.received.error &&
               f.sent.bytes == 4 && f.received.bytes == 4 && !std::memcmp(f.buffer, "ping", 4),
               "local send/receive failed")) return false;

    capy::run_async(ex)(send_all(f.a, f.primed));
    run(f.ctx);
    if (!check(f.primed.done && !f.primed.error && f.primed.bytes == 4, "priming write failed")) return false;
    std::stop_source pre_stopped;
    pre_stopped.request_stop();
    capy::run_async(ex, pre_stopped.get_token())(receive_all(f.b, f.buffer, f.precanceled));
    run(f.ctx);
    if (!check(f.precanceled.done && f.precanceled.error == capy::cond::canceled &&
               f.precanceled.bytes == 0, "pre-canceled read failed")) return false;
    std::memset(f.buffer, 0, 4);
    capy::run_async(ex)(receive_all(f.b, f.buffer, f.after_precancel));
    run(f.ctx);
    if (!check(f.after_precancel.done && !f.after_precancel.error && f.after_precancel.bytes == 4 &&
               !std::memcmp(f.buffer, "ping", 4), "pre-canceled read consumed data")) return false;

    capy::run_async(ex)(receive_all(f.b, f.buffer, f.canceled));
    if (!check(parked(f.ctx, f.canceled), "read did not park before socket cancel")) return false;
    f.b.cancel();
    run(f.ctx);
    if (!check(f.canceled.done && f.canceled.error == capy::cond::canceled && f.canceled.bytes == 0,
               "socket cancellation failed")) return false;

    std::stop_source source;
    capy::run_async(ex, source.get_token())(receive_all(f.b, f.buffer, f.token_canceled));
    if (!check(parked(f.ctx, f.token_canceled), "read did not park before stop request")) return false;
    source.request_stop();
    run(f.ctx);
    if (!check(f.token_canceled.done && f.token_canceled.error == capy::cond::canceled &&
               f.token_canceled.bytes == 0, "stop-token cancellation failed")) return false;

    capy::run_async(ex)(receive_all(f.b, f.buffer, f.stopped));
    if (!check(parked(f.ctx, f.stopped), "read did not park before context stop")) return false;
    f.ctx.stop();
    (void)f.ctx.run_for(20ms);
    if (!check(f.ctx.stopped() && !f.stopped.done, "stop unexpectedly completed pending I/O")) return false;
    f.b.cancel();
    run(f.ctx);
    if (!check(f.stopped.done && f.stopped.error == capy::cond::canceled,
               "restart did not drain canceled I/O")) return false;

    capy::run_async(ex)(receive_all(f.b, f.buffer, f.eof));
    if (!check(parked(f.ctx, f.eof), "read did not park before peer close")) return false;
    f.a.close();
    run(f.ctx);
    return check(f.eof.done && f.eof.error == capy::cond::eof && f.eof.bytes == 0,
                 "peer close did not report EOF");
}

// Distinct owners may each have a pending operation. stop() only pauses the
// executor: close the owners and restart before their coroutine frames die.
static auto multi_owner_stop_test(bool use_uring) -> bool {
    LocalFixture f(use_uring);
    corosio::tcp_acceptor first{f.ctx}, second{f.ctx};
    corosio::tcp_socket peer1{f.ctx}, peer2{f.ctx};
    Result accept1, accept2, read;
    auto cleanup = [&] {
        first.close(); second.close(); f.b.close();
        drain(f.ctx);
        f.a.close();
    };
    if (first.open() || first.bind(corosio::endpoint(corosio::ipv4_address::loopback(), 0)) || first.listen() ||
        second.open() || second.bind(corosio::endpoint(corosio::ipv4_address::loopback(), 0)) || second.listen() ||
        corosio::connect_pair(f.a, f.b)) {
        cleanup();
        return check(false, "multi-owner setup failed");
    }
    auto ex = f.ctx.get_executor();
    capy::run_async(ex)(accept(first, peer1, accept1));
    capy::run_async(ex)(accept(second, peer2, accept2));
    capy::run_async(ex)(receive_all(f.b, f.buffer, read));
    run(f.ctx, 20ms);
    bool ok = check(accept1.started && accept2.started && read.started &&
                    !accept1.done && !accept2.done && !read.done && !f.ctx.stopped(),
                    "multi-owner operations did not park");
    f.ctx.stop();
    (void)f.ctx.run_for(20ms);
    ok = check(f.ctx.stopped() && !accept1.done && !accept2.done && !read.done,
               "context stop completed pending multi-owner operations") && ok;
    cleanup();
    if (!(accept1.done && accept2.done && read.done &&
          accept1.error == capy::cond::canceled && accept2.error == capy::cond::canceled &&
          read.error == capy::cond::canceled && read.bytes == 0)) {
        std::cerr << "multi-owner drain: accept=" << accept1.done << ":" << accept1.error.message()
                  << ", " << accept2.done << ":" << accept2.error.message()
                  << "; read=" << read.done << ":" << read.error.message() << ":" << read.bytes << '\n';
        return false;
    }
    return ok;
}

static auto tcp_test(bool use_uring) -> bool {
    TcpFixture f(use_uring);
    if (!check(!f.listener.open(), "TCP listener open failed") ||
        !check(!f.listener.bind(corosio::endpoint(corosio::ipv4_address::loopback(), 0)), "TCP bind failed") ||
        !check(!f.listener.listen(), "TCP listen failed") ||
        !check(!f.client.open(), "TCP client open failed")) return false;
    auto ex = f.ctx.get_executor();
    capy::run_async(ex)(accept(f.listener, f.peer, f.accepted));
    capy::run_async(ex)(connect(f.client, f.listener.local_endpoint(), f.connected));
    run(f.ctx);
    if (!check(f.connected.done && f.accepted.done && !f.connected.error && !f.accepted.error,
               "TCP connect/accept failed")) return false;
    capy::run_async(ex)(send_all(f.client, f.sent));
    capy::run_async(ex)(receive_all(f.peer, f.buffer, f.received));
    run(f.ctx);
    return check(f.sent.done && f.received.done && !f.sent.error && !f.received.error &&
                 f.sent.bytes == 4 && f.received.bytes == 4 && !std::memcmp(f.buffer, "ping", 4),
                 "TCP send/receive failed");
}

static auto tcp_failure_test(bool use_uring) -> bool {
    TcpFixture f(use_uring);
    if (!check(!f.listener.open(), "TCP failure listener open failed") ||
        !check(!f.listener.bind(corosio::endpoint(corosio::ipv4_address::loopback(), 0)), "TCP failure bind failed") ||
        !check(!f.client.open(), "TCP failure client open failed")) return false;
    // Keep the port bound without listening, so no other server can accept it.
    capy::run_async(f.ctx.get_executor())(connect(f.client, f.listener.local_endpoint(), f.connected));
    run(f.ctx);
    return check(f.connected.done && static_cast<bool>(f.connected.error),
                 "connection to non-listening TCP port did not fail");
}

int main() {
#if defined(__cpp_exceptions)
    try {
#endif
        if (!local_test(false) || !multi_owner_stop_test(false) || !tcp_test(false) || !tcp_failure_test(false)) return 1;
        std::cout << "epoll: local and TCP I/O, cancellation, stop and close passed\n";
#if BOOST_COROSIO_HAVE_LIBURING
        if (!local_test(true) || !multi_owner_stop_test(true) || !tcp_test(true) || !tcp_failure_test(true)) return 1;
        std::cout << "io_uring: local and TCP I/O, cancellation, stop and close passed\n";
#endif
#if defined(__cpp_exceptions)
    } catch (std::exception const& error) {
        std::cerr << "I/O test failed: " << error.what() << '\n';
        return 1;
    }
#endif
}
