#include <boost/capy/ex/async_waker.hpp>
#include <boost/capy/ex/run_async.hpp>
#include <boost/capy/quitter.hpp>
#include <boost/corosio/backend.hpp>
#include <boost/corosio/io_context.hpp>

import std;

namespace capy = boost::capy;
namespace io = boost::corosio;
using namespace std::chrono_literals;

struct State {
    bool entered = false;
    bool destroyed = false;
};

struct Guard {
    bool& destroyed;
    ~Guard() { destroyed = true; }
};

auto parked(capy::async_waker& waker, State& state) -> capy::quitter<> {
    Guard guard{state.destroyed};
    state.entered = true;
    auto [error] = co_await waker.wait();
    if (!error) state.entered = false;
}

auto test(bool use_uring) -> bool {
#if BOOST_COROSIO_HAVE_LIBURING
    io::io_context context = use_uring ? io::io_context(io::uring) : io::io_context(io::epoll);
#else
    (void)use_uring;
    io::io_context context(io::epoll);
#endif
    capy::async_waker waker;
    State state;
    std::stop_source stop;
    capy::run_async(context.get_executor(), stop.get_token())(parked(waker, state));
    context.restart();
    (void)context.run_for(20ms);
    if (!state.entered || state.destroyed || context.stopped()) return false;
    stop.request_stop();
    context.restart();
    (void)context.run_for(1s);
    return state.destroyed && context.stopped();
}

auto main() -> int {
    if (!test(false)) return 1;
#if BOOST_COROSIO_HAVE_LIBURING
    if (!test(true)) return 2;
#endif
    std::println("Capy quitter owner unwind passed");
}
