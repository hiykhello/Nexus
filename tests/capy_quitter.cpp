#include <boost/capy/ex/async_waker.hpp>
#include <boost/capy/ex/run_async.hpp>
#include <boost/capy/concept/context_runnable.hpp>
#include "../src/coro/quitter.hpp"
#include <boost/capy/when_all.hpp>
#include <boost/corosio/backend.hpp>
#include <boost/corosio/delay.hpp>
#include <boost/corosio/io_context.hpp>
#include <boost/corosio/local_connect_pair.hpp>
#include <boost/corosio/local_stream_socket.hpp>

import std;

namespace capy = boost::capy;
namespace io = boost::corosio;
using namespace std::chrono_literals;

auto stopped_handler(std::exception_ptr error) -> void {
    try {std::rethrow_exception(error);}
    catch(coro::stop_requested const&) {}
}

struct State {
    bool entered = false;
    bool destroyed = false;
};

struct Guard {
    bool& destroyed;
    ~Guard() { destroyed = true; }
};

auto parked(capy::async_waker& waker, State& state) -> coro::quitter<> {
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
    capy::run_async(context.get_executor(), stop.get_token(), [] {}, stopped_handler)(parked(waker, state));
    context.restart();
    (void)context.run_for(20ms);
    if (!state.entered || state.destroyed || context.stopped()) return false;
    stop.request_stop();
    context.restart();
    (void)context.run_for(1s);
    return state.destroyed && context.stopped();
}

auto socket_parked(io::local_stream_socket& socket, State& state) -> coro::quitter<> {
    Guard guard{state.destroyed};
    state.entered = true;
    std::array<char, 1> buffer{};
    auto [error, bytes] = co_await socket.read_some(capy::mutable_buffer(buffer.data(), buffer.size()));
    if (!error && bytes) state.entered = false;
}

auto socket_test(bool use_uring) -> bool {
#if BOOST_COROSIO_HAVE_LIBURING
    io::io_context context = use_uring ? io::io_context(io::uring) : io::io_context(io::epoll);
#else
    (void)use_uring;
    io::io_context context(io::epoll);
#endif
    io::local_stream_socket first{context}, second{context};
    if (io::connect_pair(first, second)) return false;
    State state;
    std::stop_source stop;
    capy::run_async(context.get_executor(), stop.get_token(), [] {}, stopped_handler)(socket_parked(first, state));
    context.restart();
    (void)context.run_for(20ms);
    if (!state.entered || state.destroyed || context.stopped()) return false;
    stop.request_stop();
    context.restart();
    (void)context.run_for(1s);
    auto unwound = state.destroyed;
    first.close();
    second.close();
    context.restart();
    (void)context.run_for(1s);
    return unwound && context.stopped();
}

struct JoinState {
    std::array<bool, 2> entered{};
    std::array<bool, 2> destroyed{};
    bool returned = false;
    bool threw = false;
    bool drained_on_return = false;
};

auto join_child(capy::async_waker& waker, JoinState& state, unsigned index, bool fail, bool signal = false)
    -> capy::task<capy::results<>> {
    Guard guard{state.destroyed[index]};
    state.entered[index] = true;
    auto [error] = co_await waker.wait();
    if (!error && fail) throw std::runtime_error("child failure");
    if (!error && signal) co_return capy::results<>{std::make_error_code(std::errc::operation_canceled)};
    co_return capy::results<>{error};
}

auto join_parent(capy::async_waker& first, capy::async_waker& second, JoinState& state, unsigned mode, bool range)
    -> capy::task<> {
    try {
        if (range) {
            std::vector<capy::task<capy::results<>>> children;
            children.push_back(join_child(first, state, 0, mode == 1, mode == 3));
            children.push_back(join_child(second, state, 1, false));
            (void)co_await capy::when_all(std::move(children));
        } else {
            (void)co_await capy::when_all(join_child(first, state, 0, mode == 1, mode == 3),
                                         join_child(second, state, 1, false));
        }
    } catch (std::runtime_error const&) { state.threw = true; }
    state.drained_on_return = state.destroyed[0] && state.destroyed[1];
    state.returned = true;
}

// mode: parent cancellation, child exception, independent completion, or error result.
auto join_test(bool use_uring, unsigned mode, bool range) -> bool {
#if BOOST_COROSIO_HAVE_LIBURING
    io::io_context context = use_uring ? io::io_context(io::uring) : io::io_context(io::epoll);
#else
    (void)use_uring;
    io::io_context context(io::epoll);
#endif
    capy::async_waker first, second;
    JoinState state;
    std::stop_source stop;
    capy::run_async(context.get_executor(), stop.get_token())(join_parent(first, second, state, mode, range));
    context.restart();
    (void)context.run_for(20ms);
    if (!state.entered[0] || !state.entered[1] || state.returned) return false;
    if (mode) first.wake();
    else stop.request_stop();
    context.restart();
    if (mode == 2) {
        (void)context.run_for(20ms);
        if (!state.destroyed[0] || state.destroyed[1] || state.returned) return false;
        second.wake();
        context.restart();
    }
    (void)context.run_for(1s);
    return state.returned && state.drained_on_return && state.threw == (mode == 1) && context.stopped();
}

struct AbandonState {
    std::array<bool, 2> entered{};
    std::array<bool, 2> destroyed{};
    bool parent_destroyed = false;
    bool children_destroyed_first = false;
    bool returned = false;
};

auto abandon_child(io::local_stream_socket& socket, AbandonState& state, unsigned index)
    -> capy::task<capy::results<>> {
    Guard guard{state.destroyed[index]};
    state.entered[index] = true;
    std::array<char, 1> buffer{};
    auto [error, bytes] = co_await socket.read_some(capy::mutable_buffer(buffer.data(), buffer.size()));
    (void)bytes;
    co_return capy::results<>{error};
}

auto abandon_parent(io::io_context& context, AbandonState& state, bool range) -> capy::task<> {
    io::local_stream_socket first{context}, second{context};
    struct ParentGuard {
        AbandonState& state;
        ~ParentGuard() {
            state.children_destroyed_first = state.destroyed[0] && state.destroyed[1];
            state.parent_destroyed = true;
        }
    } guard{state};
    if (io::connect_pair(first, second)) co_return;
    if (range) {
        std::vector<capy::task<capy::results<>>> children;
        children.push_back(abandon_child(first, state, 0));
        children.push_back(abandon_child(second, state, 1));
        (void)co_await capy::when_all(std::move(children));
    } else {
        (void)co_await capy::when_all(abandon_child(first, state, 0), abandon_child(second, state, 1));
    }
    state.returned = true;
}

auto abandon_test(bool use_uring, bool range) -> bool {
    AbandonState state;
    {
#if BOOST_COROSIO_HAVE_LIBURING
        io::io_context context = use_uring ? io::io_context(io::uring) : io::io_context(io::epoll);
#else
        (void)use_uring;
        io::io_context context(io::epoll);
#endif
        capy::run_async(context.get_executor())(abandon_parent(context, state, range));
        context.restart();
        (void)context.run_for(20ms);
        if (!state.entered[0] || !state.entered[1] || state.parent_destroyed) return false;
    }
    return state.parent_destroyed && state.children_destroyed_first && !state.returned;
}

auto value_child(int value) -> capy::task<capy::results<int>> {
    co_return capy::results<int>{std::error_code{}, value};
}

auto signaled_value() -> capy::task<capy::results<int>> {
    co_return capy::results<int>{std::make_error_code(std::errc::operation_canceled), 59};
}

auto value_parent(bool& passed) -> capy::task<> {
    auto [error, first, second] = co_await capy::when_all(value_child(17), value_child(29));
    std::vector<capy::task<capy::results<int>>> children;
    children.push_back(value_child(31));
    children.push_back(value_child(47));
    auto [range_error, values] = co_await capy::when_all(std::move(children));
    auto [signal, value, ignored] = co_await capy::when_all(signaled_value(), value_child(61));
    (void)ignored;
    passed = !error && first == 17 && second == 29 && !range_error &&
        values.size() == 2 && values[0] == 31 && values[1] == 47 &&
        signal == std::errc::operation_canceled && value == 59;
}

auto value_test(bool use_uring) -> bool {
#if BOOST_COROSIO_HAVE_LIBURING
    io::io_context context = use_uring ? io::io_context(io::uring) : io::io_context(io::epoll);
#else
    (void)use_uring;
    io::io_context context(io::epoll);
#endif
    bool passed = false;
    capy::run_async(context.get_executor())(value_parent(passed));
    context.restart();
    (void)context.run_for(1s);
    return passed && context.stopped();
}

struct HandlerLifetimeState {
    bool entered=false, destroyed=false, error_called=false, error_saw_owner=false;
};
struct HandlerOwner {
    HandlerLifetimeState& state;
    ~HandlerOwner() { state.destroyed=true; }
};
auto handler_lifetime_task(std::unique_ptr<HandlerOwner> owner, io::io_context& context, bool abandon)
    -> capy::task<> {
    owner->state.entered=true;
    if (!abandon) {
        (void)co_await io::delay(1ms);
        throw std::runtime_error("injected task failure");
    }
    io::local_stream_socket first(context), second(context);
    if (io::connect_pair(first,second)) throw std::runtime_error("socket pair");
    std::array<char,1> buffer{};
    (void)co_await first.read_some(capy::mutable_buffer(buffer.data(),buffer.size()));
}
auto handler_lifetime_test(bool use_uring, bool abandon) -> bool {
    HandlerLifetimeState state;
    {
#if BOOST_COROSIO_HAVE_LIBURING
        io::io_context context = use_uring ? io::io_context(io::uring) : io::io_context(io::epoll);
#else
        (void)use_uring;
        io::io_context context(io::epoll);
#endif
        auto owner=std::make_unique<HandlerOwner>(state);
        auto* borrowed=owner.get();
        capy::run_async(context.get_executor(), [] {}, [borrowed,&state](std::exception_ptr error) noexcept {
            state.error_called=true;
            state.error_saw_owner=error && !state.destroyed && &borrowed->state==&state;
        })(handler_lifetime_task(std::move(owner),context,abandon));
        context.restart();
        (void)context.run_for(30ms);
        if (!state.entered) return false;
        if (abandon && (state.destroyed || state.error_called)) return false;
        if (!abandon && (!state.destroyed || !state.error_called || !state.error_saw_owner)) return false;
    }
    return state.destroyed && (abandon ? !state.error_called : state.error_saw_owner);
}

class FailingResource final : public std::pmr::memory_resource {
    void* do_allocate(std::size_t,std::size_t) override { throw std::bad_alloc{}; }
    void do_deallocate(void*,std::size_t,std::size_t) override {}
    bool do_is_equal(std::pmr::memory_resource const& other) const noexcept override { return this==&other; }
};
template<class T> struct FailingAllocator {
    using value_type=T;
    FailingAllocator()=default;
    template<class U> FailingAllocator(FailingAllocator<U> const&) noexcept {}
    auto allocate(std::size_t) -> T* { throw std::bad_alloc{}; }
    void deallocate(T*,std::size_t) noexcept {}
};
auto launch_allocation_test(bool use_uring) -> bool {
#if BOOST_COROSIO_HAVE_LIBURING
    io::io_context context = use_uring ? io::io_context(io::uring) : io::io_context(io::epoll);
#else
    (void)use_uring;
    io::io_context context(io::epoll);
#endif
    auto* previous=capy::get_current_frame_allocator();
    bool constructed=false, passed=false;
    auto task=[&]() -> capy::task<> { constructed=true; return value_parent(passed); };
    FailingResource resource;
    bool caught_resource=false, caught_allocator=false;
    try { capy::run_async(context.get_executor(), &resource)(task()); }
    catch (std::bad_alloc const&) { caught_resource=true; }
    try { capy::run_async(context.get_executor(), FailingAllocator<std::byte>{})(task()); }
    catch (std::bad_alloc const&) { caught_allocator=true; }
    context.restart();
    (void)context.run_for(20ms);
    return caught_resource && caught_allocator && !constructed && !passed && context.stopped() &&
           capy::get_current_frame_allocator()==previous;
}

static_assert(capy::ContextRunnable<coro::quitter<bool>>);

struct AcquireState {
    bool entered=false,held=false,touched=false,resumed=false,delivered=false,after=false,destroyed=false,stopped=false;
};
struct Acquired {
    bool* held;
    explicit Acquired(bool& value) :held(&value) {}
    Acquired(Acquired&& other) noexcept :held(std::exchange(other.held,nullptr)) {}
    ~Acquired() {if(held)*held=false;}
};
// Each synchronous completion form can acquire before it requests stop.
// Skipping await_resume would leave held set and leak that acquisition.
template<unsigned Mode> struct AcquireOnStop {
    std::stop_source& stop;
    AcquireState& state;
    auto acquire() -> void {state.touched=true;state.held=true;stop.request_stop();}
    auto await_ready() -> bool {
        if constexpr(Mode==0) {acquire();return true;}
        return false;
    }
    auto await_suspend(std::coroutine_handle<> current,capy::await_context const*) {
        acquire();
        if constexpr(Mode==1)return false;
        else return current;
    }
    auto await_resume() -> Acquired {state.resumed=true;return Acquired{state.held};}
};
template<unsigned Mode>
auto acquire_task(std::stop_source& stop,AcquireState& state,capy::async_waker& waker,bool pre_stopped)
    -> coro::quitter<bool> {
    Guard guard{state.destroyed};state.entered=true;
    if(pre_stopped)stop.request_stop();
    auto acquired=co_await AcquireOnStop<Mode>{stop,state};
    state.delivered=true;
    (void)co_await waker.wait();
    state.after=true;co_return true;
}
template<unsigned Mode> auto acquisition_test(bool use_uring,bool pre_stopped) -> bool {
#if BOOST_COROSIO_HAVE_LIBURING
    io::io_context context=use_uring ? io::io_context(io::uring) : io::io_context(io::epoll);
#else
    (void)use_uring;io::io_context context(io::epoll);
#endif
    AcquireState state;std::stop_source stop;capy::async_waker waker;
    capy::run_async(context.get_executor(),stop.get_token(),[](bool) {std::terminate();},
        [&state](std::exception_ptr error) {
            try {std::rethrow_exception(error);}
            catch(coro::stop_requested const&) {state.stopped=state.destroyed && !state.held;}
        })(acquire_task<Mode>(stop,state,waker,pre_stopped));
    context.restart();(void)context.run_for(1s);
    return context.stopped() && state.entered && state.stopped && !state.held && !state.after &&
        state.touched==!pre_stopped && state.resumed==!pre_stopped && state.delivered==!pre_stopped;
}

auto main() -> int {
    if (!test(false)) return 1;
#if BOOST_COROSIO_HAVE_LIBURING
    if (!test(true)) return 2;
#endif
    if (!socket_test(false)) return 3;
#if BOOST_COROSIO_HAVE_LIBURING
    if (!socket_test(true)) return 4;
#endif
    for (bool range : {false, true})
        if (!join_test(false, 0, range) || !join_test(false, 1, range) || !join_test(false, 2, range) || !join_test(false, 3, range)) return 5;
#if BOOST_COROSIO_HAVE_LIBURING
    for (bool range : {false, true})
        if (!join_test(true, 0, range) || !join_test(true, 1, range) || !join_test(true, 2, range) || !join_test(true, 3, range)) return 6;
#endif
    if (!abandon_test(false, false) || !abandon_test(false, true)) return 7;
    if (!value_test(false)) return 9;
    if (!handler_lifetime_test(false,false) || !handler_lifetime_test(false,true)) return 11;
    if (!launch_allocation_test(false)) return 13;
    for(bool stopped:{false,true})
        if(!acquisition_test<0>(false,stopped) || !acquisition_test<1>(false,stopped) || !acquisition_test<2>(false,stopped))return 15;
#if BOOST_COROSIO_HAVE_LIBURING
    if (!abandon_test(true, false) || !abandon_test(true, true)) return 8;
    if (!value_test(true)) return 10;
    if (!handler_lifetime_test(true,false) || !handler_lifetime_test(true,true)) return 12;
    if (!launch_allocation_test(true)) return 14;
    for(bool stopped:{false,true})
        if(!acquisition_test<0>(true,stopped) || !acquisition_test<1>(true,stopped) || !acquisition_test<2>(true,stopped))return 16;
#endif
    std::println("Capy quitter owner unwind passed");
}
