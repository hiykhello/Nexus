#include <boost/capy/when_all.hpp>
#include <boost/capy/ex/run_async.hpp>
#include <boost/corosio/backend.hpp>
#include <boost/corosio/io_context.hpp>

#include <array>
#include <cstdio>
#include <new>
#include <tuple>
#include <vector>

namespace capy = boost::capy;
namespace io = boost::corosio;

extern int fail_after;
extern int allocations;
extern int releases;

auto child() -> capy::task<capy::results<>> { co_return capy::results<>{}; }

// Invoke the launcher directly to target its runner allocations, with all
// child and parent storage already created. Failed starts must publish none.
auto variadic_failure(int index) -> bool {
    io::io_context context(io::epoll);
    auto ex = context.get_executor();
    capy::await_context env{ex, {}, nullptr, nullptr};
    using Task = decltype(child());
    std::tuple<Task, Task, Task> children{child(), child(), child()};
    capy::detail::when_all_state<capy::results<>, capy::results<>, capy::results<>> state;
    capy::detail::when_all_results_launcher<Task, Task, Task> launcher(&children, &state);
    allocations = releases = 0;
    fail_after = index;
    auto resumed = launcher.await_suspend(std::noop_coroutine(), &env);
    fail_after = -1;
    bool threw = false;
    try { if (state.core_.first_exception_) std::rethrow_exception(state.core_.first_exception_); }
    catch (std::bad_alloc const&) { threw = true; }
    context.restart();
    (void)context.poll();
    return resumed == std::noop_coroutine() && threw && allocations == index && releases == index && context.stopped();
}

auto range_failure(int index) -> bool {
    io::io_context context(io::epoll);
    auto ex = context.get_executor();
    capy::await_context env{ex, {}, nullptr, nullptr};
    using Task = decltype(child());
    std::vector<Task> children;
    children.reserve(3);
    for (int i = 0; i < 3; ++i) children.push_back(child());
    capy::detail::when_all_homogeneous_state<std::tuple<>> state(3);
    capy::detail::when_all_homogeneous_launcher<std::vector<Task>> launcher(&children, &state);
    allocations = releases = 0;
    fail_after = index;
    auto resumed = launcher.await_suspend(std::noop_coroutine(), &env);
    fail_after = -1;
    bool threw = false;
    try { if (state.core_.first_exception_) std::rethrow_exception(state.core_.first_exception_); }
    catch (std::bad_alloc const&) { threw = true; }
    context.restart();
    (void)context.poll();
    return resumed == std::noop_coroutine() && threw && allocations == index && releases == index && context.stopped();
}

struct IntegrationState { bool caught = false; bool returned = false; int entered = 0; };
auto counted_child(IntegrationState& state) -> capy::task<capy::results<>> {
    ++state.entered;
    co_return capy::results<>{};
}
auto integration_parent(IntegrationState& state, int index, bool range) -> capy::task<> {
    try {
        if (range) {
            std::vector<capy::task<capy::results<>>> children;
            children.reserve(3);
            for (int i = 0; i < 3; ++i) children.push_back(counted_child(state));
            auto joined = capy::when_all(std::move(children));
            allocations = releases = 0;
            fail_after = index;
            (void)co_await std::move(joined);
        } else {
            auto joined = capy::when_all(counted_child(state), counted_child(state), counted_child(state));
            allocations = releases = 0;
            fail_after = index;
            (void)co_await std::move(joined);
        }
    } catch (std::bad_alloc const&) {
        state.caught = true;
    }
    fail_after = -1;
    state.returned = true;
}
auto integration_failure(int index, bool range) -> bool {
    io::io_context context(io::epoll);
    IntegrationState state;
    capy::run_async(context.get_executor())(integration_parent(state, index, range));
    context.restart();
    (void)context.run();
    return state.caught && state.returned && state.entered == 0 &&
        allocations == index && releases == index && context.stopped();
}

int main() {
    for (int i = 0; i < 3; ++i) {
        if (!variadic_failure(i) || !range_failure(i) ||
            !integration_failure(i, false) || !integration_failure(i, true)) {
            std::fprintf(stderr, "runner failure at %d: allocations=%d releases=%d\n", i, allocations, releases);
            return 1;
        }
    }
    std::puts("when_all startup allocation failures passed");
}
