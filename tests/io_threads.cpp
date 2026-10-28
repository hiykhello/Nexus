#include <boost/capy/ex/run_async.hpp>
#include <boost/capy/task.hpp>
#include <boost/corosio/backend.hpp>
#include <boost/corosio/io_context.hpp>
import std;
namespace io=boost::corosio;
using namespace std::chrono_literals;

struct Posted {
    struct promise_type {
        auto get_return_object() -> Posted { return {std::coroutine_handle<promise_type>::from_promise(*this)}; }
        auto initial_suspend() noexcept -> std::suspend_always { return {}; }
        auto final_suspend() noexcept -> std::suspend_never { return {}; }
        auto return_void() noexcept -> void {}
        auto unhandled_exception() noexcept -> void { std::terminate(); }
    };
    std::coroutine_handle<promise_type> handle;
};

auto record(std::atomic<unsigned>& count, std::atomic<bool>& wrong_thread,
            io::io_context::executor_type executor) -> Posted {
    if (!executor.running_in_this_thread()) wrong_thread=true;
    count.fetch_add(1,std::memory_order_relaxed);
    co_return;
}

auto notify(std::promise<void>& signal) -> Posted {
    signal.set_value();
    co_return;
}

auto failing_task() -> boost::capy::task<> {
    throw std::runtime_error("controlled task failure");
    co_return;
}

auto successful_task(std::atomic<unsigned>& success) -> boost::capy::task<> {
    ++success;
    co_return;
}

template<class Backend>
auto check(Backend backend) -> bool {
    io::io_context context{backend};
    auto executor=context.get_executor();
    std::atomic<unsigned> count=0;
    std::atomic<bool> wrong_thread=false;
    executor.on_work_started();
    std::thread worker([&] { (void)context.run(); });
    std::promise<void> ready;
    auto ready_future=ready.get_future();
    auto first=notify(ready);
    executor.post(std::coroutine_handle<>(first.handle));
    if (ready_future.wait_for(2s)!=std::future_status::ready) {
        context.stop(); worker.join(); executor.on_work_finished(); return false;
    }
    // Give the guarded loop an opportunity to become idle before posting again.
    std::this_thread::sleep_for(50ms);
    std::promise<void> awakened;
    auto wake_future=awakened.get_future();
    auto wake=notify(awakened);
    executor.post(std::coroutine_handle<>(wake.handle));
    if (wake_future.wait_for(2s)!=std::future_status::ready) {
        context.stop(); worker.join(); executor.on_work_finished(); return false;
    }
    std::vector<std::thread> producers;
    for (int p=0; p<4; ++p) producers.emplace_back([&] {
        for (int i=0; i<250; ++i) {
            auto task=record(count,wrong_thread,executor);
            executor.post(std::coroutine_handle<>(task.handle));
        }
    });
    for (auto& producer : producers) producer.join();
    // Finishing the work guard lets run drain all already-posted continuations.
    executor.on_work_finished();
    worker.join();
    if (count!=1000 || wrong_thread) return false;

    // stop() leaves work queued. A restart must execute it before destruction.
    context.restart();
    executor.on_work_started();
    std::thread stopped_worker([&] { (void)context.run(); });
    context.stop();
    stopped_worker.join();
    auto task=record(count,wrong_thread,executor);
    executor.post(std::coroutine_handle<>(task.handle));
    executor.on_work_finished();
    if (count!=1000) return false;
    context.restart();
    std::thread drain([&] { (void)context.run(); });
    drain.join();
    if (count!=1001 || wrong_thread) return false;
    context.restart();
    std::atomic<unsigned> success=0, errors=0, wrong=0;
    boost::capy::run_async(executor, [] {}, [&](std::exception_ptr error) noexcept {
        if (!executor.running_in_this_thread()) ++wrong;
        try { std::rethrow_exception(error); }
        catch (std::runtime_error const& e) {
            if (std::string_view(e.what())=="controlled task failure") ++errors;
        } catch (...) { ++wrong; }
    })(failing_task());
    boost::capy::run_async(executor)(successful_task(success));
    std::thread failure_worker([&] { (void)context.run(); });
    failure_worker.join();
    return errors==1 && success==1 && wrong==0;
}

auto main() -> int {
    if (!check(io::epoll)) return 1;
#if BOOST_COROSIO_HAVE_LIBURING
    if (!check(io::uring)) return 2;
#endif
    std::println("Corosio cross-thread post, drain, restart and task exception handling passed");
}
