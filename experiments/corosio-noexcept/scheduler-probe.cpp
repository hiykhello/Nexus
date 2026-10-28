#include <boost/corosio/native/detail/uring/uring_scheduler.hpp>
#include <atomic>
#include <barrier>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <dirent.h>
#include <liburing.h>
#include <system_error>
#include <thread>
#include <vector>

namespace bc = boost::corosio;
struct Context : boost::capy::execution_context { Context() : execution_context(this) {} };
enum class Point { none, setup, event, submit };
static std::atomic<Point> fault{Point::none};
static std::atomic<int> setup_calls{0};
extern "C" int __real_io_uring_queue_init_params(unsigned, io_uring*, io_uring_params*);
extern "C" int __real_eventfd(unsigned, int);
extern "C" int __real_io_uring_submit(io_uring*);
static bool inject(Point p) { return fault.compare_exchange_strong(p, Point::none); }
extern "C" int __wrap_io_uring_queue_init_params(unsigned n, io_uring* ring, io_uring_params* params) {
    ++setup_calls;
    if (inject(Point::setup)) return -EPERM;
    return __real_io_uring_queue_init_params(n, ring, params);
}
extern "C" int __wrap_eventfd(unsigned init, int flags) {
    if (inject(Point::event)) { errno = EPERM; return -1; }
    return __real_eventfd(init, flags);
}
extern "C" int __wrap_io_uring_submit(io_uring* ring) {
    if (inject(Point::submit)) return -EPERM;
    return __real_io_uring_submit(ring);
}
static int count(char const* path) {
    auto* dir = opendir(path); if (!dir) return -1;
    int n = 0; while (readdir(dir)) ++n; closedir(dir); return n;
}
static bool retry(Point p, char const* operation, bool legacy_first) {
    Context context;
    bc::detail::uring_scheduler scheduler(context);
    fault = p;
    if (legacy_first) {
        try { scheduler.init_ring(); return false; }
        catch (std::system_error const& e) {
            if (e.code() != std::errc::operation_not_permitted || !std::strstr(e.what(), operation)) return false;
        }
        if (scheduler.try_init_ring()) return false;
    } else {
        if (scheduler.try_init_ring() != std::errc::operation_not_permitted) return false;
        scheduler.init_ring();
    }
    auto before = setup_calls.load();
    return !scheduler.try_init_ring() && (scheduler.init_ring(), setup_calls == before);
}
int main() {
    int fds = count("/proc/self/fd"), threads = count("/proc/self/task");
    if (fds < 0 || threads < 0) return 1;
    for (auto [point, operation] : {std::pair{Point::setup, "io_uring_queue_init_params"},
                                    std::pair{Point::event, "eventfd"},
                                    std::pair{Point::submit, "io_uring_submit (wakeup)"}}) {
        if (!retry(point, operation, true) || !retry(point, operation, false)) return 2;
        if (count("/proc/self/fd") != fds || count("/proc/self/task") != threads) return 3;
    }
    {
        Context context;
        bc::detail::uring_scheduler scheduler(context);
        constexpr int n = 16;
        std::barrier gate(n);
        std::atomic<int> errors{0}, successes{0}, bad{0};
        std::vector<std::thread> workers;
        setup_calls = 0; fault = Point::setup;
        for (int i = 0; i < n; ++i) workers.emplace_back([&, i] {
            gate.arrive_and_wait();
            if (i % 2 == 0) {
                auto error = scheduler.try_init_ring();
                if (!error) ++successes;
                else if (error == std::errc::operation_not_permitted) ++errors;
                else ++bad;
            } else {
                try { scheduler.init_ring(); ++successes; }
                catch (std::system_error const& e) {
                    if (e.code() == std::errc::operation_not_permitted && std::strstr(e.what(), "io_uring_queue_init_params")) ++errors;
                    else ++bad;
                }
            }
        });
        for (auto& worker : workers) worker.join();
        if (bad || errors != 1 || successes != n - 1 || setup_calls < 2 || setup_calls > 3) return 4;
        auto before = setup_calls.load();
        scheduler.init_ring();
        if (scheduler.try_init_ring() || setup_calls != before) return 5;
    }
    if (count("/proc/self/fd") != fds || count("/proc/self/task") != threads) return 6;
    std::puts("scheduler mixed concurrency, retries, error descriptions and cleanup passed");
}
