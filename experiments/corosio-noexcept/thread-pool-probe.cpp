#include <boost/corosio/detail/thread_pool.hpp>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <dirent.h>
#include <pthread.h>
#include <thread>

namespace detail = boost::corosio::detail;
struct Context : boost::capy::execution_context { Context() : execution_context(this) {} };
static std::atomic<int> calls{0}, fail_at{-1};
static std::atomic<bool> join_entered{false};
extern "C" int __real_pthread_join(pthread_t, void**);
extern "C" int __wrap_pthread_join(pthread_t thread, void** result) {
    join_entered = true;
    return __real_pthread_join(thread, result);
}
extern "C" int __real_pthread_create(pthread_t*, pthread_attr_t const*, void* (*)(void*), void*);
extern "C" int __wrap_pthread_create(pthread_t* t, pthread_attr_t const* a, void* (*fn)(void*), void* arg) {
    int index = calls.fetch_add(1);
    if (index == fail_at.load()) return EAGAIN;
    return __real_pthread_create(t, a, fn, arg);
}
static int count_threads() {
    auto* dir = opendir("/proc/self/task"); if (!dir) return -1;
    int n = 0; while (readdir(dir)) ++n; closedir(dir); return n;
}
struct Work : detail::pool_work_item {
    std::atomic<int>* done;
    explicit Work(std::atomic<int>& target) : done(&target) {
        func_ = [](detail::pool_work_item* p) noexcept { ++*static_cast<Work*>(p)->done; };
    }
};
static bool wait_for(std::atomic<int>& value, int expected) {
    auto end = std::chrono::steady_clock::now() + std::chrono::seconds(3);
    while (value.load() != expected && std::chrono::steady_clock::now() < end) std::this_thread::yield();
    return value == expected;
}
int main() {
    int baseline = count_threads(); if (baseline < 0) return 1;
    {
        Context ctx; detail::thread_pool pool(ctx, 2); std::atomic<int> done{0}; Work item(done);
        calls = 0; fail_at = 0;
        if (pool.post(&item) != std::errc::resource_unavailable_try_again || pool.worker_count() || done) return 2;
        fail_at = -1;
        if (pool.post(&item) || !wait_for(done, 1) || pool.worker_count() != 2) return 3;
        pool.shutdown();
        if (pool.worker_count() || !pool.post(&item)) return 4;
    }
    if (count_threads() != baseline) return 5;
    {
        Context ctx; detail::thread_pool pool(ctx, 3); std::atomic<int> done{0}; Work a(done), b(done);
        calls = 0; fail_at = 1;
        if (pool.post(&a) || !wait_for(done, 1) || pool.worker_count() != 1 || calls != 2) return 6;
        fail_at = -1;
        if (pool.post(&b) || !wait_for(done, 2) || pool.worker_count() != 1 || calls != 2) return 7;
        pool.shutdown();
    }
    if (count_threads() != baseline) return 8;
    {
        Context ctx; detail::thread_pool pool(ctx, 1);
        struct Gate : detail::pool_work_item {
            std::atomic<bool> started{false}, release{false};
            Gate() { func_ = [](detail::pool_work_item* p) noexcept {
                auto& g = *static_cast<Gate*>(p); g.started = true;
                while (!g.release.load()) std::this_thread::yield();
            }; }
        } gate;
        struct Queued : detail::pool_work_item {
            std::atomic<int> ran{0}, destroyed{0};
            Queued() {
                func_ = [](detail::pool_work_item* p) noexcept { ++static_cast<Queued*>(p)->ran; };
                destroy_ = [](detail::pool_work_item* p) noexcept { ++static_cast<Queued*>(p)->destroyed; };
            }
        } queued;
        fail_at = -1;
        if (pool.post(&gate)) return 9;
        auto end = std::chrono::steady_clock::now() + std::chrono::seconds(3);
        while (!gate.started && std::chrono::steady_clock::now() < end) std::this_thread::yield();
        if (!gate.started || pool.post(&queued)) { gate.release = true; return 10; }
        join_entered = false;
        std::thread closer([&] { pool.shutdown(); });
        end = std::chrono::steady_clock::now() + std::chrono::seconds(3);
        while (!join_entered && std::chrono::steady_clock::now() < end) std::this_thread::yield();
        bool observed = join_entered;
        gate.release = true;
        closer.join();
        if (!observed || queued.ran || queued.destroyed != 1 || pool.worker_count()) return 11;
    }
    if (count_threads() != baseline) return 12;
    std::puts("pthread pool refusal, retry, partial startup, work and cleanup passed");
}
