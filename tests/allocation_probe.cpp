#include <boost/capy/ex/run_async.hpp>
#include <boost/capy/task.hpp>
#include <boost/corosio/io_context.hpp>
#include <atomic>
#include <cstddef>
#include <cstdlib>
#include <memory_resource>
#include <new>
#include <vector>
#include <cstdio>
#include <sys/wait.h>
#include <unistd.h>

namespace {
    std::atomic<unsigned> plain{}, aligned{};
    std::atomic<bool> fail{};
    auto allocate(std::size_t n, std::size_t alignment) noexcept -> void* {
        if (fail.exchange(false)) return nullptr;
        if (alignment == 0) return std::malloc(n ? n : 1);
        void* result=nullptr;
        return ::posix_memalign(&result,alignment,n ? n : 1)==0 ? result : nullptr;
    }
    auto required(void* p) noexcept -> void* {
        if (!p) std::abort();
        return p;
    }
}
void* operator new(std::size_t n) { ++plain; return required(allocate(n,0)); }
void* operator new[](std::size_t n) { ++plain; return required(allocate(n,0)); }
void* operator new(std::size_t n,std::align_val_t a) { ++aligned; return required(allocate(n,static_cast<std::size_t>(a))); }
void* operator new[](std::size_t n,std::align_val_t a) { ++aligned; return required(allocate(n,static_cast<std::size_t>(a))); }
void* operator new(std::size_t n,std::nothrow_t const&) noexcept { ++plain; return allocate(n,0); }
void* operator new[](std::size_t n,std::nothrow_t const&) noexcept { ++plain; return allocate(n,0); }
void* operator new(std::size_t n,std::align_val_t a,std::nothrow_t const&) noexcept { ++aligned; return allocate(n,static_cast<std::size_t>(a)); }
void* operator new[](std::size_t n,std::align_val_t a,std::nothrow_t const&) noexcept { ++aligned; return allocate(n,static_cast<std::size_t>(a)); }
void operator delete(void* p) noexcept { std::free(p); }
void operator delete[](void* p) noexcept { std::free(p); }
void operator delete(void* p,std::size_t) noexcept { std::free(p); }
void operator delete[](void* p,std::size_t) noexcept { std::free(p); }
void operator delete(void* p,std::align_val_t) noexcept { std::free(p); }
void operator delete[](void* p,std::align_val_t) noexcept { std::free(p); }
void operator delete(void* p,std::size_t,std::align_val_t) noexcept { std::free(p); }
void operator delete[](void* p,std::size_t,std::align_val_t) noexcept { std::free(p); }
void operator delete(void* p,std::nothrow_t const&) noexcept { std::free(p); }
void operator delete[](void* p,std::nothrow_t const&) noexcept { std::free(p); }
void operator delete(void* p,std::align_val_t,std::nothrow_t const&) noexcept { std::free(p); }
void operator delete[](void* p,std::align_val_t,std::nothrow_t const&) noexcept { std::free(p); }

struct Resource : std::pmr::memory_resource {
    unsigned allocations=0, frees=0;
    void* do_allocate(std::size_t n,std::size_t a) override {
        ++allocations; return std::pmr::new_delete_resource()->allocate(n,a);
    }
    void do_deallocate(void* p,std::size_t n,std::size_t a) override {
        ++frees; std::pmr::new_delete_resource()->deallocate(p,n,a);
    }
    bool do_is_equal(std::pmr::memory_resource const& other) const noexcept override { return this==&other; }
};
boost::capy::task<> work(bool& done) { done=true; co_return; }
auto main() -> int {
    auto before=plain.load();
    std::vector<int> v(128,7);
    if (plain<=before || v[127]!=7) return 1;
    before=aligned.load();
    void* p=::operator new(128,std::align_val_t{64});
    if (aligned<=before || reinterpret_cast<std::uintptr_t>(p)%64) return 2;
    ::operator delete(p,std::align_val_t{64});
    fail=true;
    p=::operator new(64,std::nothrow);
    if (p || fail) return 3;
    fail=true;
    p=::operator new(64,std::align_val_t{64},std::nothrow);
    if (p || fail) return 4;
    auto pid=::fork();
    if (pid<0) return 5;
    if (pid==0) { fail=true; (void)::operator new(64); std::_Exit(9); }
    int status=0;
    if (::waitpid(pid,&status,0)!=pid || !WIFSIGNALED(status) || WTERMSIG(status)!=SIGABRT) return 6;
    boost::corosio::io_context context;
    bool default_done=false;
    auto total_before=plain.load()+aligned.load();
    boost::capy::run_async(context.get_executor())(work(default_done));
    context.restart(); (void)context.run();
    if (!default_done || plain.load()+aligned.load()<=total_before) return 8;
    Resource resource;
    bool done=false;
    before=aligned.load();
    boost::capy::run_async(context.get_executor(),&resource)(work(done));
    context.restart(); (void)context.run();
    if (!done || resource.allocations!=2 || resource.frees!=2 || aligned<before+2) return 7;
    std::puts("vector, aligned allocation, failure behavior and Capy launch allocations verified");
}
