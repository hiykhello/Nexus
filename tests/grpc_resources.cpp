import std;
namespace allocation_audit {
    bool enabled=false,fired=false;
    std::size_t live=0,live_bytes=0;
    std::array<void*,100000> pointers{};
    std::array<std::size_t,100000> tracked_sizes{};
    std::size_t calls=0,fail_at=0,ordinary=0,arrays=0,aligned=0;
    std::array<std::size_t,100000> sizes{};
    std::array<char,100000> kinds{};
    auto track(void* p,std::size_t n) noexcept -> void {
        if (enabled && calls && calls<=pointers.size()) {pointers[calls-1]=p;tracked_sizes[calls-1]=n;++live;live_bytes+=n;}
    }
    auto untrack(void* p) noexcept -> void {
        if (!p) return;for (std::size_t i=0;i<std::min(calls,pointers.size());++i) if (pointers[i]==p) {pointers[i]=nullptr;--live;live_bytes-=tracked_sizes[i];return;}
    }
    auto audit_exit() noexcept -> void {
        std::cerr<<"natural-exit tracked-live="<<live<<" bytes="<<live_bytes<<'\n'<<std::flush;
        if (live) std::_Exit(68);
    }
    auto admit(std::size_t n,char kind) -> void {
        if (!enabled) return;
        ++calls;if (kind=='o') ++ordinary;else if (kind=='a') ++arrays;else ++aligned;
        if (calls<=sizes.size()) {sizes[calls-1]=n;kinds[calls-1]=kind;}
        if (fail_at && calls==fail_at) {fired=true;throw std::bad_alloc();}
    }
}
auto operator new(std::size_t n) -> void* {allocation_audit::admit(n,'o');if (auto p=std::malloc(n ? n : 1)) {allocation_audit::track(p,n);return p;}throw std::bad_alloc();}
auto operator new[](std::size_t n) -> void* {allocation_audit::admit(n,'a');if (auto p=std::malloc(n ? n : 1)) {allocation_audit::track(p,n);return p;}throw std::bad_alloc();}
auto operator delete(void* p) noexcept -> void {allocation_audit::untrack(p);std::free(p);}
auto operator delete[](void* p) noexcept -> void {allocation_audit::untrack(p);std::free(p);}
auto operator delete(void* p,std::size_t) noexcept -> void {allocation_audit::untrack(p);std::free(p);}
auto operator delete[](void* p,std::size_t) noexcept -> void {allocation_audit::untrack(p);std::free(p);}
auto operator new(std::size_t n,std::align_val_t a) -> void* {allocation_audit::admit(n,'l');auto align=static_cast<std::size_t>(a);auto size=(std::max(n,std::size_t{1})+align-1)/align*align;if (auto p=std::aligned_alloc(align,size)) {allocation_audit::track(p,n);return p;}throw std::bad_alloc();}
auto operator new[](std::size_t n,std::align_val_t a) -> void* {return ::operator new(n,a);}
auto operator delete(void* p,std::align_val_t) noexcept -> void {allocation_audit::untrack(p);std::free(p);}
auto operator delete[](void* p,std::align_val_t) noexcept -> void {allocation_audit::untrack(p);std::free(p);}
auto operator delete(void* p,std::size_t,std::align_val_t) noexcept -> void {allocation_audit::untrack(p);std::free(p);}
auto operator delete[](void* p,std::size_t,std::align_val_t) noexcept -> void {allocation_audit::untrack(p);std::free(p);}

extern "C" int nexus_test_grpc_resources(char const*,char const*,unsigned,unsigned,unsigned,unsigned,
    void (*)(bool,std::size_t) noexcept,bool (*)() noexcept);
extern "C" void nexus_grpc_frame_report();
auto main(int argc,char** argv) -> int {
    std::atexit(allocation_audit::audit_exit);
    if (argc!=7) return 64;
    auto number=[](char const* text) {return static_cast<unsigned>(std::stoul(text));};
    int result=nexus_test_grpc_resources(argv[1],argv[2],number(argv[3]),number(argv[4]),number(argv[5]),number(argv[6]),
        [](bool enabled,std::size_t fail) noexcept {allocation_audit::enabled=enabled;allocation_audit::fail_at=fail;},
        []() noexcept {return allocation_audit::fired;});
    std::println("audit calls={} ordinary={} array={} aligned={} fired={} tracked-live={}",allocation_audit::calls,allocation_audit::ordinary,allocation_audit::arrays,allocation_audit::aligned,allocation_audit::fired,allocation_audit::live);
    if (!number(argv[6])) for (std::size_t i=0;i<std::min(allocation_audit::calls,allocation_audit::sizes.size());++i)
        std::println("allocation={} kind={} size={}",i+1,allocation_audit::kinds[i],allocation_audit::sizes[i]);
    nexus_grpc_frame_report();
    return result;
}
