import std;
extern "C" void* __real_malloc(std::size_t);
extern "C" void* __real_calloc(std::size_t,std::size_t);
extern "C" void* __real_realloc(void*,std::size_t);
extern "C" void __real_free(void*);
namespace {
    struct Entry {void* pointer=nullptr;std::size_t bytes=0;};
    std::array<Entry,16384> tracked{};
    std::size_t kind=0,calls=0,fail_at=0,live=0;
    bool failed=false;
    auto admit(std::size_t allocation_kind) noexcept -> bool {
        if(kind!=allocation_kind)return true;
        ++calls;if(fail_at&&calls==fail_at){failed=true;return false;}return true;
    }
    auto add(void* p,std::size_t n,std::size_t allocation_kind) noexcept -> void {
        if(!p||kind!=allocation_kind)return;
        for(auto& entry:tracked)if(!entry.pointer){entry={p,n};live+=n;return;}std::abort();
    }
    auto remove(void* p) noexcept -> void {
        if(!p)return;for(auto& entry:tracked)if(entry.pointer==p){live-=entry.bytes;entry={};return;}
    }
    auto allocate(std::size_t n,std::size_t alignment=0) -> void* {
        if(!admit(1))throw std::bad_alloc();n=std::max(std::size_t{1},n);
        auto p=alignment?std::aligned_alloc(alignment,((n+alignment-1)/alignment)*alignment):__real_malloc(n);
        if(!p)throw std::bad_alloc();add(p,n,1);return p;
    }
    auto dispose(void* p) noexcept -> void {remove(p);__real_free(p);}
}
extern "C" auto meter_begin(std::size_t selected,std::size_t fail) -> void {
    if(live)std::abort();kind=selected;calls=0;fail_at=fail;failed=false;
}
extern "C" auto meter_end() -> std::size_t {kind=0;return calls;}
extern "C" auto meter_failed() -> bool {return failed;}
extern "C" auto meter_live() -> std::size_t {return live;}
extern "C" auto __wrap_malloc(std::size_t n) -> void* {if(!admit(2))return nullptr;auto p=__real_malloc(n);add(p,n,2);return p;}
extern "C" auto __wrap_calloc(std::size_t n,std::size_t m) -> void* {if(!admit(2))return nullptr;auto p=__real_calloc(n,m);add(p,n*m,2);return p;}
extern "C" auto __wrap_realloc(void* old,std::size_t n) -> void* {
    if(!admit(2))return nullptr;auto p=__real_realloc(old,n);if(p||!n)remove(old);add(p,n,2);return p;
}
extern "C" auto __wrap_free(void* p) -> void {dispose(p);}
auto operator new(std::size_t n) -> void* {return allocate(n);}
auto operator new[](std::size_t n) -> void* {return allocate(n);}
auto operator new(std::size_t n,std::align_val_t a) -> void* {return allocate(n,static_cast<std::size_t>(a));}
auto operator new[](std::size_t n,std::align_val_t a) -> void* {return allocate(n,static_cast<std::size_t>(a));}
auto operator delete(void* p) noexcept -> void {dispose(p);}
auto operator delete[](void* p) noexcept -> void {dispose(p);}
auto operator delete(void* p,std::size_t) noexcept -> void {dispose(p);}
auto operator delete[](void* p,std::size_t) noexcept -> void {dispose(p);}
auto operator delete(void* p,std::align_val_t) noexcept -> void {dispose(p);}
auto operator delete[](void* p,std::align_val_t) noexcept -> void {dispose(p);}
auto operator delete(void* p,std::size_t,std::align_val_t) noexcept -> void {dispose(p);}
auto operator delete[](void* p,std::size_t,std::align_val_t) noexcept -> void {dispose(p);}
