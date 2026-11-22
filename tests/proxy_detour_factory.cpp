import std;

namespace {
    std::atomic<std::size_t> live=0;
    thread_local std::ptrdiff_t remaining=-1;
    auto allocate(std::size_t size,std::size_t alignment=0) -> void* {
        if (remaining==0) throw std::bad_alloc();
        if (remaining>0) --remaining;
        size=std::max<std::size_t>(size,1);
        if (alignment && size>std::numeric_limits<std::size_t>::max()-(alignment-1)) throw std::bad_alloc();
        void* result=alignment ? std::aligned_alloc(alignment,((size+alignment-1)/alignment)*alignment) : std::malloc(size);
        if (!result) throw std::bad_alloc();
        ++live;
        return result;
    }
    auto release(void* pointer) noexcept -> void {
        if (pointer) { --live; std::free(pointer); }
    }
}

auto operator new(std::size_t size) -> void* { return allocate(size); }
auto operator new[](std::size_t size) -> void* { return allocate(size); }
auto operator new(std::size_t size,std::align_val_t alignment) -> void* { return allocate(size,static_cast<std::size_t>(alignment)); }
auto operator new[](std::size_t size,std::align_val_t alignment) -> void* { return allocate(size,static_cast<std::size_t>(alignment)); }
auto operator delete(void* pointer) noexcept -> void { release(pointer); }
auto operator delete[](void* pointer) noexcept -> void { release(pointer); }
auto operator delete(void* pointer,std::size_t) noexcept -> void { release(pointer); }
auto operator delete[](void* pointer,std::size_t) noexcept -> void { release(pointer); }
auto operator delete(void* pointer,std::align_val_t) noexcept -> void { release(pointer); }
auto operator delete[](void* pointer,std::align_val_t) noexcept -> void { release(pointer); }
auto operator delete(void* pointer,std::size_t,std::align_val_t) noexcept -> void { release(pointer); }
auto operator delete[](void* pointer,std::size_t,std::align_val_t) noexcept -> void { release(pointer); }

extern "C" int nexus_test_detour_factory(char const*,char const*,
    void (*)(std::ptrdiff_t) noexcept,std::size_t (*)() noexcept);

auto main(int argc,char** argv) -> int {
    if (argc!=3) return 1;
    return nexus_test_detour_factory(argv[1],argv[2],
        [](std::ptrdiff_t budget) noexcept { remaining=budget; },
        []() noexcept { return live.load(); });
}
