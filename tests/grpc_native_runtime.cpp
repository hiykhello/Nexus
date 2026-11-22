import std;
extern "C" void* __real_malloc(std::size_t);
extern "C" void* __real_calloc(std::size_t,std::size_t);
extern "C" void* __real_realloc(void*,std::size_t);
extern "C" void __real_free(void*);
extern "C" int* __errno_location() noexcept;
extern "C" char __executable_start;
namespace native_audit {
    bool enabled=false,fired=false,persistent=false;
    thread_local bool audit_thread=false;
    std::size_t calls=0,fail_at=0,live=0,bytes=0,peak=0,mallocs=0,callocs=0,reallocs=0;
    struct Allocation {void* pointer=nullptr;std::size_t size=0;};
    std::array<Allocation,100000> pointers{};
    std::array<std::size_t,100000> sizes{};
    std::array<char,100000> kinds{};
    std::array<std::uintptr_t,100000> callers{};
    auto admit(std::size_t size,char kind,void* caller) noexcept -> bool {
        if (!enabled) return true;
        ++calls;if (kind=='m') ++mallocs;else if (kind=='c') ++callocs;else ++reallocs;
        if (calls<=sizes.size()) {sizes[calls-1]=size;kinds[calls-1]=kind;callers[calls-1]=reinterpret_cast<std::uintptr_t>(caller)-reinterpret_cast<std::uintptr_t>(&__executable_start);}
        if (fail_at && (calls==fail_at || (persistent && calls>fail_at))) {fired=true;*__errno_location()=static_cast<int>(std::errc::not_enough_memory);return false;}
        return true;
    }
    auto track(void* pointer,std::size_t size) noexcept -> void {
        if (enabled && pointer && calls<=pointers.size()) {
            pointers[calls-1]={pointer,size};++live;bytes+=size;peak=std::max(peak,bytes);
        }
    }
    auto untrack(void* pointer) noexcept -> void {
        if (!pointer) return;
        for (std::size_t i=0;i<std::min(calls,pointers.size());++i) if (pointers[i].pointer==pointer) {
            --live;bytes-=pointers[i].size;pointers[i]={};return;
        }
    }
    auto audit_exit() noexcept -> void {
        std::cerr<<"natural-exit native-live="<<live<<" bytes="<<bytes<<'\n'<<std::flush;
        if (live) std::_Exit(68);
    }
}
extern "C" void* __wrap_malloc(std::size_t size) {
    if (!native_audit::audit_thread) return __real_malloc(size);
    if (!native_audit::admit(size,'m',__builtin_return_address(0))) return nullptr;
    auto* result=__real_malloc(size);native_audit::track(result,size);return result;
}
extern "C" void* __wrap_calloc(std::size_t count,std::size_t width) {
    if (!native_audit::audit_thread) return __real_calloc(count,width);
    auto size=width && count>std::numeric_limits<std::size_t>::max()/width ? std::size_t{0} : count*width;
    if (!native_audit::admit(size,'c',__builtin_return_address(0))) return nullptr;
    auto* result=__real_calloc(count,width);native_audit::track(result,size);return result;
}
extern "C" void* __wrap_realloc(void* pointer,std::size_t size) {
    if (!native_audit::audit_thread) return __real_realloc(pointer,size);
    if (!native_audit::admit(size,'r',__builtin_return_address(0))) return nullptr;
    auto index=native_audit::pointers.size();
    for (std::size_t i=0;i<std::min(native_audit::calls,native_audit::pointers.size());++i)
        if (pointer && native_audit::pointers[i].pointer==pointer) {index=i;break;}
    auto* result=__real_realloc(pointer,size);
    if (result || !size) {
        if (index!=native_audit::pointers.size()) {
            --native_audit::live;native_audit::bytes-=native_audit::pointers[index].size;native_audit::pointers[index]={};
            if (!native_audit::enabled && result) {native_audit::pointers[index]={result,size};++native_audit::live;native_audit::bytes+=size;}
        }
        native_audit::track(result,size);
    }
    return result;
}
extern "C" void __wrap_free(void* pointer) {if (native_audit::audit_thread) native_audit::untrack(pointer);__real_free(pointer);}
extern "C" int nexus_test_grpc_runtime(char const*,char const*,unsigned,unsigned,unsigned,unsigned,
    void (*)(bool,std::size_t) noexcept,bool (*)() noexcept);
auto main(int argc,char** argv) -> int {
    std::atexit(native_audit::audit_exit);
    if (argc!=7 && argc!=8) return 64;
    native_audit::persistent=argc==8 && std::string_view(argv[7])=="persistent";
    auto number=[](char const* text) {return static_cast<unsigned>(std::stoul(text));};
    int result=0;std::thread worker([&] {result=nexus_test_grpc_runtime(argv[1],argv[2],number(argv[3]),number(argv[4]),number(argv[5]),number(argv[6]),
        [](bool enabled,std::size_t fail) noexcept {native_audit::audit_thread=true;native_audit::enabled=enabled;native_audit::fail_at=fail;},
        []() noexcept {return native_audit::fired;});});worker.join();
    std::println("audit calls={} malloc={} calloc={} realloc={} fired={} native-live={} bytes={} peak={}",native_audit::calls,native_audit::mallocs,native_audit::callocs,native_audit::reallocs,native_audit::fired,native_audit::live,native_audit::bytes,native_audit::peak);
    if (!number(argv[6])) for (std::size_t i=0;i<std::min(native_audit::calls,native_audit::sizes.size());++i)
        std::println("allocation={} kind={} size={} caller=0x{:x}",i+1,native_audit::kinds[i],native_audit::sizes[i],native_audit::callers[i]);
    return result;
}
