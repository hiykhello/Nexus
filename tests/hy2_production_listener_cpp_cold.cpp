import std;
import crypto;
import tls.server_credential;
import nexus.thirdparty.corosio;
import nexus.test.quic_tls_link;
import hysteria2.credential;
import nexus.test.hy2_production_resource_link;
namespace io=nex::corosio;namespace support=nexus::test::quic_tls;namespace mem=nexus::test::hy2_production_resource;
namespace allocations {
    struct Header { void* raw; std::size_t size; };
    std::size_t live=0,bytes=0,calls=0;
    bool enabled=false,denied=false;
    std::ptrdiff_t allowance=-1;
    bool verify_exit=false;
    auto allocate(std::size_t size,std::size_t alignment=alignof(std::max_align_t)) -> void* {
        if (enabled) { ++calls; if (!allowance) { denied=true;mem::cpp_denied=true;enabled=false;throw std::bad_alloc(); } if (allowance>0) --allowance; }
        size=std::max<std::size_t>(size,1); alignment=std::max(alignment,alignof(Header));
        if (size>std::numeric_limits<std::size_t>::max()-alignment-sizeof(Header)) throw std::bad_alloc();
        auto* raw=std::malloc(size+alignment+sizeof(Header)); if (!raw) throw std::bad_alloc();
        auto address=(reinterpret_cast<std::uintptr_t>(raw)+sizeof(Header)+alignment-1)/alignment*alignment;
        auto* out=reinterpret_cast<Header*>(address); out[-1]={raw,size}; ++live; bytes+=size; return out;
    }
    auto release(void* pointer) noexcept -> void {
        if (!pointer) return;
        auto saved=static_cast<Header*>(pointer)[-1]; --live; bytes-=saved.size; std::free(saved.raw);
    }
    struct Final {
        ~Final() {
            if (!verify_exit) return;
            if (live || bytes) { std::printf("Hy2 C++ process-exit allocation leak live=%zu bytes=%zu\n",live,bytes); std::fflush(nullptr); std::_Exit(91); }
            std::puts("Hy2 C++ process-exit tracked ordinary/array/aligned allocations=0");
        }
    } final;
}
auto operator new(std::size_t size) -> void* { return allocations::allocate(size); }
auto operator new[](std::size_t size) -> void* { return allocations::allocate(size); }
auto operator new(std::size_t size,std::align_val_t alignment) -> void* { return allocations::allocate(size,static_cast<std::size_t>(alignment)); }
auto operator new[](std::size_t size,std::align_val_t alignment) -> void* { return allocations::allocate(size,static_cast<std::size_t>(alignment)); }
auto operator delete(void* pointer) noexcept -> void { allocations::release(pointer); }
auto operator delete[](void* pointer) noexcept -> void { allocations::release(pointer); }
auto operator delete(void* pointer,std::size_t) noexcept -> void { allocations::release(pointer); }
auto operator delete[](void* pointer,std::size_t) noexcept -> void { allocations::release(pointer); }
auto operator delete(void* pointer,std::align_val_t) noexcept -> void { allocations::release(pointer); }
auto operator delete[](void* pointer,std::align_val_t) noexcept -> void { allocations::release(pointer); }
auto operator delete(void* pointer,std::size_t,std::align_val_t) noexcept -> void { allocations::release(pointer); }
auto operator delete[](void* pointer,std::size_t,std::align_val_t) noexcept -> void { allocations::release(pointer); }

auto main(int argc,char** argv) -> int {
    if(argc!=5)return 1;
    allocations::verify_exit=true;
    auto cert=support::read(argv[1]),key=support::read(argv[2]);auto credential=tls::ServerCredential::create(cert,key);::crypto::cleanse(key);if(!credential)return 2;
    bool uring=std::string_view(argv[3])=="1";auto target=std::stoull(argv[4]);
    io::io_context context=io::make_io_context(uring);mem::Heap::arm(0);
    auto password=hysteria2::Password::create(support::bytes("test-password"));if(!password)return 2;
    bool passed=false,clean=false,caught=false;
    allocations::enabled=true;allocations::calls=0;allocations::denied=false;allocations::allowance=target?static_cast<std::ptrdiff_t>(target-1):-1;
    try {passed=mem::phase(context,*credential,cert,*password,&clean);}
    catch(std::bad_alloc const&){caught=true;}
    allocations::enabled=false;auto denied=allocations::denied;auto calls=allocations::calls;
    if(!denied && (!passed || !clean))return 3;
    if(mem::Heap::blocks)return 4;
    mem::cpp_denied=false;
    if(!mem::phase(context,*credential,cert,*password) || mem::Heap::blocks)return 5;
    std::printf("Hy2 shared port C++ cold backend=%d target=%llu denied=%s calls=%zu caught=%d phase_clean=%d native_oracle=%d native_objects=%zu same_context_new_owner_recovery=true\n",uring,target,denied?"true":"false",calls,caught,clean,!mem::Heap::blocks,mem::Heap::blocks);
    return target && !denied?6:0;
}
