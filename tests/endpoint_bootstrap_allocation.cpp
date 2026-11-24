import std;
import endpoint.config;
import endpoint.credentials;
import endpoint.process_signals;
import endpoint.bootstrap;
import corosio;
import endpoint.owner;
import wireguard.port;
import capy;
namespace allocation {
    struct Header { void* raw; std::size_t size; bool tracked; };
    std::size_t calls=0,live=0,bytes=0,total=0,peak=0;
    std::ptrdiff_t allowance=-1;
    bool enabled=false,denied=false,verify_exit=false;
    auto allocate(std::size_t size,std::size_t alignment=alignof(std::max_align_t)) -> void* {
        if (enabled) { ++calls; if (!allowance) { denied=true; throw std::bad_alloc(); } if (allowance>0) --allowance; }
        size=std::max<std::size_t>(size,1); alignment=std::max(alignment,alignof(Header));
        if (size>std::numeric_limits<std::size_t>::max()-alignment-sizeof(Header)) throw std::bad_alloc();
        auto* raw=std::malloc(size+alignment+sizeof(Header)); if (!raw) throw std::bad_alloc();
        auto address=(reinterpret_cast<std::uintptr_t>(raw)+sizeof(Header)+alignment-1)/alignment*alignment;
        auto* out=reinterpret_cast<Header*>(address); out[-1]={raw,size,enabled};
        if (enabled) { ++live; bytes+=size; total+=size;peak=std::max(peak,bytes); } return out;
    }
    auto release(void* pointer) noexcept -> void {
        if (!pointer) return;
        auto block=static_cast<Header*>(pointer)[-1]; if (block.tracked) { --live; bytes-=block.size; } std::free(block.raw);
    }
    struct Final {
        ~Final() {
            if (!verify_exit) return;
            if (live || bytes) { std::println("process-exit tracked allocation leak live={} bytes={}",live,bytes); std::fflush(nullptr); std::_Exit(91); }
            std::println("process-exit tracked ordinary/array/aligned allocations=0 after upstream recycling pools destruct");
        }
    } final;
}
auto operator new(std::size_t size) -> void* { return allocation::allocate(size); }
auto operator new[](std::size_t size) -> void* { return allocation::allocate(size); }
auto operator new(std::size_t size,std::align_val_t alignment) -> void* { return allocation::allocate(size,static_cast<std::size_t>(alignment)); }
auto operator new[](std::size_t size,std::align_val_t alignment) -> void* { return allocation::allocate(size,static_cast<std::size_t>(alignment)); }
auto operator delete(void* pointer) noexcept -> void { allocation::release(pointer); }
auto operator delete[](void* pointer) noexcept -> void { allocation::release(pointer); }
auto operator delete(void* pointer,std::size_t) noexcept -> void { allocation::release(pointer); }
auto operator delete[](void* pointer,std::size_t) noexcept -> void { allocation::release(pointer); }
auto operator delete(void* pointer,std::align_val_t) noexcept -> void { allocation::release(pointer); }
auto operator delete[](void* pointer,std::align_val_t) noexcept -> void { allocation::release(pointer); }
auto operator delete(void* pointer,std::size_t,std::align_val_t) noexcept -> void { allocation::release(pointer); }
auto operator delete[](void* pointer,std::size_t,std::align_val_t) noexcept -> void { allocation::release(pointer); }

auto main(int argc,char**argv) -> int {
    if(argc!=4)return 2;
    if(std::string_view(argv[2])=="uring" && !corosio::has_uring)return 77;
    auto input=std::ifstream(argv[1]);std::string text((std::istreambuf_iterator<char>(input)),{});
    auto config=endpoint::parse_kdl(text);if(!config)return 1;
    endpoint::process::Signals signals;if(!signals.install())return 1;
    auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(3);
    auto material=endpoint::prepare_credentials(config->wireguard,deadline);if(!material)return 1;
    auto descriptors=[] {std::size_t count=0;for(auto const& entry:std::filesystem::directory_iterator("/proc/self/fd")){(void)entry;++count;}return count;};
    auto original_fds=descriptors();
    auto before=capy::get_current_frame_allocator();
    allocation::allowance=std::stoll(argv[3]);allocation::enabled=true;allocation::verify_exit=true;
    bool success=false,caught=false;
    try { auto resolved=endpoint::bootstrap(config->wireguard,*material,deadline,signals,std::string_view(argv[2])=="uring");success=resolved.has_value(); }
    catch(std::bad_alloc const&) {caught=true;}
    allocation::enabled=false;allocation::allowance=-1;
    auto calls=allocation::calls;auto denied=allocation::denied;
    if(capy::get_current_frame_allocator()!=before)return 5;
    if(!denied && (!success || caught))return 6;
    std::raise(15);if(!signals.requested())return 7;
    // Recovery uses a fresh local owner with the same process signal globals,
    // backend and credentials after the rejected initialization fully unwinds.
    endpoint::process::requested_signal=0;
    auto recovered=endpoint::bootstrap(config->wireguard,*material,std::chrono::steady_clock::now()+std::chrono::seconds(3),signals,std::string_view(argv[2])=="uring");
    if(!recovered)return 8;
    std::raise(2);if(!signals.requested())return 9;
    if(descriptors()!=original_fds)return 12;
    for(std::size_t i=0;i<material->count;++i)if(!material->peers[i].selected || material->peers[i].selected->address[3]!=i+2)return 10;
    allocation::calls=0;allocation::enabled=true;
    {endpoint::Owner<> owner(config->wireguard,*material);}
    allocation::enabled=false;auto construction=allocation::calls;if(construction)return 11;
    std::printf("denied=%u calls=%zu success=%u caught=%u bytes=%zu peak=%zu owner=%zu port=%zu process_signals=%zu owner_ctor_new=%zu signal_wake_fds_after=0\n",unsigned(denied),calls,unsigned(success),unsigned(caught),allocation::total,allocation::peak,sizeof(endpoint::Owner<>),sizeof(wireguard::UdpPort<>),sizeof(endpoint::process::Signals),construction);
    return 0;
}
