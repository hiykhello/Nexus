import std;
import net.datagram_driver;
import capy;
import corosio;

namespace io = ::corosio;
using Clock=std::chrono::steady_clock;
using namespace std::chrono_literals;
namespace allocations {
    struct Header { void* raw; std::size_t size; };
    std::size_t live=0,bytes=0,calls=0;
    bool enabled=false,denied=false;
    std::ptrdiff_t allowance=-1;
    bool verify_exit=false;
    auto allocate(std::size_t size,std::size_t alignment=alignof(std::max_align_t)) -> void* {
        if (enabled) { ++calls; if (!allowance) { denied=true; throw std::bad_alloc(); } if (allowance>0) --allowance; }
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
            if (live || bytes) { std::println("driver process-exit allocation leak live={} bytes={}",live,bytes); std::fflush(nullptr); std::_Exit(91); }
            std::println("driver process-exit tracked ordinary/array/aligned allocations=0");
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
namespace {
    struct Frames:std::pmr::memory_resource {
        struct Entry { void* pointer=nullptr; std::size_t bytes=0,alignment=0; };
        std::array<Entry,32> live{};
        std::array<std::size_t,128> sizes{};
        std::size_t calls=0,used=0,peak=0,denied=0;
        std::ptrdiff_t allowance=-1;
        auto do_allocate(std::size_t size,std::size_t alignment) -> void* override {
            if (calls>=sizes.size()) throw std::bad_alloc();
            sizes[calls++]=size;
            if (!allowance) { ++denied; throw std::bad_alloc(); }
            if (allowance>0) --allowance;
            auto slot=std::ranges::find(live,nullptr,&Entry::pointer); if (slot==live.end()) throw std::bad_alloc();
            auto* pointer=std::pmr::new_delete_resource()->allocate(size,alignment); *slot={pointer,size,alignment}; used+=size; peak=std::max(peak,used); return pointer;
        }
        auto do_deallocate(void* pointer,std::size_t size,std::size_t alignment) -> void override {
            auto slot=std::ranges::find(live,pointer,&Entry::pointer);
            if (slot==live.end() || slot->bytes!=size || slot->alignment!=alignment) std::terminate();
            used-=size; *slot={}; std::pmr::new_delete_resource()->deallocate(pointer,size,alignment);
        }
        auto do_is_equal(std::pmr::memory_resource const& other) const noexcept -> bool override { return this==&other; }
    };
    struct FrameScope {
        std::pmr::memory_resource* previous=capy::get_current_frame_allocator();
        explicit FrameScope(Frames& frames) { capy::set_current_frame_allocator(&frames); }
        ~FrameScope() { capy::set_current_frame_allocator(previous); }
    };
    struct Protocol {
        enum class Failure { unexpected_data };
        using Driver=net::DatagramDriver<Protocol>;
        Driver* driver=nullptr;
        io::endpoint peer;
        unsigned outputs=0,received=0,transmitted_count=0,requested=0,stops=0,drains=0;
        unsigned target=1;
        bool steady=false;
        std::size_t steady_calls=0;
        bool alive=true,business=true,broken=false;
        auto request_stop() noexcept -> void { ++requested; business=false; broken|=!alive; }
        auto stop() noexcept -> void { ++stops; alive=false; }
        auto drain() noexcept -> void { ++drains; broken|=alive; }
        auto next_expiry() const noexcept -> net::DatagramDeadline { return {}; }
        auto expire(Clock::time_point) -> std::expected<void,Failure> { return {}; }
        auto output(std::span<std::uint8_t> bytes,Clock::time_point) -> std::expected<std::optional<net::DatagramOutput>,Failure> {
            broken|=!business;
            if (outputs>received) return std::optional<net::DatagramOutput>{};
            ++outputs;
            std::fill(bytes.begin(),bytes.end(),42); return net::DatagramOutput{peer,bytes.size(),7};
        }
        auto transmitted(std::uint64_t token,Clock::time_point) -> std::expected<void,Failure> { broken|=!business || token!=7; ++transmitted_count; return {}; }
        auto receive(io::endpoint const&,std::span<std::uint8_t const> bytes,Clock::time_point) -> std::expected<void,Failure> {
            if (bytes.size()!=1500 || std::ranges::any_of(bytes,[](auto byte) { return byte!=42; })) return std::unexpected(Failure::unexpected_data);
            ++received;
            if (steady && received==100) { allocations::calls=0; allocations::allowance=-1; allocations::enabled=true; }
            if (received==target) { steady_calls=allocations::calls; if (steady) allocations::enabled=false; driver->finish(); }
            return {};
        }
    };
    auto trial(bool uring,std::ptrdiff_t allowance,Frames& frames,std::ptrdiff_t cpp=-1,unsigned count=1,bool steady=false) -> int {
        frames.allowance=allowance;
        bool done=false,caught=false,failed=false;
        {
            FrameScope scope(frames); io::io_context context=io::make_io_context(uring); context.set_frame_allocator(&frames);
            io::udp_socket socket(context); if (socket.open() || socket.bind(io::endpoint(io::ipv4_address::loopback(),0))) return 1;
            Protocol protocol; protocol.peer=socket.local_endpoint(); protocol.target=count; protocol.steady=steady;
            allocations::allowance=cpp; allocations::enabled=cpp>=0; allocations::denied=false; allocations::calls=0;
            {
                Protocol::Driver driver(socket,protocol,Clock::now()+300ms); protocol.driver=&driver;
                try {
                    auto run=driver.run();
                    capy::run_async(context.get_executor(),[&](auto result) { failed=bool(std::get<0>(result)); done=true; },
                        [&](std::exception_ptr) noexcept { caught=true; done=true; })(std::move(run));
                    context.run_for(500ms);
                } catch (std::bad_alloc const&) { caught=true; }
                allocations::enabled=false;
                if (!frames.denied && !allocations::denied && (!done || caught || failed || !driver.drained() || driver.failure() || protocol.received!=count || protocol.transmitted_count!=count || (steady && protocol.steady_calls))) return 2;
                if ((frames.denied || allocations::denied) && !caught && !driver.failure()) return 3;
                driver.cancel();
            }
            if (protocol.broken || protocol.alive || protocol.requested!=1 || protocol.stops!=1 || protocol.drains!=1) return 4;
        }
        return frames.used ? 5 : 0;
    }
}
auto main(int argc,char** argv) -> int {
    if (argc==3 && std::string_view(argv[1])=="--steady") {
        bool uring=std::string_view(argv[2])=="1"; Frames frames;
        auto error=trial(uring,-1,frames,-1,1100,true);
        if (error) { std::println("driver steady allocation failed backend={} error={}",uring,error); return 9; }
        std::println("driver real UDP backend={} 1000 steady datagrams, ordinary/array/aligned new=0; total persistent frame allocations={} peak={} bytes",uring,frames.calls,frames.peak);
        return 0;
    }
    if (argc==4) {
        bool pmr=std::string_view(argv[1])=="pmr",uring=std::string_view(argv[3])=="1";
        (void)pmr;
        Frames frames;
        auto error=trial(uring,-1,frames,-1);
        if (error) { std::println("driver fresh-process backend={} error={}",uring,error); return 6; }
        Frames recovery; if (trial(uring,-1,recovery)) return 7;
        allocations::verify_exit=true;
        std::println("driver fresh-process backend={} denied=false cppcalls={} framecalls={} framepeak={} recovery=true context-unwind=true",uring,allocations::calls,frames.calls,frames.peak);
        return 0;
    }
    if (argc!=1) return 8;
    for (bool uring:{false,true}) {
        if (uring && !io::has_uring) continue;
        Frames steady_frames;
        if (auto error=trial(uring,-1,steady_frames,-1,1100,true)) {
            std::println("driver steady allocation failed backend={} error={}",uring,error);
            return 9;
        }
        Frames recovery;
        if (auto error=trial(uring,-1,recovery,-1)) {
            std::println("driver recovery allocation failed backend={} error={}",uring,error);
            return 10;
        }
        std::println("driver real UDP backend={} 1000 steady datagrams, ordinary/array/aligned new=0; persistent frame calls={} peak={} bytes",uring,steady_frames.calls,steady_frames.peak);
    }
    std::println("steady-state zero-allocation datagram driver verified; every PMR frame released after stop/join");
}
