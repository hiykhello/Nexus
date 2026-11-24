import std;
import net.datagram_driver;
import capy;
import corosio;
namespace io = ::corosio;
using namespace std::chrono_literals;
using Clock=std::chrono::steady_clock;
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

struct Socket {
    io::io_context& ctx;
    bool reading=false,writing=false,closed=false;
    struct Flight { bool& flag; explicit Flight(bool& value):flag(value) { if (flag) std::abort(); flag=true; } ~Flight() { flag=false; } };
    auto context() const noexcept -> io::io_context& { return ctx; }
    auto close() noexcept -> void { closed=true; }
    auto recv_from(capy::mutable_buffer,io::endpoint&) -> capy::task<capy::results<std::size_t>> {
        Flight flight(reading); auto [error]=co_await io::delay(60s); co_return capy::results<std::size_t>{error,0};
    }
    auto send_to(capy::const_buffer,io::endpoint const&) -> capy::task<capy::results<std::size_t>> {
        Flight flight(writing); auto [error]=co_await io::delay(60s); co_return capy::results<std::size_t>{error,0};
    }
};
struct Protocol {
    using Failure=int;
    Socket& socket;
    unsigned requests=0,stops=0,drains=0;
    bool valid=true,output_started=false;
    auto request_stop() noexcept -> void { ++requests; }
    auto stop() noexcept -> void { ++stops; valid&=!socket.reading&&!socket.writing; }
    auto drain() noexcept -> void { ++drains; valid&=!socket.reading&&!socket.writing; }
    auto next_expiry() const noexcept -> net::DatagramDeadline { return Clock::now()+30s; }
    auto expire(Clock::time_point) -> std::expected<void,int> { return {}; }
    auto receive(io::endpoint const&,std::span<std::uint8_t const>,Clock::time_point) -> std::expected<void,int> { return {}; }
    auto output(std::span<std::uint8_t> bytes,Clock::time_point) -> std::expected<std::optional<net::DatagramOutput>,int> {
        if (std::exchange(output_started,true)) return std::optional<net::DatagramOutput>{};
        bytes[0]=42; return net::DatagramOutput{io::endpoint(io::ipv4_address::loopback(),9),1,1};
    }
    auto transmitted(std::uint64_t,Clock::time_point) -> std::expected<void,int> { return {}; }
};
auto trial(bool uring) -> bool {
    auto context=std::unique_ptr<io::io_context>(new io::io_context(io::make_io_context(uring)));
    Socket socket{*context}; Protocol protocol{socket}; bool done=false;
    net::DatagramDriver<Protocol,Socket> driver(socket,protocol,Clock::now()+30s);
    // Creating and discarding an unstarted task leaves the one-shot driver
    // untouched. A dormant duplicate must also leave an active run untouched.
    { auto discarded=driver.run(); }
    std::optional<decltype(driver.run())> dormant_duplicate;
    dormant_duplicate.emplace(driver.run());
    capy::run_async(context->get_executor(),[&](auto) { done=true; },[&](std::exception_ptr) noexcept { done=true; })(driver.run());
    context->run_for(5ms);
    if (done || !socket.reading || !socket.writing || !driver.running()) return false;
    dormant_duplicate.reset();
    if (done || !driver.running() || protocol.requests || protocol.stops || protocol.drains) return false;
    bool duplicate_done=false,duplicate_failed=false;
    capy::run_async(context->get_executor(),[&](capy::results<> result) { duplicate_done=true;duplicate_failed=std::get<0>(result)==std::make_error_code(std::errc::operation_not_permitted); },[&](std::exception_ptr) noexcept { duplicate_done=true; })(driver.run());
    context->restart();context->run_for(1ms);
    if (!duplicate_done || !duplicate_failed || done || !driver.running() || protocol.requests) return false;
    context.reset();
    std::println("driver natural context abandon backend={} done={} reading={} writing={} drained={} requests={} stops={} drains={} valid={}",uring,done,socket.reading,socket.writing,driver.drained(),protocol.requests,protocol.stops,protocol.drains,protocol.valid);
    std::fflush(nullptr);
    return !done && !socket.reading && !socket.writing && driver.drained() && protocol.requests==1 && protocol.stops==1 && protocol.drains==1 && protocol.valid;
}
auto queued(bool uring) -> bool {
    auto context=std::unique_ptr<io::io_context>(new io::io_context(io::make_io_context(uring)));
    Socket socket{*context};Protocol protocol{socket};bool done=false;
    net::DatagramDriver<Protocol,Socket> driver(socket,protocol);
    capy::run_async(context->get_executor(),[&](auto) { done=true; })(driver.run());
    // The executor has queued the launcher but has never run it.
    context.reset();
    bool valid=!done && !socket.reading && !socket.writing && !driver.drained() && !driver.running() && !protocol.requests && !protocol.stops && !protocol.drains;
    driver.cancel();
    std::println("driver queued never-started context abandon backend={} valid={} native_stops_before_owner_destroy={}",uring,valid,protocol.stops);
    return valid;
}
auto main(int argc,char** argv) -> int {
    if (argc!=2) return 1;
    bool uring=std::string_view(argv[1])=="1";
    if (!trial(uring) || !queued(uring)) return 2;
    allocations::verify_exit=true;
}
