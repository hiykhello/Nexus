import std;
import tailscale.control;
import tailscale.control_connection;
import tls.profiles;
import tls.connector;
import tls.corosio_application;
import tls.corosio_client;
import platform.socket_options;
import http2.client_channel;
import memory.budget;
import crypto;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;
namespace noise=tailscale::control;
namespace cc=tailscale::control_connection;
namespace tls=tls;
namespace capy=nex::capy;
namespace io=nex::corosio;
using namespace std::chrono_literals;
std::size_t ordinary=0,aligned=0;
auto operator new(std::size_t n) -> void* {++ordinary;if (auto p=std::malloc(n ? n : 1)) return p;throw std::bad_alloc();}
auto operator new[](std::size_t n) -> void* {return ::operator new(n);}
auto operator delete(void* p) noexcept -> void {std::free(p);}
auto operator delete[](void* p) noexcept -> void {std::free(p);}
auto operator delete(void* p,std::size_t) noexcept -> void {std::free(p);}
auto operator delete[](void* p,std::size_t) noexcept -> void {std::free(p);}
auto operator new(std::size_t n,std::align_val_t a) -> void* {++aligned;auto align=static_cast<std::size_t>(a);auto size=(std::max(n,std::size_t{1})+align-1)/align*align;if (auto p=std::aligned_alloc(align,size)) return p;throw std::bad_alloc();}
auto operator new[](std::size_t n,std::align_val_t a) -> void* {return ::operator new(n,a);}
auto operator delete(void* p,std::align_val_t) noexcept -> void {std::free(p);}
auto operator delete[](void* p,std::align_val_t) noexcept -> void {std::free(p);}
auto operator delete(void* p,std::size_t,std::align_val_t) noexcept -> void {std::free(p);}
auto operator delete[](void* p,std::size_t,std::align_val_t) noexcept -> void {std::free(p);}
struct Meter : std::pmr::memory_resource {
    std::size_t count=0,bytes=0,live=0;
    auto do_allocate(std::size_t n,std::size_t a) -> void* override {++count;bytes+=n;++live;return std::pmr::new_delete_resource()->allocate(n,a);}
    auto do_deallocate(void* p,std::size_t n,std::size_t a) -> void override {--live;std::pmr::new_delete_resource()->deallocate(p,n,a);}
    auto do_is_equal(std::pmr::memory_resource const& o) const noexcept -> bool override {return this==&o;}
};
struct CountingConnector {
    using Socket=io::tcp_socket;
    std::size_t& calls;
    auto cancel() noexcept -> void {}
    auto application() noexcept -> tls::detail::ApplicationConnection<Socket>* {return nullptr;}
    auto start(cc::Clock::time_point) -> capy::task<tls::detail::ConnectResult> {++calls;co_return tls::detail::ConnectResult::failed;}
};
using Test=cc::Connection<CountingConnector,4>;
struct Resolver {
    auto cancel() noexcept -> void {}
    auto operator()(cc::Clock::time_point) -> capy::task<std::expected<std::array<io::endpoint,1>,int>> {co_return std::unexpected(1);}
};
using Physical=tls::detail::PhysicalConnector<Resolver,tls::ClientProfile>;
using Production=cc::Connection<Physical,4>;
struct Status {bool done=false,passed=false;};
auto rejected(Test& owner,Status& status,cc::Clock::time_point deadline,http2::ClientLimits limits,cc::Error wanted) -> capy::task<> {
    std::array<std::uint8_t,1> storage{};auto result=co_await owner.start("localhost",storage,deadline,limits);status.passed=!result && result.error().error==wanted && owner.drained() && !owner.channel();status.done=true;
}
auto key() -> noise::MachinePrivate {noise::KeyBytes bytes{};bytes[0]=1;auto result=noise::MachinePrivate::from_bytes(bytes);if (!result) throw std::runtime_error("key");return std::move(*result);}
auto main() -> int {
    auto local=key();noise::KeyBytes bytes{};bytes[0]=9;auto pin=*noise::ControlPublic::from_bytes(bytes);std::size_t calls=0;
    auto budget=std::make_shared<::memory::Budget>(8*1024*1024);auto old_ordinary=ordinary,old_aligned=aligned;
    for (unsigned i=0;i<1000;++i) {Test owner(local,pin,budget,0,calls);}
    auto construct_ordinary=ordinary-old_ordinary,construct_aligned=aligned-old_aligned;
    Test owner(local,pin,budget,0,calls);Meter meter;auto original=capy::get_current_frame_allocator();capy::set_current_frame_allocator(&meter);
    {std::array<std::uint8_t,1> storage{};auto operation=owner.start("localhost",storage,cc::Clock::now()+1s);}
    capy::set_current_frame_allocator(original);
    for (int mode=0;mode<5;++mode) {
        auto context=io::make_io_context(false);auto specific=mode==0 ? std::shared_ptr<::memory::Budget>{} :
            mode==1 ? std::make_shared<::memory::Budget>(Test::minimum_transport_bytes()-1) : std::make_shared<::memory::Budget>(8*1024*1024);
        Test test(local,pin,specific,mode==2 ? std::numeric_limits<std::size_t>::max() : 0,calls);http2::ClientLimits limits;
        if (mode==1) limits.shared_bytes=specific->limit();if (mode==3) limits.shared_bytes-=1;
        Status status;auto deadline=cc::Clock::now()+(mode==4 ? -1s : 1s);
        capy::run_async(context.get_executor())(rejected(test,status,deadline,limits,mode==4 ? cc::Error::timeout : cc::Error::limit));context.run_for(2s);
        if (!status.done || !status.passed || calls || (specific && specific->used())) return 1;
    }
    // A connector failure releases only when its owner is destroyed, preserving
    // admission while any asynchronous phase could still be in flight.
    {Test test(local,pin,budget,0,calls);auto context=io::make_io_context(false);Status status;
        capy::run_async(context.get_executor())(rejected(test,status,cc::Clock::now()+1s,{},cc::Error::connect));context.run_for(2s);
        if (!status.done || !status.passed || calls!=1 || budget->used()!=Test::minimum_transport_bytes()) return 2;
    }
    if (budget->used()) return 3;
    std::println("owner construct1000 ordinary={} aligned={}; start-frame count={} requested={} live={}",construct_ordinary,construct_aligned,meter.count,meter.bytes,meter.live);
    std::println("sizeof test={} physical={} tls-client={} TLSByteStream={} NoiseStream={} Channel={}; production-min-transport={}",sizeof(Test),sizeof(Production),sizeof(tls::detail::OwnedClient),sizeof(Production::TlsStream),sizeof(Production::NoiseStream),sizeof(Production::Channel),Production::minimum_transport_bytes());
    std::println("budget null/small/overflow/mismatch/expired reject before connector; connector failure and release all passed");
    return construct_ordinary || construct_aligned || meter.count!=1 || meter.live ? 4 : 0;
}
