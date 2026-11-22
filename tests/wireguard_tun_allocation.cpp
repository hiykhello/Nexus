import std;
import wireguard;
import wireguard.crypto;
import wireguard.port_types;
import wireguard.port;
import wireguard.tun;

extern "C" int fcntl(int,int,...);
namespace {
    bool tracking=false;
    std::size_t calls=0,bytes=0,live=0;
    auto allocate(std::size_t size,std::size_t alignment=0) -> void* {
        auto count=std::max<std::size_t>(size,1);
        auto value=alignment ? std::aligned_alloc(alignment,((count+alignment-1)/alignment)*alignment) : std::malloc(count);
        if (!value) throw std::bad_alloc{};
        ++live; if (tracking) { ++calls; bytes+=size; } return value;
    }
    auto release(void* value) noexcept -> void { if (value) { --live; std::free(value); } }
}
auto operator new(std::size_t size) -> void* { return allocate(size); }
auto operator new[](std::size_t size) -> void* { return allocate(size); }
auto operator new(std::size_t size,std::align_val_t alignment) -> void* { return allocate(size,static_cast<std::size_t>(alignment)); }
auto operator new[](std::size_t size,std::align_val_t alignment) -> void* { return allocate(size,static_cast<std::size_t>(alignment)); }
auto operator delete(void* value) noexcept -> void { release(value); }
auto operator delete[](void* value) noexcept -> void { release(value); }
auto operator delete(void* value,std::size_t) noexcept -> void { release(value); }
auto operator delete[](void* value,std::size_t) noexcept -> void { release(value); }
auto operator delete(void* value,std::align_val_t) noexcept -> void { release(value); }
auto operator delete[](void* value,std::align_val_t) noexcept -> void { release(value); }
auto operator delete(void* value,std::size_t,std::align_val_t) noexcept -> void { release(value); }
auto operator delete[](void* value,std::size_t,std::align_val_t) noexcept -> void { release(value); }

namespace {
    using namespace wireguard;
    using namespace std::chrono_literals;
    using Port=UdpPort<2,2,256,4>;
    using Tun=LinuxTunPort<Port>;
    auto run() -> bool {
        std::array<std::uint8_t,32> private_bytes{}; private_bytes[0]=42;
        auto port=Port::create(private_bytes); auto now=Clock::time_point(10s);
        if (!port || !port->open({4,{127,0,0,1},0},now,now+2s)) return false;
        auto closed=Port::create(private_bytes); if (!closed) return false;
        auto conflicting=Port::create(private_bytes); auto address=port->local_endpoint();
        if (!conflicting || !address || conflicting->open(*address,now) || conflicting->native_handle()<0 || conflicting->status().opened) return false;
        auto unbound=Tun::create(*conflicting,"nx-wg-cost",128);
        if (unbound || std::get<PortFailure>(unbound.error()).code!=PortError::not_open) return false;
        auto unopened=Tun::create(*closed,"nx-wg-cost",128);
        if (unopened || std::get<PortFailure>(unopened.error()).code!=PortError::not_open) return false;
        auto invalid_mtu=Tun::create(*port,"nx-wg-cost",257);
        if (invalid_mtu || port->native_handle()<0) return false;
        auto invalid_name=Tun::create(*port,"bad%name",128);
        if (invalid_name || port->native_handle()<0) return false;
        calls=bytes=0; tracking=true;
        auto adapter=Tun::create(*port,"nx-wg-cost",128); tracking=false;
        if (!adapter || calls || bytes || adapter->name()!="nx-wg-cost" || adapter->pending()) return false;
        auto fd=adapter->native_handle(),network_fd=port->native_handle();
        auto conflict=Tun::create(*port,"nx-wg-cost",128);
        if (conflict || adapter->native_handle()!=fd || port->native_handle()!=network_fd) return false;
        calls=bytes=0; tracking=true;
        for (unsigned i=0;i<1000;++i) {
            auto result=adapter->step(now+std::chrono::milliseconds(i),std::chrono::system_clock::time_point{});
            if (!result || result->device.input || result->device.output_delivered || adapter->pending()) { tracking=false; return false; }
        }
        auto expired=adapter->step(now+2s,std::chrono::system_clock::time_point{}); tracking=false;
        if (expired || std::get<PortFailure>(expired.error()).code!=PortError::timeout || calls || bytes || !adapter->drained() || ::fcntl(fd,3)>=0 || ::fcntl(network_fd,3)>=0) return false;
        adapter->stop(); return adapter->drained() && !adapter->pending() && adapter->native_handle()==-1;
    }
}

auto main() -> int {
    auto baseline=live;
    if (!run() || live!=baseline) { tracking=false; std::println("WireGuard real TUN allocation/lifetime/rollback failed"); return 1; }
    std::println("WireGuard real Linux TUN create, 1000 idle steps and deadline drain: 0 ordinary/aligned C++ allocations; failed name/MTU/port setup preserves active owners; sizeof default adapter={} test={}",sizeof(LinuxTunPort<UdpPort<>>),sizeof(Tun));
}
