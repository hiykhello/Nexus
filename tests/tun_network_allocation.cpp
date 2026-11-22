import std;
import platform.netlink_abi;
import platform.netlink_socket;
import packet.tun_linux;
import packet.tun_network_types;
import packet.tun_network;
import nexus.test.lease_support;
namespace a = ::platform::netlink_abi;
namespace n = ::platform::netlink;
namespace p = ::packet;
namespace t=nexus::test::lease;
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
auto operator new(std::size_t size,std::nothrow_t const&) noexcept -> void* { try { return allocate(size); } catch (...) { return nullptr; } }
auto operator new[](std::size_t size,std::nothrow_t const&) noexcept -> void* { try { return allocate(size); } catch (...) { return nullptr; } }
auto operator new(std::size_t size,std::align_val_t alignment,std::nothrow_t const&) noexcept -> void* { try { return allocate(size,static_cast<std::size_t>(alignment)); } catch (...) { return nullptr; } }
auto operator new[](std::size_t size,std::align_val_t alignment,std::nothrow_t const&) noexcept -> void* { try { return allocate(size,static_cast<std::size_t>(alignment)); } catch (...) { return nullptr; } }
auto operator delete(void* value) noexcept -> void { release(value); }
auto operator delete[](void* value) noexcept -> void { release(value); }
auto operator delete(void* value,std::size_t) noexcept -> void { release(value); }
auto operator delete[](void* value,std::size_t) noexcept -> void { release(value); }
auto operator delete(void* value,std::align_val_t) noexcept -> void { release(value); }
auto operator delete[](void* value,std::align_val_t) noexcept -> void { release(value); }
auto operator delete(void* value,std::size_t,std::align_val_t) noexcept -> void { release(value); }
auto operator delete[](void* value,std::size_t,std::align_val_t) noexcept -> void { release(value); }
auto operator delete(void* value,std::nothrow_t const&) noexcept -> void { release(value); }
auto operator delete[](void* value,std::nothrow_t const&) noexcept -> void { release(value); }
auto operator delete(void* value,std::align_val_t,std::nothrow_t const&) noexcept -> void { release(value); }
auto operator delete[](void* value,std::align_val_t,std::nothrow_t const&) noexcept -> void { release(value); }
namespace {
    struct Reject : n::NoHooks {
        static inline unsigned count=0;
        static auto before_send(std::span<std::uint8_t const>,bool mutation) noexcept -> std::error_code {
            if (mutation && ++count==4) return std::make_error_code(std::errc::permission_denied);
            return {};
        }
    };
    template<class Hooks> auto lifecycle(bool success) -> void {
        auto device=p::LinuxTun::create("nx-cost"); t::require(device.has_value());
        auto fd=device->native_handle();
        auto invalid=t::options(); invalid.mtu=0;
        t::require(!p::TunNetworkLease<Hooks>::create(*device,invalid) && device->native_handle()==fd);
        auto lease=p::TunNetworkLease<Hooks>::create(*device,t::options()); t::require(lease.has_value());
        auto started=lease->start(t::deadline()); t::require(started.has_value()==success);
        if (success) {
            auto state=lease->status(); t::require(state.started && state.addresses==2 && state.routes==2);
            auto report=lease->stop(t::deadline()); t::require(!report.total);
        }
        t::require(lease->drained() && device->native_handle()<0 && a::fcntl(fd,a::F_GETFD)<0);
    }
}
auto main(int argc,char**argv) -> int {
    try {
        t::isolation(argc,argv); auto baseline=live; tracking=true;
        lifecycle<n::NoHooks>(true); lifecycle<Reject>(false);
        tracking=false; t::require(!calls && !bytes && live==baseline && Reject::count>=4);
        std::println("real TUN lease cold create, dual-family start/readback, stop and partial-start rollback: ordinary/array/aligned/nothrow C++ new calls={} bytes={} live_delta=0; sizeof lease={} tun={} socket={} options={}",
                     calls,bytes,sizeof(p::TunNetworkLease<>),sizeof(p::LinuxTun),sizeof(n::Socket<>),sizeof(p::TunNetworkOptions));
    } catch (int value) { tracking=false; return value; }
}
