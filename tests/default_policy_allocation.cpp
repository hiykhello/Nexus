import std;
import platform.netlink_abi;
import platform.netlink_socket;
import packet.tun_linux;
import packet.tun_network_types;
import packet.tun_network;
import packet.tun_default_policy;
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
        auto device=p::LinuxTun::create("nx-cost");t::require(device.has_value());
        auto options=t::options();options.route_count=0;
        auto lease=p::TunNetworkLease<>::create(*device,options);t::require(lease.has_value());
        t::require(lease->start(t::deadline()).has_value());
        p::TunDefaultPolicy<Hooks> policy;
        auto started=policy.start(*lease,{},t::deadline(),t::deadline());t::require(started.has_value()==success);
        auto report=policy.stop(t::deadline());t::require(!report.preserved&&!report.uncertain&&policy.drained());
        if(success) {
            {p::TunDefaultPolicy<> abandoned;t::require(abandoned.start(*lease,{},t::deadline(),t::deadline()).has_value());}
            p::TunDefaultPolicy<> fresh;t::require(fresh.start(*lease,{},t::deadline(),t::deadline()).has_value());
            auto again=fresh.stop(t::deadline());t::require(!again.uncertain&&!again.preserved&&fresh.drained());
        }
        auto cleanup=lease->stop(t::deadline());t::require(!cleanup.total&&lease->drained()&&device->native_handle()<0);
    }
}
auto main(int argc,char**argv) -> int {
    try {
        t::isolation(argc,argv); auto baseline=live; tracking=true;
        lifecycle<n::NoHooks>(true); lifecycle<Reject>(false);
        tracking=false; t::require(!calls && !bytes && live==baseline && Reject::count>=4);
        std::println("default policy real TUN cold create, dual-family routes/rules/readback, stop, partial-start rollback and natural policy abandonment/recovery: ordinary/array/aligned/nothrow C++ new calls={} bytes={} live_delta=0; sizeof policy={} baselineLease={} tun={} socket={} options={}",
                     calls,bytes,sizeof(p::TunDefaultPolicy<>),sizeof(p::TunNetworkLease<>),sizeof(p::LinuxTun),sizeof(n::Socket<>),sizeof(p::TunNetworkOptions));
    } catch (int value) { tracking=false; return value; }
}
