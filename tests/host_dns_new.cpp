import std;
import platform.netlink_abi;
import platform.netlink_socket;
import platform.resolved_bus;
import packet.tun_linux;
import packet.tun_network;
import endpoint.host_dns_types;
import endpoint.resolved_dns;
import test.lease_support;
namespace e=endpoint;
namespace p = ::packet;
namespace r = ::platform::resolved;
namespace t=test::lease;
namespace {
    bool tracking=false,deny=false;
    std::size_t calls=0,bytes=0,live=0;
    auto allocate(std::size_t size,std::size_t alignment=0) -> void* {
        if(tracking && deny){++calls;bytes+=size;throw std::bad_alloc{};}
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

auto main(int argc,char**argv)->int {
 try {
  t::isolation(argc,argv);auto device=p::LinuxTun::create("nx-dnsnew");t::require(device.has_value());auto lease=p::TunNetworkLease<>::create(*device,t::options());t::require(lease.has_value());t::require(lease->start(t::deadline()).has_value());
  e::HostDnsOptions options;options.backend=e::HostDnsBackend::resolved;options.server_count=2;options.servers[0].address={10,42,0,2};options.servers[1].ipv6=true;options.servers[1].address[0]=0xfd;options.servers[1].address[1]=0x42;options.servers[1].address[15]=2;
  auto baseline=live;
  for(bool fail:{false,true}) {
   deny=fail;tracking=true;
   {e::ResolvedHostDns<> dns;auto result=dns.start(*lease,options,false,t::deadline(),t::deadline());t::require(result.has_value());auto checked=dns.poll(r::Clock::now()+std::chrono::seconds(1),t::deadline());t::require(checked.has_value());auto report=dns.stop(t::deadline());t::require(report.restored&&!report.preserved&&!report.uncertain&&dns.drained());}
   {e::ResolvedHostDns<> abandoned;auto result=abandoned.start(*lease,options,false,t::deadline(),t::deadline());t::require(result.has_value());}
   tracking=false;t::require(!calls && !bytes && live==baseline);
  }
  auto closed=lease->stop(t::deadline());t::require(!closed.total&&lease->drained());
  std::println("real resolved+sealed TUN lifecycle, runtime readback, selective stop and natural abandonment/recovery: ordinary/array/aligned/nothrow C++ new calls={} bytes={} liveDelta=0, persistent C++new failure enabled; native sd-bus allocations are measured separately",calls,bytes);
 }catch(int error){tracking=false;return error;}
}
