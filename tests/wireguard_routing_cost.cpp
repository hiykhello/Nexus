import std;
import wireguard;
import wireguard.endpoint;
import wireguard.registry;
import wireguard.host;
import wireguard.routing;

namespace {
    bool track_allocations=false;
    std::size_t allocation_calls=0,allocation_bytes=0;
    auto allocate(std::size_t size,std::size_t alignment=0) -> void* {
        if (track_allocations) { ++allocation_calls; allocation_bytes+=size; }
        size=std::max<std::size_t>(size,1);
        if (alignment && size>std::numeric_limits<std::size_t>::max()-(alignment-1)) throw std::bad_alloc{};
        auto result=alignment ? std::aligned_alloc(alignment,((size+alignment-1)/alignment)*alignment) : std::malloc(size);
        if (!result) throw std::bad_alloc{}; return result;
    }
    auto release(void* pointer) noexcept -> void { std::free(pointer); }
    struct AllocationScope {
        AllocationScope() { allocation_calls=allocation_bytes=0; track_allocations=true; }
        ~AllocationScope() { track_allocations=false; }
    };
}
auto operator new(std::size_t size) -> void* { return allocate(size); }
auto operator new[](std::size_t size) -> void* { return allocate(size); }
auto operator new(std::size_t size,std::align_val_t alignment) -> void* { return allocate(size,static_cast<std::size_t>(alignment)); }
auto operator new[](std::size_t size,std::align_val_t alignment) -> void* { return allocate(size,static_cast<std::size_t>(alignment)); }
auto operator new(std::size_t size,std::nothrow_t const&) noexcept -> void* { try { return allocate(size); } catch (...) { return nullptr; } }
auto operator new[](std::size_t size,std::nothrow_t const&) noexcept -> void* { try { return allocate(size); } catch (...) { return nullptr; } }
auto operator new(std::size_t size,std::align_val_t alignment,std::nothrow_t const&) noexcept -> void* { try { return allocate(size,static_cast<std::size_t>(alignment)); } catch (...) { return nullptr; } }
auto operator new[](std::size_t size,std::align_val_t alignment,std::nothrow_t const&) noexcept -> void* { try { return allocate(size,static_cast<std::size_t>(alignment)); } catch (...) { return nullptr; } }
auto operator delete(void* pointer) noexcept -> void { release(pointer); }
auto operator delete[](void* pointer) noexcept -> void { release(pointer); }
auto operator delete(void* pointer,std::size_t) noexcept -> void { release(pointer); }
auto operator delete[](void* pointer,std::size_t) noexcept -> void { release(pointer); }
auto operator delete(void* pointer,std::align_val_t) noexcept -> void { release(pointer); }
auto operator delete[](void* pointer,std::align_val_t) noexcept -> void { release(pointer); }
auto operator delete(void* pointer,std::size_t,std::align_val_t) noexcept -> void { release(pointer); }
auto operator delete[](void* pointer,std::size_t,std::align_val_t) noexcept -> void { release(pointer); }
auto operator delete(void* pointer,std::nothrow_t const&) noexcept -> void { release(pointer); }
auto operator delete[](void* pointer,std::nothrow_t const&) noexcept -> void { release(pointer); }
auto operator delete(void* pointer,std::align_val_t,std::nothrow_t const&) noexcept -> void { release(pointer); }
auto operator delete[](void* pointer,std::align_val_t,std::nothrow_t const&) noexcept -> void { release(pointer); }

namespace {
    using namespace wireguard;
    auto address(std::size_t index) -> std::array<std::uint8_t,4> { return {10,42,static_cast<std::uint8_t>(index>>8),static_cast<std::uint8_t>(index)}; }
    auto prefix(std::size_t index,std::uint8_t bits=32) -> routing::Prefix {
        routing::Prefix result{4,{},bits}; std::ranges::copy(address(index),result.address.begin()); return result;
    }
    auto fixed_operations_no_allocations() -> bool {
        AllocationScope tracking;
        PeerHost<2,4,256,2> host;
        routing::RouteTable<2,8> routes;
        auto& registry=host.registry(); auto peer=registry.add(),other=registry.add();
        if (!peer || !other || !routes.activate(*peer) || !routes.activate(*other) || !routes.assign(*peer,{4,{},0}) || !routes.assign(*other,prefix(1))) return false;
        if (!registry.sync(*peer,{},1)) return false;
        auto index=registry.reserve(*peer,1,7,IndexMode::exact); if (!index) return false;
        ReceiverIndexes snapshot{}; snapshot[0]={true,index->index,index->ticket};
        if (!registry.sync(*peer,snapshot,1)) return false;
        std::array<std::uint8_t,transport_overhead> wire{}; wire[0]=4; store_le32(std::span(wire).subspan<4,4>(),index->index);
        EndpointAddress source{4,{198,51,100,1},10001};
        for (unsigned step=0;step<1000;++step) {
            auto policy=routes.view(*peer);
            auto address0=address(0),address1=address(1);
            if (!policy.permits(4,address0) || policy.permits(4,address1) || routes.lookup(4,address1)!=*other) return false;
            if (!host.enqueue_indexed(wire,source,true) || !host.enqueue_indexed(wire,source,true) || host.enqueue_indexed(wire,source,true)) return false;
            auto first=host.take(),second=host.take();
            if (!first || !second || !host.valid(*first) || first->serial>=second->serial || host.take()) return false;
            if (!routes.assign(*peer,prefix(1)) || routes.lookup(4,address1)!=*peer || !routes.assign(*other,prefix(1))) return false;
        }
        if (!host.enqueue_indexed(wire,source,true) || !routes.erase(*peer) || !registry.erase(*peer) || host.status().packets || host.status().bytes) return false;
        auto replacement=registry.add();
        if (!replacement || !routes.activate(*replacement) || routes.valid(*peer) || routes.erase(*peer) || routes.activate(*peer)) return false;
        if (!routes.assign(*replacement,prefix(2)) || !routes.unassign(*replacement,prefix(2)) || !routes.erase(*replacement) || !registry.erase(*replacement) || !routes.erase(*other) || !registry.erase(*other)) return false;
        return allocation_calls==0 && allocation_bytes==0;
    }
    struct Measurement { std::chrono::nanoseconds elapsed; std::uint64_t accumulator; };
    template<class Accept> [[gnu::noinline]] auto measure(std::span<std::array<std::uint8_t,4> const> addresses,std::size_t count,Accept accept) -> Measurement {
        auto begin=std::chrono::steady_clock::now(); std::uint64_t accumulator=0;
        for (std::size_t i=0;i<count;++i) {
            auto const& current=addresses[(i*37+accumulator)%addresses.size()];
            accumulator+=std::uint64_t(accept(current))+(current[3]&3);
        }
        return {std::chrono::steady_clock::now()-begin,accumulator};
    }
    auto benchmark_equivalence(std::size_t iterations) -> bool {
        constexpr std::size_t routes_count=32,rounds=7;
        routing::RouteTable<2,routes_count+1> routes;
        PeerHandle peer{0,1},other{1,1};
        if (!routes.activate(peer) || !routes.activate(other) || !routes.assign(other,{4,{},0})) return false;
        for (std::size_t i=0;i<routes_count;++i) if (!routes.assign(i%2 ? peer : other,prefix(i))) return false;
        std::array<std::array<std::uint8_t,4>,64> addresses{};
        for (std::size_t i=0;i<addresses.size();++i) addresses[i]=address(i);
        auto policy=routes.view(peer);
        for (auto const& item:addresses) if (policy.permits(4,item)!=(routes.lookup(4,item)==peer)) return false;
        // Warm module/runtime paths outside the tracked/timed operation.
        (void)measure(addresses,addresses.size(),[&](auto const& item) { return policy.permits(4,item); });
        std::array<std::chrono::nanoseconds,rounds> direct{},view{};
        std::uint64_t checksum=0;
        {
            AllocationScope tracking;
            for (std::size_t round=0;round<rounds;++round) {
                Measurement first{},second{};
                if (round%2) {
                    first=measure(addresses,iterations,[&](auto const& item) { return policy.permits(4,item); });
                    second=measure(addresses,iterations,[&](auto const& item) { return routes.lookup(4,item)==peer; });
                    view[round]=first.elapsed; direct[round]=second.elapsed;
                } else {
                    first=measure(addresses,iterations,[&](auto const& item) { return routes.lookup(4,item)==peer; });
                    second=measure(addresses,iterations,[&](auto const& item) { return policy.permits(4,item); });
                    direct[round]=first.elapsed; view[round]=second.elapsed;
                }
                if (first.accumulator!=second.accumulator) return false;
                checksum+=first.accumulator;
            }
            if (allocation_calls || allocation_bytes) return false;
        }
        std::ranges::sort(direct); std::ranges::sort(view);
        std::println("WireGuard small-table authorization comparison: routes={} lookups/round={} rounds={} direct median={:.2f} ns/view median={:.2f} ns checksum={} C++ allocations={} bytes={}",
            routes_count+1,iterations,rounds,double(direct[rounds/2].count())/iterations,double(view[rounds/2].count())/iterations,checksum,allocation_calls,allocation_bytes);
        return true;
    }
}

auto main(int argc,char** argv) -> int {
    std::size_t iterations=200000;
    if (argc>2) return 1;
    if (argc==2) {
        auto end=argv[1]+std::char_traits<char>::length(argv[1]); auto parsed=std::from_chars(argv[1],end,iterations);
        if (parsed.ec!=std::errc{} || parsed.ptr!=end || !iterations || iterations>100000000) return 1;
    }
    if (!fixed_operations_no_allocations()) { std::println("WireGuard fixed host/registry/routing operation allocated or changed semantics"); return 2; }
    auto operation_calls=allocation_calls,operation_bytes=allocation_bytes;
    if (!benchmark_equivalence(iterations)) { std::println("WireGuard direct/view authorization equivalence or allocation check failed"); return 3; }
    std::println("WireGuard fixed operations C++ allocations={} bytes={}; sizeof registry={} host={} route-table32/1024={} source-view={}; timing covers small-table authorization only",operation_calls,operation_bytes,
        sizeof(PeerRegistry<>),sizeof(PeerHost<>),sizeof(routing::RouteTable<>),sizeof(SourcePolicyView));
}
