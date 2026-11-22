import std;
import hysteria2.udp;
import hysteria2.sessions;
import hysteria2.fragments;
namespace h=hysteria2;
namespace {
    std::ptrdiff_t allowance=-1;
    std::size_t live=0,last_size=0;
    auto allocate(std::size_t size,std::size_t alignment=0) -> void* {
        if (!allowance) throw std::bad_alloc();
        if (allowance>0) --allowance;
        size=std::max<std::size_t>(size,1);
        if (alignment && size>std::numeric_limits<std::size_t>::max()-(alignment-1)) throw std::bad_alloc();
        auto* result=alignment ? std::aligned_alloc(alignment,((size+alignment-1)/alignment)*alignment) : std::malloc(size);
        if (!result) throw std::bad_alloc();
        ++live;last_size=size;return result;
    }
    auto release(void* pointer) noexcept -> void { if (pointer) { --live; std::free(pointer); } }
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
auto main() -> int {
    using namespace std::chrono_literals;
    auto before=live;
    {
        h::UdpSessions<1> sessions;
        auto now=h::UdpClock::time_point{}+1s;
        auto owner=sessions.acquire(1,now); if (!owner) return 1;
        h::UdpReassembler<h::UdpSessions<1>,1> assembly(sessions);
        std::array<std::uint8_t,2> a{1,2},b{3,4};
        allowance=0;
        auto failed=assembly.feed(owner->handle,{1,1,0,2,"x:1",a},now);
        allowance=-1;
        if (failed!=h::ReassemblyStatus::allocation_failed || assembly.pending_packets() || assembly.buffered_bytes() || live!=before) return 2;
        if (assembly.feed(owner->handle,{1,1,0,2,"x:1",a},now)!=h::ReassemblyStatus::incomplete ||
            assembly.pending_packets()!=1 || assembly.buffered_bytes()!=2 || live!=before+1) return 3;
        allowance=0;
        failed=assembly.feed(owner->handle,{1,1,1,2,"x:1",b},now);
        allowance=-1;
        if (failed!=h::ReassemblyStatus::allocation_failed || assembly.pending_packets()!=1 || assembly.buffered_bytes()!=2 || live!=before+1) return 4;
        if (assembly.feed(owner->handle,{1,1,1,2,"x:1",b},now)!=h::ReassemblyStatus::accepted || live!=before) return 5;
        auto packet=assembly.packet(now);
        if (!packet || !std::ranges::equal(packet->payload,std::array<std::uint8_t,4>{1,2,3,4}) || !assembly.consume()) return 6;
        if (assembly.feed(owner->handle,{1,2,0,2,"x:1",a},now)!=h::ReassemblyStatus::incomplete) return 7;
        assembly.close();
    }
    if (live!=before) return 8;
    {
        h::UdpSessions<1> sessions;
        auto now=h::UdpClock::time_point{}+1s;
        auto owner=sessions.acquire(1,now);if(!owner)return 9;
        h::UdpReassembler<h::UdpSessions<1>,1,8> assembly(sessions);
        static_assert(sizeof(assembly)<200*1024);
        std::array<std::uint8_t,2> a{1,2},b{3,4};
        allowance=0;
        if(assembly.feed(owner->handle,{1,1,0,1,"x:1",a},now)!=h::ReassemblyStatus::accepted || live!=before)return 10;
        if(assembly.feed(owner->handle,{1,2,0,1,"x:1",b},now)!=h::ReassemblyStatus::allocation_failed || live!=before)return 11;
        allowance=-1;
        if(assembly.feed(owner->handle,{1,3,0,2,"x:1",a},now)!=h::ReassemblyStatus::incomplete || live!=before+1)return 12;
        allowance=0;
        if(assembly.feed(owner->handle,{1,3,1,2,"x:1",b},now)!=h::ReassemblyStatus::allocation_failed ||
            assembly.pending_packets()!=1 || assembly.buffered_bytes()!=a.size() || live!=before+1)return 13;
        allowance=-1;
        if(assembly.feed(owner->handle,{1,3,1,2,"x:1",b},now)!=h::ReassemblyStatus::accepted || live!=before+1 || last_size!=a.size()+b.size())return 14;
        auto first=assembly.packet(now);
        if(!first || !std::ranges::equal(first->payload,a) || !assembly.consume())return 15;
        auto second=assembly.packet(now);
        if(!second || !std::ranges::equal(second->payload,std::array<std::uint8_t,4>{1,2,3,4}) || !assembly.consume())return 16;
        assembly.close();if(live!=before)return 17;
    }
    if(live!=before)return 18;
    {
        h::UdpSessions<1> sessions;
        auto now=h::UdpClock::time_point{}+1s;auto owner=sessions.acquire(1,now);if(!owner)return 19;
        h::UdpReassembler<h::UdpSessions<1>,1,8> assembly(sessions);
        std::array<std::uint8_t,1> value{7};allowance=0;
        for(unsigned i=0;i<16;++i) {
            if(assembly.feed(owner->handle,{1,static_cast<std::uint16_t>(i),0,1,"x:1",value},now)!=h::ReassemblyStatus::accepted ||
                !assembly.consume() || live!=before)return 20;
        }
        allowance=-1;
    }
    {
        h::UdpSessions<1> sessions;auto now=h::UdpClock::time_point{}+1s;auto owner=sessions.acquire(1,now);if(!owner)return 21;
        h::UdpReassembler<h::UdpSessions<1>,1,2> assembly(sessions);
        std::array<std::uint8_t,3> small{1,2,3};std::array<std::uint8_t,5> larger{4,5,6,7,8};
        allowance=0;
        if(assembly.feed(owner->handle,{1,1,0,1,"x:1",small},now)!=h::ReassemblyStatus::accepted ||
            assembly.feed(owner->handle,{1,2,0,1,"x:1",{}},now)!=h::ReassemblyStatus::accepted || live!=before)return 22;
        allowance=-1;
        if(!assembly.consume() || assembly.feed(owner->handle,{1,3,0,1,"x:1",small},now)!=h::ReassemblyStatus::accepted)return 23;
        if(!assembly.consume() || !assembly.consume() || live!=before)return 24;
        if(assembly.feed(owner->handle,{1,4,0,1,"x:1",small},now)!=h::ReassemblyStatus::accepted ||
            assembly.feed(owner->handle,{1,5,0,1,"x:1",small},now)!=h::ReassemblyStatus::accepted || last_size!=small.size())return 25;
        if(!assembly.consume())return 26;
        if(assembly.feed(owner->handle,{1,6,0,1,"x:1",small},now)!=h::ReassemblyStatus::accepted || !assembly.consume())return 27;
        allowance=0;
        if(assembly.feed(owner->handle,{1,7,0,1,"x:1",larger},now)!=h::ReassemblyStatus::allocation_failed || live!=before+1)return 28;
        allowance=-1;
        if(assembly.feed(owner->handle,{1,7,0,1,"x:1",larger},now)!=h::ReassemblyStatus::accepted || last_size!=larger.size())return 29;
        if(!assembly.consume() || !assembly.consume())return 30;
        assembly.close();if(live!=before)return 31;
    }
    {
        h::UdpMemoryBudget budget(6);h::UdpSessions<1> sessions;
        auto now=h::UdpClock::time_point{}+1s;auto owner=sessions.acquire(1,now);if(!owner)return 32;
        std::array<std::uint8_t,3> small{1,2,3};std::array<std::uint8_t,4> large{4,5,6,7};
        {
            h::UdpReassembler<h::UdpSessions<1>,1,2> first(sessions,1024,1024,5s,&budget);
            h::UdpReassembler<h::UdpSessions<1>,1,2> second(sessions,1024,1024,5s,&budget);
            if(first.feed(owner->handle,{1,1,0,1,"x:1",small},now)!=h::ReassemblyStatus::accepted ||
                first.feed(owner->handle,{1,2,0,1,"x:1",small},now)!=h::ReassemblyStatus::accepted || budget.used()!=3)return 33;
            if(second.feed(owner->handle,{1,3,0,1,"x:1",small},now)!=h::ReassemblyStatus::accepted ||
                second.feed(owner->handle,{1,4,0,1,"x:1",large},now)!=h::ReassemblyStatus::full || budget.used()!=3)return 34;
            if(second.feed(owner->handle,{1,5,0,2,"x:1",large},now)!=h::ReassemblyStatus::full || budget.used()!=3)return 35;
            allowance=0;
            if(second.feed(owner->handle,{1,6,0,2,"x:1",small},now)!=h::ReassemblyStatus::allocation_failed || budget.used()!=3)return 36;
            allowance=-1;
            if(!first.consume() || !first.consume() || budget.used())return 37;
            if(second.feed(owner->handle,{1,4,0,1,"x:1",large},now)!=h::ReassemblyStatus::accepted || budget.used()!=4)return 38;
        }
        if(budget.used() || live!=before)return 39;
    }
    {
        h::UdpMemoryBudget budget(7);h::UdpSessions<1> sessions;
        auto now=h::UdpClock::time_point{}+1s;auto owner=sessions.acquire(1,now);if(!owner)return 40;
        h::UdpReassembler<h::UdpSessions<1>,1,2> assembly(sessions,1024,1024,5s,&budget);
        std::array<std::uint8_t,3> small{1,2,3};std::array<std::uint8_t,5> large{4,5,6,7,8};
        if(assembly.feed(owner->handle,{1,1,0,1,"x:1",small},now)!=h::ReassemblyStatus::accepted ||
           assembly.feed(owner->handle,{1,2,0,1,"x:1",small},now)!=h::ReassemblyStatus::accepted || budget.used()!=3 ||
           !assembly.consume() ||
           assembly.feed(owner->handle,{1,3,0,1,"x:1",small},now)!=h::ReassemblyStatus::accepted || !assembly.consume())return 41;
        if(assembly.feed(owner->handle,{1,4,0,1,"x:1",large},now)!=h::ReassemblyStatus::full || budget.used()!=3)return 42;
        auto packet=assembly.packet(now);if(!packet || !std::ranges::equal(packet->payload,small))return 43;
    }
    if(live!=before)return 44;
    {
        h::UdpMemoryBudget budget(5);h::UdpSessions<1> sessions;
        auto now=h::UdpClock::time_point{}+1s;auto owner=sessions.acquire(1,now);if(!owner)return 45;
        h::UdpReassembler<h::UdpSessions<1>,1,2> assembly(sessions,1024,1024,5s,&budget);
        std::array<std::uint8_t,2> a{1,2},b{3,4};
        if(assembly.feed(owner->handle,{1,1,0,1,"x:1",a},now)!=h::ReassemblyStatus::accepted ||
           assembly.feed(owner->handle,{1,2,0,2,"x:1",a},now)!=h::ReassemblyStatus::incomplete || budget.used()!=2)return 46;
        if(assembly.feed(owner->handle,{1,2,1,2,"x:1",b},now)!=h::ReassemblyStatus::full ||
           budget.used()!=2 || assembly.buffered_bytes()!=2 || live!=before+1)return 47;
        if(!assembly.consume() || assembly.feed(owner->handle,{1,2,1,2,"x:1",b},now)!=h::ReassemblyStatus::accepted ||
           budget.used() || !assembly.consume())return 48;
    }
    {
        h::UdpMemoryBudget budget(16);h::UdpSessions<1> sessions;
        auto now=h::UdpClock::time_point{}+1s;auto owner=sessions.acquire(1,now);if(!owner)return 49;
        h::UdpReassembler<h::UdpSessions<1>,1,2> assembly(sessions,1024,1024,5s,&budget);
        std::array<std::uint8_t,2> a{1,2},b{3,4};
        if(assembly.feed(owner->handle,{1,1,0,1,"x:1",a},now)!=h::ReassemblyStatus::accepted ||
           assembly.feed(owner->handle,{1,2,0,2,"x:1",a},now)!=h::ReassemblyStatus::incomplete)return 50;
        allowance=1;
        auto result=assembly.feed(owner->handle,{1,2,1,2,"x:1",b},now);allowance=-1;
        if(result!=h::ReassemblyStatus::allocation_failed || budget.used()!=2 || assembly.buffered_bytes()!=2 || live!=before+1)return 51;
        if(assembly.feed(owner->handle,{1,2,1,2,"x:1",b},now)!=h::ReassemblyStatus::accepted ||
           budget.used()!=4 || !assembly.consume() || !assembly.consume() || budget.used())return 52;
    }
    if(live!=before)return 53;
    std::println("Hy2 fragment and lazy ready-buffer allocation failures preserve queued packets, prior fragments and all owned storage");
}

