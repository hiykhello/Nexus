import std;
import nexus.shadowsocks.replay;
namespace s=nexus::shadowsocks;
using namespace std::chrono_literals;
int main() {
    auto start=std::chrono::steady_clock::time_point{};
    std::array<std::uint8_t,16> a{},b{}; b[0]=1;
    std::array<std::uint8_t,32> c{};
    s::ReplayTable table(2);
    if (!table.admit(a,start,1000) || table.admit(a,start+60s,1060).error()!=s::ReplayError::duplicate) return 1;
    if (table.admit(b,start+59s,1059).error()!=s::ReplayError::time_reversed || table.size()!=1) return 2;
    if (!table.admit(b,start+60s,1060) || table.admit(c,start+60s,1060).error()!=s::ReplayError::full) return 3;
    if (table.admit(a,start+61s+999ms,1061).error()!=s::ReplayError::duplicate) return 4;
    if (!table.admit(c,start+62s,1062) || table.size()!=2) return 5;
    if (table.admit(a,start+62s,1062).error()!=s::ReplayError::full) return 6;
    if (table.admit(std::span{a}.first(15),start+200s,1200).error()!=s::ReplayError::invalid_salt || table.size()!=2) return 7;
    if (table.admit(c,start+60s,1060).error()!=s::ReplayError::time_reversed || table.size()!=2) return 8;
    if (table.admit(a,start+123s,1000).error()!=s::ReplayError::time_reversed || table.size()!=2) return 9;
    if (!table.admit(a,start+124s,1124) || table.size()!=1) return 10;
    s::ReplayTable empty(0); if (empty.admit(a,start,1000).error()!=s::ReplayError::full) return 11;
    s::ReplayTable clock(4); if (!clock.admit(a,start,1000)) return 12;
    if (!clock.admit(b,start+10s,1009)) return 13; // whole-second sampling tolerance
    if (clock.admit(c,start+20s,1018).error()!=s::ReplayError::time_reversed) return 14;
    if (!clock.admit(c,start+20s,1100)) return 15; // forward jump raises the watermark
    if (clock.admit(a,start+21s,1021).error()!=s::ReplayError::time_reversed) return 16;
    if (clock.admit(a,start+82s,1100).error()!=s::ReplayError::time_reversed) return 17;
    {
        constexpr std::size_t workers=32;
        s::ReplayTable shared(workers); std::latch gate(workers); std::atomic<unsigned> accepted=0, duplicate=0;
        std::vector<std::jthread> threads;
        for (std::size_t i=0;i<workers;++i) threads.emplace_back([&] {
            gate.arrive_and_wait(); auto result=shared.admit(a,start,1000);
            if (result) ++accepted; else if (result.error()==s::ReplayError::duplicate) ++duplicate;
        });
        threads.clear();
        if (accepted!=1 || duplicate!=workers-1 || shared.size()!=1) return 18;
    }
    {
        constexpr std::size_t workers=32, capacity=8;
        s::ReplayTable shared(capacity); std::latch gate(workers); std::atomic<unsigned> accepted=0, full=0;
        std::vector<std::jthread> threads;
        for (std::size_t i=0;i<workers;++i) threads.emplace_back([&,i] {
            std::array<std::uint8_t,16> salt{}; salt[0]=static_cast<std::uint8_t>(i);
            gate.arrive_and_wait(); auto result=shared.admit(salt,start,1000);
            if (result) ++accepted; else if (result.error()==s::ReplayError::full) ++full;
        });
        threads.clear();
        if (accepted!=capacity || full!=workers-capacity || shared.size()!=capacity) return 19;
    }
    {
        s::ReplayTable current(2);
        auto wall=static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
        if (current.admit_current(a,wall-31).error()!=s::ReplayError::invalid_timestamp || current.size()!=0) return 20;
        if (!current.admit_current(a,wall) || current.admit_current(a,wall).error()!=s::ReplayError::duplicate) return 21;
    }
    {
        // Exercise the production capacity and verify both indexing and expiry.
        constexpr std::size_t capacity=65536;
        s::ReplayTable large(capacity);
        auto salt_for=[](std::size_t value) {
            std::array<std::uint8_t,16> salt{};
            salt[0]=static_cast<std::uint8_t>(value>>8);
            salt[1]=static_cast<std::uint8_t>(value);
            return salt;
        };
        for (std::size_t i=0;i<capacity;++i)
            if (!large.admit(salt_for(i),start,1000)) return 22;
        for (std::size_t i : {std::size_t{0},capacity/2,capacity-1})
            if (large.admit(salt_for(i),start+61s,1061).error()!=s::ReplayError::duplicate) return 23;
        std::array<std::uint8_t,32> same_prefix{};
        if (large.admit(same_prefix,start+61s,1061).error()!=s::ReplayError::full) return 24;
        if (!large.admit(same_prefix,start+62s,1062) || large.size()!=1) return 25;
        if (!large.admit(salt_for(0),start+62s,1062) || large.size()!=2) return 26;
        if (large.admit(same_prefix,start+62s,1062).error()!=s::ReplayError::duplicate) return 27;
    }
    std::cout << "Shadowsocks 2022 replay table passed\n";
}
