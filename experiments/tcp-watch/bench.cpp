import std;
import tcp.table;

namespace p = ::packet;
namespace t = tcp;
using Clock = std::chrono::steady_clock;

template<class Table, class View>
void measure(char const* family, View syn, std::size_t backlog) {
    auto table = Table::create(1, 8);
    if (!table) std::abort();
    std::vector<std::shared_ptr<p::TcpGeneration>> held;
    held.reserve(backlog);
    for (std::size_t i = 0; i < backlog; ++i) {
        auto segment = syn;
        segment.source_port = static_cast<std::uint16_t>(1000 + i % 60000);
        held.push_back(table->watch(segment));
    }
    constexpr std::size_t iterations = 20000;
    auto start = Clock::now();
    for (std::size_t i = 0; i < iterations; ++i) {
        auto token = table->watch(syn);
        if (!token->valid) std::abort();
    }
    auto watch_end = Clock::now();
    auto shared = table->watch(syn);
    auto shared_start = Clock::now();
    for (std::size_t i = 0; i < iterations; ++i) {
        auto token = table->watch(syn);
        if (token != shared) std::abort();
    }
    auto shared_end = Clock::now();
    for (std::size_t i = 0; i < iterations; ++i) {
        auto id = table->open(syn, 1, 0);
        if (!id || !table->abort(*id)) std::abort();
    }
    auto end = Clock::now();
    auto ns = [](auto duration) { return std::chrono::duration_cast<std::chrono::nanoseconds>(duration).count() / double(iterations); };
    std::cout << family << ',' << backlog << ',' << ns(watch_end-start) << ',' << ns(shared_end-shared_start)
              << ',' << ns(end-shared_end) << '\n';
}

int main() {
    p::Tcp4View syn4{.source={10,0,0,1},.destination={10,0,0,2},.source_port=65000,.destination_port=80,.flags=2};
    p::Tcp6View syn6{.source={0x20,1,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,1},
        .destination={0x20,1,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,2},.source_port=65000,.destination_port=80,.flags=2};
    std::cout << "family,retained,watch_ns,shared_watch_ns,open_abort_ns\n";
    for (auto count : {0u, 64u, 256u, 1024u}) {
        measure<t::ConnectionTable>("ipv4", syn4, count);
        measure<t::ConnectionTable6>("ipv6", syn6, count);
    }
}
