import std;
import net.udp_dial;
import net.udp_socket;
import platform.socket_options;

namespace {
    std::atomic<std::size_t> allocations=0;
    auto allocate(std::size_t size,std::size_t alignment=0) -> void* {
        ++allocations; size=std::max<std::size_t>(size,1);
        auto result=alignment ? std::aligned_alloc(alignment,((size+alignment-1)/alignment)*alignment) : std::malloc(size);
        if (!result) throw std::bad_alloc(); return result;
    }
}
auto operator new(std::size_t size) -> void* { return allocate(size); }
auto operator new[](std::size_t size) -> void* { return allocate(size); }
auto operator new(std::size_t size,std::align_val_t alignment) -> void* { return allocate(size,static_cast<std::size_t>(alignment)); }
auto operator new[](std::size_t size,std::align_val_t alignment) -> void* { return allocate(size,static_cast<std::size_t>(alignment)); }
auto operator delete(void* value) noexcept -> void { std::free(value); }
auto operator delete[](void* value) noexcept -> void { std::free(value); }
auto operator delete(void* value,std::size_t) noexcept -> void { std::free(value); }
auto operator delete[](void* value,std::size_t) noexcept -> void { std::free(value); }
auto operator delete(void* value,std::align_val_t) noexcept -> void { std::free(value); }
auto operator delete[](void* value,std::align_val_t) noexcept -> void { std::free(value); }
auto operator delete(void* value,std::size_t,std::align_val_t) noexcept -> void { std::free(value); }
auto operator delete[](void* value,std::size_t,std::align_val_t) noexcept -> void { std::free(value); }

auto main(int argc,char** argv) -> int {
    if (argc!=4) return 1;
    std::array<unsigned,3> values{};
    for (std::size_t i=0;i<values.size();++i) {
        std::string_view text(argv[i+1]);
        auto [end,error]=std::from_chars(text.data(),text.data()+text.size(),values[i]);
        if (error!=std::errc{} || end!=text.data()+text.size()) return 1;
    }
    auto mode=values[2];
    platform::SocketBinding binding;
    if (mode&1) { binding.bind_interface[0]='l'; binding.bind_interface[1]='o'; }
    if (mode&2) binding.inet4_bind_address=std::array<std::uint8_t,4>{127,0,0,2};
    if (mode&4) { std::array<std::uint8_t,16> local{};local[15]=1;binding.inet6_bind_address=local; }
    if (mode&8) binding.reuse_addr=true;
    if (mode&16) binding.routing_mark=0x4201;
    if (mode&32) binding.reuse_addr=false;
    if (mode==64) std::ranges::copy(std::string_view("nexus-missing0"),binding.bind_interface.begin());
    if (mode==128) binding.inet4_bind_address=std::array<std::uint8_t,4>{203,0,113,99};
    if (mode==256) binding.bind_interface.fill('a');
    auto before=allocations.load();
    net::UdpDialSockets sockets(&binding);
    net::UdpEndpoint target4{.family=4,.port=static_cast<std::uint16_t>(values[0])},target6{.family=6,.port=static_cast<std::uint16_t>(values[1])};
    target4.address[0]=127;target4.address[3]=1;target6.address[15]=1;
    if (mode>=64) {
        auto error=mode==64 ? std::errc::no_such_device : mode==128 ? std::errc::address_not_available : std::errc::invalid_argument;
        auto first=sockets.send(target4,{}),second=sockets.send(target6,{});
        if (first || second || first.error()!=error || second.error()!=error || allocations.load()!=before) return 11;
        std::println("UDP binding failure mode={} rejects before data, preserves error and closes sockets: C++ new=0",mode);
        return 0;
    }
    std::array<std::uint8_t,256> payload{};
    for (std::size_t i=0;i<payload.size();++i) payload[i]=static_cast<std::uint8_t>(i);
    for (auto target:{target4,target6})
        if (!sockets.send(target,{}) || !sockets.send(target,payload)) return 2;
    std::array<std::array<bool,2>,2> seen{};
    auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(3);
    std::size_t count=0;
    std::array<std::uint8_t,512> input{};
    while (count<4 && std::chrono::steady_clock::now()<deadline) {
        auto peeked=(mode&32) ? sockets.receive(input) : sockets.peek(input);
        if (!peeked) return 3;
        if (!*peeked) { std::this_thread::sleep_for(std::chrono::milliseconds(1));continue; }
        auto const& packet=**peeked;
        if (!packet.valid || (packet.source!=target4 && packet.source!=target6) || (packet.size && packet.size!=payload.size())) return 4;
        if (packet.size && !std::ranges::equal(std::span(input).first(packet.size),payload)) return 5;
        auto family=packet.source.family==4 ? 0U : 1U;auto length=packet.size ? 1U : 0U;
        if (seen[family][length]) return 7;
        if (!(mode&32)) {
            // Repeated peek and a following receive/consume keep the same fd.
            auto repeated=sockets.peek(input);
            if (!repeated || !*repeated || (**repeated).source!=packet.source || (**repeated).size!=packet.size) return 6;
            if (count%2) {
                auto consumed=sockets.receive(input);
                if (!consumed || !*consumed || (**consumed).source!=packet.source || (**consumed).size!=packet.size) return 8;
                if (packet.size && !std::ranges::equal(std::span(input).first(packet.size),payload)) return 5;
            } else {
                auto consumed=sockets.consume();
                if (!consumed || !*consumed || **consumed!=packet.size) return 8;
            }
        }
        seen[family][length]=true;++count;
    }
    if (count!=4) return 9;
    sockets.close();
    if (allocations.load()!=before) return 10;
    std::println("UDP binding mode={} dual-family empty/payload and peek/consume passed: C++ new=0, binding={}, TCP options={}, UDP owner={}",
        mode,sizeof(binding),sizeof(platform::TcpSocketOptions),sizeof(net::UdpDialSockets));
}
