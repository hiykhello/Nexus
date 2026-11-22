import std;
import net.udp_dial;
import platform.socket_options;

namespace {
    std::atomic<std::size_t> allocations=0;
    auto allocate(std::size_t size,std::size_t alignment=0) -> void* {
        ++allocations;size=std::max<std::size_t>(size,1);
        auto* result=alignment ? std::aligned_alloc(alignment,(size+alignment-1)/alignment*alignment) : std::malloc(size);
        if (!result) throw std::bad_alloc();return result;
    }
}
auto operator new(std::size_t size) -> void* {return allocate(size);}
auto operator new[](std::size_t size) -> void* {return allocate(size);}
auto operator new(std::size_t size,std::align_val_t alignment) -> void* {return allocate(size,static_cast<std::size_t>(alignment));}
auto operator new[](std::size_t size,std::align_val_t alignment) -> void* {return allocate(size,static_cast<std::size_t>(alignment));}
auto operator delete(void* p) noexcept -> void {std::free(p);}
auto operator delete[](void* p) noexcept -> void {std::free(p);}
auto operator delete(void* p,std::size_t) noexcept -> void {std::free(p);}
auto operator delete[](void* p,std::size_t) noexcept -> void {std::free(p);}
auto operator delete(void* p,std::align_val_t) noexcept -> void {std::free(p);}
auto operator delete[](void* p,std::align_val_t) noexcept -> void {std::free(p);}
auto operator delete(void* p,std::size_t,std::align_val_t) noexcept -> void {std::free(p);}
auto operator delete[](void* p,std::size_t,std::align_val_t) noexcept -> void {std::free(p);}

auto main(int argc,char** argv) -> int {
    if (argc!=5) return 1;
    std::array<unsigned,4> values{};
    for (std::size_t i=0;i<values.size();++i) {
        std::string_view text(argv[i+1]);auto [end,error]=std::from_chars(text.data(),text.data()+text.size(),values[i]);
        if (error!=std::errc{} || end!=text.data()+text.size()) return 1;
    }
    auto family=values[0],port=values[1],fragment=values[2],mode=values[3];
    if ((family!=4 && family!=6) || !port || port>65535 || fragment>1 || mode>3) return 1;
    platform::SocketBinding binding;binding.udp_fragment=bool(fragment);
    if (mode&1) {
        std::ranges::copy(std::string_view("nxfa"),binding.bind_interface.begin());
        binding.inet4_bind_address=std::array<std::uint8_t,4>{10,77,0,1};
        std::array<std::uint8_t,16> local{};local[0]=0xfd;local[1]=0x77;local[15]=1;binding.inet6_bind_address=local;
    }
    net::UdpEndpoint target{.family=static_cast<std::uint8_t>(family),.port=static_cast<std::uint16_t>(port)};
    if (family==4) {target.address[0]=10;target.address[1]=77;target.address[3]=2;}
    else {target.address[0]=0xfd;target.address[1]=0x77;target.address[15]=2;}
    auto before=allocations.load();
    net::UdpDialSockets sockets(&binding);
    if (mode&2) {
        auto first=sockets.send(target,{}),second=sockets.send(target,{});
        if (first || second || first.error()!=std::errc::operation_not_permitted || second.error()!=first.error() || allocations.load()!=before) return 11;
        std::println("prepare denied: preserved EPERM, no business, C++new=0");return 0;
    }
    std::array<std::uint8_t,2048> payload{};
    for (std::size_t i=0;i<payload.size();++i) payload[i]=static_cast<std::uint8_t>(i*71);
    if (!sockets.send(target,{})) return 2;
    auto large=sockets.send(target,payload);
    if (fragment ? !large : (large || large.error()!=std::errc::message_size)) return 3;
    if (!sockets.send(target,std::span(payload).first(1200))) return 4;
    std::array<bool,3> seen{};std::size_t count=0;
    auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(3);
    std::array<std::uint8_t,4096> input{};
    while (count<(fragment ? 3u : 2u) && std::chrono::steady_clock::now()<deadline) {
        auto received=sockets.receive(input);if (!received) return 5;
        if (!*received) {std::this_thread::sleep_for(std::chrono::milliseconds(1));continue;}
        auto const& packet=**received;
        if (!packet.valid || packet.source!=target || (packet.size && packet.size!=1200 && packet.size!=2048)) return 6;
        auto index=packet.size==0 ? 0u : packet.size==1200 ? 1u : 2u;
        if (seen[index] || (!fragment && index==2) || !std::ranges::equal(std::span(input).first(packet.size),std::span(payload).first(packet.size))) return 7;
        seen[index]=true;++count;
    }
    sockets.close();
    if (count!=(fragment ? 3u : 2u) || allocations.load()!=before) return 8;
    std::println("IPv{} fragment={} binding={} empty/1200/2048/recovery passed C++new=0 SocketBinding={} TcpSocketOptions={} UdpDialSockets={}",
        family,fragment,bool(mode&1),sizeof(binding),sizeof(platform::TcpSocketOptions),sizeof(net::UdpDialSockets));
}
