import std;
import hysteria2.client;
import hysteria2.client_profile;
import platform.socket_options;
import corosio;

namespace io = ::corosio;
namespace h=hysteria2;
namespace allocation {
    bool armed=false,denied=false;
    std::size_t count=0,target=0;
    auto allocate(std::size_t size,std::size_t alignment=alignof(std::max_align_t)) -> void* {
        if (armed && ++count==target) {armed=false;denied=true;throw std::bad_alloc();}
        alignment=std::max(alignment,alignof(void*));
        if (size>std::numeric_limits<std::size_t>::max()-alignment-sizeof(void*)) throw std::bad_alloc();
        auto raw=std::malloc(std::max(size,std::size_t{1})+alignment+sizeof(void*));if(!raw)throw std::bad_alloc();
        auto address=(reinterpret_cast<std::uintptr_t>(raw)+sizeof(void*)+alignment-1)/alignment*alignment;
        auto result=reinterpret_cast<void*>(address);static_cast<void**>(result)[-1]=raw;return result;
    }
    auto release(void* value) noexcept -> void {if(value)std::free(static_cast<void**>(value)[-1]);}
}
auto operator new(std::size_t size) -> void* {return allocation::allocate(size);}
auto operator new[](std::size_t size) -> void* {return allocation::allocate(size);}
auto operator new(std::size_t size,std::align_val_t alignment) -> void* {return allocation::allocate(size,static_cast<std::size_t>(alignment));}
auto operator new[](std::size_t size,std::align_val_t alignment) -> void* {return allocation::allocate(size,static_cast<std::size_t>(alignment));}
auto operator delete(void* value) noexcept -> void {allocation::release(value);}
auto operator delete[](void* value) noexcept -> void {allocation::release(value);}
auto operator delete(void* value,std::size_t) noexcept -> void {allocation::release(value);}
auto operator delete[](void* value,std::size_t) noexcept -> void {allocation::release(value);}
auto operator delete(void* value,std::align_val_t) noexcept -> void {allocation::release(value);}
auto operator delete[](void* value,std::align_val_t) noexcept -> void {allocation::release(value);}
auto operator delete(void* value,std::size_t,std::align_val_t) noexcept -> void {allocation::release(value);}
auto operator delete[](void* value,std::size_t,std::align_val_t) noexcept -> void {allocation::release(value);}

auto main(int argc,char** argv) -> int {
    if(argc!=3)return 1;
    auto profile=h::ClientProfile::load("localhost",argv[1],argv[2]);if(!profile)return 2;
    for(bool uring:{false,true}) {
        io::io_context context=io::make_io_context(uring);
        io::udp_socket reserve(context);io::endpoint local(io::ipv4_address::loopback(),0);
        if(reserve.open() || reserve.bind(local))return 3;
        auto port=reserve.local_endpoint().port();reserve.close();
        ::platform::SocketBinding binding;binding.udp_bind_port=port;
        io::endpoint peer(io::ipv4_address::loopback(),443);
        std::size_t fault_count=0;
        for(std::size_t target=1;target<1024;++target) {
            allocation::count=0;allocation::target=target;allocation::denied=false;
            bool success=false;
            {
                h::Client client(context,**profile);
                allocation::armed=true;
                try {success=client.start(peer,&binding).has_value();}
                catch(std::bad_alloc const&) {}
                allocation::armed=false;
                client.stop();client.joined();
            }
            io::udp_socket probe(context);if(probe.open() || probe.bind(io::endpoint(io::ipv4_address::loopback(),port)))return 4;
            probe.close();
            if(!allocation::denied) {
                if(!success)return 5;
                std::println("Hy2 client startup backend={} denied={} source-port-recovered=true success=true",uring,fault_count);
                break;
            }
            ++fault_count;
            if(target==1023)return 6;
        }
        if(!fault_count)return 7;
    }
}
