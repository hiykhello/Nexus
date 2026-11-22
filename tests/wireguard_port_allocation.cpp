import std;
import crypto;
import wireguard;
import wireguard.crypto;
import wireguard.endpoint;
import wireguard.port_types;
import wireguard.port;

namespace {
    std::ptrdiff_t allowance=-1;
    bool tracking=false;
    std::size_t calls=0,allocated_bytes=0,live=0;
    auto allocate(std::size_t size,std::size_t alignment=0) -> void* {
        if (!allowance) throw std::bad_alloc{};
        if (allowance>0) --allowance;
        auto bytes=std::max<std::size_t>(size,1);
        if (alignment && bytes>std::numeric_limits<std::size_t>::max()-(alignment-1)) throw std::bad_alloc{};
        auto value=alignment ? std::aligned_alloc(alignment,((bytes+alignment-1)/alignment)*alignment) : std::malloc(bytes);
        if (!value) throw std::bad_alloc{};
        ++live; if (tracking) { ++calls; allocated_bytes+=size; } return value;
    }
    auto release(void* value) noexcept -> void { if (value) { --live; std::free(value); } }
}
auto operator new(std::size_t size) -> void* { return allocate(size); }
auto operator new[](std::size_t size) -> void* { return allocate(size); }
auto operator new(std::size_t size,std::align_val_t align) -> void* { return allocate(size,static_cast<std::size_t>(align)); }
auto operator new[](std::size_t size,std::align_val_t align) -> void* { return allocate(size,static_cast<std::size_t>(align)); }
auto operator delete(void* value) noexcept -> void { release(value); }
auto operator delete[](void* value) noexcept -> void { release(value); }
auto operator delete(void* value,std::size_t) noexcept -> void { release(value); }
auto operator delete[](void* value,std::size_t) noexcept -> void { release(value); }
auto operator delete(void* value,std::align_val_t) noexcept -> void { release(value); }
auto operator delete[](void* value,std::align_val_t) noexcept -> void { release(value); }
auto operator delete(void* value,std::size_t,std::align_val_t) noexcept -> void { release(value); }
auto operator delete[](void* value,std::size_t,std::align_val_t) noexcept -> void { release(value); }

namespace {
    using namespace wireguard;
    using namespace std::chrono_literals;
    using Port=UdpPort<2,2,256,4>;
    auto bytes(unsigned first) -> Key { Key result; for (std::size_t i=0;i<32;++i) result[i]=static_cast<std::uint8_t>(first+i); return result; }
    auto config(unsigned first) -> EndpointConfig {
        auto identity=::crypto::X25519Private::from_bytes(bytes(first)); if (!identity) std::terminate();
        auto key=identity->public_key(); if (!key) std::terminate();
        EndpointConfig result; result.peer_public=*key; result.peer=EndpointAddress{4,{127,0,0,1},10002}; result.allowed_ips={{4,{},0}}; result.mtu=128; return result;
    }
    auto loopback() -> EndpointAddress { return {4,{127,0,0,1},0}; }
    auto configure_and_idle() -> bool {
        calls=allocated_bytes=0; tracking=true;
        auto port=Port::create(bytes(0)); auto now=Clock::time_point(10s); auto wall=std::chrono::system_clock::now();
        if (!port || !port->open(loopback(),now)) { tracking=false; return false; }
        tracking=false;
        if (calls || allocated_bytes) return false;
        auto first=config(32),second=config(64);
        calls=allocated_bytes=0; tracking=true;
        auto a=port->add_peer(std::move(first)),b=port->add_peer(std::move(second)); tracking=false;
        if (!a || !b || !calls || !allocated_bytes) return false;
        auto configuration_calls=calls,configuration_bytes=allocated_bytes;
        calls=allocated_bytes=0; tracking=true;
        for (unsigned step=0;step<1000;++step) {
            auto current=port->poll(now+std::chrono::milliseconds(step),wall+std::chrono::milliseconds(step));
            if (!current || current->received || current->sent || current->write_blocked || port->status().pending_sends) { tracking=false; return false; }
        }
        tracking=false;
        if (calls || allocated_bytes) return false;
        port->stop(); if (!port->drained()) return false;
        std::println("WireGuard port create/open and 1000 idle steps C++ allocations=0; two existing Endpoint queue owners initialized with {} allocations/{} bytes (prepared config vectors excluded)",configuration_calls,configuration_bytes);
        return true;
    }
    auto failed_peer_construction_rolls_back() -> bool {
        auto port=Port::create(bytes(0)); auto now=Clock::time_point(10s);
        if (!port || !port->open(loopback(),now)) return false;
        auto before=live; auto peer_config=config(32);
        allowance=0; auto failed=port->add_peer(std::move(peer_config)); allowance=-1;
        if (failed || failed.error().code!=PortError::allocation || port->status().registry.peers || port->status().keys || port->status().routes || port->status().pending_sends || live!=before) return false;
        auto peer=port->add_peer(config(32));
        if (!peer || peer->generation<2 || port->status().registry.peers!=1) return false;
        port->stop(); return port->drained();
    }
    auto handshake_allocation_failure_stops_all() -> bool {
        auto port=Port::create(bytes(0)); auto now=Clock::time_point(10s);
        if (!port || !port->open(loopback(),now)) return false;
        auto peer=port->add_peer(config(32));
        if (!peer || !port->assign_route(*peer,{4,{},0})) return false;
        std::array<std::uint8_t,24> packet{0x45,0,0,24,0,0,0,0,64,253,0,0,10,42,0,1,10,42,0,2,1,2,3,4};
        if (!port->enqueue_ip(packet,now)) return false;
        allowance=0; auto failed=port->poll(now,std::chrono::system_clock::now()); allowance=-1;
        return !failed && failed.error().code==PortError::allocation && port->drained() && port->native_handle()==-1 && !port->status().registry.reservations;
    }
}

auto main() -> int {
    auto baseline=live;
    if (!configure_and_idle() || live!=baseline) { std::println("WireGuard port create/config/idle allocation accounting failed"); return 1; }
    if (!failed_peer_construction_rolls_back() || live!=baseline) { std::println("WireGuard port peer construction allocation rollback failed"); return 2; }
    if (!handshake_allocation_failure_stops_all() || live!=baseline) { std::println("WireGuard port handshake allocation failure drain failed"); return 3; }
    std::println("WireGuard port allocation failures leave no peers, reservations, socket, pending sends or C++ allocation leaks; sizeof default={} test={}",sizeof(UdpPort<>),sizeof(Port));
}
