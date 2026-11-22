import std;
import crypto;
import net.udp_socket;
import packet.fd;
import wireguard;
import wireguard.crypto;
import wireguard.noise;
import wireguard.session;
import wireguard.endpoint;
import wireguard.registry;
import wireguard.port_types;
import wireguard.port;
import wireguard.packet_link;

// Linux/glibc test boundary. Production read/write signatures and descriptor
// flags are checked against the existing system headers in packet/fd.cpp.
extern "C" int socketpair(int,int,int,int*);
extern "C" int close(int);
extern "C" std::ptrdiff_t read(int,void*,std::size_t);
extern "C" std::ptrdiff_t write(int,void const*,std::size_t);
extern "C" int* __errno_location() noexcept;
namespace {
    bool tracking=false;
    std::size_t allocations=0;
    auto allocate(std::size_t size,std::size_t alignment=0) -> void* {
        if (tracking) ++allocations;
        auto bytes=std::max<std::size_t>(size,1);
        auto value=alignment ? std::aligned_alloc(alignment,((bytes+alignment-1)/alignment)*alignment) : std::malloc(bytes);
        if (!value) throw std::bad_alloc{}; return value;
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

namespace {
    using namespace wireguard;
    using namespace std::chrono_literals;
    template<class T> auto require(T const& condition,std::source_location source=std::source_location::current()) -> void {
        if (!condition) { std::println("WireGuard packet link failed at line {}",source.line()); throw 1; }
    }
    auto bytes(unsigned first) -> Key { Key result; for (std::size_t i=0;i<32;++i) result[i]=static_cast<std::uint8_t>(first+i); return result; }
    auto key(unsigned first) -> ::crypto::X25519Private {
        auto result=::crypto::X25519Private::from_bytes(bytes(first)); require(result); return std::move(*result);
    }
    auto public_key(unsigned first) -> Key { auto result=key(first).public_key(); require(result); return *result; }
    auto outer() -> EndpointAddress { return {4,{127,0,0,1},0}; }
    auto prefix(unsigned node) -> AllowedPrefix { return {4,{10,42,0,static_cast<std::uint8_t>(node)},32}; }
    auto packet(unsigned from,unsigned to=1) -> std::array<std::uint8_t,24> {
        return {0x45,0,0,24,0,0,0,0,64,253,0,0,10,42,0,static_cast<std::uint8_t>(from),10,42,0,static_cast<std::uint8_t>(to),1,2,3,4};
    }
    struct Hooks {
        static inline bool block_data=false;
        static auto before_send(std::optional<PeerHandle>,OutboundKind kind,std::span<std::uint8_t const>) noexcept -> std::optional<std::error_code> {
            if (block_data && kind==OutboundKind::data) return std::make_error_code(std::errc::resource_unavailable_try_again);
            return {};
        }
    };
    struct ExhaustionHooks : Hooks { static auto initial_policy_epoch() noexcept -> std::uint64_t { return std::numeric_limits<std::uint64_t>::max()-2; } };
    struct Pair {
        int fd[2]{-1,-1};
        Pair() { require(::socketpair(1,2|00004000|02000000,0,fd)==0); }
        ~Pair() { for (int value:fd) if (value>=0) ::close(value); }
        auto fill() -> void {
            std::array<std::uint8_t,100> filler{}; unsigned count=0;
            while (::write(fd[0],filler.data(),filler.size())==100) ++count;
            require(count>0); require(*::__errno_location()==std::to_underlying(std::errc::resource_unavailable_try_again));
        }
        auto drain() -> void {
            std::array<std::uint8_t,256> buffer{};
            while (::read(fd[1],buffer.data(),buffer.size())>0) {}
            require(*::__errno_location()==std::to_underlying(std::errc::resource_unavailable_try_again));
        }
        auto empty() -> void {
            std::array<std::uint8_t,256> buffer{}; require(::read(fd[1],buffer.data(),buffer.size())<0);
            require(*::__errno_location()==std::to_underlying(std::errc::resource_unavailable_try_again));
        }
        auto receive(unsigned node) -> void {
            std::array<std::uint8_t,256> buffer{}; auto count=::read(fd[1],buffer.data(),buffer.size());
            require(count==24 && std::ranges::equal(std::span(buffer).first(24),packet(node)));
        }
    };
    template<class TestHooks=Hooks> struct Context {
        using Port=UdpPort<2,2,256,4,TestHooks>;
        using Link=PortPacketLink<Port>;
        using Pump=::packet::StaticFdPump<Link,256>;
        static_assert(!std::move_constructible<Pump>);
        std::expected<Port,PortFailure> port=Port::create(bytes(0));
        std::array<net::UdpSocket,2> sockets;
        std::array<std::optional<Session>,2> sessions;
        std::array<PeerHandle,2> peers;
        Clock::time_point now{10s};
        Context() {
            Hooks::block_data=false; require(port); require(port->open(outer(),now));
            for (std::size_t i=0;i<2;++i) {
                require(sockets[i].bind(outer())); auto added=port->add_peer(config(i)); require(added); peers[i]=*added;
                require(port->assign_route(peers[i],prefix(i+2)));
            }
        }
        auto config(unsigned position) -> EndpointConfig {
            auto address=sockets[position].local_endpoint(); require(address);
            return {.peer_public=public_key(32*(position+1)),.allowed_ips={{4,{},0}},.peer=*address,.mtu=128};
        }
        auto poll() -> PortProgress {
            now+=1ms; auto result=port->poll(now,std::chrono::system_clock::now()); require(result); return *result;
        }
        auto connect(unsigned position,unsigned epoch=1) -> void {
            auto identity=key(32*(position+1)); auto handshake=Handshake::create(identity,public_key(0)); require(handshake);
            auto timestamp=make_timestamp(epoch,0); require(timestamp);
            auto initiation=handshake->initiate(100+position,*timestamp,key(96+position+epoch)); require(initiation);
            auto local=port->local_endpoint(); require(local); require(sockets[position].send(*local,*initiation));
            poll();
            std::array<std::uint8_t,256> buffer{}; auto response=sockets[position].receive(buffer); require(response && *response);
            require(handshake->consume_response(std::span(buffer).first((**response).size)));
            auto session=handshake->finish(now); require(session); sessions[position]=std::move(*session);
        }
        auto deliver(unsigned position) -> void {
            require(sessions[position]); auto wire=sessions[position]->seal(packet(position+2),now,128); require(wire);
            auto local=port->local_endpoint(); require(local); require(sockets[position].send(*local,*wire)); poll();
        }
        auto flush_socket(unsigned position) -> void {
            std::array<std::uint8_t,256> buffer{};
            for (;;) { auto received=sockets[position].receive(buffer); require(received); if (!*received) break; }
        }
    };
    auto stale_delivery(unsigned action,bool pending) -> void {
        Context context; context.connect(0); context.connect(1);
        Pair pair; Context<>::Link link(*context.port); link.time(context.now);
        auto pump=Context<>::Pump::create(pair.fd[0],link,128); require(pump);
        context.deliver(0); require(context.port->status().delivery_packets==1);
        if (pending) {
            pair.fill(); allocations=0; tracking=true;
            auto blocked=pump->step(); tracking=false;
            require(blocked.output_backpressured && pump->pending() && !allocations && !context.port->status().delivery_packets);
        }
        if (action==0) {
            require(context.port->assign_route(context.peers[1],prefix(2)));
            require(context.port->assign_route(context.peers[0],prefix(2)));
        } else if (action==1) {
            auto old=context.peers[0]; require(context.port->erase_peer(old));
            auto replacement=context.port->add_peer(context.config(0)); require(replacement);
            require(replacement->slot==old.slot && replacement->generation!=old.generation);
            context.peers[0]=*replacement; require(context.port->assign_route(*replacement,prefix(2)));
        } else context.port->stop();
        if (pending) pair.drain();
        allocations=0; tracking=true; auto result=pump->step(); tracking=false;
        require(!allocations && !result.output_delivered && (!pending || result.output_discarded) && !pump->pending());
        require(!context.port->status().delivery_packets); pair.empty();
        if (action==2) { require(context.port->drained()); return; }
        if (action==1) {
            context.deliver(0); require(!context.port->status().delivery_packets); // Previous receiver index is retired.
            context.connect(0,2);
        }
        context.deliver(0); require(context.port->status().delivery_packets==1);
        allocations=0; tracking=true; result=pump->step(); tracking=false;
        require(!allocations && result.output_delivered); pair.receive(2);
        context.port->stop(); require(context.port->drained());
    }
    auto exhaustion_is_transactional() -> void {
        Context<ExhaustionHooks> context; context.connect(0);
        Pair pair; Context<ExhaustionHooks>::Link link(*context.port); link.time(context.now);
        auto pump=Context<ExhaustionHooks>::Pump::create(pair.fd[0],link,128); require(pump);
        context.deliver(0); pair.fill(); require(pump->step().output_backpressured);
        auto failed=context.port->assign_route(context.peers[1],prefix(2));
        require(!failed && failed.error().code==PortError::policy_exhausted);
        failed=context.port->erase_peer(context.peers[0]);
        require(!failed && failed.error().code==PortError::policy_exhausted && context.port->valid(context.peers[0]));
        auto selected=context.port->enqueue_ip(packet(1,2),context.now); require(selected && *selected==context.peers[0]);
        pair.drain(); require(pump->step().output_delivered); pair.receive(2);
        context.deliver(0); pair.fill(); require(pump->step().output_backpressured);
        context.port->stop(); require(context.port->drained()); pair.drain();
        require(pump->step().output_discarded); pair.empty();
    }
    auto outbound_policy_discards_without_nonce_reuse() -> void {
        Context context; context.connect(0); context.deliver(0); require(context.port->take_packet()); context.flush_socket(0);
        Hooks::block_data=true;
        require(context.port->enqueue_ip(packet(1,2),context.now)); auto progress=context.poll();
        require(progress.write_blocked && context.port->status().business_packets==1 && context.port->status().pending_sends==1);
        require(context.port->enqueue_ip(packet(1,2),context.now)); require(context.port->status().business_packets==2);
        require(context.port->assign_route(context.peers[1],prefix(2)));
        require(context.port->assign_route(context.peers[0],prefix(2)));
        require(!context.port->status().business_packets && !context.port->status().pending_sends);
        Hooks::block_data=false; require(context.port->enqueue_ip(packet(1,2),context.now)); context.poll();
        std::array<std::uint8_t,256> buffer{}; auto received=context.sockets[0].receive(buffer); require(received && *received);
        auto wire=std::span(buffer).first((**received).size); auto transport=parse_transport(wire); require(transport && transport->counter==1);
        auto opened=context.sessions[0]->open(wire,context.now); require(opened && std::ranges::equal(std::span(*opened).first(24),packet(1,2)));
        context.port->stop(); require(context.port->drained());
    }
    auto pump_input_retry_and_idle_allocations() -> void {
        Context context; Pair pair; Context<>::Link link(*context.port); link.time(context.now);
        allocations=0; tracking=true; auto pump=Context<>::Pump::create(pair.fd[0],link,128); tracking=false;
        require(pump && !allocations);
        for (unsigned i=0;i<64;++i) require(context.port->enqueue_ip(packet(1,2),context.now));
        auto input=packet(1,2); require(::write(pair.fd[1],input.data(),input.size())==24);
        auto blocked=pump->step(); require(blocked.input && blocked.input_backpressured && pump->pending());
        require(context.port->assign_route(context.peers[1],prefix(2))); // Retained device input retries against the new route owner.
        auto retried=pump->step(); require(!retried.input && retried.input_delivered && !pump->pending());
        require(context.port->status().business_packets==1);
        require(!context.port->peer_status(context.peers[0])->queued_packets && context.port->peer_status(context.peers[1])->queued_packets==1);
        require(context.port->assign_route(context.peers[0],prefix(2)));
        allocations=0; tracking=true;
        for (unsigned i=0;i<1000;++i) { auto idle=pump->step(); require(!idle.input && !idle.output_delivered && !pump->pending()); }
        tracking=false; require(!allocations);
        std::println("WireGuard static link/pump construct, fixed delivery/EAGAIN/policy drop and 1000 idle steps: 0 C++ allocations; sizeof link={} pump={}",sizeof(link),sizeof(*pump));
    }
}

auto main() -> int {
    try {
        for (unsigned action=0;action<3;++action) for (bool pending:{false,true}) stale_delivery(action,pending);
        exhaustion_is_transactional(); outbound_policy_discards_without_nonce_reuse(); pump_input_retry_and_idle_allocations();
        std::println("WireGuard descriptor path rejects stale route/peer packets before write, route revert does not revive them, epoch exhaustion is transactional and discarded ciphertext counters are never reused");
    } catch (int failure) { tracking=false; return failure; }
}
