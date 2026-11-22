import std;
import anytls.pool;
import grpc.headers;
import grpc.session;
import grpc.stream;
import net.socket_stream;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;
namespace capy=nex::capy;
struct Frames final:std::pmr::memory_resource {
    std::size_t calls=0,bytes=0,live=0;std::array<std::size_t,64> sizes{};
    auto do_allocate(std::size_t n,std::size_t alignment) -> void* override {
        auto p=std::aligned_alloc(alignment,((n+alignment-1)/alignment)*alignment);if (!p) throw std::bad_alloc();sizes.at(calls++)=n;bytes+=n;live+=n;return p;
    }
    auto do_deallocate(void* p,std::size_t n,std::size_t) -> void override {live-=n;std::free(p);}
    auto do_is_equal(std::pmr::memory_resource const& other) const noexcept -> bool override {return this==&other;}
};
template<class Factory> auto sample(std::string_view name,Factory factory) -> void {
    Frames frames;auto previous=capy::get_current_frame_allocator();capy::set_current_frame_allocator(&frames);
    {auto operation=factory();(void)operation;}
    capy::set_current_frame_allocator(previous);if (frames.live) std::abort();std::println("{} {} {}",name,frames.calls,frames.bytes);
}
namespace audit {bool enabled=false;std::size_t calls=0,bytes=0;}
void* operator new(std::size_t n) {if (audit::enabled) {++audit::calls;audit::bytes+=n;}if (auto p=std::malloc(n?n:1)) return p;throw std::bad_alloc();}
void operator delete(void* p) noexcept {std::free(p);}
void operator delete(void* p,std::size_t) noexcept {std::free(p);}
struct Node {
    bool usable_=true,done=false;
    auto usable() const noexcept -> bool {return usable_;}
    auto cancel() noexcept -> void {usable_=false;}
    auto drained() const noexcept -> bool {return done;}
};
auto main() -> int {
    using Pool=anytls::ClientPool<Node>;
    audit::enabled=true;
    {
        Pool pool({.max_sessions=3});auto creating=pool.reserve();if (!creating) return 1;
        auto lease=creating->commit(std::make_unique<Node>());if (!lease) return 2;
        lease->connection().done=true;lease->reset();pool.stop();pool.reap(anytls::PoolClock::now());if (!pool.drained()) return 3;
    }
    audit::enabled=false;
    std::println("pool-layout {} {} {} new {} {}",sizeof(Pool),sizeof(Pool::Lease),sizeof(Pool::Creation),audit::calls,audit::bytes);
    auto context=nex::corosio::make_io_context(false);nex::corosio::local_stream_socket socket(context);net::SocketByteStream lower(socket);
    auto profile=grpc::RequestProfile::create("nexus.Service","host",false);if (!profile) return 4;
    auto protocol=grpc::Session::create(grpc::Role::client,*profile);if (!protocol) return 5;
    using Channel=grpc::Channel<decltype(lower)>;
    audit::calls=audit::bytes=0;audit::enabled=true;
    Channel channel(lower,std::move(*protocol));audit::enabled=false;
    std::println("grpc-layout {} {} new {} {}",sizeof(Channel),sizeof(grpc::Session),audit::calls,audit::bytes);
    std::array<std::uint8_t,17> bytes{};
    sample("run",[&] {return channel.run();});sample("accept",[&] {return channel.accept();});sample("read",[&] {return channel.read(bytes);});
    sample("send",[&] {return channel.send(bytes);});sample("close",[&] {return channel.close_output();});
    Frames frames;capy::run_async(context.get_executor(),static_cast<std::pmr::memory_resource*>(&frames))(channel.run());context.run();
    if (!context.stopped() || !channel.drained() || frames.live) return 6;
    std::println("failed-run {} {} {}",frames.calls,frames.bytes,std::span(frames.sizes).first(frames.calls));
}
