import std;
import http2.client_channel;
import memory.budget;
import net.socket_stream;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;
namespace h=http2;
namespace m=::memory;
namespace capy=nex::capy;
namespace io=nex::corosio;
extern "C" auto meter_begin(std::size_t,std::size_t) -> void;
extern "C" auto meter_end() -> std::size_t;
extern "C" auto meter_live() -> std::size_t;
struct Frames final:std::pmr::memory_resource {
    std::array<std::size_t,128> sizes{};std::size_t calls=0,bytes=0,live=0,peak=0;
    auto do_allocate(std::size_t n,std::size_t alignment) -> void* override {
        auto p=std::aligned_alloc(alignment,((n+alignment-1)/alignment)*alignment);if(!p)throw std::bad_alloc();if(calls==sizes.size())std::abort();sizes[calls++]=n;bytes+=n;live+=n;peak=std::max(peak,live);return p;
    }
    auto do_deallocate(void* p,std::size_t n,std::size_t) -> void override{live-=n;std::free(p);}
    auto do_is_equal(std::pmr::memory_resource const& other) const noexcept -> bool override{return this==&other;}
};
template<class Factory>auto task(std::string_view name,Factory factory) -> void {
    Frames frames;auto previous=capy::get_current_frame_allocator();capy::set_current_frame_allocator(&frames);
    {auto operation=factory();if(!operation.handle())std::abort();}
    capy::set_current_frame_allocator(previous);if(frames.live)std::abort();std::println("{} frame_allocations={} requested_bytes={}",name,frames.calls,frames.bytes);
}
auto main() -> int {
    using Lower=net::SocketByteStream<io::local_stream_socket>;using Channel=h::ClientChannel<Lower,4>;
    static_assert(!std::is_polymorphic_v<Channel>&&!std::is_polymorphic_v<h::Client<4>>);
    auto context=io::make_io_context(false);io::local_stream_socket socket(context);Lower lower(socket);h::ClientLimits limits;
    auto budget=std::make_shared<m::Budget>(limits.shared_bytes);auto reservation=m::Budget::reserve(budget,Channel::transport_buffer_bytes+sizeof(Channel)+4096);if(!reservation)return 1;
    auto client=h::Client<4>::create(limits,budget);if(!client)return 2;
    {
        meter_begin(1,0);Channel channel(lower,std::move(*client));auto constructors=meter_end();if(constructors||meter_live())return 3;
        std::println("HTTP2 Client1={} Client4={} Client16={} Channel={} lower={} constructor_cpp_allocations={} lower_plaintext_buffers={} explicit_transport_reservation={}",sizeof(h::Client<1>),sizeof(h::Client<4>),sizeof(h::Client<16>),sizeof(Channel),sizeof(Lower),constructors,Channel::transport_buffer_bytes,reservation->size());
        task("run",[&]{return channel.run();});task("wait_change",[&]{return channel.wait_change();});
        Frames running;capy::run_async(context.get_executor(),static_cast<std::pmr::memory_resource*>(&running))(channel.run());context.run();
        if(!context.stopped()||!channel.drained()||running.live||!channel.failure())return 4;
        std::println("failed-lower-run frame_allocations={} requested_bytes={} peak={} sizes={}",running.calls,running.bytes,running.peak,std::span(running.sizes).first(running.calls));
    }
    if(budget->used()!=reservation->size())return 5;
    std::println("HTTP2 caller transport reservation survives driver failure and returns to its exact baseline after owner destruction");
}
