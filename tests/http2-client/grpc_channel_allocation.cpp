import std;
import grpc.headers;
import grpc.session;
import grpc.stream;
import net.socket_stream;
import capy;
import corosio;
namespace g=grpc;
namespace io = ::corosio;
extern "C" auto meter_begin(std::size_t,std::size_t) -> void;
extern "C" auto meter_end() -> std::size_t;
extern "C" auto meter_live() -> std::size_t;
struct Frames final:std::pmr::memory_resource {
    std::size_t calls=0,bytes=0,live=0;
    std::array<std::size_t,128> sizes{};
    auto do_allocate(std::size_t n,std::size_t alignment) -> void* override {
        auto p=std::aligned_alloc(alignment,((n+alignment-1)/alignment)*alignment);if(!p)throw std::bad_alloc();if(calls==sizes.size())std::abort();sizes[calls++]=n;bytes+=n;live+=n;return p;
    }
    auto do_deallocate(void* p,std::size_t n,std::size_t) -> void override{live-=n;std::free(p);}
    auto do_is_equal(std::pmr::memory_resource const& other) const noexcept -> bool override{return this==&other;}
};
template<class Factory>auto task(std::string_view name,Factory factory) -> void {
    Frames frames;auto previous=capy::get_current_frame_allocator();capy::set_current_frame_allocator(&frames);
    {auto operation=factory();if(!operation.handle())std::abort();}
    capy::set_current_frame_allocator(previous);if(frames.live)std::abort();
    std::println("{} frame_allocations={} requested_bytes={}",name,frames.calls,frames.bytes);
}
auto main() -> int {
    auto context=io::make_io_context(false);io::local_stream_socket socket(context);net::SocketByteStream lower(socket);
    auto profile=g::RequestProfile::create("nexus.Service","control.example",false);if(!profile)return 1;
    auto protocol=g::Session::create(g::Role::client,*profile);if(!protocol)return 2;
    using Channel=g::Channel<decltype(lower)>;
    meter_begin(1,0);Channel channel(lower,std::move(*protocol));auto constructs=meter_end();if(constructs||meter_live())return 3;
    std::println("channel_size={} session_size={} channel_constructor_cpp_allocations={}",sizeof(Channel),sizeof(g::Session),constructs);
    std::array<std::uint8_t,17> bytes{};
    task("run",[&]{return channel.run();});task("accept",[&]{return channel.accept();});task("read",[&]{return channel.read(bytes);});
    task("send",[&]{return channel.send(bytes);});task("close",[&]{return channel.close_output();});
    Frames running;capy::run_async(context.get_executor(),static_cast<std::pmr::memory_resource*>(&running))(channel.run());context.run();
    if(!context.stopped()||!channel.drained()||running.live)return 4;
    std::println("failed-lower-run frame_allocations={} requested_bytes={} sizes={}",running.calls,running.bytes,std::span(running.sizes).first(running.calls));
}
