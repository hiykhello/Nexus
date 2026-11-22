import std;
import httpupgrade.stream;
import net.socket_stream;
import net.buffered_input;
import net.framed_stream;
import tailscale.control_record_codec;
import nexus.thirdparty.capy;
namespace capy=nex::capy;
using Deadline=net::StreamDeadline;
std::size_t ordinary=0,aligned=0;
auto operator new(std::size_t size) -> void* {++ordinary;if (auto p=std::malloc(size ? size : 1)) return p;throw std::bad_alloc();}
auto operator new[](std::size_t size) -> void* {return ::operator new(size);}
auto operator delete(void* p) noexcept -> void {std::free(p);}
auto operator delete[](void* p) noexcept -> void {std::free(p);}
auto operator delete(void* p,std::size_t) noexcept -> void {std::free(p);}
auto operator delete[](void* p,std::size_t) noexcept -> void {std::free(p);}
auto operator new(std::size_t size,std::align_val_t alignment) -> void* {++aligned;auto align=static_cast<std::size_t>(alignment);auto n=std::max(size,std::size_t{1});n=(n+align-1)/align*align;if (auto p=std::aligned_alloc(align,n)) return p;throw std::bad_alloc();}
auto operator new[](std::size_t size,std::align_val_t alignment) -> void* {return ::operator new(size,alignment);}
auto operator delete(void* p,std::align_val_t) noexcept -> void {std::free(p);}
auto operator delete[](void* p,std::align_val_t) noexcept -> void {std::free(p);}
auto operator delete(void* p,std::size_t,std::align_val_t) noexcept -> void {std::free(p);}
auto operator delete[](void* p,std::size_t,std::align_val_t) noexcept -> void {std::free(p);}
struct Meter : std::pmr::memory_resource {
    std::size_t count=0,bytes=0,live=0;
    auto do_allocate(std::size_t size,std::size_t align) -> void* override {++count;bytes+=size;++live;return std::pmr::new_delete_resource()->allocate(size,align);}
    auto do_deallocate(void* p,std::size_t size,std::size_t align) -> void override {--live;std::pmr::new_delete_resource()->deallocate(p,size,align);}
    auto do_is_equal(std::pmr::memory_resource const& other) const noexcept -> bool override {return this==&other;}
};
struct Lower {
    std::size_t canceled=0;
    auto read(std::span<std::uint8_t>,Deadline) -> capy::task<std::expected<std::size_t,int>> {co_return 0;}
    auto send(std::span<std::uint8_t const>,Deadline) -> capy::task<bool> {co_return true;}
    auto close_output(Deadline) -> capy::task<bool> {co_return true;}
    auto cancel() noexcept -> void {++canceled;}
};
using Codec=tailscale::control::RecordCodec;
using Frame=net::FramedByteStream<Lower,Codec>;
auto main() -> int {
    Lower lower;auto old_ordinary=ordinary,old_aligned=aligned;
    for (unsigned i=0;i<1000;++i) {Frame frame(lower);}
    auto construct_ordinary=ordinary-old_ordinary,construct_aligned=aligned-old_aligned;
    Meter read,send,close;std::array<std::uint8_t,1> bytes{};Frame frame(lower);
    auto original=capy::get_current_frame_allocator();capy::set_current_frame_allocator(&read);
    {auto task=frame.read(bytes);}
    capy::set_current_frame_allocator(&send);{auto task=frame.send(bytes);}
    capy::set_current_frame_allocator(&close);{auto task=frame.close_output();}
    capy::set_current_frame_allocator(original);
    std::println("construct1000 ordinary={} aligned={}",construct_ordinary,construct_aligned);
    std::println("task-read count={} bytes={} live={}; send count={} bytes={} live={}; close count={} bytes={} live={}",read.count,read.bytes,read.live,send.count,send.bytes,send.live,close.count,close.bytes,close.live);
    std::println("layout window={} codec={} frame={} header-state={} input-step={} failure={}",sizeof(Frame::Window),sizeof(Codec),sizeof(Frame),sizeof(httpupgrade::detail::HeaderReadState),sizeof(net::InputStep),sizeof(Frame::Failure));
    return construct_ordinary || construct_aligned || read.count!=1 || send.count!=1 || close.count!=1 || read.live || send.live || close.live ? 1 : 0;
}
