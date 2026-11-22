import std;
import crypto;
import tls.client_flight;
import tls.corosio_application;
import tls.byte_stream;
import vless;
import vless.corosio_client;
import vless.tls_server;
import vless.vision_client;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;
namespace t=tls;
namespace v=vless::detail;
namespace io=nex::corosio;
static thread_local bool watch_allocations=false;
static thread_local std::size_t allocations=0;
void* operator new(std::size_t size) {
    if (watch_allocations) ++allocations;
    if (auto pointer=std::malloc(size ? size : 1)) return pointer;
    throw std::bad_alloc{};
}
void operator delete(void* pointer) noexcept { std::free(pointer); }
void operator delete(void* pointer,std::size_t) noexcept { std::free(pointer); }
using Socket=io::local_stream_socket;
using Client=v::TcpClient<Socket>;
using VisionClient=v::TcpClient<Socket,true>;
using Relay=v::DuplexRelay<Socket,Socket>;
using Inbound=v::TlsInbound<Socket>;
using VisionInbound=v::TlsInbound<Socket,true>;
auto secret(unsigned value) -> t::Secret { return t::Secret(::crypto::Bytes(32,static_cast<std::uint8_t>(value))); }
auto layer(t::RecordDirection direction,unsigned value) -> t::RecordLayer {
    auto root=secret(value);
    auto key=t::expand_label(::crypto::Hash::sha256,root.view(),"key",{},16),iv=t::expand_label(::crypto::Hash::sha256,root.view(),"iv",{},12);
    if (!key || !iv) std::abort();
    auto result=t::RecordLayer::create(direction,::crypto::Aead::aes_128_gcm,key->view(),iv->view());
    if (!result) std::abort(); return std::move(*result);
}
auto records() -> t::ApplicationRecords {
    return {layer(t::RecordDirection::send,1),layer(t::RecordDirection::receive,2),16385,16385,::crypto::Hash::sha256,
        ::crypto::Aead::aes_128_gcm,16,secret(1),secret(2),t::ApplicationRole::client};
}
struct Frames final:std::pmr::memory_resource {
    std::size_t calls=0,bytes=0,live=0;
    auto do_allocate(std::size_t n,std::size_t alignment) -> void* override {
        auto p=std::aligned_alloc(alignment,((n+alignment-1)/alignment)*alignment);if (!p) throw std::bad_alloc();++calls;bytes+=n;live+=n;return p;
    }
    auto do_deallocate(void* p,std::size_t n,std::size_t) -> void override {live-=n;std::free(p);}
    auto do_is_equal(std::pmr::memory_resource const& other) const noexcept -> bool override {return this==&other;}
};
template<class Factory> auto sample(std::string_view name,Factory factory) -> void {
    Frames frames;auto previous=nex::capy::get_current_frame_allocator();nex::capy::set_current_frame_allocator(&frames);
    {auto operation=factory();(void)operation;}
    nex::capy::set_current_frame_allocator(previous);if (frames.live) std::abort();
    std::println("{} {} {}",name,frames.calls,frames.bytes);
}
auto main() -> int {
    auto context=io::make_io_context(false);Socket remote(context),local(context);
    t::detail::ApplicationConnection connection(remote,records(),{});
    vless::UserId user{};std::array<vless::UserId,1> users{user};
    auto plain=vless::ServerHandshake::create(users),vision=vless::ServerHandshake::create_vision(users);
    if (!plain || !vision) return 1;
    Client client(connection);Relay relay(local,connection,client);
    Inbound inbound(connection,std::move(*plain));VisionClient vision_client(connection);VisionInbound vision_inbound(connection,std::move(*vision));
    std::array<std::uint8_t,17> bytes{};vless::TcpRequest request{user,vless::AddressKind::ipv4,443,{127,0,0,1}};
    sample("client-start",[&] {return client.start(request);});sample("client-send",[&] {return client.send(bytes);});
    sample("client-response",[&] {return client.receive_response();});sample("client-mux",[&] {return client.start_mux(user);});
    sample("relay-read",[&] {return relay.read(bytes);});sample("relay-write",[&] {return relay.write(bytes);});
    sample("relay-close",[&] {return relay.close_output();});sample("relay-upload",[&] {return relay.upload();});sample("relay-download",[&] {return relay.download();});
    sample("inbound-header",[&] {return inbound.read_header();});sample("inbound-request",[&] {return inbound.read_request();});
    sample("inbound-complete",[&] {return inbound.complete_dial(true);});sample("inbound-send-state-rejection",[&] {return inbound.send(bytes);});
    sample("inbound-close-state-rejection",[&] {return inbound.close_output();});
    sample("vision-start",[&] {return vision_client.start_vision(request);});sample("vision-response",[&] {return vision_client.receive_response();});
    sample("vision-header",[&] {return vision_inbound.read_header();});sample("vision-complete",[&] {return vision_inbound.complete_dial(true);});
    std::println("layout {} {} {} {} {}",sizeof(Client),sizeof(Relay),sizeof(Inbound),sizeof(VisionClient),sizeof(VisionInbound));
}
