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
auto main() -> int {
    static_assert(!std::is_polymorphic_v<Client> && !std::is_polymorphic_v<Relay> && !std::is_polymorphic_v<Inbound>);
    auto context=io::make_io_context(false); Socket remote(context),local(context);
    t::detail::ApplicationConnection connection(remote,records(),{});
    vless::UserId user{}; std::array<vless::UserId,1> users{user};
    auto plain=vless::ServerHandshake::create(users),vision=vless::ServerHandshake::create_vision(users);
    if (!plain || !vision) return 1;
    allocations=0; watch_allocations=true;
    Client client(connection); Relay relay(local,connection,client);
    Inbound inbound(connection,std::move(*plain));
    VisionClient vision_client(connection); VisionInbound vision_inbound(connection,std::move(*vision));
    watch_allocations=false;
    if (allocations) { std::println("VLESS TLS owner/relay construction unexpectedly allocated {} blocks",allocations); return 2; }
    std::println("VLESS TLS layout: client={} relay={} combined={} inbound={} vision-client-core={} vision-inbound-core={} byte-stream={} reader={} mutex={} constructor-allocations={}",
        sizeof(Client),sizeof(Relay),sizeof(Client)+sizeof(Relay),sizeof(Inbound),sizeof(VisionClient),sizeof(VisionInbound),
        sizeof(t::detail::ByteStream<Socket>),sizeof(t::detail::ApplicationStreamReader<Socket>),sizeof(nex::capy::async_mutex),allocations);
    std::println("VLESS TLS awaiting results: relay-read={} relay-write={} inbound-read={}",
        sizeof(decltype(relay.read(std::span<std::uint8_t>{}))),sizeof(decltype(relay.write(std::span<std::uint8_t const>{}))),
        sizeof(decltype(inbound.read(std::span<std::uint8_t>{}))));
}
