import std;
import grpc.headers;
import grpc.session;
import grpc.stream;
import net.socket_stream;
import tls.byte_stream;
import vless;
import vless.corosio_client;
import vless.tls_server;
import capy;
import corosio;
namespace g=grpc;
namespace v=vless;
namespace io = ::corosio;
using namespace std::chrono_literals;
struct ReadPolicy {
    using Error=tls::detail::ByteStreamError;
    static auto convert(g::Failure failure) noexcept -> Error {
        return failure.error==g::Error::state ? Error::state : failure.error==g::Error::transport ||
            failure.error==g::Error::timeout || failure.error==g::Error::canceled ? Error::io : Error::protocol;
    }
};
using Lower=net::SocketByteStream<io::local_stream_socket>;
using Channel=g::Channel<Lower,ReadPolicy>;
using Client=v::detail::TcpClient<io::local_stream_socket,false,Channel&>;
using Inbound=v::detail::TlsInbound<io::local_stream_socket,false,Channel&>;
using Relay=v::detail::DuplexRelay<io::local_stream_socket,io::local_stream_socket,Channel&>;
struct Result {bool done=false,passed=false;};
auto failure() -> capy::results<> {return {std::make_error_code(std::errc::io_error)};}
auto client_app(Channel& channel,io::local_stream_socket& unused,std::span<std::uint8_t const> payload,bool mux)
    -> capy::task<capy::results<>> {
    Client client(channel);Relay relay(unused,client,{},false);
    v::UserId user{};v::TcpRequest request{user,v::AddressKind::ipv4,1234,{127,0,0,1}};
    auto started=mux ? co_await client.start_mux(user,false,g::Clock::now()+3s) : co_await client.start(request,g::Clock::now()+3s);
    if (!started || !co_await relay.write(payload) || !co_await relay.close_output()) co_return failure();
    std::array<std::uint8_t,137> bytes{};std::size_t offset=0;
    for (;;) {
        auto got=co_await relay.read(bytes);if (!got || *got>payload.size()-offset) co_return failure();
        if (!*got) break;
        if (!std::ranges::equal(std::span(bytes).first(*got),payload.subspan(offset,*got))) co_return failure();
        offset+=*got;
    }
    co_return offset==payload.size() ? capy::results<>{} : failure();
}
auto server_app(Channel& channel,std::span<std::uint8_t const> payload,bool mux) -> capy::task<capy::results<>> {
    if (!co_await channel.accept(g::Clock::now()+3s)) co_return failure();
    std::array<v::UserId,1> users{};auto handshake=v::ServerHandshake::create(users);if (!handshake) co_return failure();
    Inbound inbound(channel,std::move(*handshake));if (!inbound.allow_mux()) co_return failure();
    auto header=co_await inbound.read_header(g::Clock::now()+3s);
    if (!header || std::holds_alternative<v::UserId>(*header)!=mux) co_return failure();
    if (!mux) {
        auto const& request=std::get<v::TcpRequest>(*header);
        if (request.port!=1234 || request.kind!=v::AddressKind::ipv4 || request.address!=std::vector<std::uint8_t>{127,0,0,1}) co_return failure();
    }
    if (!co_await inbound.complete_dial(true,g::Clock::now()+3s)) co_return failure();
    auto [delayed]=co_await io::delay(40ms);if (delayed) co_return failure();
    std::array<std::uint8_t,1031> bytes{};std::size_t offset=0;
    for (;;) {
        auto got=co_await inbound.read(bytes);if (!got || *got>payload.size()-offset) co_return failure();
        if (!*got) break;
        if (!std::ranges::equal(std::span(bytes).first(*got),payload.subspan(offset,*got))) co_return failure();
        offset+=*got;
    }
    if (offset!=payload.size() || !co_await inbound.send(payload) || !co_await inbound.close_output()) co_return failure();
    co_return capy::results<>{};
}
auto run(Channel& client,Channel& server,io::local_stream_socket& unused,std::span<std::uint8_t const> payload,bool mux,Result& result) -> capy::task<> {
    try {
        auto [error,cr,sr,ca,sa]=co_await capy::when_all(client.run(),server.run(),client_app(client,unused,payload,mux),server_app(server,payload,mux));
        (void)cr;(void)sr;(void)ca;(void)sa;
        result.passed=!error && client.finished() && server.finished() && client.drained() && server.drained() && !client.failure() && !server.failure();
    } catch (...) {client.cancel();server.cancel();}
    result.done=true;
}
auto main() -> int {
    static_assert(!std::is_polymorphic_v<Client> && !std::is_polymorphic_v<Inbound>);
    static_assert(std::is_same_v<decltype(std::declval<Channel&>().read(std::span<std::uint8_t>{})),capy::task<std::expected<std::size_t,tls::detail::ByteStreamError>>>);
    for (bool uring:{false,true}) for (bool mux:{false,true}) {
        auto context=io::make_io_context(uring);io::local_stream_socket left(context),right(context),unused(context);
        if (io::connect_pair(left,right)) return 1;
        auto profile=g::RequestProfile::create("nexus.Service","host",false);if (!profile) return 2;
        g::Limits limits{2048,1032,1024,131072,64,4194304};
        auto cp=g::Session::create(g::Role::client,*profile,g::ResponsePolicy::standard,limits);
        auto sp=g::Session::create(g::Role::server,*profile,g::ResponsePolicy::standard,limits);if (!cp || !sp) return 3;
        Lower cl(left),sl(right);Channel c(cl,std::move(*cp),g::Clock::now()+4s),s(sl,std::move(*sp),g::Clock::now()+4s);
        std::vector<std::uint8_t> payload(131072);for (std::size_t i=0;i<payload.size();++i) payload[i]=static_cast<std::uint8_t>(i*37);
        Result result;capy::run_async(context.get_executor())(run(c,s,unused,payload,mux,result));context.run_for(5s);
        if (!result.done || !context.stopped()) std::_Exit(65);
        if (!result.passed) {std::println("failed backend={} mux={}",uring,mux);return 4;}
    }
    std::println("Shared VLESS parser/response/relay over direct gRPC read tasks: TCP and mux, small-window128KiB, independent FIN and full graceful H2 EOF both backends passed");
    std::println("gRPC specialization client={} relay={} inbound={}; no forwarding byte actor",sizeof(Client),sizeof(Relay),sizeof(Inbound));
}
