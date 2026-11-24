import std;
import grpc.headers;
import grpc.session;
import grpc.stream;
import net.socket_stream;
import capy;
import corosio;
namespace g=grpc;
namespace io = ::corosio;
using namespace std::chrono_literals;
using Lower=net::SocketByteStream<io::local_stream_socket>;
using Channel=g::Channel<Lower>;
struct Result { bool done=false,success=false; std::string_view stage="start"; };
auto pattern() -> std::vector<std::uint8_t> {
    std::vector<std::uint8_t> data(128*1024);
    for (std::size_t i=0;i<data.size();++i) data[i]=static_cast<std::uint8_t>(i*13);
    return data;
}
auto receive(Channel& channel,std::span<std::uint8_t const> expected) -> capy::task<bool> {
    std::array<std::uint8_t,137> buffer{}; std::size_t offset=0;
    for (;;) {
        auto received=co_await channel.read(buffer,g::Clock::now()+3s);
        if (!received || *received>expected.size()-offset) co_return false;
        if (!*received) co_return offset==expected.size();
        if (!std::ranges::equal(std::span(buffer).first(*received),expected.subspan(offset,*received))) co_return false;
        offset+=*received;
    }
}
auto client_app(Channel& client,std::span<std::uint8_t const> payload,Result& result) -> capy::task<capy::results<>> {
    result.stage="client send";
    if (!co_await client.send(payload,g::Clock::now()+3s)) co_return capy::results<>{std::make_error_code(std::errc::io_error)};
    result.stage="client close output";
    if (!co_await client.close_output(g::Clock::now()+3s)) co_return capy::results<>{std::make_error_code(std::errc::io_error)};
    result.stage="client response";
    if (!co_await receive(client,payload)) co_return capy::results<>{std::make_error_code(std::errc::io_error)};
    co_return capy::results<>{};
}
auto server_app(Channel& server,std::span<std::uint8_t const> payload,Result& result) -> capy::task<capy::results<>> {
    if (!co_await server.accept(g::Clock::now()+3s)) co_return capy::results<>{std::make_error_code(std::errc::io_error)};
    auto [error]=co_await io::delay(40ms);
    if (error) co_return capy::results<>{error};
    if (!co_await receive(server,payload)) co_return capy::results<>{std::make_error_code(std::errc::io_error)};
    auto [delayed]=co_await io::delay(5ms);
    if (delayed || !co_await server.send(payload,g::Clock::now()+3s) || !co_await server.close_output(g::Clock::now()+3s))
        co_return capy::results<>{std::make_error_code(std::errc::io_error)};
    (void)result; co_return capy::results<>{};
}
auto exercise(Channel& client,Channel& server,std::span<std::uint8_t const> payload,Result& result) -> capy::task<> {
    try {
        auto [error,crun,srun,capp,sapp]=co_await capy::when_all(client.run(),server.run(),client_app(client,payload,result),server_app(server,payload,result));
        (void)crun; (void)srun; (void)capp; (void)sapp;
        result.success=!error && client.finished() && server.finished() && client.drained() && server.drained() && !client.failure() && !server.failure();
    } catch (...) { client.cancel(); server.cancel(); }
    result.done=true;
}
auto bidirectional(bool uring) -> bool {
    auto context=io::make_io_context(uring);
    io::local_stream_socket left(context),right(context);
    if (io::connect_pair(left,right)) return false;
    auto profile=g::RequestProfile::create("nexus.Service","cover.example",false); if (!profile) return false;
    g::Limits limits{2048,1032,1024,128*1024,64,4*1024*1024};
    auto c=g::Session::create(g::Role::client,*profile,g::ResponsePolicy::standard,limits);
    auto s=g::Session::create(g::Role::server,*profile,g::ResponsePolicy::standard,limits);
    if (!c || !s) return false;
    Lower clower(left),slower(right);
    Channel client(clower,std::move(*c),g::Clock::now()+4s),server(slower,std::move(*s),g::Clock::now()+4s);
    auto payload=pattern(); Result result;
    capy::run_async(context.get_executor())(exercise(client,server,payload,result)); context.run_for(5s);
    if (!result.done) { client.cancel(); server.cancel(); context.restart(); context.run_for(1s); }
    if (!result.done || !context.stopped()) std::_Exit(90);
    if (!result.success) {
        std::cerr << "gRPC stream " << result.stage << " failed: backend=" << uring;
        if (auto failure=client.failure()) std::cerr << " client=" << int(failure->error) << ':' << failure->code;
        if (auto failure=server.failure()) std::cerr << " server=" << int(failure->error) << ':' << failure->code;
        std::cerr << '\n';
    }
    return result.success;
}
struct Pending { bool done=false; std::optional<g::Failure> failure; };
auto waiting(Channel& channel,g::Clock::time_point deadline,Pending& pending) -> capy::task<capy::results<>> {
    auto accepted=co_await channel.accept(deadline);
    if (!accepted) pending.failure=accepted.error();
    pending.done=true;
    co_return capy::results<>{};
}
auto lifecycle_run(Channel& channel,g::Clock::time_point deadline,Pending& pending) -> capy::task<> {
    try {
        auto [error,run,app]=co_await capy::when_all(channel.run(),waiting(channel,deadline,pending));
        (void)error; (void)run; (void)app;
    } catch (...) { channel.cancel(); }
}
auto lifecycle(bool uring,bool cancel) -> bool {
    auto context=io::make_io_context(uring);
    io::local_stream_socket socket(context),peer(context);
    if (io::connect_pair(socket,peer)) return false;
    auto profile=g::RequestProfile::create("nexus.Service","host",false); if (!profile) return false;
    auto protocol=g::Session::create(g::Role::server,*profile); if (!protocol) return false;
    Lower lower(socket); Channel channel(lower,std::move(*protocol)); Pending pending;
    capy::run_async(context.get_executor())(lifecycle_run(channel,g::Clock::now()+(cancel ? 5s : 40ms),pending));
    context.run_for(cancel ? 10ms : 200ms);
    if (cancel) {
        if (pending.done) return false;
        channel.cancel(); context.restart(); context.run_for(1s);
    }
    return pending.done && pending.failure && pending.failure->error==(cancel ? g::Error::canceled : g::Error::timeout) && channel.drained() && context.stopped();
}
struct AbandonState { bool entered=false,destroyed=false,canceled=false,returned=false; };
struct TrackedLower {
    Lower lower; AbandonState& state;
    ~TrackedLower() { state.destroyed=true; }
    auto read(std::span<std::uint8_t> bytes,g::Deadline deadline) { return lower.read(bytes,deadline); }
    auto send(std::span<std::uint8_t const> bytes,g::Deadline deadline) { return lower.send(bytes,deadline); }
    auto close_output(g::Deadline deadline){return lower.close_output(deadline);}
    auto cancel() noexcept -> void { state.canceled=true; lower.cancel(); }
};
template<class Stream>
auto abandon_wait(Stream& channel) -> capy::task<capy::results<>> {
    auto accepted=co_await channel.accept(g::Clock::now()+5s);
    co_return capy::results<>{accepted ? std::error_code{} : std::make_error_code(std::errc::io_error)};
}
auto abandoned(io::io_context& context,AbandonState& state) -> capy::task<> {
    io::local_stream_socket socket(context),peer(context);
    if (io::connect_pair(socket,peer)) co_return;
    auto profile=g::RequestProfile::create("nexus.Service","host",false); if (!profile) co_return;
    auto protocol=g::Session::create(g::Role::server,*profile); if (!protocol) co_return;
    TrackedLower lower{Lower(socket),state};
    g::Channel channel(lower,std::move(*protocol),g::Clock::now()+5s);
    state.entered=true;
    auto [error,run,app]=co_await capy::when_all(channel.run(),abandon_wait(channel));
    (void)error; (void)run; (void)app; state.returned=true;
}
auto abandonment(bool uring) -> bool {
    AbandonState state;
    {
        auto context=io::make_io_context(uring);
        capy::run_async(context.get_executor())(abandoned(context,state)); context.run_for(10ms);
        if (!state.entered || state.destroyed || state.canceled || state.returned) return false;
    }
    return state.destroyed && state.canceled && !state.returned;
}
auto main() -> int {
    for (bool uring:{false,true}) {
        if (uring && !io::has_uring) continue;
        if (!bidirectional(uring)) return 1;
        if (!lifecycle(uring,false) || !lifecycle(uring,true)) { std::println("gRPC pending deadline/cancellation failed: backend={}",uring); return 2; }
        if (!abandonment(uring)) { std::println("gRPC context abandonment failed: backend={}",uring); return 3; }
    }
    std::println("gRPC real socket small-window slow-read duplex transfer, independent half-close, deadlines, cancellation and abandonment passed");
}
