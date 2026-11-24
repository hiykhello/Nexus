import std;
import tls.profiles;
import tls.server_credential;
import tls.corosio_client;
import tls.corosio_server_handshake;
import capy;
import corosio;
namespace t=tls;
namespace io = ::corosio;
using Clock=std::chrono::steady_clock;
using namespace std::chrono_literals;
struct State;
struct Socket {
    io::tcp_socket& raw; State& state;
    auto read_some(capy::mutable_buffer) -> capy::task<capy::results<std::size_t>>;
    auto write_some(capy::const_buffer) -> capy::task<capy::results<std::size_t>>;
    auto cancel() noexcept -> void;
};
struct State {
    std::string_view mode;
    Clock::time_point deadline=Clock::now()+5s;
    std::stop_source stop;
    capy::async_event changed,release;
    t::detail::ClientConnection<Socket>* client=nullptr;
    Socket* server=nullptr;
    std::size_t reading=0,writing=0,cancels=0,owner_cleanup=0;
    bool entered=false,destroyed=false,peer=false,observed=false,abandon=false,finished=false,done=false;
    bool rejected=false,caught=false,idle=false,inactive=false,valid=true;
    int error=-1;
    auto notify() noexcept -> void { changed.set(); }
};
struct Flight {
    State& state; std::size_t& count;
    Flight(State& state_,std::size_t& count_) : state(state_),count(count_) { ++count; state.notify(); }
    ~Flight() { --count; state.notify(); }
};
auto Socket::read_some(capy::mutable_buffer buffer) -> capy::task<capy::results<std::size_t>> {
    if (state.mode.ends_with("exception")) throw std::bad_alloc{};
    Flight flight(state,state.reading); co_return co_await raw.read_some(buffer);
}
auto Socket::write_some(capy::const_buffer buffer) -> capy::task<capy::results<std::size_t>> {
    Flight flight(state,state.writing); co_return co_await raw.write_some(buffer);
}
auto Socket::cancel() noexcept -> void { ++state.cancels; raw.cancel(); }
template<class Owner> struct CancelGuard { Owner& owner; State& state; ~CancelGuard() { ++state.owner_cleanup; owner.cancel(); } };
struct Lifetime {
    State& state;
    ~Lifetime() { state.client=nullptr; state.server=nullptr; state.destroyed=true; state.notify(); }
};
auto milliseconds(Clock::time_point point) -> std::uint64_t {
    return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(point.time_since_epoch()).count());
}
auto failure() -> capy::results<> { return capy::results<>{std::make_error_code(std::errc::io_error)}; }
template<class Predicate>
auto until(State& state,Predicate predicate) -> capy::task<bool> {
    while (!predicate()) {
        state.changed.clear(); auto [error]=co_await io::timeout(state.changed.wait(),state.deadline);
        if (error) co_return false;
    }
    co_return true;
}
auto client(io::io_context& context,std::uint16_t port,t::ClientProfile const& profile,State& state) -> capy::task<capy::results<>> {
    io::tcp_socket raw(context);
    auto [connected]=co_await io::timeout(raw.connect(io::endpoint(io::ipv4_address::loopback(),port)),state.deadline);
    auto now=Clock::now();
    auto wall=std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    auto handshake=profile.handshake(milliseconds(now),milliseconds(state.deadline),wall);
    if (connected || !handshake) co_return failure();
    Socket socket{raw,state}; t::detail::ClientConnection connection(socket,std::move(*handshake));
    Lifetime lifetime{state}; CancelGuard guard{connection,state};
    state.client=&connection; state.entered=true; state.notify();
    try {
        auto result=co_await connection.start(); state.rejected=!result;
        if (!result) state.error=static_cast<int>(result.error());
    } catch (std::bad_alloc const&) { state.caught=true; }
    state.idle=connection.idle(); state.inactive=connection.application()==nullptr;
    state.done=true; state.notify(); co_return capy::results<>{};
}
auto server(io::tcp_acceptor& listener,t::ServerCredential const& credential,State& state) -> capy::task<capy::results<>> {
    auto [accepted,raw]=co_await listener.accept(); listener.close();
    if (accepted) co_return failure();
    Socket socket{raw,state}; auto now=Clock::now();
    auto handshake=t::make_server_handshake(credential,milliseconds(now),milliseconds(state.deadline),{},"h2");
    if (!handshake) co_return failure();
    Lifetime lifetime{state}; CancelGuard guard{socket,state};
    state.server=&socket; state.entered=true; state.notify();
    try {
        auto result=co_await t::detail::server_handshake(socket,*handshake); state.rejected=!result;
        if (!result) state.error=static_cast<int>(result.error());
    } catch (std::bad_alloc const&) { state.caught=true; }
    state.idle=!state.reading && !state.writing;
    state.inactive=!handshake->tick(milliseconds(Clock::now())) && handshake->pending_output().empty();
    state.done=true; state.notify(); co_return capy::results<>{};
}
auto stalled_peer(io::io_context& context,io::tcp_acceptor& listener,std::uint16_t port,bool client,State& state) -> capy::task<capy::results<>> {
    io::tcp_socket raw(context);
    if (client) {
        auto [connected]=co_await io::timeout(raw.connect(io::endpoint(io::ipv4_address::loopback(),port)),state.deadline);
        if (connected) co_return failure();
    } else {
        auto [accepted,socket]=co_await listener.accept(); listener.close();
        if (accepted) co_return failure(); raw=std::move(socket);
    }
    state.peer=true; state.notify();
    auto [released]=co_await state.release.wait(); (void)released;
    co_return capy::results<>{};
}
auto control(io::io_context& context,State& state) -> capy::task<capy::results<>> {
    if (state.mode.ends_with("exception")) {
        if (!co_await until(state,[&] { return state.done; })) co_return failure();
        state.release.set(); co_return capy::results<>{};
    }
    if (!co_await until(state,[&] { return state.entered && state.peer && state.reading; })) co_return failure();
    auto [delayed]=co_await io::delay(30ms);
    if (delayed || state.done || !state.reading) co_return failure();
    state.observed=true;
    if (state.mode.ends_with("abandon")) {
        state.abandon=true; context.stop(); auto [released]=co_await state.release.wait(); co_return capy::results<>{released};
    }
    if (state.mode.ends_with("stop")) state.stop.request_stop();
    else if (state.client) state.client->cancel();
    else if (state.server) state.server->cancel();
    state.release.set(); co_return capy::results<>{};
}
auto root(io::io_context& context,t::ClientProfile const& profile,t::ServerCredential const& credential,State& state) -> capy::task<> {
    io::tcp_acceptor listener(context);
    if (listener.open() || listener.bind(io::endpoint(io::ipv4_address::loopback(),0)) || listener.listen()) co_return;
    auto port=listener.local_endpoint().port();
    if (state.mode.starts_with("client")) {
        auto [error,active,peer,controller]=co_await capy::when_all(client(context,port,profile,state),stalled_peer(context,listener,port,false,state),control(context,state));
        (void)active; (void)peer; (void)controller; if (error && !state.stop.stop_requested()) state.valid=false;
    } else {
        auto [error,active,peer,controller]=co_await capy::when_all(server(listener,credential,state),stalled_peer(context,listener,port,true,state),control(context,state));
        (void)active; (void)peer; (void)controller; if (error && !state.stop.stop_requested()) state.valid=false;
    }
    state.finished=true;
}
auto main(int argc,char** argv) -> int {
    if (argc!=5 || (std::string_view(argv[4])!="0" && std::string_view(argv[4])!="1")) return 64;
    auto mode=std::string_view(argv[1]);
    if ((mode!="client-cancel" && mode!="server-cancel" && mode!="client-stop" && mode!="server-stop" && mode!="client-abandon" && mode!="server-abandon" &&
         mode!="client-exception" && mode!="server-exception")) return 64;
    bool uring=std::string_view(argv[4])=="1"; if (uring && !io::has_uring) return 77;
    constexpr std::array<std::string_view,1> alpn{"h2"};
    auto profile=t::ClientProfile::load("localhost",argv[2],0x001d,false,alpn);
    auto credential=t::load_server_credential(argv[2],argv[3]); if (!profile || !credential) return 65;
    State state{mode}; auto context=std::unique_ptr<io::io_context>(new io::io_context(io::make_io_context(uring)));
    capy::run_async(context->get_executor(),state.stop.get_token(),[] {},[&](std::exception_ptr) { state.valid=false; })(root(*context,*profile,*credential,state));
    context->run_for(6s);
    if (!state.abandon && !state.finished) { state.release.set(); state.stop.request_stop(); context->restart(); context->run_for(1s); }
    auto stopped=context->stopped(); context.reset();
    bool success=state.valid && stopped && state.entered && state.destroyed && state.owner_cleanup && !state.reading && !state.writing;
    if (mode.ends_with("abandon")) success=success && state.abandon && state.observed && !state.finished && !state.done;
    else if (mode.ends_with("exception")) success=success && state.finished && state.done && state.caught && state.idle && state.inactive;
    else success=success && state.finished && state.done && state.observed && state.rejected && state.error==0 && state.idle && state.inactive;
    if (!success) std::cerr << "gRPC TLS handshake " << mode << " failed: backend=" << uring << " valid=" << state.valid << " done=" << state.done
        << " finished=" << state.finished << " observed=" << state.observed << " rejected=" << state.rejected << " caught=" << state.caught << " error=" << state.error
        << " flights=" << state.reading << ':' << state.writing << " idle=" << state.idle << " inactive=" << state.inactive << '\n';
    return success ? 0 : 1;
}
