import std;
import grpc.headers;
import grpc.session;
import grpc.stream;
import tls.profiles;
import tls.server_credential;
import tls.byte_stream;
import tls.corosio_client;
import tls.corosio_application;
import tls.corosio_server_handshake;
import capy;
import corosio;
namespace g=grpc;
namespace t=tls;
namespace io = ::corosio;
using namespace std::chrono_literals;
struct State;
struct Socket {
    io::tcp_socket& socket;
    State& state;
    std::size_t role;
    auto read_some(capy::mutable_buffer) -> capy::task<capy::results<std::size_t>>;
    auto write_some(capy::const_buffer) -> capy::task<capy::results<std::size_t>>;
    auto cancel() noexcept -> void;
};
using Connection=t::detail::ApplicationConnection<Socket>;
using Lower=t::detail::ByteStream<Socket>;
using Channel=g::Channel<Lower>;
struct State {
    std::string_view mode;
    g::Clock::time_point deadline=g::Clock::now()+15s;
    std::stop_source stop;
    capy::async_event changed,go,release;
    std::array<Channel*,2> channels{};
    std::array<Lower*,2> lowers{};
    std::array<bool,2> entered{},destroyed{},ready{},done{},success{},idle{},exception{},pause{},paused{},throw_read{},throw_write{},socket_stopped{};
    std::array<std::size_t,2> reading{},writing{},cancels{},wire_bytes{},updates{};
    std::array<std::optional<g::Failure>,2> failure{};
    std::optional<std::uint32_t> remote_status;
    bool started=false,send_started=false,send_done=false,sent=false,close_started=false,close_done=false,closed=false;
    bool blocked=false,abandon=false,finished=false,valid=true;
    std::string_view stage="setup";
    auto notify() noexcept -> void { changed.set(); }
    auto cancel() noexcept -> void { for (auto channel:channels) if (channel) channel->cancel(); release.set(); go.set(); }
};
struct Flight {
    State& state; std::size_t& count;
    Flight(State& state_,std::size_t& count_) : state(state_),count(count_) { ++count; state.notify(); }
    ~Flight() { --count; state.notify(); }
};
auto Socket::read_some(capy::mutable_buffer buffer) -> capy::task<capy::results<std::size_t>> {
    while (state.pause[role]) {
        state.paused[role]=true; state.notify();
        auto [error]=co_await state.release.wait();
        if (error) co_return capy::results<std::size_t>{error,0};
        if (state.pause[role]) state.release.clear();
    }
    if (state.socket_stopped[role]) co_return capy::results<std::size_t>{std::make_error_code(std::errc::operation_canceled),0};
    if (state.throw_read[role]) throw std::bad_alloc{};
    Flight flight(state,state.reading[role]);
    co_return co_await socket.read_some(buffer);
}
auto Socket::write_some(capy::const_buffer buffer) -> capy::task<capy::results<std::size_t>> {
    if (state.socket_stopped[role]) co_return capy::results<std::size_t>{std::make_error_code(std::errc::operation_canceled),0};
    if (state.throw_write[role]) throw std::bad_alloc{};
    Flight flight(state,state.writing[role]);
    auto [error,size]=co_await socket.write_some(buffer);
    state.wire_bytes[role]+=size;
    co_return capy::results<std::size_t>{error,size};
}
auto Socket::cancel() noexcept -> void { ++state.cancels[role]; state.socket_stopped[role]=true; state.pause[role]=false; socket.cancel(); state.release.set(); }
auto milliseconds(g::Clock::time_point point) -> std::uint64_t {
    return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(point.time_since_epoch()).count());
}
template<class Predicate>
auto until(State& state,Predicate predicate) -> capy::task<bool> {
    while (!predicate()) {
        state.changed.clear(); auto [error]=co_await io::timeout(state.changed.wait(),state.deadline);
        if (error) co_return false;
    }
    co_return true;
}
auto failure() -> capy::results<> { return capy::results<>{std::make_error_code(std::errc::io_error)}; }
auto pattern(std::size_t size,unsigned seed=0) -> std::vector<std::uint8_t> {
    std::vector<std::uint8_t> bytes(size);
    for (std::size_t i=0;i<size;++i) bytes[i]=static_cast<std::uint8_t>(i*29+seed);
    return bytes;
}
auto receive(Channel& channel,std::size_t size,unsigned seed=0) -> capy::task<bool> {
    std::array<std::uint8_t,16384> output{}; std::size_t offset=0;
    for (;;) {
        auto read=co_await channel.read(output);
        if (!read || *read>size-offset) co_return false;
        if (!*read) co_return offset==size;
        for (std::size_t i=0;i<*read;++i) if (output[i]!=static_cast<std::uint8_t>((offset+i)*29+seed)) co_return false;
        offset+=*read;
    }
}
auto update(State& state,std::size_t role) -> capy::task<capy::results<>> {
    if (!co_await until(state,[&] { return state.send_started; })) co_return failure();
    for (unsigned index=0;index<8;++index) {
        if (!co_await state.lowers[role]->key_update(true,state.deadline)) co_return failure();
        ++state.updates[role]; state.notify();
        auto [error]=co_await io::delay(1ms); if (error) co_return capy::results<>{error};
    }
    co_return capy::results<>{};
}
auto send_key_data(State& state,std::size_t role) -> capy::task<capy::results<>> {
    auto bytes=pattern(2*1024*1024,static_cast<unsigned>(role));
    state.send_started=true; state.notify();
    if (!co_await state.channels[role]->send(bytes)) co_return failure();
    if (!co_await until(state,[&] { return state.updates[role]==8; })) co_return failure();
    auto suffix=pattern(65536,static_cast<unsigned>(role));
    if (!co_await state.channels[role]->send(suffix) || !co_await state.channels[role]->close_output()) co_return failure();
    co_return capy::results<>{};
}
auto receive_key_data(State& state,std::size_t role) -> capy::task<capy::results<>> {
    if (!co_await receive(*state.channels[role],2*1024*1024+65536,static_cast<unsigned>(1-role))) co_return failure();
    co_return capy::results<>{};
}
auto queued_close(State& state) -> capy::task<capy::results<>> {
    if (!co_await until(state,[&] { return state.send_started; })) co_return failure();
    state.close_started=true; state.notify();
    state.closed=co_await state.channels[0]->close_output(); state.close_done=true; state.notify();
    co_return capy::results<>{};
}
auto upload(State& state) -> capy::task<capy::results<>> {
    auto bytes=pattern(4*1024*1024); state.send_started=true; state.notify();
    state.sent=co_await state.channels[0]->send(bytes); state.send_done=true; state.notify();
    if (state.mode=="backpressure") {
        if (!state.sent || !co_await state.channels[0]->close_output() || !co_await receive(*state.channels[0],bytes.size())) co_return failure();
    }
    co_return capy::results<>{};
}
auto application(State& state,std::size_t role) -> capy::task<capy::results<>> {
    auto& channel=*state.channels[role];
    if (!co_await channel.accept(state.deadline)) co_return failure();
    state.ready[role]=true; state.notify();
    auto [released]=co_await state.go.wait(); if (released) co_return capy::results<>{released};
    if (state.mode=="status") {
        if (role) { (void)co_await channel.close_output({},12); co_return capy::results<>{}; }
        std::array<std::uint8_t,16> bytes{};
        (void)co_await channel.read(bytes); co_return capy::results<>{};
    }
    if (state.mode=="key-update") {
        auto [error,send,read,control]=co_await capy::when_all(send_key_data(state,role),receive_key_data(state,role),update(state,role));
        (void)send; (void)read; (void)control; co_return capy::results<>{error};
    }
    if (!role) {
        if (state.mode=="backpressure" || state.mode.starts_with("exception-") || state.mode.ends_with("send")) co_return co_await upload(state);
        auto [error,send,close]=co_await capy::when_all(upload(state),queued_close(state));
        (void)send; (void)close; co_return capy::results<>{error};
    }
    if (!co_await receive(channel,4*1024*1024)) co_return failure();
    auto bytes=pattern(4*1024*1024);
    if (!co_await channel.send(bytes) || !co_await channel.close_output()) co_return failure();
    co_return capy::results<>{};
}
struct Lifetime {
    State& state; std::size_t role;
    ~Lifetime() { state.destroyed[role]=true; state.channels[role]=nullptr; state.lowers[role]=nullptr; state.notify(); }
};
auto run_channel(State& state,Connection& connection,std::size_t role) -> capy::task<> {
    auto profile=g::RequestProfile::create("nexus.Service","localhost",true); if (!profile) co_return;
    auto protocol=g::Session::create(role ? g::Role::server : g::Role::client,*profile); if (!protocol) co_return;
    Lower lower(connection); Channel channel(lower,std::move(*protocol),state.deadline);
    state.entered[role]=true; state.channels[role]=&channel; state.lowers[role]=&lower;
    Lifetime lifetime{state,role};
    try {
        auto [error,run,app]=co_await capy::when_all(channel.run(),application(state,role));
        (void)run; (void)app;
        state.success[role]=!error && channel.finished() && !channel.failure();
    } catch (std::bad_alloc const&) { state.exception[role]=true; channel.cancel(); }
    state.failure[role]=channel.failure(); state.idle[role]=connection.idle();
    if (!role) state.remote_status=channel.remote_status();
}
auto tune(io::tcp_socket& socket) -> bool {
    return !socket.set_option(io::socket_option::send_buffer_size(16384)) &&
        !socket.set_option(io::socket_option::receive_buffer_size(32768));
}
auto client(io::io_context& context,std::uint16_t port,t::ClientProfile const& profile,State& state) -> capy::task<capy::results<>> {
    io::tcp_socket raw(context);
    if (raw.open() || !tune(raw)) co_return failure();
    Socket socket{raw,state,0};
    auto [error]=co_await io::timeout(raw.connect(io::endpoint(io::ipv4_address::loopback(),port)),state.deadline);
    auto now=g::Clock::now(); auto wall=std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    auto handshake=profile.handshake(milliseconds(now),milliseconds(state.deadline),wall);
    if (error || !handshake) co_return failure();
    t::detail::ClientConnection connection(socket,std::move(*handshake));
    auto started=co_await connection.start();
    if (!started || !connection.application() || !connection.negotiated() || connection.negotiated()->alpn!=std::optional{std::vector<std::uint8_t>{'h','2'}}) co_return failure();
    co_await run_channel(state,*connection.application(),0);
    state.done[0]=true; state.notify(); co_return capy::results<>{};
}
auto server(io::tcp_acceptor& listener,t::ServerCredential const& credential,State& state) -> capy::task<capy::results<>> {
    auto [error,raw]=co_await listener.accept(); listener.close();
    if (error || !tune(raw)) co_return failure();
    Socket socket{raw,state,1}; auto now=g::Clock::now();
    auto handshake=t::make_server_handshake(credential,milliseconds(now),milliseconds(state.deadline),{},"h2");
    if (!handshake) co_return failure();
    auto started=co_await t::detail::server_handshake(socket,*handshake);
    if (!started) co_return failure();
    Connection connection(socket,std::move(started->records),std::move(started->unread));
    if (!started->release_unread_reservation()) co_return failure();
    co_await run_channel(state,connection,1);
    state.done[1]=true; state.notify(); co_return capy::results<>{};
}
auto control(io::io_context& context,State& state) -> capy::task<capy::results<>> {
    if (!co_await until(state,[&] { return state.ready[0] && state.ready[1]; })) co_return failure();
    state.started=true;
    if (state.mode=="key-update") { state.go.set(); co_return capy::results<>{}; }
    if (state.mode=="status") {
        state.go.set();
        if (!co_await until(state,[&] { return state.done[0]; })) co_return failure();
        state.cancel(); co_return capy::results<>{};
    }
    if (state.mode.starts_with("exception-")) {
        state.throw_read[0]=state.mode=="exception-read"; state.throw_write[0]=state.mode=="exception-write";
        state.go.set();
        if (!co_await until(state,[&] { return state.done[0]; })) co_return failure();
        state.cancel(); co_return capy::results<>{};
    }
    state.pause[1]=true; state.go.set();
    if (!co_await until(state,[&] { return state.paused[1] && state.writing[0] && state.send_started; })) co_return failure();
    auto [settled]=co_await io::delay(40ms); if (settled) co_return capy::results<>{settled};
    auto initial=state.wire_bytes[0],quiet=initial;
    auto stable=g::Clock::now(),started=stable;
    for (;;) {
        auto [error]=co_await io::delay(40ms);
        if (error || state.send_done || !state.writing[0] || !state.paused[1]) {
            state.valid=false; state.stage="blocked write invariant"; state.cancel(); co_return failure();
        }
        if (state.mode!="backpressure") break;
        if (quiet!=state.wire_bytes[0]) { quiet=state.wire_bytes[0]; stable=g::Clock::now(); }
        if (g::Clock::now()-stable>=1100ms) break;
        if (g::Clock::now()-started>=3s) {
            state.valid=false; state.stage="stable kernel backpressure";
            std::cerr << "wire-progress=" << initial << ':' << state.wire_bytes[0] << '\n';
            state.cancel(); co_return failure();
        }
    }
    state.blocked=true;
    if (state.mode=="backpressure") { state.pause[1]=false; state.release.set(); co_return capy::results<>{}; }
    if (state.mode.ends_with("close") && (!state.close_started || state.close_done)) { state.valid=false; state.stage="pending serialized close"; state.cancel(); co_return failure(); }
    if (state.mode.starts_with("abandon-")) {
        state.abandon=true; context.stop();
        auto [stopped]=co_await state.release.wait(); co_return capy::results<>{stopped};
    }
    if (state.mode=="stop-send" || state.mode=="stop-close") state.stop.request_stop();
    else state.cancel();
    co_return capy::results<>{};
}
auto root(io::io_context& context,t::ClientProfile const& profile,t::ServerCredential const& credential,State& state) -> capy::task<> {
    io::tcp_acceptor listener(context);
    if (listener.open() || listener.bind(io::endpoint(io::ipv4_address::loopback(),0)) || listener.listen()) co_return;
    auto port=listener.local_endpoint().port();
    auto [error,c,s,controller]=co_await capy::when_all(client(context,port,profile,state),server(listener,credential,state),control(context,state));
    (void)c; (void)s; (void)controller;
    if (error && !state.stop.stop_requested() && !state.mode.starts_with("exception-") && !state.mode.starts_with("cancel-")) state.valid=false;
    state.finished=true;
}
auto main(int argc,char** argv) -> int {
    if (argc!=5 || (std::string_view(argv[4])!="0" && std::string_view(argv[4])!="1")) return 64;
    auto mode=std::string_view(argv[1]);
    if (mode!="key-update" && mode!="backpressure" && mode!="cancel-send" && mode!="cancel-close" && mode!="stop-send" && mode!="stop-close" &&
        mode!="exception-read" && mode!="exception-write" && mode!="abandon-send" && mode!="abandon-close" && mode!="status") return 64;
    bool uring=std::string_view(argv[4])=="1"; if (uring && !io::has_uring) return 77;
    constexpr std::array<std::string_view,1> alpn{"h2"};
    auto profile=t::ClientProfile::load("localhost",argv[2],0x001d,false,alpn);
    auto credential=t::load_server_credential(argv[2],argv[3]); if (!profile || !credential) return 65;
    State state{mode}; auto context=std::unique_ptr<io::io_context>(new io::io_context(io::make_io_context(uring)));
    capy::run_async(context->get_executor(),state.stop.get_token(),[] {},[&](std::exception_ptr) { state.valid=false; })(root(*context,*profile,*credential,state));
    context->run_for(16s);
    if (!state.abandon && !state.finished) { state.cancel(); context->restart(); context->run_for(1s); }
    auto stopped=context->stopped(); context.reset();
    bool success=state.valid && stopped && state.started && state.destroyed[0] && state.destroyed[1] &&
        !state.reading[0] && !state.reading[1] && !state.writing[0] && !state.writing[1];
    if (mode=="key-update") success=success && state.finished && state.success[0] && state.success[1] && state.updates==std::array<std::size_t,2>{8,8};
    else if (mode=="backpressure") success=success && state.finished && state.blocked && state.success[0] && state.success[1];
    else if (mode.starts_with("exception-")) success=success && state.finished && state.exception[0] && state.cancels[0] && state.idle[0];
    else if (mode.starts_with("abandon-")) success=success && state.abandon && !state.finished && state.blocked && state.cancels[0] && state.cancels[1] && !state.send_done &&
        (!mode.ends_with("close") || (state.close_started && !state.close_done));
    else if (mode=="status") success=success && state.finished && state.remote_status==12 && state.failure[0] && state.failure[0]->error==g::Error::headers && state.idle[0];
    else success=success && state.finished && state.blocked && state.send_done && !state.sent &&
        (!mode.ends_with("close") || (state.close_done && !state.closed)) && state.idle[0] && state.idle[1];
    if (!success) {
        std::cerr << "gRPC TLS " << mode << " failed: backend=" << uring << " stage=" << state.stage << " valid=" << state.valid << " finished=" << state.finished
            << " blocked=" << state.blocked << " send=" << state.send_done << ':' << state.sent << " close=" << state.close_done << ':' << state.closed
            << " updates=" << state.updates[0] << ':' << state.updates[1] << '\n';
        for (std::size_t role=0;role<2;++role) if (state.failure[role]) std::cerr << "role=" << role << " failure=" << int(state.failure[role]->error) << ':' << state.failure[role]->code << '\n';
    }
    return success ? 0 : 1;
}
