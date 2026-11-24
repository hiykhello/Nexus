import std;
import crypto;
import tls.client_flight;
import tls.application_io;
import tls.corosio_application;
import tls.byte_stream;
import net.socket_stream;
import capy;
import corosio;
namespace t=tls;
namespace c = ::crypto;
namespace io = ::corosio;
using Clock=std::chrono::steady_clock;
using namespace std::chrono_literals;
struct State {
    capy::async_event changed;
    std::size_t reading=0,writing=0,reads=0,cancels=0;
    bool sender_done=false,sender_sent=false,waiter_done=false,accepted=true,blocked=false,done=false;
    Clock::duration elapsed{};
};
struct Socket {
    io::local_stream_socket& raw; State& state;
    struct Guard { State& state; std::size_t& count; ~Guard() { --count; state.changed.set(); } };
    auto read_some(capy::mutable_buffer buffer) -> capy::task<capy::results<std::size_t>> {
        ++state.reads; ++state.reading; Guard guard{state,state.reading}; state.changed.set();
        co_return co_await raw.read_some(buffer);
    }
    auto write_some(capy::const_buffer buffer) -> capy::task<capy::results<std::size_t>> {
        ++state.writing; Guard guard{state,state.writing}; state.changed.set();
        co_return co_await raw.write_some(buffer);
    }
    auto cancel() noexcept -> void { ++state.cancels; raw.cancel(); }
};
auto secret(unsigned value) -> t::Secret { return t::Secret(c::Bytes(32,static_cast<std::uint8_t>(value))); }
auto layer(t::RecordDirection direction,unsigned value) -> t::RecordLayer {
    auto key_secret=secret(value);
    auto key=t::expand_label(c::Hash::sha256,key_secret.view(),"key",{},16);
    auto iv=t::expand_label(c::Hash::sha256,key_secret.view(),"iv",{},12);
    if (!key || !iv) std::abort();
    auto record=t::RecordLayer::create(direction,c::Aead::aes_128_gcm,key->view(),iv->view());
    if (!record) std::abort(); return std::move(*record);
}
auto records(bool client) -> t::ApplicationRecords {
    unsigned send=client ? 1 : 2,read=client ? 2 : 1;
    return {layer(t::RecordDirection::send,send),layer(t::RecordDirection::receive,read),16385,16385,
        c::Hash::sha256,c::Aead::aes_128_gcm,16,secret(send),secret(read),client ? t::ApplicationRole::client : t::ApplicationRole::server};
}
using Stream=t::detail::ByteStream<Socket>;
auto send(Stream& stream,State& state) -> capy::task<capy::results<>> {
    c::Bytes bytes(4*1024*1024,173);
    state.sender_sent=co_await stream.send(bytes); state.sender_done=true; state.changed.set();
    co_return capy::results<>{};
}
auto waiter(Stream& stream,io::local_stream_socket& peer,State& state,int mode) -> capy::task<capy::results<>> {
    while (!state.writing) {
        state.changed.clear(); auto [error]=co_await io::timeout(state.changed.wait(),Clock::now()+1s);
        if (error) { stream.cancel(); co_return capy::results<>{error}; }
    }
    auto [delayed]=co_await io::delay(30ms);
    state.blocked=!delayed && !state.sender_done && state.writing;
    if (!state.blocked) { stream.cancel(); co_return capy::results<>{}; }
    if (mode==3) {
        auto opposite=records(false); auto update=opposite.key_update(true);
        net::SocketByteStream raw(peer);
        if (!update || !co_await raw.send(*update,Clock::now()+1s)) { stream.cancel(); co_return capy::results<>{}; }
    }
    auto started=Clock::now(),deadline=started+50ms;
    std::array<std::uint8_t,8> bytes{};
    if (mode==0) state.accepted=co_await stream.send(std::span(bytes).first(1),deadline);
    else if (mode==1) state.accepted=co_await stream.key_update(true,deadline);
    else if (mode==2) state.accepted=co_await stream.close_output(deadline);
    else state.accepted=bool(co_await stream.read(bytes,deadline));
    state.elapsed=Clock::now()-started;
    state.waiter_done=true; stream.cancel();
    co_return capy::results<>{};
}
auto root(Stream& stream,io::local_stream_socket& peer,State& state,int mode) -> capy::task<> {
    auto [error,sender,waiting]=co_await capy::when_all(send(stream,state),waiter(stream,peer,state,mode));
    (void)error; (void)sender; (void)waiting; state.done=true;
}
auto exercise(bool uring,int mode) -> bool {
    auto context=io::make_io_context(uring);
    io::local_stream_socket raw(context),peer(context);
    if (io::connect_pair(raw,peer) || raw.set_option(io::socket_option::send_buffer_size(16384))) return false;
    State state; Socket socket{raw,state};
    t::detail::ApplicationConnection connection(socket,records(true),c::Bytes{}); Stream stream(connection);
    capy::run_async(context.get_executor())(root(stream,peer,state,mode)); context.run_for(1s);
    if (!state.done) { stream.cancel(); context.restart(); context.run_for(1s); }
    bool success=context.stopped() && state.done && state.sender_done && !state.sender_sent && state.waiter_done && !state.accepted && state.blocked &&
        state.elapsed>=35ms && state.elapsed<300ms && state.cancels && !state.reading && !state.writing && connection.idle() && !connection.active() &&
        (mode!=3 || state.reads);
    if (!success) std::cerr << "gRPC shared TLS writer lock deadline failed: backend=" << uring << " mode=" << mode << " done=" << state.done
        << " sender=" << state.sender_done << ':' << state.sender_sent << " waiter=" << state.waiter_done << ':' << state.accepted
        << " blocked=" << state.blocked << " elapsed-ms=" << std::chrono::duration_cast<std::chrono::milliseconds>(state.elapsed).count() << '\n';
    return success;
}
auto main() -> int {
    for (bool uring:{false,true}) {
        if (uring && !io::has_uring) continue;
        for (int mode=0;mode<4;++mode) if (!exercise(uring,mode)) return 1;
    }
    std::println("gRPC shared TLS send/KeyUpdate/close/read-control writer lock deadlines and cancellation drainage passed");
}
