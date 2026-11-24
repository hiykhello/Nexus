import std;
import crypto;
import httpupgrade;
import httpupgrade.stream;
import vless;
import vless.corosio_client;
import vless.tls_server;
import tls.client_flight;
import tls.corosio_application;
import tls.byte_stream;
import capy;
import corosio;
namespace h=httpupgrade;
namespace v=vless;
namespace t=tls;
namespace io = ::corosio;
using namespace std::chrono_literals;
struct State {
    std::string_view mode;
    h::Clock::time_point deadline=h::Clock::now()+6s;
    std::stop_source stop;
    capy::async_event changed,release;
    std::array<std::size_t,2> reading{},writing{},wire{},cancels{};
    std::array<bool,2> stopped{},sent{},received{};
    bool pause=false,paused=false,throw_read=false,throw_write=false,blocked=false,finished=false,abandon=false,caught=false,valid=true;
    bool send_started=false,send_done=false,close_started=false,close_done=false,closed=false,partial=false;
    std::size_t updates=0,overlap=0;
    std::optional<h::Failure> upgrade_error;
    auto notify() noexcept -> void { changed.set(); }
};
struct Socket {
    io::local_stream_socket& raw; State& state; std::size_t role;
    struct Flight { State& state; std::size_t& count; ~Flight() { --count; state.notify(); } };
    auto read_some(capy::mutable_buffer buffer) -> capy::task<capy::results<std::size_t>> {
        while (role && state.pause) {
            state.paused=true; state.notify(); auto [error]=co_await state.release.wait();
            if (error) co_return capy::results<std::size_t>{error,0};
            if (state.pause) state.release.clear();
        }
        if (state.stopped[role]) co_return capy::results<std::size_t>{std::make_error_code(std::errc::operation_canceled),0};
        if (!role && state.throw_read) throw std::bad_alloc{};
        ++state.reading[role]; Flight flight{state,state.reading[role]}; state.notify(); co_return co_await raw.read_some(buffer);
    }
    auto write_some(capy::const_buffer buffer) -> capy::task<capy::results<std::size_t>> {
        if (state.stopped[role]) co_return capy::results<std::size_t>{std::make_error_code(std::errc::operation_canceled),0};
        if (!role && state.throw_write) throw std::bad_alloc{};
        ++state.writing[role]; Flight flight{state,state.writing[role]}; state.notify();
        auto [error,size]=co_await raw.write_some(buffer); state.wire[role]+=size; co_return capy::results<std::size_t>{error,size};
    }
    auto cancel() noexcept -> void { state.stopped[role]=true; ++state.cancels[role]; state.pause=false; state.release.set(); raw.cancel(); }
};
using Connection=t::detail::ApplicationConnection<Socket>;
using Lower=t::detail::ByteStream<Socket>;
using Client=v::detail::TcpClient<Socket>;
using Relay=v::detail::DuplexRelay<io::local_stream_socket,Socket>;
using Inbound=v::detail::TlsInbound<Socket>;
template<class Owner> struct CancelGuard { Owner& owner; ~CancelGuard() { owner.cancel(); } };
auto failure() -> capy::results<> { return capy::results<>{std::make_error_code(std::errc::io_error)}; }
auto user() -> v::UserId { v::UserId value{}; std::iota(value.begin(),value.end(),std::uint8_t{0}); return value; }
auto secret(unsigned value) -> t::Secret { return t::Secret(::crypto::Bytes(32,static_cast<std::uint8_t>(value))); }
auto layer(t::RecordDirection direction,unsigned value) -> t::RecordLayer {
    auto root=secret(value); auto key=t::expand_label(::crypto::Hash::sha256,root.view(),"key",{},16),iv=t::expand_label(::crypto::Hash::sha256,root.view(),"iv",{},12);
    if (!key || !iv) std::abort();
    auto record=t::RecordLayer::create(direction,::crypto::Aead::aes_128_gcm,key->view(),iv->view()); if (!record) std::abort(); return std::move(*record);
}
auto records(bool client) -> t::ApplicationRecords {
    unsigned send=client ? 1 : 2,read=client ? 2 : 1;
    return {layer(t::RecordDirection::send,send),layer(t::RecordDirection::receive,read),16385,16385,::crypto::Hash::sha256,
        ::crypto::Aead::aes_128_gcm,16,secret(send),secret(read),client ? t::ApplicationRole::client : t::ApplicationRole::server};
}
template<class Predicate> auto until(State& state,Predicate predicate) -> capy::task<bool> {
    while (!predicate()) {
        state.changed.clear(); auto [error]=co_await io::timeout(state.changed.wait(),state.deadline); if (error) co_return false;
    }
    co_return true;
}
template<class Stream> auto send(Stream& stream,std::span<std::uint8_t const> bytes,h::Clock::time_point deadline) {
    if constexpr (requires { stream.write(bytes,deadline); }) return stream.write(bytes,deadline);
    else return stream.send(bytes,deadline);
}
auto peer_start(Lower& peer,bool client,State& state) -> capy::task<capy::results<>> {
    auto profile=client ? h::Profile::client("cover.example","/nexus-upgrade") : h::Profile::server("cover.example","/nexus-upgrade");
    if (!profile) co_return failure();
    if (state.mode.starts_with("upgrade-")) {
        if (client) {
            auto wire=profile->wire();
            if (!co_await peer.send({reinterpret_cast<std::uint8_t const*>(wire.data()),13},state.deadline)) co_return failure();
        } else {
            h::HeaderDecoder decoder(*profile); std::array<std::uint8_t,512> bytes{};
            while (true) {
                auto size=co_await peer.read(bytes,state.deadline); if (!size || !*size) co_return failure();
                auto step=decoder.feed(std::span(bytes).first(*size));
                if (step.status==h::Status::accepted) break;
                if (step.status!=h::Status::incomplete) co_return failure();
            }
            auto wire=profile->wire();
            if (!co_await peer.send({reinterpret_cast<std::uint8_t const*>(wire.data()),13},state.deadline)) co_return failure();
        }
        state.partial=true; state.notify(); auto [error]=co_await state.release.wait(); (void)error; co_return capy::results<>{};
    }
    std::expected<h::Ready,h::Failure> ready=std::unexpected(h::Failure{h::Error::state});
    if (client) ready=co_await h::connect(peer,*profile,state.deadline);
    else ready=co_await h::accept(peer,*profile,state.deadline);
    if (!ready || !peer.prepend_owned(std::move(ready->unread))) co_return failure();
    if (client) {
        auto request=v::encode_tcp_request({user(),v::AddressKind::ipv4,443,{127,0,0,1}}); if (!request || !co_await peer.send(*request,state.deadline)) co_return failure();
        std::array<std::uint8_t,2> response{}; std::size_t offset=0;
        while (offset<response.size()) {
            auto size=co_await peer.read(std::span(response).subspan(offset),state.deadline); if (!size || !*size) co_return failure(); offset+=*size;
        }
        if (response!=std::array<std::uint8_t,2>{0,0}) co_return failure();
    } else {
        std::array<v::UserId,1> users{user()}; auto handshake=v::ServerHandshake::create(users); if (!handshake) co_return failure();
        std::array<std::uint8_t,4096> bytes{};
        while (true) {
            auto size=co_await peer.read(bytes,state.deadline); if (!size || !*size) co_return failure();
            auto step=handshake->feed(std::span(bytes).first(*size));
            if (step.status==v::ServerStatus::rejected || step.consumed!=*size) co_return failure();
            if (step.status==v::ServerStatus::dialing) break;
        }
        auto response=handshake->complete_dial(true); if (!response || !co_await peer.send(*response,state.deadline)) co_return failure();
    }
    co_return capy::results<>{};
}
auto start(Client& client,State& state) -> capy::task<capy::results<>> {
    auto profile=h::Profile::client("cover.example","/nexus-upgrade"); if (!profile) co_return failure();
    auto upgraded=co_await client.upgrade(*profile,state.deadline);
    if (!upgraded) { state.upgrade_error=upgraded.error(); co_return state.mode.starts_with("upgrade-") ? capy::results<>{} : failure(); }
    if (!co_await client.start({user(),v::AddressKind::ipv4,443,{127,0,0,1}},state.deadline)) co_return failure();
    co_return capy::results<>{};
}
auto start(Inbound& inbound,State& state) -> capy::task<capy::results<>> {
    auto profile=h::Profile::server("cover.example","/nexus-upgrade"); if (!profile) co_return failure();
    auto upgraded=co_await inbound.upgrade(*profile,state.deadline);
    if (!upgraded) { state.upgrade_error=upgraded.error(); co_return state.mode.starts_with("upgrade-") ? capy::results<>{} : failure(); }
    auto request=co_await inbound.read_request(state.deadline);
    if (!request || request->user!=user() || request->port!=443 || !co_await inbound.complete_dial(true,state.deadline)) co_return failure();
    co_return capy::results<>{};
}
template<class Stream> auto upload(Stream& stream,State& state,std::size_t role) -> capy::task<capy::results<>> {
    if (role && state.mode!="key-update") { auto [error]=co_await state.release.wait(); if (error) co_return capy::results<>{error}; }
    auto chunk=state.mode=="key-update" ? 65536u : 4u*1024*1024;
    std::vector<std::uint8_t> bytes(chunk,static_cast<std::uint8_t>(role ? 197 : 173));
    if (!role) { state.send_started=true; state.notify(); }
    auto count=state.mode=="key-update" ? 33u : 1u;
    for (unsigned index=0;index<count;++index) {
        if (!co_await send(stream,bytes,state.deadline)) { if (!role) state.send_done=true; co_return failure(); }
        if (state.mode=="key-update") { auto [error]=co_await io::delay(1ms); if (error) co_return capy::results<>{error}; }
    }
    state.sent[role]=true; if (!role) state.send_done=true; state.notify();
    if (state.mode=="key-update" && !co_await until(state,[&] { return state.updates==8; })) co_return failure();
    if ((state.mode=="key-update" || state.mode=="backpressure") && !co_await stream.close_output(state.deadline)) co_return failure();
    co_return capy::results<>{};
}
template<class Stream> auto download(Stream& stream,State& state,std::size_t role) -> capy::task<capy::results<>> {
    std::size_t expected=state.mode=="key-update" ? 33*65536 : 4*1024*1024,offset=0;
    std::array<std::uint8_t,16384> bytes{};
    for (;;) {
        auto size=co_await stream.read(bytes,state.deadline); if (!size || *size>expected-offset) co_return failure();
        if (!*size) { state.received[role]=offset==expected; co_return state.received[role] ? capy::results<>{} : failure(); }
        if (!std::ranges::all_of(std::span(bytes).first(*size),[role](auto value) { return value==(role ? 173 : 197); })) co_return failure();
        offset+=*size;
    }
}
auto key_updates(Lower& peer,State& state) -> capy::task<capy::results<>> {
    if (state.mode!="key-update") co_return capy::results<>{};
    if (!co_await until(state,[&] { return state.send_started; })) co_return failure();
    for (unsigned index=0;index<8;++index) {
        if (!co_await peer.key_update(true,state.deadline)) co_return failure();
        ++state.updates; if (!state.sent[0] && !state.sent[1]) ++state.overlap; state.notify();
        auto [error]=co_await io::delay(1ms); if (error) co_return capy::results<>{error};
    }
    co_return capy::results<>{};
}
template<class Stream> auto queued_close(Stream& stream,State& state) -> capy::task<capy::results<>> {
    if (state.mode=="key-update" || state.mode=="backpressure" || state.mode.starts_with("exception-")) co_return capy::results<>{};
    if (!co_await until(state,[&] { return state.send_started; })) co_return failure();
    state.close_started=true; state.notify(); state.closed=co_await stream.close_output(state.deadline); state.close_done=true;
    co_return capy::results<>{};
}
template<class Stream> auto control(Stream& stream,Lower& peer,io::io_context& context,State& state) -> capy::task<capy::results<>> {
    if (state.mode=="key-update" || state.mode.starts_with("exception-")) co_return capy::results<>{};
    if (!co_await until(state,[&] { return state.mode.starts_with("upgrade-") ? state.partial && state.reading[0] : state.paused && state.writing[0]; })) co_return failure();
    auto quiet=state.wire[0]; auto stable=h::Clock::now(),began=stable;
    for (;;) {
        auto [error]=co_await io::delay(40ms); if (error) co_return capy::results<>{error};
        if (state.mode.starts_with("upgrade-")) { if (!state.reading[0]) co_return failure(); break; }
        if (!state.writing[0] || state.send_done) co_return failure();
        if (state.mode!="backpressure") break;
        if (quiet!=state.wire[0]) { quiet=state.wire[0]; stable=h::Clock::now(); }
        if (h::Clock::now()-stable>=1100ms) break;
        if (h::Clock::now()-began>=3s) co_return failure();
    }
    state.blocked=true;
    if (state.mode=="backpressure") { state.pause=false; state.release.set(); co_return capy::results<>{}; }
    if (state.mode=="abandon" || state.mode=="upgrade-abandon") {
        state.abandon=true; context.stop(); auto [error]=co_await state.release.wait(); co_return capy::results<>{error};
    }
    if (state.mode=="stop" || state.mode=="upgrade-stop") state.stop.request_stop(); else { stream.cancel(); peer.cancel(); }
    state.release.set(); co_return capy::results<>{};
}
template<class Stream> auto data(Stream& stream,Lower& peer,io::io_context& context,State& state) -> capy::task<> {
    CancelGuard guard{stream}; CancelGuard peer_guard{peer};
    state.pause=state.mode!="key-update" && !state.mode.starts_with("exception-");
    state.throw_read=state.mode=="exception-read"; state.throw_write=state.mode=="exception-write";
    try {
        auto [error,usend,uread,psend,pread,updates,closing,controller]=co_await capy::when_all(
            upload(stream,state,0),download(stream,state,0),upload(peer,state,1),download(peer,state,1),
            key_updates(peer,state),queued_close(stream,state),control(stream,peer,context,state));
        (void)usend; (void)uread; (void)psend; (void)pread; (void)updates; (void)closing; (void)controller;
        if ((state.mode=="key-update" || state.mode=="backpressure") && error) state.valid=false;
    } catch (std::bad_alloc const&) { state.caught=true; }
}
template<bool Server> auto root(io::io_context& context,State& state) -> capy::task<> {
    io::local_stream_socket a(context),b(context),local(context); if (io::connect_pair(a,b) || a.set_option(io::socket_option::send_buffer_size(16384))) co_return;
    Socket socket{a,state,0},other{b,state,1}; Connection connection(socket,records(!Server),{}),opposite(other,records(Server),{}); Lower peer(opposite);
    if constexpr (Server) {
        std::array<v::UserId,1> users{user()}; auto handshake=v::ServerHandshake::create(users); if (!handshake) co_return;
        Inbound inbound(connection,std::move(*handshake)); CancelGuard guard{inbound}; CancelGuard peer_guard{peer};
        if (state.mode.starts_with("upgrade-")) {
            auto [error,uut,p,controller]=co_await capy::when_all(start(inbound,state),peer_start(peer,true,state),control(inbound,peer,context,state));
            (void)uut; (void)p; (void)controller; (void)error;
        } else {
            auto [error,uut,p]=co_await capy::when_all(start(inbound,state),peer_start(peer,true,state)); (void)uut; (void)p;
            if (error) co_return; co_await data(inbound,peer,context,state);
        }
    } else {
        Client client(connection); Relay relay(local,connection,client,{},false); CancelGuard guard{relay}; CancelGuard peer_guard{peer};
        if (state.mode.starts_with("upgrade-")) {
            auto [error,uut,p,controller]=co_await capy::when_all(start(client,state),peer_start(peer,false,state),control(relay,peer,context,state));
            (void)uut; (void)p; (void)controller; (void)error;
        } else {
            auto [error,uut,p]=co_await capy::when_all(start(client,state),peer_start(peer,false,state)); (void)uut; (void)p;
            if (error) co_return; co_await data(relay,peer,context,state);
        }
    }
    if (!connection.idle() || !opposite.idle()) state.valid=false; state.finished=true;
}
auto main(int argc,char** argv) -> int {
    if (argc!=4) return 64;
    auto mode=std::string_view(argv[1]),role=std::string_view(argv[2]),backend=std::string_view(argv[3]);
    if ((role!="client" && role!="server") || (backend!="0" && backend!="1") ||
        (mode!="key-update" && mode!="backpressure" && mode!="cancel" && mode!="stop" && mode!="abandon" && mode!="exception-read" && mode!="exception-write" &&
         mode!="upgrade-cancel" && mode!="upgrade-stop" && mode!="upgrade-abandon")) return 64;
    bool uring=backend=="1"; if (uring && !io::has_uring) return 77;
    State state{mode}; auto context=std::unique_ptr<io::io_context>(new io::io_context(io::make_io_context(uring)));
    auto operation=role=="server" ? root<true>(*context,state) : root<false>(*context,state);
    capy::run_async(context->get_executor(),state.stop.get_token(),[] {},[&](std::exception_ptr) { state.valid=false; })(std::move(operation));
    context->run_for(7s); auto stopped=context->stopped(); context.reset();
    bool valid=state.valid && stopped && !state.reading[0] && !state.reading[1] && !state.writing[0] && !state.writing[1];
    if (mode=="key-update") valid=valid && state.finished && state.updates==8 && state.overlap && state.sent[0] && state.sent[1] && state.received[0] && state.received[1];
    else if (mode=="backpressure") valid=valid && state.finished && state.blocked && state.sent[0] && state.sent[1] && state.received[0] && state.received[1];
    else if (mode=="abandon" || mode=="upgrade-abandon") valid=valid && state.abandon && !state.finished && state.blocked && state.cancels[0] && state.cancels[1];
    else if (mode.starts_with("exception-")) valid=valid && state.finished && state.caught && state.cancels[0] && state.cancels[1];
    else if (mode.starts_with("upgrade-")) valid=valid && state.finished && state.blocked && state.upgrade_error && state.upgrade_error->error==h::Error::transport;
    else valid=valid && state.finished && state.blocked && state.send_done && !state.sent[0] && state.close_started && state.close_done && !state.closed;
    if (!valid) std::cerr << "production VLESS/Upgrade " << mode << " " << role << " failed: backend=" << backend << " finished=" << state.finished
        << " valid=" << state.valid << " blocked=" << state.blocked << " updates=" << state.updates << " overlap=" << state.overlap
        << " sent=" << state.sent[0] << ':' << state.sent[1] << " received=" << state.received[0] << ':' << state.received[1]
        << " close=" << state.close_started << ':' << state.close_done << ':' << state.closed << " caught=" << state.caught << '\n';
    return valid ? 0 : 1;
}
