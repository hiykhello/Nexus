import std;
import anytls;
import anytls.auth;
import anytls.padding;
import anytls.session;
import anytls.settings;
import anytls.writer;
import net.datagram_frame;
import net.socket_stream;
import capy;
import corosio;
namespace a=anytls;
namespace io = ::corosio;
using namespace std::chrono_literals;
using Lower=net::SocketByteStream<io::local_stream_socket>;
using Session=a::Session<Lower>;
struct State { std::stop_source peer_stop; bool done=false,passed=false,second=false; };
auto exact(Lower& stream,std::span<std::uint8_t> output) -> capy::task<bool> {
    while (!output.empty()) {
        auto read=co_await stream.read(output,a::IoClock::now()+6s);
        if (!read || !*read) co_return false;
        output=output.subspan(*read);
    }
    co_return true;
}
auto frame(Lower& stream,a::Command command,std::uint32_t id,std::span<std::uint8_t const> bytes={}) -> capy::task<bool> {
    auto encoded=a::encode_frame(command,id,bytes);
    co_return encoded && co_await stream.send(*encoded,a::IoClock::now()+1s);
}
auto peer(Lower& stream,State& state,int mode) -> capy::task<> {
    std::array<std::uint8_t,34> auth{};
    if (!co_await exact(stream,auth)) co_return;
    auto skip=(std::size_t(auth[32])<<8)|auth[33];
    std::array<std::uint8_t,256> padding{};
    while (skip) {
        auto size=std::min(skip,padding.size());
        if (!co_await exact(stream,std::span(padding).first(size))) co_return;
        skip-=size;
    }
    a::FrameDecoder decoder;
    std::array<std::uint8_t,4096> input{};
    for (;;) {
        auto received=co_await stream.read(input,a::IoClock::now()+6s);
        if (!received || !*received) co_return;
        auto bytes=std::span(input).first(*received);
        while (!bytes.empty()) {
            auto fed=decoder.feed(bytes); bytes=bytes.subspan(fed.consumed);
            if (fed.status==a::Status::incomplete) break;
            auto message=decoder.frame();
            if (!message || fed.status!=a::Status::accepted) co_return;
            if (message->header.command==a::Command::settings) {
                auto settings=a::encode_server_settings();
                if (!co_await frame(stream,a::Command::server_settings,0,settings)) co_return;
            } else if (message->header.command==a::Command::syn && message->header.stream==1) {
                if (!co_await frame(stream,a::Command::push,1,std::array<std::uint8_t,1>{1})) co_return;
            } else if (message->header.command==a::Command::syn && message->header.stream==2) {
                state.second=true;
                if (mode==1) {
                    auto [error]=co_await io::delay(20ms);
                    if (error || !co_await frame(stream,a::Command::waste,0)) co_return;
                    auto [later]=co_await io::delay(150ms);
                    if (!later) (void)co_await frame(stream,a::Command::push,2,std::array<std::uint8_t,1>{2});
                } else (void)co_await io::delay(6s);
                co_return;
            }
            if (!decoder.consume()) co_return;
        }
    }
}
auto application(Session& session,State& state,int mode) -> capy::task<capy::results<>> {
    a::Address address{net::ProxyAddressFamily::ipv4,{127,0,0,1},4,443};
    auto first=co_await session.open(address,a::IoClock::now()+1s);
    std::array<std::uint8_t,1> byte{};
    if (!first || !co_await session.read(*first,byte,a::IoClock::now()+1s) || byte[0]!=1 ||
        !co_await session.finish(*first,a::IoClock::now()+1s)) { session.cancel(); co_return capy::results<>{}; }
    session.release(*first);
    auto start=a::IoClock::now();
    auto second=co_await session.open(address,start+(mode==2 ? 5s : 80ms));
    if (!second || *second!=2) { session.cancel(); co_return capy::results<>{}; }
    auto read=co_await session.read(*second,byte,start+5s);
    auto elapsed=a::IoClock::now()-start;
    if (mode==1) state.passed=read && *read==1 && byte[0]==2 && elapsed>=150ms && elapsed<500ms && session.usable();
    else state.passed=!read && !session.usable() && elapsed>=(mode==2 ? 2850ms : 60ms) && elapsed<(mode==2 ? 3600ms : 400ms);
    session.release(*second); session.cancel();
    co_return capy::results<>{};
}
auto client(Session& session,State& state,int mode,std::span<std::uint8_t const> key) -> capy::task<> {
    if (co_await session.start_client(key,a::IoClock::now()+1s))
        (void)co_await capy::when_all(session.run(),application(session,state,mode));
    state.done=true; state.peer_stop.request_stop();
}
auto check(bool uring,int mode) -> bool {
    auto context=io::make_io_context(uring);
    io::local_stream_socket first(context),second(context);
    if (io::connect_pair(first,second)) return false;
    Lower one(first),two(second);
    auto padding=a::PaddingScheme::parse(a::default_padding_scheme);
    auto key=a::PasswordKey::from_password(std::array<std::uint8_t,1>{'k'});
    if (!padding || !key) return false;
    Session session(one,*padding,true); State state;
    capy::run_async(context.get_executor(),state.peer_stop.get_token(),[] {},[&](std::exception_ptr) { session.cancel(); })(peer(two,state,mode));
    capy::run_async(context.get_executor(),[] {},[&](std::exception_ptr) { session.cancel(); state.peer_stop.request_stop(); })(client(session,state,mode,key->view()));
    context.run_for(6s);
    if (!state.done) { session.cancel(); state.peer_stop.request_stop(); context.restart(); context.run_for(1s); }
    auto passed=state.done && state.passed && state.second && session.drained() && context.stopped();
    if (!passed) std::cerr<<"AnyTLS watchdog mode="<<mode<<" backend="<<uring<<" done="<<state.done<<" passed="<<state.passed<<" second="<<state.second<<'\n';
    return passed;
}
auto main() -> int {
    for (bool uring:{false,true}) if (!uring || io::has_uring)
        for (int mode:{0,1,2}) if (!check(uring,mode)) return 1;
    std::cout<<"AnyTLS reused stream watchdog honors the original deadline, caps at 3s and accepts non-ACK peer progress\n";
}
