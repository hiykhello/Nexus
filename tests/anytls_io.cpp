import std;
import anytls;
import anytls.auth;
import anytls.padding;
import anytls.session;
import anytls.writer;
import net.socket_stream;
import capy;
import corosio;

namespace a=anytls;
namespace io = ::corosio;
using namespace std::chrono_literals;
struct Capture {
    std::vector<std::vector<std::uint8_t>> writes;
    bool canceled=false;
    auto cancel() noexcept -> void { canceled=true; }
    auto send(std::span<std::uint8_t const> bytes,a::Deadline) -> capy::task<bool> {
        writes.emplace_back(bytes.begin(),bytes.end()); co_return !canceled;
    }
};
auto writer(a::Writer<Capture>& output,bool& done) -> capy::task<> {
    a::Key key{};
    auto deadline=a::IoClock::now()+1s;
    a::Address destination{net::ProxyAddressFamily::ipv4,{127,0,0,1},4,443};
    if (!co_await output.start(key,{},deadline) || !co_await output.open(1,destination,deadline) ||
        !co_await output.open(2,destination,deadline) || !co_await output.data(2,std::array<std::uint8_t,4>{1,2,3,4},deadline)) co_return;
    done=true;
}
auto check_writer() -> bool {
    auto padding=a::PaddingScheme::parse(a::default_padding_scheme); if (!padding) return false;
    auto context=io::make_io_context(false);
    Capture stream; a::Writer output(stream,*padding,true); bool done=false;
    capy::run_async(context.get_executor())(writer(output,done)); context.run_for(2s);
    if (!done || stream.canceled || stream.writes.size()<4 || stream.writes[0].size()!=64 ||
        stream.writes[0][32] || stream.writes[0][33]!=30) return false;
    std::vector<std::uint8_t> wire;
    for (std::size_t i=1;i<stream.writes.size();++i) wire.insert(wire.end(),stream.writes[i].begin(),stream.writes[i].end());
    a::FrameDecoder decoder;
    std::vector<a::Command> commands;
    std::vector<std::uint32_t> streams;
    std::size_t offset=0;
    while (offset<wire.size()) {
        auto fed=decoder.feed(std::span(wire).subspan(offset)); offset+=fed.consumed;
        auto frame=decoder.frame();
        if (!frame || fed.status!=a::Status::accepted) return false;
        if (frame->header.command!=a::Command::waste) { commands.push_back(frame->header.command); streams.push_back(frame->header.stream); }
        if (!decoder.consume()) return false;
    }
    return commands==std::vector{a::Command::settings,a::Command::syn,a::Command::push,a::Command::syn,a::Command::push,a::Command::push} &&
        streams==std::vector<std::uint32_t>{0,1,1,2,2,2};
}
struct DelayedCapture {
    std::vector<std::chrono::milliseconds> delays;
    std::vector<std::vector<std::uint8_t>> writes;
    std::vector<a::Deadline> deadlines;
    std::vector<a::IoClock::time_point> started;
    std::size_t index=0;
    bool canceled=false;
    capy::async_event cancel_ev;
    auto cancel() noexcept -> void { canceled=true; cancel_ev.set(); }
    auto send(std::span<std::uint8_t const> bytes,a::Deadline deadline) -> capy::task<bool> {
        auto slot=index++;
        started.push_back(a::IoClock::now());
        deadlines.push_back(deadline);
        if (slot<delays.size() && delays[slot]>0ms) {
            cancel_ev.clear();
            auto target=a::IoClock::now()+delays[slot];
            bool clamped=deadline && *deadline<target;
            if (clamped) target=*deadline;
            auto [ec]=co_await io::timeout(cancel_ev.wait(),target);
            if (canceled) co_return false;
            if (deadline && (a::IoClock::now()>=*deadline || (clamped && ec==capy::cond::timeout))) co_return false;
        }
        writes.emplace_back(bytes.begin(),bytes.end());
        co_return !canceled;
    }
};
auto check_frame_timeout() -> bool {
    auto padding=a::PaddingScheme::parse(a::default_padding_scheme); if (!padding) return false;
    auto context=io::make_io_context(false);
    // 1. Lock wait longer than write_timeout must NOT starve post-lock write timeout.
    DelayedCapture stream; stream.delays={120ms,0ms};
    a::Writer out(stream,*padding,false);
    bool done1=false,done2=false,ok1=false,ok2=false;
    auto hold=[&]() -> capy::task<> {
        ok1=co_await out.data(1,std::array<std::uint8_t,4>{1,2,3,4},a::IoClock::now()+1s);
        done1=true;
    };
    auto ctrl=[&]() -> capy::task<> {
        auto [ec]=co_await io::delay(10ms); (void)ec;
        ok2=co_await out.frame_timeout(a::Command::heart_response,7,{},80ms);
        done2=true;
    };
    capy::run_async(context.get_executor())(hold());
    capy::run_async(context.get_executor())(ctrl());
    context.run_for(2s);
    if (!done1 || !done2 || !ok1 || !ok2 || out.failed() || stream.writes.size()!=2 ||
        !stream.deadlines[1] || (*stream.deadlines[1]-stream.started[1])<40ms) return false;
    a::FrameDecoder dec;
    auto fed=dec.feed(stream.writes[1]);
    auto frame=dec.frame();
    if (fed.status!=a::Status::accepted || !frame || frame->header.command!=a::Command::heart_response ||
        frame->header.stream!=7) return false;
    // 2. Post-lock send exceeding write_timeout fails cleanly.
    DelayedCapture slow; slow.delays={150ms};
    a::Writer slow_out(slow,*padding,false);
    bool slow_done=false,slow_ok=true;
    auto run_slow=[&]() -> capy::task<> {
        slow_ok=co_await slow_out.frame_timeout(a::Command::heart_response,9,{},40ms);
        slow_done=true;
    };
    context.restart();
    capy::run_async(context.get_executor())(run_slow());
    context.run_for(2s);
    if (!slow_done || slow_ok || !slow_out.failed()) return false;
    // 3. Cancellation while queued on mutex exits cleanly.
    DelayedCapture blocked; blocked.delays={500ms};
    a::Writer blocked_out(blocked,*padding,false);
    bool b1=false,b2=false,bok2=true;
    auto hold3=[&]() -> capy::task<> {
        (void)co_await blocked_out.data(1,std::array<std::uint8_t,2>{9,8},a::IoClock::now()+2s);
        b1=true;
    };
    auto wait3=[&]() -> capy::task<> {
        auto [ec]=co_await io::delay(10ms); (void)ec;
        bok2=co_await blocked_out.frame_timeout(a::Command::fin,3,{},5s);
        b2=true;
    };
    auto cancel3=[&]() -> capy::task<> {
        auto [ec]=co_await io::delay(30ms); (void)ec;
        blocked_out.cancel();
    };
    context.restart();
    capy::run_async(context.get_executor())(hold3());
    capy::run_async(context.get_executor())(wait3());
    capy::run_async(context.get_executor())(cancel3());
    context.run_for(2s);
    if (!b1 || !b2 || bok2 || !blocked_out.failed()) return false;
    // 4. Bounded lock_timeout expires cleanly without poisoning a live writer.
    DelayedCapture held; held.delays={150ms};
    a::Writer held_out(held,*padding,false);
    bool h1=false,h2=false,hok1=false,hok2=true;
    auto hold4=[&]() -> capy::task<> {
        hok1=co_await held_out.data(1,std::array<std::uint8_t,2>{5,6},a::IoClock::now()+1s);
        h1=true;
    };
    auto wait4=[&]() -> capy::task<> {
        auto [ec]=co_await io::delay(10ms); (void)ec;
        hok2=co_await held_out.frame_timeout(a::Command::heart_response,11,{},5s,40ms);
        h2=true;
    };
    context.restart();
    capy::run_async(context.get_executor())(hold4());
    capy::run_async(context.get_executor())(wait4());
    context.run_for(2s);
    return h1 && h2 && hok1 && !hok2 && !held_out.failed();
}
using Lower=net::SocketByteStream<io::local_stream_socket>;
using Session=a::Session<Lower>;
auto read_exact(Session& session,std::uint32_t id,std::span<std::uint8_t> bytes) -> capy::task<bool> {
    auto deadline=a::IoClock::now()+2s;
    while (!bytes.empty()) {
        auto received=co_await session.read(id,bytes,deadline);
        if (!received || !*received) co_return false;
        bytes=bytes.subspan(*received);
    }
    co_return true;
}
auto serve(Session& session,int& result) -> capy::task<> {
    for (unsigned iteration=0;iteration<5;++iteration) {
        auto id=co_await session.accept(a::IoClock::now()+2s);
        if (!id || *id!=iteration+1) { result=20; session.cancel(); co_return; }
        std::array<std::uint8_t,7> address{};
        if (!co_await read_exact(session,*id,address) || address!=std::array<std::uint8_t,7>{1,127,0,0,1,1,187}) { result=21; session.cancel(); co_return; }
        if (iteration!=2 && iteration!=3 && !co_await session.acknowledge(*id,iteration!=1,a::IoClock::now()+2s)) { result=22; session.cancel(); co_return; }
        if (iteration==1) { session.release(*id); continue; }
        std::array<std::uint8_t,4096> bytes{};
        if (iteration==3) {
            auto closed=co_await session.read(*id,bytes,a::IoClock::now()+2s);
            if (!closed || *closed || !session.usable()) { result=25; session.cancel(); co_return; }
            session.release(*id); continue;
        }
        for (unsigned packet=0;packet<32;++packet) {
            if (!co_await read_exact(session,*id,bytes) || !std::ranges::all_of(bytes,[&](auto byte) { return byte==packet; })) {
                result=23; session.cancel(); co_return;
            }
            // A reused UoT/DNS handler can need application bytes before ACK.
            if (iteration==2 && !packet && !co_await session.acknowledge(*id,true,a::IoClock::now()+2s)) { result=26; session.cancel(); co_return; }
            if (!co_await session.send(*id,bytes,a::IoClock::now()+2s)) { result=23; session.cancel(); co_return; }
        }
        if (!co_await session.finish(*id,a::IoClock::now()+2s)) { result=24; session.cancel(); co_return; }
        session.release(*id);
    }
    result=0; session.cancel();
}
auto client(Session& session,int& result) -> capy::task<> {
    a::Address target{net::ProxyAddressFamily::ipv4,{127,0,0,1},4,443};
    for (unsigned iteration=0;iteration<5;++iteration) {
        auto id=co_await session.open(target,a::IoClock::now()+2s);
        if (iteration==1) {
            if (!id) { result=30; session.cancel(); co_return; }
            std::array<std::uint8_t,1> rejected{};
            auto response=co_await session.read(*id,rejected,a::IoClock::now()+2s);
            if (response || response.error()!=a::SessionError::remote || !session.usable()) { result=30; session.cancel(); co_return; }
            session.release(*id);
            continue;
        }
        if (!id || *id!=iteration+1) { result=31; session.cancel(); co_return; }
        if (iteration==3) { session.cancel_stream(*id); session.release(*id); continue; }
        std::array<std::uint8_t,4096> bytes{},response{};
        for (unsigned packet=0;packet<32;++packet) {
            std::ranges::fill(bytes,packet);
            if (!co_await session.send(*id,bytes,a::IoClock::now()+2s) || !co_await read_exact(session,*id,response) || bytes!=response) {
                result=32; session.cancel(); co_return;
            }
        }
        auto eof=co_await session.read(*id,response,a::IoClock::now()+2s);
        if (!eof || *eof || !co_await session.finish(*id,a::IoClock::now()+2s)) { result=33; session.cancel(); co_return; }
        session.release(*id);
    }
    result=0; session.cancel();
}
auto complete(capy::task<> task) -> capy::task<capy::results<>> { co_await std::move(task); co_return capy::results<>{}; }
auto server_root(Session& session,std::span<a::PasswordKey const> users,int& result,bool& done) -> capy::task<> {
    auto user=co_await session.start_server(users,a::IoClock::now()+2s);
    if (!user || *user) { result=10; session.cancel(); done=true; co_return; }
    (void)co_await capy::when_all(session.run(),complete(serve(session,result))); done=true;
}
auto client_root(Session& session,std::span<std::uint8_t const> key,int& result,bool& done) -> capy::task<> {
    if (!co_await session.start_client(key,a::IoClock::now()+2s)) { result=11; done=true; co_return; }
    (void)co_await capy::when_all(session.run(),complete(client(session,result))); done=true;
}
auto duplex(bool uring) -> bool {
    auto context=io::make_io_context(uring);
    io::local_stream_socket first(context),second(context);
    if (io::connect_pair(first,second)) return false;
    Lower one(first),two(second);
    auto client_padding=a::PaddingScheme::parse(a::default_padding_scheme),server_padding=a::PaddingScheme::parse("stop=2\n0=30-30\n1=200-300");
    auto key=a::PasswordKey::from_password(std::array<std::uint8_t,6>{'s','e','c','r','e','t'});
    if (!client_padding || !server_padding || !key) return false;
    std::vector<a::PasswordKey> users; users.push_back(std::move(*key));
    Session outgoing(one,*client_padding,true),incoming(two,*server_padding,false);
    bool client_done=false,server_done=false;
    int client_result=99,server_result=99;
    capy::run_async(context.get_executor(),[] {},[&](std::exception_ptr) { outgoing.cancel(); incoming.cancel(); client_result=90; })(client_root(outgoing,users[0].view(),client_result,client_done));
    capy::run_async(context.get_executor(),[] {},[&](std::exception_ptr) { outgoing.cancel(); incoming.cancel(); server_result=90; })(server_root(incoming,users,server_result,server_done));
    context.run_for(5s);
    outgoing.cancel(); incoming.cancel(); context.restart(); context.run_for(1s);
    if (!context.stopped()) return false;
    if (!client_done || !server_done || client_result || server_result || client_padding->raw()!=server_padding->raw()) {
        std::println("AnyTLS I/O failure: client={} server={} done={}/{}",client_result,server_result,client_done,server_done); return false;
    }
    return true;
}
auto main() -> int {
    if (!check_writer()) return 1;
    if (!check_frame_timeout()) return 3;
    for (bool uring:{false,true}) if ((!uring || io::has_uring) && !duplex(uring)) return 2;
    std::println("AnyTLS duplex framing, padding updates, reused IDs, isolated rejection/cancellation, frame_timeout and FIN passed on both backends");
}
