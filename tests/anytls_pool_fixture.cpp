import std;
import anytls;
import anytls.auth;
import anytls.client;
import anytls.connection;
import anytls.padding;
import anytls.session;
import anytls.writer;
import anytls.pool;
import net.datagram_frame;
import tls.profiles;
import tls.connector;
import platform.socket_options;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;

namespace a=anytls;
namespace io=nex::corosio;
namespace capy=nex::capy;
using namespace std::chrono_literals;
struct Counters {
    capy::async_event gate;
    unsigned made=0,entered=0,canceled=0;
    bool blocked=false,fail_once=false;
};
struct Resolver {
    io::endpoint node;
    Counters* counters;
    bool canceled=false;
    auto cancel() noexcept -> void {
        if (canceled) return;
        canceled=true; ++counters->canceled; counters->gate.set();
    }
    auto operator()(a::IoClock::time_point deadline) -> capy::task<std::optional<std::vector<io::endpoint>>> {
        ++counters->entered;
        if (counters->blocked) {
            auto [error]=co_await io::timeout(counters->gate.wait(),deadline);
            if (error) co_return std::nullopt;
        }
        if (std::exchange(counters->fail_once,false) || canceled || a::IoClock::now()>=deadline) co_return std::nullopt;
        co_return std::vector<io::endpoint>{node};
    }
};
using Connector=tls::detail::PhysicalConnector<Resolver,tls::ClientProfile>;
struct Factory {
    using Connection=a::PooledConnection<Connector>;
    io::io_context* context;
    tls::ClientProfile const* profile;
    ::platform::TcpSocketOptions const* options;
    Counters* counters;
    std::uint16_t port;
    auto operator()(a::PaddingScheme& padding,capy::async_event* changed) -> std::unique_ptr<Connection> {
        ++counters->made;
        return std::make_unique<Connection>(padding,changed,*context,
            Resolver{io::endpoint(io::ipv4_address::loopback(),port),counters},*profile,*options);
    }
};
using Client=a::Client<Factory>;
struct State {
    tls::ClientProfile profile;
    ::platform::TcpSocketOptions options;
    Counters counters;
    std::optional<Client> client;
    explicit State(tls::ClientProfile value) : profile(std::move(value)) {}
};
struct Stop { Client& owner; ~Stop() { owner.stop(); } };
template<class Predicate>
auto until(Predicate predicate,a::IoClock::time_point deadline) -> capy::task<bool> {
    while (!predicate()) {
        if (a::IoClock::now()>=deadline) co_return false;
        auto [error]=co_await io::delay(1ms);
        if (error) co_return false;
    }
    co_return true;
}
auto exchange(Client::Lease& lease,std::uint16_t port,unsigned stream_id) -> capy::task<bool> {
    auto* session=lease.connection().protocol();
    a::Address address{net::ProxyAddressFamily::ipv4,{127,0,0,1},4,port};
    auto deadline=a::IoClock::now()+3s;
    auto id=co_await session->open(address,deadline);
    if (!id || *id!=stream_id) co_return false;
    a::StreamChannel channel(*session,*id);
    std::array<std::uint8_t,16384> sent{},received{};
    for (std::size_t i=0;i<sent.size();++i) sent[i]=static_cast<std::uint8_t>(i+stream_id);
    if (!co_await channel.send(sent,deadline)) co_return false;
    std::size_t size=0;
    while (size<received.size()) {
        auto read=co_await channel.read(std::span(received).subspan(size),deadline);
        if (!read || !*read) co_return false;
        size+=*read;
    }
    co_return sent==received && co_await channel.close_output(deadline);
}
auto release_later(Client::Lease& lease) -> capy::task<capy::results<>> {
    (void)co_await io::delay(20ms); lease.reset();
    co_return capy::results<>{};
}
auto stop_later(Client& owner) -> capy::task<capy::results<>> {
    (void)co_await io::delay(20ms); owner.stop();
    co_return capy::results<>{};
}
auto waiting(Client& owner,bool& passed) -> capy::task<capy::results<>> {
    auto lease=co_await owner.acquire(a::IoClock::now()+2s);
    passed=lease && lease->sequence()==3;
    co_return capy::results<>{};
}
auto waiting_stop(Client& owner,bool& passed) -> capy::task<capy::results<>> {
    auto lease=co_await owner.acquire(a::IoClock::now()+2s);
    passed=!lease && lease.error()==a::ClientError::closed;
    co_return capy::results<>{};
}
auto cancel_later(std::stop_source& source) -> capy::task<capy::results<>> {
    (void)co_await io::delay(20ms); source.request_stop();
    co_return capy::results<>{};
}
auto waiting_cancel(Client& owner,std::stop_token token,bool& passed) -> capy::task<capy::results<>> {
    auto lease=co_await owner.acquire(a::IoClock::now()+2s,token);
    passed=!lease && lease.error()==a::ClientError::closed;
    co_return capy::results<>{};
}
auto cancel_request(State& state,std::uint16_t target,std::string_view mode,int& result) -> capy::task<> {
    auto& client=*state.client; Stop stop{client};
    std::optional<Client::Lease> held;
    if (mode=="waiter-cancel") {
        if (!co_await until([&] { return client.idle_count()==1; },a::IoClock::now()+3s)) { result=31; co_return; }
        auto acquired=co_await client.acquire(a::IoClock::now()+3s);
        if (!acquired) { result=32; co_return; }
        held.emplace(std::move(*acquired));
    }
    bool passed=false; std::stop_source source;
    (void)co_await capy::when_all(waiting_cancel(client,source.get_token(),passed),cancel_later(source));
    if (!passed || (held && !held->connection().usable()) || (!held && state.counters.canceled!=1)) { result=33; co_return; }
    held.reset(); state.counters.blocked=false; state.counters.gate.clear();
    auto made=state.counters.made;
    auto already_canceled=co_await client.acquire(a::IoClock::now()+3s,source.get_token());
    if (already_canceled || already_canceled.error()!=a::ClientError::closed || state.counters.made!=made) { result=34; co_return; }
    auto reused=co_await client.acquire(a::IoClock::now()+3s);
    if (!reused || reused->sequence()!=1 || !co_await exchange(*reused,target,1) ||
        state.counters.made!=(mode=="waiter-cancel" ? 1u : 2u)) { result=35; co_return; }
    reused->reset(); client.stop();
    result=co_await until([&] { return client.drained(); },a::IoClock::now()+3s) ? 0 : 36;
}
auto warm_reuse(State& state,std::uint16_t target,int& result) -> capy::task<> {
    auto& client=*state.client; Stop stop{client};
    if (!co_await until([&] { return client.idle_count()==2; },a::IoClock::now()+3s) || state.counters.made!=2) { result=10; co_return; }
    auto newest=co_await client.acquire(a::IoClock::now()+3s),older=co_await client.acquire(a::IoClock::now()+3s);
    if (!newest || !older || newest->sequence()!=2 || older->sequence()!=1) { result=11; co_return; }
    auto extra=co_await client.acquire(a::IoClock::now()+3s);
    if (!extra || extra->sequence()!=3 || state.counters.made!=3 || client.size()!=3) { result=12; co_return; }
    auto began=a::IoClock::now();
    auto full=co_await client.acquire(began+40ms);
    if (full || full.error()!=a::ClientError::timeout || a::IoClock::now()-began<35ms || state.counters.made!=3) { result=13; co_return; }
    bool passed=false;
    (void)co_await capy::when_all(waiting(client,passed),release_later(*extra));
    if (!passed) { result=14; co_return; }
    newest->reset(); older->reset();
    for (unsigned index=1;index<=2;++index) {
        auto reused=co_await client.acquire(a::IoClock::now()+3s);
        if (!reused || reused->sequence()!=3 || !co_await exchange(*reused,target,index)) { result=15; co_return; }
    }
    if (!co_await until([&] { return client.size()==2 && client.idle_count()==2; },a::IoClock::now()+3s) || state.counters.made!=3) {
        result=16; co_return;
    }
    client.stop();
    result=co_await until([&] { return client.drained(); },a::IoClock::now()+3s) ? 0 : 17;
}
auto lifecycle(State& state,std::uint16_t target,std::string_view mode,bool& ready,int& result) -> capy::task<> {
    auto& client=*state.client; Stop stop{client};
    if (mode=="starting-abandon" || mode=="starting-stop") {
        if (!co_await until([&] { return state.counters.entered==1; },a::IoClock::now()+3s)) { result=20; co_return; }
    } else {
        if (!co_await until([&] { return client.idle_count()==1; },a::IoClock::now()+3s)) { result=21; co_return; }
        if (mode=="recover" && state.counters.made!=2) { result=22; co_return; }
    }
    if (mode=="active-abandon") {
        auto lease=co_await client.acquire(a::IoClock::now()+3s);
        if (!lease) { result=23; co_return; }
        auto* session=lease->connection().protocol();
        a::Address address{net::ProxyAddressFamily::ipv4,{127,0,0,1},4,target};
        auto id=co_await session->open(address,a::IoClock::now()+3s);
        if (!id) { result=24; co_return; }
        a::StreamChannel channel(*session,*id);
        ready=true;
        std::array<std::uint8_t,1> bytes{};
        (void)co_await channel.read(bytes,a::IoClock::now()+60s);
        result=25; co_return;
    }
    if (mode=="waiter-stop") {
        auto lease=co_await client.acquire(a::IoClock::now()+3s);
        if (!lease) { result=26; co_return; }
        bool passed=false;
        (void)co_await capy::when_all(waiting_stop(client,passed),stop_later(client));
        if (!passed) { result=27; co_return; }
        lease->reset();
    } else if (mode.ends_with("abandon")) {
        ready=true; (void)co_await io::delay(60s);
        result=28; co_return;
    }
    client.stop();
    auto closed=co_await client.acquire(a::IoClock::now()+1s);
    if (closed || closed.error()!=a::ClientError::closed) { result=29; co_return; }
    result=co_await until([&] { return client.drained(); },a::IoClock::now()+3s) ? 0 : 30;
}
auto main(int argc,char** argv) -> int {
    if (argc!=8) return 64;
    auto mode=std::string_view(argv[1]);
    if (mode!="warm" && mode!="recover" && mode!="waiter-stop" && mode!="starting-stop" && mode!="waiter-cancel" && mode!="starting-cancel" && mode!="idle-abandon" &&
        mode!="active-abandon" && mode!="starting-abandon" && mode!="queued-abandon") return 64;
    auto number=[](char const* text) -> unsigned {
        unsigned value=0; auto end=text+std::char_traits<char>::length(text); auto parsed=std::from_chars(text,end,value);
        return parsed.ec==std::errc{} && parsed.ptr==end ? value : 0;
    };
    auto peer=number(argv[2]),target=number(argv[3]);
    if (!peer || peer>65535 || !target || target>65535) return 64;
    auto profile=tls::ClientProfile::load("localhost",argv[4]);
    auto password=a::PasswordKey::load(argv[6]);
    auto padding=a::PaddingScheme::parse(a::default_padding_scheme);
    if (!profile || !password || !padding) return 65;
    State state(std::move(*profile));
    state.counters.blocked=mode.starts_with("starting-");
    state.counters.fail_once=mode=="recover";
    int result=99; bool ready=false,done=false;
    {
        auto context=io::make_io_context(std::string_view(argv[7])=="1");
        a::PoolOptions options{.max_sessions=mode=="warm" ? 3u : 1u,.min_idle=mode=="warm" ? 2u : mode=="starting-cancel" ? 0u : 1u,
            .idle_timeout=80ms,.check_interval=10ms};
        state.client.emplace(context,Factory{&context,&state.profile,&state.options,&state.counters,static_cast<std::uint16_t>(peer)},
            password->view(),std::move(*padding),options,3s);
        state.client->start();
        if (mode=="queued-abandon") { ready=true; result=0; }
        else {
            auto finished=[&] { done=true; };
            auto failed=[&](std::exception_ptr error) {
                try { if (error) std::rethrow_exception(error); }
                catch (std::exception const& e) { std::cerr<<e.what()<<std::endl; }
                state.client->stop(); result=98; done=true;
            };
            auto operation=mode=="warm" ? warm_reuse(state,target,result) :
                mode.ends_with("cancel") ? cancel_request(state,target,mode,result) : lifecycle(state,target,mode,ready,result);
            capy::run_async(context.get_executor(),finished,failed)(std::move(operation));
            auto deadline=a::IoClock::now()+8s;
            while (!ready && !done && a::IoClock::now()<deadline) { context.restart(); context.run_for(5ms); }
            if (!ready && !done) {
                state.client->stop(); context.restart(); context.run_for(1s);
                std::cerr<<"pool fixture timed out"<<std::endl; std::_Exit(66);
            }
            if (ready && done) result=67;
            else if (ready) result=0;
        }
        // The state, TLS identity and key outlive this deliberate destruction.
    }
    if (!state.client->drained()) { std::cerr<<"client roots survived context abandonment"<<std::endl; std::_Exit(68); }
    if (result) std::cerr<<"AnyTLS pool mode "<<mode<<" failed: "<<result<<std::endl;
    else std::cout<<"pool-passed"<<std::endl;
    return result;
}
