import std;
import net.stream_datagrams;
import net.udp_direct;
import rules;
import xudp;
import xudp.client_io;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;

namespace n=net;
namespace d=net::stream_datagrams;
namespace x=xudp;
namespace capy=nex::capy;
namespace io=nex::corosio;
using namespace std::chrono_literals;

struct Tunnel {
    capy::async_event release;
    bool entered=false,canceled=false,borrow_intact=false;
    auto send(std::span<std::uint8_t const> bytes) -> capy::task<bool> {
        entered=true;
        auto saved=std::vector<std::uint8_t>(bytes.begin(),bytes.end());
        (void)co_await release.wait();
        // Model a transport whose cancellation acknowledgement is delayed.
        // The caller must keep encoded bytes alive until this await returns.
        borrow_intact=std::ranges::equal(bytes,saved);
        co_return true;
    }
    auto cancel() noexcept -> void {canceled=true;}
};
struct Session {
    bool closed=false;
    void* dns_operation=nullptr;
    void (*cancel_dns)(void*) noexcept=nullptr;
    auto close() noexcept -> void {closed=true;}
};
struct State {
    struct Slot {std::optional<d::Clock::time_point> active_deadline;};
    Session session;
    Slot slot;
    Slot* forwarding=&slot;
    Tunnel tunnel;
    bool resolving=false,canceled=false;
    d::Clock::time_point deadline{};
    bool writer_done=false,write_failed=false,payload_live=false,held_until_release=false;
    auto cancel() noexcept -> void {tunnel.cancel();}
};

auto write_xudp(State& state) -> capy::task<capy::results<>> {
    auto* pointer=&state.tunnel;
    d::MultiplexStream<Tunnel*> stream{&pointer,&state.slot.active_deadline,&state.session.closed};
    x::ClientIo<decltype(stream)> client(stream,1);
    std::vector<std::uint8_t> payload(128,0x5a);
    state.payload_live=true;
    struct Guard {bool& live;~Guard(){live=false;}} guard{state.payload_live};
    x::Address target{x::Family::ipv4,{127,0,0,1},4,443};
    state.slot.active_deadline=d::Clock::now()+10ms;
    auto sent=co_await client.open(target,payload);
    // A transport success after expiry must not become a committed XUDP ID.
    state.write_failed=!sent;
    state.writer_done=true;
    co_return capy::results<>{};
}

auto release_after_timeout(State& state) -> capy::task<capy::results<>> {
    auto bound=d::Clock::now()+500ms;
    while(!state.session.closed && d::Clock::now()<bound)(void)co_await io::delay(1ms);
    state.held_until_release=state.session.closed && state.tunnel.canceled &&
        state.tunnel.entered && state.payload_live && !state.writer_done;
    state.tunnel.release.set();
    co_return capy::results<>{};
}

auto supervised(State& state) -> capy::task<> {
    (void)co_await capy::when_all(write_xudp(state),d::timeout(state),release_after_timeout(state));
}

auto timeout_and_drain(bool uring) -> bool {
    auto context=io::make_io_context(uring);
    State state;state.slot.active_deadline=d::Clock::time_point::max();
    bool done=false,failed=false;
    capy::run_async(context.get_executor(),[&]{done=true;},[&](std::exception_ptr){failed=true;})(supervised(state));
    context.run_for(1s);
    auto completed=done;
    if(!done) {
        state.session.close();state.cancel();state.tunnel.release.set();
        context.run_for(100ms);
    }
    return completed && !failed && state.held_until_release && state.writer_done && state.write_failed &&
        !state.payload_live && state.tunnel.borrow_intact;
}

auto expired_direct() -> bool {
    auto policy=::rules::RouteMatcher::compile(std::span<::rules::RouteRule const>{},0,2);
    if(!policy)return false;
    n::UdpSocket origin;
    if(!origin.open() || !origin.bind({4,{127,0,0,1},0}))return false;
    auto endpoint=origin.local_endpoint();if(!endpoint)return false;
    n::UdpDirect direct(*policy);
    n::UdpTarget target{n::UdpTargetKind::ipv4,std::span(endpoint->address).first(4),endpoint->port};
    std::array<std::uint8_t,3> data{1,2,3};
    auto denied=direct.send_selected(target,*endpoint,data,d::Clock::now()-1ms);
    if(denied)return false;
    auto error=std::get_if<std::error_code>(&denied.error());
    if(!error || *error!=std::errc::timed_out)return false;
    std::array<std::uint8_t,32> bytes{};
    auto empty=origin.receive(bytes);if(!empty || *empty)return false;
    if(!direct.send(target,*endpoint,data,nullptr,{},d::Clock::now()+1s))return false;
    auto until=d::Clock::now()+100ms;
    do {
        auto received=origin.receive(bytes);if(!received)return false;
        if(*received)return (**received).size==data.size() &&
            std::ranges::equal(std::span(bytes).first(data.size()),data);
        std::this_thread::sleep_for(1ms);
    } while(d::Clock::now()<until);
    return false;
}

auto main() -> int {
    if(!expired_direct())return 1;
    if(!timeout_and_drain(false))return 2;
    if(io::has_uring && !timeout_and_drain(true))return 3;
    std::println("stream datagram deadline: expired direct skip, late XUDP write rejection and payload held through cancellation acknowledgement passed");
}
