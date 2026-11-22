import std;
import httpupgrade;
import httpupgrade.stream;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;

namespace h=httpupgrade;
namespace capy=nex::capy;
namespace io=nex::corosio;
using namespace std::chrono_literals;
struct MemoryStream {
    std::string input,output;
    std::size_t position=0,chunk=4096,reads=0,writes=0,cancels=0;
    std::optional<h::Clock::time_point> observed;
    std::chrono::milliseconds read_delay{0};
    bool mismatch=false,fail_write=false,fail_read=false,throw_read=false;
    auto cancel() noexcept -> void { ++cancels; }
    auto record(h::Deadline deadline) -> void {
        if (!observed) observed=deadline;
        else if (observed!=deadline) mismatch=true;
    }
    auto read(std::span<std::uint8_t> bytes,h::Deadline deadline) -> capy::task<std::expected<std::size_t,int>> {
        record(deadline); ++reads;
        if (read_delay.count()) { auto [error]=co_await io::delay(read_delay); if (error) co_return std::unexpected(1); }
        if (throw_read) throw std::bad_alloc();
        if (fail_read) co_return std::unexpected(1);
        auto size=std::min({bytes.size(),chunk,input.size()-position});
        std::copy_n(input.begin()+position,size,bytes.begin()); position+=size; co_return size;
    }
    auto send(std::span<std::uint8_t const> bytes,h::Deadline deadline) -> capy::task<bool> {
        record(deadline); ++writes;
        if (fail_write) co_return false;
        output.append(reinterpret_cast<char const*>(bytes.data()),bytes.size()); co_return true;
    }
};
struct Result { bool done=false; std::optional<std::expected<h::Ready,h::Failure>> value; std::exception_ptr exception; };
auto upgrade(MemoryStream& stream,h::Profile const& profile,h::Clock::time_point deadline,Result& result) -> capy::task<> {
    try {
        if (profile.is_client()) result.value=co_await h::connect(stream,profile,deadline);
        else result.value=co_await h::accept(stream,profile,deadline);
    }
    catch (...) { result.exception=std::current_exception(); }
    result.done=true;
}
auto memory(bool uring) -> bool {
    auto fail=[uring](std::string_view stage) {
        std::cerr << "HTTPUpgrade memory " << stage << " failed: backend=" << uring << '\n'; return false;
    };
    auto client=h::Profile::client("cover.example","/tunnel"),server=h::Profile::server("cover.example","/tunnel");
    if (!client || !server) return fail("profile");
    for (auto const* profile:{&*client,&*server}) for (auto chunk:{1u,3u,4096u}) {
        auto context=io::make_io_context(uring);
        MemoryStream stream{std::string(profile->is_client() ? server->wire() : client->wire())+"prefetched"};
        stream.chunk=chunk;
        Result result; auto deadline=h::Clock::now()+1s;
        capy::run_async(context.get_executor())(upgrade(stream,*profile,deadline,result)); context.run_for(1s);
        if (!result.done || !result.value || !*result.value || result.exception || stream.cancels || stream.mismatch ||
            stream.output!=profile->wire() || stream.observed!=deadline) {
            std::cerr << "client=" << profile->is_client() << " chunk=" << chunk << " done=" << result.done
                      << " returned=" << result.value.has_value() << " exception=" << bool(result.exception)
                      << " reads=" << stream.reads << " writes=" << stream.writes << " cancels=" << stream.cancels
                      << " mismatch=" << stream.mismatch << '\n';
            return fail("successful handshake");
        }
        auto& ready=**result.value;
        std::string received(ready.unread.begin(),ready.unread.end()); received.append(stream.input.substr(stream.position));
        if (received!="prefetched" || (chunk==4096 && ready.unread.size()!=10)) return fail("pre-read handoff");
    }
    for (auto mode:{0,1,2,3,4,5}) {
        auto context=io::make_io_context(uring);
        MemoryStream stream{mode==3 ? "HTTP/1.1 101" : "HTTP/1.1 403 Forbidden\r\n\r\n"};
        stream.fail_write=mode==1; stream.fail_read=mode==2; stream.throw_read=mode==4;
        Result result; auto deadline=h::Clock::now()+(mode==5 ? -1s : 1s);
        capy::run_async(context.get_executor())(upgrade(stream,*client,deadline,result)); context.run_for(1s);
        auto rejected=[&](std::string_view stage) { std::cerr << "mode=" << mode << '\n'; return fail(stage); };
        if (!result.done || !stream.cancels || stream.mismatch) return rejected("failure cleanup");
        if (mode==4) { if (!result.exception) return rejected("read exception"); }
        else if (!result.value || *result.value || result.exception) return rejected("failure result");
        if (mode==3 && result.value->error().error!=h::Error::truncated) return rejected("truncated header");
        if (mode==5 && (stream.reads || stream.writes || result.value->error().error!=h::Error::timeout)) return rejected("expired before I/O");
    }
    {
        auto context=io::make_io_context(uring);
        MemoryStream stream{std::string(client->wire())}; stream.chunk=1; stream.read_delay=15ms;
        Result result; auto started=h::Clock::now();
        capy::run_async(context.get_executor())(upgrade(stream,*server,started+50ms,result)); context.run_for(1s);
        if (!result.done || !result.value || *result.value || result.value->error().error!=h::Error::timeout ||
            !stream.cancels || stream.mismatch || stream.writes || h::Clock::now()-started>=300ms) return fail("slow input shared deadline");
    }
    return true;
}
struct Pending { bool done=false; h::Error error=h::Error::state; };
auto pending(io::local_stream_socket& socket,h::Profile const& profile,h::Clock::time_point deadline,Pending& result) -> capy::task<> {
    h::SocketByteStream lower(socket);
    auto accepted=co_await h::accept(lower,profile,deadline);
    result.error=accepted ? h::Error::state : accepted.error().error;
    result.done=true;
}
auto lifecycle(bool uring,bool stop) -> bool {
    auto context=io::make_io_context(uring);
    io::local_stream_socket incoming(context),peer(context);
    if (io::connect_pair(incoming,peer)) return false;
    auto profile=h::Profile::server(); if (!profile) return false;
    Pending result;
    capy::run_async(context.get_executor())(pending(incoming,*profile,h::Clock::now()+(stop ? 5s : 50ms),result));
    context.run_for(stop ? 10ms : 200ms);
    if (stop) {
        if (result.done) return false;
        incoming.cancel(); context.restart(); context.run_for(1s);
    }
    return result.done && result.error==(stop ? h::Error::transport : h::Error::timeout) && context.stopped();
}
struct AbandonState { bool entered=false,destroyed=false,canceled=false,returned=false; };
struct TrackedStream {
    h::SocketByteStream<io::local_stream_socket> lower;
    AbandonState& state;
    ~TrackedStream() { state.destroyed=true; }
    auto read(std::span<std::uint8_t> bytes,h::Deadline deadline) { return lower.read(bytes,deadline); }
    auto send(std::span<std::uint8_t const> bytes,h::Deadline deadline) { return lower.send(bytes,deadline); }
    auto cancel() noexcept -> void { state.canceled=true; lower.cancel(); }
};
auto abandon_child(io::io_context& context,h::Profile const& profile,AbandonState& state) -> capy::task<> {
    io::local_stream_socket incoming(context),peer(context);
    if (io::connect_pair(incoming,peer)) co_return;
    TrackedStream stream{h::SocketByteStream(incoming),state};
    state.entered=true;
    (void)co_await h::accept(stream,profile,h::Clock::now()+5s);
    state.returned=true;
}
auto abandonment(bool uring) -> bool {
    auto profile=h::Profile::server(); if (!profile) return false;
    AbandonState state;
    {
        auto context=io::make_io_context(uring);
        capy::run_async(context.get_executor())(abandon_child(context,*profile,state));
        context.run_for(10ms);
        if (!state.entered || state.destroyed || state.canceled || state.returned) return false;
    }
    return state.destroyed && state.canceled && !state.returned;
}
auto main() -> int {
    for (bool uring:{false,true}) {
        if (uring && !io::has_uring) continue;
        if (!memory(uring)) return 1;
        if (!lifecycle(uring,false)) { std::cerr << "HTTPUpgrade read timeout failed: backend=" << uring << '\n'; return 2; }
        if (!lifecycle(uring,true)) { std::cerr << "HTTPUpgrade read cancellation failed: backend=" << uring << '\n'; return 2; }
        if (!abandonment(uring)) { std::cerr << "HTTPUpgrade context abandonment failed: backend=" << uring << '\n'; return 3; }
    }
    std::println("HTTPUpgrade byte-stream handshake preserves pre-read input, one deadline, error cleanup and pending cancellation on both backends");
}
