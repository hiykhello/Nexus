#include <boost/corosio/backend.hpp>
#include <unistd.h>
import std;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;
import nexus.shadowsocks.corosio_client;
import nexus.shadowsocks.corosio_relay;
namespace io=nex::corosio; namespace capy=nex::capy; namespace s=nexus::shadowsocks;
using namespace std::chrono_literals;
using Relay=s::detail::DuplexRelay<io::local_stream_socket,io::tcp_socket>;
struct Fixture {
#if BOOST_COROSIO_HAVE_LIBURING
    io::io_context context{io::uring};
#else
    io::io_context context;
#endif
    io::local_stream_socket local{context}; io::tcp_socket remote{context};
    std::array<std::uint8_t,32> psk{}; std::size_t size=0; std::uint16_t port=0;
    bool done=false,success=false;
};
struct State { Relay& relay; capy::async_event finished; unsigned pending=2; bool up=false,down=false;
    auto complete() -> void { if (--pending==0) finished.set(); } };
auto upload(State& state) -> capy::task<> { state.up=co_await state.relay.upload(); state.complete(); }
auto download(State& state) -> capy::task<> { state.down=co_await state.relay.download(); state.complete(); }
auto run(Fixture& f) -> capy::task<> {
    std::array<std::uint8_t,7> address{1,127,0,0,1,static_cast<std::uint8_t>(f.port>>8),static_cast<std::uint8_t>(f.port)};
    auto key=std::span{f.psk}.first(f.size);
    auto started=co_await s::detail::start_request(f.remote,key,address,std::chrono::steady_clock::now()+5s);
    if (!started) { f.done=true; co_return; }
    Relay relay(f.local,f.remote,key,std::move(*started)); State state{relay};
    capy::run_async(f.context.get_executor())(upload(state)); capy::run_async(f.context.get_executor())(download(state));
    (void)co_await state.finished.wait(); f.success=state.up && state.down; f.done=true;
}
auto main(int argc,char** argv) -> int {
    if (argc!=5) return 1;
    int local=std::stoi(argv[1]),remote=std::stoi(argv[2]); auto size=std::stoul(argv[3]),port=std::stoul(argv[4]);
    if ((size!=16 && size!=32) || port>65535) return 2;
    Fixture fixture; fixture.size=size; fixture.port=static_cast<std::uint16_t>(port);
    for (std::size_t i=0;i<size;++i) fixture.psk[i]=static_cast<std::uint8_t>(i);
    if (fixture.local.assign(local) || fixture.remote.assign(remote)) return 3;
    capy::run_async(fixture.context.get_executor())(run(fixture)); fixture.context.run_for(15s);
    if (!fixture.done) {
        fixture.local.cancel(); fixture.remote.cancel(); fixture.context.restart(); fixture.context.run_for(1s);
        if (!fixture.done) std::_Exit(90);
    }
    return fixture.success ? 0 : 4;
}
