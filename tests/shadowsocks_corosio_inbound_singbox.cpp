#include <boost/capy/buffers.hpp>
#include <boost/capy/task.hpp>
#include <boost/capy/cond.hpp>
#include <boost/capy/ex/async_mutex.hpp>
#include <boost/capy/ex/run_async.hpp>
#include <boost/corosio/backend.hpp>
#include <boost/corosio/io_context.hpp>
#include <boost/corosio/tcp_socket.hpp>
#include <boost/corosio/shutdown_type.hpp>
#include <sys/socket.h>
#include <unistd.h>
#include "../src/shadowsocks/probe_close.hpp"
import std;
import shadowsocks.replay;
import shadowsocks.corosio_server;
import shadowsocks.corosio_inbound;
namespace capy=boost::capy; namespace io=boost::corosio; namespace s=shadowsocks;
using namespace std::chrono_literals;
struct Fixture {
#if BOOST_COROSIO_HAVE_LIBURING
    io::io_context context{io::uring};
#else
    io::io_context context;
#endif
    io::tcp_socket socket{context}; s::ReplayTable replay{16};
    std::array<std::uint8_t,32> key{}; std::size_t size=0; bool done=false,ok=false;
};
auto run(Fixture& f) -> capy::task<> {
    auto deadline=std::chrono::steady_clock::now()+10s;
    auto key=std::span{f.key}.first(f.size);
    auto request=co_await s::detail::receive_request(f.socket,key,f.replay,deadline);
    if (!request) {
        if (request.error()==s::detail::ServerReadError::invalid_request &&
            s::detail::prepare_probe_reset(f.socket.native_handle())) std::cerr << "failed to configure probe reset\n";
        f.socket.close(); f.done=true; co_return;
    }
    s::detail::InboundStream stream(f.socket,key,std::move(*request));
    std::array<std::uint8_t,7> expected{1,203,0,113,5,1,187};
    if (!std::ranges::equal(stream.address(),expected)) { f.done=true; co_return; }
    std::vector<std::uint8_t> input; std::array<std::uint8_t,8> buffer{};
    for (;;) {
        auto received=co_await stream.read(buffer,deadline);
        if (!received) { std::cerr << "read: " << static_cast<int>(received.error()) << "\n"; f.done=true; co_return; }
        if (!*received) break;
        input.insert(input.end(),buffer.begin(),buffer.begin()+*received);
        if (input.size()>5) { f.done=true; co_return; }
        if (input.size()==5) break;
    }
    if (std::string(input.begin(),input.end())!="hello") { std::cerr << "payload mismatch\n"; f.done=true; co_return; }
    std::array<std::uint8_t,5> first{'w','o','r','l','d'},second{'a','g','a','i','n'};
    f.ok=co_await stream.send(first,deadline);
    if (f.ok) f.ok=co_await stream.send(second,deadline);
    if (f.ok) f.ok=co_await stream.close_output();
    f.done=true;
}
auto main(int argc,char** argv) -> int {
    if (argc!=3) return 1;
    int listener=std::stoi(argv[1]); auto size=std::stoul(argv[2]);
    if (size!=16 && size!=32) return 2;
    int fd=::accept(listener,nullptr,nullptr); if (fd<0) return 3;
    Fixture f; f.size=size; for (std::size_t i=0;i<size;++i) f.key[i]=static_cast<std::uint8_t>(i);
    if (f.socket.assign(fd)) { ::close(fd); return 4; }
    capy::run_async(f.context.get_executor())(run(f)); f.context.run_for(12s);
    if (!f.done) {
        f.socket.cancel(); f.context.restart(); f.context.run_for(1s);
        if (!f.done) std::_Exit(90);
    }
    return f.ok ? 0 : 5;
}
