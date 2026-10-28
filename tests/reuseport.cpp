#include <boost/capy/buffers.hpp>
#include <boost/capy/ex/run_async.hpp>
#include <boost/capy/task.hpp>
#include <boost/corosio/backend.hpp>
#include <boost/corosio/io_context.hpp>
#include <boost/corosio/tcp_acceptor.hpp>
#include <boost/corosio/tcp_socket.hpp>
#include <boost/corosio/socket_option.hpp>
#include <boost/corosio/endpoint.hpp>
#include <boost/corosio/ipv4_address.hpp>
import std;
namespace io=boost::corosio;
namespace capy=boost::capy;
using namespace std::chrono_literals;

auto context(bool uring) -> io::io_context {
#if BOOST_COROSIO_HAVE_LIBURING
    if (uring) return io::io_context{io::uring};
#else
    (void)uring;
#endif
    return io::io_context{};
}
struct Worker {
    io::io_context ctx;
    io::tcp_acceptor listener{ctx};
    char id;
    bool finished=false, failed=false;
    explicit Worker(char id_,bool uring) : ctx(context(uring)), id(id_) {}
};
auto accept_loop(Worker& worker) -> capy::task<> {
    for (;;) {
        auto [error, peer]=co_await worker.listener.accept();
        if (error) break;
        auto [write_error,n]=co_await peer.write_some(capy::const_buffer(&worker.id,1));
        if (write_error || n!=1) worker.failed=true;
        peer.close();
    }
    worker.finished=true;
}
auto main(int argc,char** argv) -> int {
    bool uring=argc==2 && std::string_view(argv[1])=="uring";
    Worker a{'A',uring}, b{'B',uring};
    auto setup=[](Worker& worker,std::uint16_t port) {
        if (worker.listener.open()) return false;
        if (worker.listener.set_option(io::socket_option::reuse_port(true))) return false;
        auto [option_error, option] = worker.listener.get_option<io::socket_option::reuse_port>();
        if (option_error || !option.value()) return false;
        return !worker.listener.bind(io::endpoint(io::ipv4_address::loopback(),port)) && !worker.listener.listen();
    };
    if (!setup(a,0)) return 2;
    auto port=a.listener.local_endpoint().port();
    if (!port || !setup(b,port) || b.listener.local_endpoint().port()!=port) return 3;
    std::atomic<bool> stopping=false;
    auto drive=[&](Worker& worker) {
        capy::run_async(worker.ctx.get_executor())(accept_loop(worker));
        while (!stopping.load(std::memory_order_relaxed)) {
            worker.ctx.restart(); (void)worker.ctx.run_for(20ms);
        }
        worker.listener.close();
        worker.ctx.restart(); (void)worker.ctx.run_for(1s);
    };
    std::thread one(drive,std::ref(a)), two(drive,std::ref(b));
    std::cout << port << std::endl;
    std::string line;
    std::getline(std::cin,line);
    stopping=true;
    one.join(); two.join();
    return a.finished && b.finished && !a.failed && !b.failed ? 0 : 4;
}
