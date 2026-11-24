import std;
import capy;
import corosio;
namespace io = ::corosio;
using namespace std::chrono_literals;

auto context(bool uring) -> io::io_context {
    return io::make_io_context(uring);
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
    if (uring && !io::has_uring) return 5;
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
