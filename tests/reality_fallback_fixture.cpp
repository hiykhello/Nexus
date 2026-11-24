#include <fcntl.h>
#include <unistd.h>
import std;
import capy;
import corosio;
import reality.fallback;
namespace io = ::corosio;
using namespace std::chrono_literals;
struct Fixture { io::io_context context{io::epoll}; io::local_stream_socket client{context},cover{context}; bool done=false,ok=false; };
auto run(Fixture& f,std::span<std::uint8_t const> prefix) -> capy::task<> {
    try { f.ok=co_await reality::fallback(f.client,f.cover,prefix); }
    catch (...) { f.ok=false; }
    f.done=true;
}
int main(int argc,char** argv) {
    if (argc!=4 && argc!=5) return 1;
    bool cancel=argc==5 && std::string_view(argv[4])=="cancel";
    auto a=std::atoi(argv[1]), b=std::atoi(argv[2]);
    if (fcntl(a,F_SETFL,fcntl(a,F_GETFL,0)|O_NONBLOCK)<0 || fcntl(b,F_SETFL,fcntl(b,F_GETFL,0)|O_NONBLOCK)<0) return 2;
    std::ifstream file(argv[3],std::ios::binary); std::vector<std::uint8_t> prefix{std::istreambuf_iterator<char>(file),{}};
    Fixture f; if (f.client.assign(a) || f.cover.assign(b)) return 3;
    capy::run_async(f.context.get_executor())(run(f,prefix)); (void)f.context.run_for(cancel ? 200ms : 10000ms);
    if (!f.done) { f.client.cancel(); f.cover.cancel(); f.context.restart(); (void)f.context.run_for(2s); }
    if (!f.done || (cancel ? f.ok : !f.ok)) std::cerr << "done=" << f.done << " ok=" << f.ok << "\n";
    return f.done && (cancel ? !f.ok : f.ok) ? 0 : 4;
}
