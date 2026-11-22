import std;
import proxy;

namespace {
    std::mutex mutex;
    std::array<std::thread::id,16> worker_ids;
    std::array<void const*,16> caches{};
    std::size_t workers=0,calls=0;
}
extern "C" void nexus_test_dns_shared_access(void const* cache) noexcept {
    std::lock_guard lock(mutex);
    auto id=std::this_thread::get_id();
    for (std::size_t i=0;i<workers;++i) if (worker_ids[i]==id) {
        if (caches[i]!=cache) std::abort();
        ++calls; return;
    }
    if (workers==worker_ids.size()) std::abort();
    worker_ids[workers]=id; caches[workers]=cache; ++workers; ++calls;
}
auto main(int argc,char** argv) -> int {
    if (argc!=3) return 2;
    auto port=std::stoi(argv[1]),count=std::stoi(argv[2]);
    if (port<1 || port>65535 || count<2 || count>16) return 2;
    namespace p=proxy;
    p::Server server;
    if (!server.set_dns_upstream(std::array<std::uint8_t,4>{127,0,0,1},port)) return 3;
    auto bound=server.start(0,p::Inbound::socks5,count);
    if (!bound) return 4;
    std::cout<<*bound<<std::endl;
    std::string line; std::getline(std::cin,line);
    server.stop();
    std::size_t distinct=0;
    for (std::size_t i=0;i<workers;++i) {
        bool found=false;
        for (std::size_t j=0;j<i;++j) found|=caches[j]==caches[i];
        if (!found) ++distinct;
    }
    std::cout<<workers<<' '<<distinct<<' '<<calls<<std::endl;
    return line=="stop" ? 0 : 5;
}
