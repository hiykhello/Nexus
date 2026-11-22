import std;
import proxy;
import dns.local_config;
using namespace std::chrono_literals;
auto count(std::string_view path) -> std::size_t {
    return std::ranges::distance(std::filesystem::directory_iterator(path),std::filesystem::directory_iterator{});
}
auto main(int argc, char** argv) -> int {
    if (argc != 2 || (std::string_view(argv[1]) != "1" && std::string_view(argv[1]) != "2" && std::string_view(argv[1]) != "race")) return 5;
    // The process-wide DNS refresh thread outlives each server.
    (void)dns::system_local_snapshots();
    bool race=std::string_view(argv[1])=="race";
    unsigned workers = race ? 2u : static_cast<unsigned>(argv[1][0] - '0');
    proxy::Server server;
    auto fds=count("/proc/self/fd"), threads=count("/proc/self/task");
    auto port=server.start(0,proxy::Inbound::socks5,workers);
    if (!port) return 1;
    auto deadline=std::chrono::steady_clock::now()+3s;
    while (server.healthy() && std::chrono::steady_clock::now()<deadline) server.poll(10ms);
    if (server.healthy()) return 2;
    auto failure=server.failure();
    if (!failure || failure->kind!=proxy::FailureKind::accept ||
        (failure->system_error!=std::errc::io_error && (!race || failure->system_error!=std::errc::no_space_on_device)) ||
        proxy::describe(failure->kind)!="accept failed") return 8;
    auto before_stop=server.prepare_vless_inbound("","",{});
    if (before_stop || before_stop.error()!="server is running") return 11;
    server.stop();
    auto after_stop=server.prepare_vless_inbound("","",{});
    if (after_stop || after_stop.error()=="server is running") return 12;
    if (!server.failure() || server.failure()->system_error!=failure->system_error || server.failure()->kind!=failure->kind) return 9;
    if (count("/proc/self/fd")!=fds || count("/proc/self/task")!=threads) return 3;
    auto again=server.start(*port,proxy::Inbound::socks5,workers);
    if (!again || *again != *port || !server.healthy() || server.failure()) return 4;
    for (int i=0;i<5;++i) server.poll(10ms);
    if (!server.healthy()) return 6;
    server.stop();
    if (server.failure()) return 10;
    if (count("/proc/self/fd")!=fds || count("/proc/self/task")!=threads) return 7;
    std::println("{} worker(s): accept failure reported, resources recovered and server restarted", workers);
}
