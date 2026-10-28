import std;
import nexus.proxy;

auto count(std::string_view path) -> std::size_t {
    return std::ranges::distance(std::filesystem::directory_iterator(path), std::filesystem::directory_iterator{});
}
auto main(int argc, char** argv) -> int {
    auto fds=count("/proc/self/fd"), threads=count("/proc/self/task");
    auto first=nexus::proxy::Server::create();
    if (argc==2 && std::string_view(argv[1])=="fallback") {
        if (!first) return 6;
        auto port=(*first)->start(0);
        if (!port || !(*first)->healthy()) return 7;
        (*first)->stop(); first->reset();
        if (count("/proc/self/fd")!=fds || count("/proc/self/task")!=threads) return 8;
        std::println("unsupported ring flag fell back and server started");
        return 0;
    }
    if (argc!=1) return 9;
    if (first || first.error()!=std::errc::operation_not_permitted) return 1;
    if (count("/proc/self/fd")!=fds || count("/proc/self/task")!=threads) return 2;
    auto second=nexus::proxy::Server::create();
    if (!second) return 3;
    auto port=(*second)->start(0);
    if (!port || !(*second)->healthy()) return 4;
    (*second)->stop();
    second->reset();
    if (count("/proc/self/fd")!=fds || count("/proc/self/task")!=threads) return 5;
    std::println("context initialization error returned; retry and cleanup succeeded");
}
