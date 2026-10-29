#include <boost/capy/ex/frame_allocator.hpp>
#include <boost/capy/ex/recycling_memory_resource.hpp>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <atomic>
#include <cstring>
#include <memory_resource>
#include <new>
import std;
import nexus.proxy;
using namespace std::chrono_literals;
namespace capy=boost::capy;

static std::atomic<unsigned> phase{0}, injected{0};
static thread_local bool fail_frame=false;
class TestResource final : public std::pmr::memory_resource {
    void* do_allocate(std::size_t size,std::size_t alignment) override {
        if (phase==3) { ++injected; throw std::bad_alloc{}; }
        return std::pmr::new_delete_resource()->allocate(size,alignment);
    }
    void do_deallocate(void* p,std::size_t size,std::size_t alignment) override {
        std::pmr::new_delete_resource()->deallocate(p,size,alignment);
    }
    bool do_is_equal(std::pmr::memory_resource const& other) const noexcept override { return this==&other; }
};
extern "C" std::pmr::memory_resource* nexus_test_root_resource() {
    static TestResource resource;
    return &resource;
}
extern "C" void nexus_test_root_launch(unsigned stage) {
    if (phase==1 && stage==0) { ++injected; throw std::bad_alloc{}; }
    if (phase==2 && stage==1) fail_frame=true;
}

// Override the weak Capy frame allocator only in this test binary. The normal
// path preserves its allocation layout so Capy's ordinary delete can free it.
extern "C" void* test_frame_new(std::size_t size)
    asm("_ZN5boost4capy17frame_alloc_mixinnwEm");
extern "C" void* test_frame_new(std::size_t size) {
    if (fail_frame) { fail_frame=false; ++injected; throw std::bad_alloc{}; }
    auto* mr=capy::get_current_frame_allocator();
    if (!mr) mr=std::pmr::get_default_resource();
    auto* recycling=capy::get_recycling_memory_resource();
    auto total=size+sizeof(std::pmr::memory_resource*);
    void* raw=mr==recycling ? static_cast<capy::recycling_memory_resource*>(mr)->allocate_fast(total,alignof(std::max_align_t)) :
                              mr->allocate(total,alignof(std::max_align_t));
    std::memcpy(static_cast<char*>(raw)+size,&mr,sizeof(mr));
    return raw;
}

static auto count(std::string_view path) -> std::size_t {
    return std::ranges::distance(std::filesystem::directory_iterator(path),std::filesystem::directory_iterator{});
}
static auto connect_to(std::uint16_t port) -> int {
    int fd=socket(AF_INET,SOCK_STREAM,0);
    if (fd<0) return -1;
    timeval limit{3,0};
    (void)setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&limit,sizeof(limit));
    sockaddr_in address{};
    address.sin_family=AF_INET; address.sin_addr.s_addr=htonl(INADDR_LOOPBACK); address.sin_port=htons(port);
    if (connect(fd,reinterpret_cast<sockaddr*>(&address),sizeof(address))) { close(fd); return -1; }
    return fd;
}
static auto greeting(std::uint16_t port) -> bool {
    int fd=connect_to(port);
    if (fd<0) return false;
    unsigned char request[]{5,1,0}, response[2]{};
    bool ok=send(fd,request,sizeof(request),MSG_NOSIGNAL)==sizeof(request) &&
            recv(fd,response,sizeof(response),MSG_WAITALL)==sizeof(response) && response[0]==5 && response[1]==0;
    close(fd);
    return ok;
}
int main() {
    for (unsigned workers : {1u,2u}) for (unsigned point : {1u,2u,3u}) {
        nexus::proxy::Server server;
        auto fds=count("/proc/self/fd"), threads=count("/proc/self/task");
        phase=point; injected=0;
        auto port=server.start(0,nexus::proxy::Inbound::socks5,workers);
        if (!port) return 1;
        int client=connect_to(*port);
        if (client<0) return 2;
        auto deadline=std::chrono::steady_clock::now()+5s;
        while (server.healthy() && std::chrono::steady_clock::now()<deadline) server.poll(10ms);
        close(client);
        if (server.healthy() || injected!=1 || !server.failure()) return 3;
        server.stop();
        if (count("/proc/self/fd")!=fds || count("/proc/self/task")!=threads) return 4;
        phase=0;
        auto retry=server.start(0,nexus::proxy::Inbound::socks5,workers);
        if (!retry) return 5;
        auto result=std::async(std::launch::async,greeting,*retry);
        deadline=std::chrono::steady_clock::now()+5s;
        while (result.wait_for(0ms)!=std::future_status::ready && std::chrono::steady_clock::now()<deadline)
            server.poll(10ms);
        if (!result.get()) return 6;
        server.stop();
        if (count("/proc/self/fd")!=fds || count("/proc/self/task")!=threads) return 7;
        std::println("{} worker(s), launch failure {}: session released and restart succeeded",workers,point);
    }
}
