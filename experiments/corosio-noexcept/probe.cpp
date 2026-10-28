#include <boost/capy/ex/run_async.hpp>
#include <boost/capy/task.hpp>
#include <boost/capy/buffers.hpp>
#include <boost/capy/cond.hpp>
#include <boost/corosio/io_context.hpp>
#include <boost/corosio/local_connect_pair.hpp>
#include <boost/corosio/local_stream_socket.hpp>
#include <chrono>
#include <cstring>
#include <dirent.h>
#include <cstdlib>
#include <cstdio>
#include <system_error>
static int count(char const* path) {
    auto* dir=opendir(path); if (!dir) return -1;
    int n=0; while (readdir(dir)) ++n; closedir(dir); return n;
}
static boost::capy::task<> work(bool& done) { done=true; co_return; }
static boost::capy::task<> send(boost::corosio::local_stream_socket& socket, bool& done) {
    auto [error,n]=co_await socket.write_some(boost::capy::const_buffer("ping",4));
    done=!error && n==4;
}
static boost::capy::task<> read(boost::corosio::local_stream_socket& socket, char* data, bool& done) {
    auto [error,n]=co_await socket.read_some(boost::capy::mutable_buffer(data,4));
    done=!error && n==4;
}
static boost::capy::task<> canceled(boost::corosio::local_stream_socket& socket, char* data, bool& done) {
    auto [error,n]=co_await socket.read_some(boost::capy::mutable_buffer(data,4));
    done=error==boost::capy::cond::canceled && n==0;
}
int main() {
    int fds=count("/proc/self/fd"), threads=count("/proc/self/task");
    auto failed=boost::corosio::io_context::try_create_uring();
    if (failed || failed.error()!=std::errc::operation_not_permitted) return 1;
    if (count("/proc/self/fd")!=fds || count("/proc/self/task")!=threads) return 2;
    auto created=boost::corosio::io_context::try_create_uring();
    if (!created) return 3;
    bool done=false;
    boost::capy::run_async((*created)->get_executor())(work(done));
    (*created)->restart(); (void)(*created)->run();
    if (!done) return 4;
    {
        auto& ctx=**created;
        boost::corosio::local_stream_socket a(ctx), b(ctx);
        if (boost::corosio::connect_pair(a,b)) return 6;
        bool sent=false, received=false; char data[4]{};
        boost::capy::run_async(ctx.get_executor())(send(a,sent));
        boost::capy::run_async(ctx.get_executor())(read(b,data,received));
        ctx.restart(); (void)ctx.run_for(std::chrono::seconds(1));
        if (!sent || !received || std::memcmp(data,"ping",4)) return 7;
        bool stopped=false;
        boost::capy::run_async(ctx.get_executor())(canceled(b,data,stopped));
        ctx.restart(); (void)ctx.run_for(std::chrono::milliseconds(20));
        if (stopped) return 8;
        b.cancel(); ctx.restart(); (void)ctx.run_for(std::chrono::seconds(1));
        if (!stopped) return 9;
        a.close(); b.close(); ctx.restart(); (void)ctx.run();
    }
    created->reset();
    if (count("/proc/self/fd")!=fds || count("/proc/self/task")!=threads) return 5;
    std::puts("error result, cleanup, retry and coroutine passed");
}
