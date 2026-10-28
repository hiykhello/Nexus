#include <boost/capy/ex/run_async.hpp>
#include <boost/capy/task.hpp>
#include <boost/corosio/io_context.hpp>
#include <boost/corosio/resolver.hpp>
import std;
namespace io=boost::corosio;
namespace capy=boost::capy;

auto query(io::io_context& context, std::atomic<unsigned>& completed) -> capy::task<> {
    io::resolver resolver{context};
    auto [error, endpoints]=co_await resolver.resolve("nexus-delay.test","80");
    if (error && endpoints.empty()) completed.fetch_add(1,std::memory_order_relaxed);
}

auto main(int argc,char** argv) -> int {
    if (argc!=2) return 2;
    int threads=std::stoi(argv[1]);
    if (threads!=1 && threads!=2) return 3;
    std::array<std::unique_ptr<io::io_context>,3> contexts;
    io::io_context_options options;
    options.thread_pool_size=static_cast<unsigned>(threads);
    for (auto& context : contexts) {
        if (threads==1) context=std::make_unique<io::io_context>();
        else context=std::make_unique<io::io_context>(options);
    }
    std::atomic<unsigned> completed=0;
    for (auto& context : contexts)
        for (int i=0;i<3;++i) capy::run_async(context->get_executor())(query(*context,completed));
    std::vector<std::thread> workers;
    for (auto& context : contexts) workers.emplace_back([ctx=context.get()] { (void)ctx->run(); });
    for (auto& worker : workers) worker.join();
    return completed==9 ? 0 : 4;
}
