// Exercise rollback when each proxy worker fails during refresh startup.
import std;
import dns.cache;
import dns.shared_cache;
import proxy;

namespace {
    enum class Stage { none, refresh, launch };
    Stage stage=Stage::none;
    unsigned target_call=0,hook_calls=0;

    auto inject(Stage where) -> void {
        if (stage==where && ++hook_calls==target_call) throw std::bad_alloc();
    }
}

extern "C" void nexus_test_dns_shared_access(void const*) noexcept {}
extern "C" void nexus_test_group_refresh_construct() { inject(Stage::refresh); }
extern "C" void nexus_test_start_throw() { inject(Stage::launch); }

namespace {
    namespace p=proxy;
    using Cache=dns_hp_experiment::GroupSnapshot;
    using Budget=dns::detail::RefreshBudget;

    auto ensure(bool value,char const* reason) -> void {
        if (!value) throw std::runtime_error(reason);
    }
    auto count(std::string_view path) -> std::size_t {
        return std::ranges::distance(std::filesystem::directory_iterator(path),std::filesystem::directory_iterator{});
    }
    auto settled_threads(std::size_t maximum) -> bool {
        using namespace std::chrono_literals;
        for (unsigned attempt=0;attempt<50;++attempt) {
            if (count("/proc/self/task")<=maximum) return true;
            std::this_thread::sleep_for(2ms);
        }
        return false;
    }
    auto claim_readers(Cache& cache,unsigned workers) -> void {
        for (unsigned index=0;index<workers;++index) {
            auto reader=cache.reader(index);
        }
    }
    auto run(unsigned workers) -> void {
        std::array<std::size_t,2> capacities{1,1};
        Cache old(capacities,Cache::SharedCapacity{32},3,10000,1024*1024);
        Cache fresh(capacities,Cache::SharedCapacity{32},3,10000,1024*1024);
        Budget old_budget(8),fresh_budget(8);
        p::Server server;
        p::DnsServer upstream; upstream.address[0]=127; upstream.address[3]=1; upstream.port=53;
        p::DnsRouting routing; routing.servers.push_back(upstream);
        ensure(server.set_dns_routing(routing).has_value(),"routing setup failed");
        auto bind=[&](Cache& cache,Budget& budget) {
            ensure(server.set_dns_group_for_test(cache,0,0,&budget).has_value(),"owner rebind failed");
        };
        auto start=[&] {
            auto result=server.start(0,p::Inbound::socks5,workers);
            ensure(result.has_value() && server.healthy(),"server start failed");
        };
        bind(fresh,fresh_budget); start(); server.stop(); bind(old,old_budget);
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
        auto fds=count("/proc/self/fd"),threads=count("/proc/self/task");
        unsigned failures=0;
        for (auto selected:{Stage::refresh,Stage::launch}) {
            for (unsigned ordinal=1;ordinal<=workers;++ordinal) {
                stage=selected; target_call=ordinal; hook_calls=0;
                bool caught=false;
                try { (void)server.start(0,p::Inbound::socks5,workers); }
                catch (std::bad_alloc const&) { caught=true; }
                stage=Stage::none;
                ensure(caught && hook_calls==ordinal,"fault hook did not fire");
                ++failures; server.stop();
                ensure(!old_budget.active(),"old refresh budget still active");
                bind(fresh,fresh_budget); claim_readers(old,workers);
                start(); server.stop();
                ensure(!fresh_budget.active(),"new refresh budget still active");
                bind(old,old_budget); claim_readers(fresh,workers);
                ensure(count("/proc/self/fd")==fds && settled_threads(threads),"start leaked resources");
            }
        }
        bind(fresh,fresh_budget); claim_readers(old,workers);
        std::println("TCP {} worker(s): {} refresh construction/launch faults recovered",workers,failures);
    }
}

int main() {
    try { run(1); run(2); }
    catch (std::exception const& error) { std::cerr << "TCP refresh startup fault: " << error.what() << '\n'; return 1; }
}
