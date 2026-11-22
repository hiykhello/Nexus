import std;
import ss_udp.shared_coordinator;
import rules;
import proxy;

namespace {
    thread_local int fail_after=-1;
    thread_local bool injected=false;
}
void* operator new(std::size_t size) {
    if (fail_after>=0 && fail_after--==0) {
        fail_after=-1; injected=true; throw std::bad_alloc();
    }
    if (auto* memory=std::malloc(size ? size : 1)) return memory;
    throw std::bad_alloc();
}
void operator delete(void* memory) noexcept { std::free(memory); }
void operator delete(void* memory,std::size_t) noexcept { std::free(memory); }
auto udp_reset_attached() noexcept -> void;
auto udp_attached_count() noexcept -> std::size_t;

namespace {
    namespace p=proxy;
    namespace u=proxy::udp_runtime;
    namespace io=nex::corosio;
    using Cache=dns_hp_experiment::GroupSnapshot;
    using Budget=dns::detail::RefreshBudget;

    auto open_port() -> std::uint16_t {
        auto context=io::make_io_context(io::has_uring);
        io::udp_socket socket(context);
        auto endpoint=io::endpoint(io::ipv4_address::loopback(),0);
        if (socket.open(endpoint.address().family()) || socket.bind(endpoint)) throw std::runtime_error("cannot reserve UDP port");
        return socket.local_endpoint().port();
    }
    auto fds() -> std::size_t {
        return std::ranges::distance(std::filesystem::directory_iterator("/proc/self/fd"),std::filesystem::directory_iterator{});
    }
    template<class Udp>
    auto run() -> void {
        std::array<std::size_t,1> capacities{1};
        Cache old(capacities,Cache::SharedCapacity{64},1,10000,8*1024*1024);
        Cache fresh(capacities,Cache::SharedCapacity{64},1,10000,8*1024*1024);
        Budget old_budget(8),fresh_budget(8);
        std::unique_ptr<dns_hp_experiment::Coordinator> coordinator;
        std::unique_ptr<dns_hp_experiment::ViewRegistry> views;
        Udp owner;
        auto policy=::rules::RouteMatcher::compile({},0,1);
        if (!policy) throw std::runtime_error("policy");
        auto port0=open_port(),port1=open_port();
        while (port0==port1) port1=open_port();
        std::array<std::uint8_t,16> key0{},key1{};
        std::iota(key0.begin(),key0.end(),0); std::iota(key1.begin(),key1.end(),16);
        if (!owner.add(key0,port0,*policy) || !owner.add(key1,port1,*policy)) throw std::runtime_error("listeners");
        p::DnsRouting routing;
        p::DnsServer upstream; upstream.address[0]=127; upstream.address[3]=1; upstream.port=53;
        routing.servers.push_back(upstream);
        auto bind=[&](Cache& cache,Budget& budget) {
            if constexpr (std::same_as<Udp,u::GroupRefreshUdpInbounds>) {
                if (!owner.setup().bind(cache,0,0,&budget)) throw std::runtime_error("group binding");
            } else if (!owner.setup().bind(cache,0,0)) throw std::runtime_error("group binding");
            if constexpr (std::same_as<Udp,u::CoordinatorUdpInbounds>) {
                coordinator=std::make_unique<dns_hp_experiment::Coordinator>(8,64);
                views=std::make_unique<dns_hp_experiment::ViewRegistry>(16,65536,64);
                if (!owner.setup().bind_coordinator(*coordinator,*views,routing,true)) throw std::runtime_error("coordinator binding");
                views->seal();
            }
        };
        auto check_drained=[&](Cache& cache,Budget& budget) {
            if (budget.active()) throw std::runtime_error("refresh still active");
            if constexpr (std::same_as<Udp,u::CoordinatorUdpInbounds>)
                if (coordinator->counts()!=std::pair<std::size_t,std::size_t>{0,0} || coordinator->direct_active())
                    throw std::runtime_error("coordinator still active");
            auto reader=cache.reader(0);
        };
        bind(fresh,fresh_budget);
        if (owner.start(routing)) throw std::runtime_error("warmup");
        owner.stop(); check_drained(fresh,fresh_budget);
        auto baseline=fds();
        unsigned failures=0;
        bool exhausted=false,late=false;
        for (int position=0;position<256;++position) {
            bind(old,old_budget);
            udp_reset_attached(); injected=false; fail_after=position;
            try {
                auto error=owner.start(routing);
                fail_after=-1;
                if (!injected) {
                    if (error) throw std::runtime_error("uninjected start");
                    exhausted=true;
                } else if (!error) throw std::runtime_error("injected start succeeded");
            } catch (std::bad_alloc const&) { fail_after=-1; if (!injected) throw; }
            fail_after=-1;
            if (injected) { ++failures; late|=udp_attached_count()>=2; }
            owner.stop(); check_drained(old,old_budget);
            bind(fresh,fresh_budget);
            if (owner.start(routing) || !owner.healthy()) throw std::runtime_error("restart");
            owner.stop(); check_drained(fresh,fresh_budget);
            if (fds()!=baseline) throw std::runtime_error("descriptor leak");
            if (exhausted) break;
        }
        if (!exhausted || !failures || !late) throw std::runtime_error("allocation sweep did not reach both listeners");
        std::println("{} startup allocation failures recovered after both listeners",failures);
    }
}
int main(int argc,char** argv) {
    if (argc!=2) return 1;
    try {
        auto mode=std::string_view(argv[1]);
        if (mode=="group") run<u::GroupUdpInbounds>();
        else if (mode=="refresh") run<u::GroupRefreshUdpInbounds>();
        else if (mode=="coordinator") run<u::CoordinatorUdpInbounds>();
        else return 1;
    } catch (std::exception const& error) {
        fail_after=-1;
        std::cerr << "UDP group startup fault: " << error.what() << '\n';
        return 2;
    }
}
