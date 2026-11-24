import std;
import dns.input_budget;
import dns.message_tcp_listener;
import dns.message_udp_listener;
import dns.message_exchange;
import dns.policy;
import capy;
import corosio;
namespace io = ::corosio;
using namespace std::chrono_literals;
auto main(int argc,char** argv) -> int {
    bool uring=argc>1 && std::string_view(argv[1])=="uring";
#if BOOST_COROSIO_HAVE_LIBURING
    io::io_context context=uring ? io::io_context(io::uring) : io::io_context(io::epoll);
#else
    if(uring)return 77;io::io_context context(io::epoll);
#endif
    {
        dns::InputBudget budget(400);std::atomic<unsigned> accepted=0;std::barrier sync(9);
        std::vector<std::thread> threads;
        for(unsigned i=0;i<8;++i)threads.emplace_back([&] {
            sync.arrive_and_wait();auto lease=budget.acquire(100);if(lease)++accepted;
            sync.arrive_and_wait();sync.arrive_and_wait();
        });
        sync.arrive_and_wait();sync.arrive_and_wait();
        if(accepted!=4 || budget.used()!=400)std::terminate();
        sync.arrive_and_wait();for(auto& thread:threads)thread.join();
        if(budget.used()!=0 || budget.acquire(401))return 3;
    }
    dns::InputBudget budget(65535+65535);
    ::policy::DnsRule reject;reject.match_all=true;reject.action=::policy::DnsAction::reject;
    std::array rules{reject};
    std::array<dns::MessageUpstream,1> upstreams{{{{io::ipv4_address::loopback(),53},false,nullptr}}};
    dns::MessageUdpListener udp(context,rules,upstreams,0,32,2s,nullptr,false,&budget);
    dns::MessageUdpListener second_udp(context,rules,upstreams,0,32,2s,nullptr,false,&budget);
    dns::MessageTcpListener tcp(context,rules,upstreams,0,32,2s,8,nullptr,false,&budget);
    auto endpoint=io::endpoint(io::ipv4_address::loopback(),0);
    if(udp.start(endpoint) || budget.used()!=65535)return 4;
    auto probe=budget.acquire(1);if(!probe || second_udp.start(endpoint)!=std::errc::no_buffer_space)std::terminate();
    probe.reset();if(tcp.start(endpoint))std::terminate();
    auto stop=[&]() -> capy::task<> {
        io::steady_timer timer(context);timer.expires_at(std::chrono::steady_clock::now()+4s);auto [error]=co_await timer.wait();
        if(!error){tcp.stop();udp.stop();}
    };
    capy::run_async(context.get_executor())(stop());
    std::cout<<tcp.local_endpoint().port()<<' '<<udp.local_endpoint().port()<<std::endl;
    (void)context.run_for(6s);
    if(!tcp.drained() || !udp.drained() || budget.used()!=0)return 5;
    if(second_udp.start(endpoint) || budget.used()!=65535)return 6;
    second_udp.stop();context.restart();(void)context.run_for(2s);
    if(!second_udp.drained() || budget.used()!=0)return 7;
    std::cout<<"input budget drained and reused\n";
}
