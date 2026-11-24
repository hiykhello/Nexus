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
    if(argc!=3)return 2;
    bool uring=std::string_view(argv[1])=="uring";
#if BOOST_COROSIO_HAVE_LIBURING
    io::io_context context=uring ? io::io_context(io::uring) : io::io_context(io::epoll);
#else
    if(uring)return 77;io::io_context context(io::epoll);
#endif
    auto port=static_cast<std::uint16_t>(std::strtoul(argv[2],nullptr,10));
    dns::InputBudget raw(2*65535),queries(20000);
    ::policy::DnsRule route;route.match_all=true;route.action=::policy::DnsAction::route;
    std::array rules{route};
    std::array<dns::MessageUpstream,1> upstreams{{{{io::ipv4_address::loopback(),port},false,nullptr}}};
    dns::MessageUdpListener udp(context,rules,upstreams,0,32,4s,nullptr,false,&raw,&queries);
    dns::MessageTcpListener tcp(context,rules,upstreams,0,32,4s,8,nullptr,false,&raw,&queries);
    auto endpoint=io::endpoint(io::ipv4_address::loopback(),0);
    if(udp.start(endpoint) || tcp.start(endpoint))return 3;
    auto stop=[&]() -> capy::task<> {
        io::steady_timer timer(context);timer.expires_at(std::chrono::steady_clock::now()+5s);auto [error]=co_await timer.wait();
        if(!error){tcp.stop();udp.stop();}
    };
    capy::run_async(context.get_executor())(stop());
    std::cout<<tcp.local_endpoint().port()<<' '<<udp.local_endpoint().port()<<std::endl;
    (void)context.run_for(7s);
    if(!tcp.drained() || !udp.drained() || raw.used() || queries.used())return 4;
    std::cout<<"listener query reservations drained\n";
}
