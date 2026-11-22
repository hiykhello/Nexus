import std;
import dns.message;
import dns.corosio_query;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;
namespace capy = nex::capy;
namespace io = nex::corosio;
using namespace std::chrono_literals;

struct Test {
    io::io_context context;
    dns::detail::FallbackQuery query{context};
    std::optional<std::expected<dns::Response,dns::detail::UdpError>> result;
    explicit Test(bool uring) : context(io::make_io_context(uring)) {}
};
auto run(Test& test, std::uint16_t port, std::chrono::milliseconds timeout,std::uint16_t advertised) -> capy::task<> {
    auto edns=advertised ? std::optional{dns::QueryEdns{advertised,0,true,{{8,{0,1,24,0,192,0,2}}}}} : std::nullopt;
    test.result = co_await test.query.query(io::endpoint(io::ipv4_address::loopback(),port),dns::QueryMessage{0x1234,0x0110,{"example.com",1},std::move(edns)},std::chrono::steady_clock::now()+timeout);
}
auto main(int argc,char** argv) -> int {
    if (argc==2 && std::string_view(argv[1])=="has-uring") {
        std::println("{}",io::has_uring ? "yes" : "no");
        return 0;
    }
    if (argc!=4 && argc!=5) return 2;
    auto port=std::stoi(argv[1]); auto mode=std::string_view(argv[2]);
    auto backend=std::string_view(argv[3]);
    if (backend!="epoll" && backend!="uring") return 2;
    if (backend=="uring" && !io::has_uring) return 77;
    auto advertised=argc==5 ? std::stoi(argv[4]) : 1232;
    if(advertised<0 || advertised>65535)return 2;
    Test test(backend=="uring");
    capy::run_async(test.context.get_executor())(run(test,static_cast<std::uint16_t>(port),(mode=="timeout" || mode=="budget") ? 200ms : 3s,static_cast<std::uint16_t>(advertised)));
    test.context.restart(); (void)test.context.run_for(mode=="cancel" ? 100ms : 4s);
    if (mode=="cancel") { test.query.cancel(); test.context.restart(); (void)test.context.run_for(1s); }
    if (!test.result) return 3;
    if (mode=="ok" || mode=="large" || mode=="capacity") {
        if (!*test.result) return 4;
        auto decoded=dns::parse_addresses((*test.result)->wire,0x1234,{"example.com",1});
        auto size=(*test.result)->wire.size();
        auto capacity_ok=mode!="capacity" || size==(advertised==65535 ? 65535u : 5000u);
        return decoded && decoded->addresses.size()==1 && decoded->addresses[0].bytes[0]==127 &&
            (mode!="large" || size>4096) && capacity_ok ? 0 : 5;
    }
    if (*test.result) return 6;
    auto expected=mode=="cancel" ? dns::detail::UdpError::canceled :
                  (mode=="timeout" || mode=="budget") ? dns::detail::UdpError::timeout :
                  mode=="short" ? dns::detail::UdpError::transport : dns::detail::UdpError::protocol;
    return test.result->error()==expected ? 0 : 7;
}
