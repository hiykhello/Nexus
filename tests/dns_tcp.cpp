#include <boost/capy/ex/run_async.hpp>
#include <boost/capy/task.hpp>
#include <boost/corosio/backend.hpp>
#include <boost/corosio/io_context.hpp>
#include <boost/corosio/ipv4_address.hpp>
import std;
import nexus.dns.message;
#include "../src/dns/corosio_tcp.hpp"
namespace capy = boost::capy;
namespace io = boost::corosio;
namespace dns = nexus::dns;
using namespace std::chrono_literals;

struct Test {
#if BOOST_COROSIO_HAVE_LIBURING
    io::io_context context{io::uring};
#else
    io::io_context context;
#endif
    dns::detail::FallbackQuery query{context};
    std::optional<std::expected<dns::Response,dns::detail::UdpError>> result;
};
auto run(Test& test, std::uint16_t port, std::chrono::milliseconds timeout) -> capy::task<> {
    test.result = co_await test.query.query(io::endpoint(io::ipv4_address::loopback(),port),0x1234,
                                            {"example.com",1},std::chrono::steady_clock::now()+timeout);
}
auto main(int argc,char** argv) -> int {
    if (argc!=3) return 2;
    auto port=std::stoi(argv[1]); auto mode=std::string_view(argv[2]);
    Test test;
    capy::run_async(test.context.get_executor())(run(test,static_cast<std::uint16_t>(port),(mode=="timeout" || mode=="budget") ? 200ms : 3s));
    test.context.restart(); (void)test.context.run_for(mode=="cancel" ? 100ms : 4s);
    if (mode=="cancel") { test.query.cancel(); test.context.restart(); (void)test.context.run_for(1s); }
    if (!test.result) return 3;
    if (mode=="ok") {
        if (!*test.result) return 4;
        auto decoded=dns::parse_addresses((*test.result)->wire,0x1234,{"example.com",1});
        return decoded && decoded->addresses.size()==1 && decoded->addresses[0].bytes[0]==127 ? 0 : 5;
    }
    if (*test.result) return 6;
    auto expected=mode=="cancel" ? dns::detail::UdpError::canceled :
                  (mode=="timeout" || mode=="budget") ? dns::detail::UdpError::timeout :
                  mode=="short" ? dns::detail::UdpError::transport : dns::detail::UdpError::protocol;
    return test.result->error()==expected ? 0 : 7;
}
