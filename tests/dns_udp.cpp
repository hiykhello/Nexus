#include <boost/capy/buffers.hpp>
#include <boost/capy/ex/run_async.hpp>
#include <boost/capy/task.hpp>
#include <boost/corosio/backend.hpp>
#include <boost/corosio/io_context.hpp>
#include <boost/corosio/ipv4_address.hpp>
#include <boost/corosio/udp_socket.hpp>
import std;
import nexus.dns.message;
#include "../src/dns/corosio_udp.hpp"

namespace capy = boost::capy;
namespace io = boost::corosio;
namespace dns = nexus::dns;
using namespace std::chrono_literals;

struct Fixture {
#if BOOST_COROSIO_HAVE_LIBURING
    io::io_context context{io::uring};
#else
    io::io_context context;
#endif
    io::udp_socket upstream{context}, rogue{context};
    dns::detail::UdpQuery client{context};
    std::optional<std::expected<dns::Response, dns::detail::UdpError>> result;
    bool server_done = false;
    int mode = 0;
    ~Fixture() { client.cancel(); upstream.close(); rogue.close(); context.restart(); (void)context.run(); }
};
auto query(Fixture& f, std::chrono::milliseconds time) -> capy::task<> {
    f.result = co_await f.client.query(f.upstream.local_endpoint(), 0x1234, {"example.com",1},
                                        std::chrono::steady_clock::now()+time);
}
auto reply(Fixture& f) -> capy::task<> {
    std::array<std::uint8_t,512> buffer{}; io::endpoint source;
    auto [error,n] = co_await f.upstream.recv_from(capy::mutable_buffer(buffer.data(),buffer.size()),source);
    if (error || n<12) co_return;
    buffer[2]=0x81; buffer[3]=0x80; buffer[7]=1;
    std::array<std::uint8_t,16> answer{0xc0,0x0c,0,1,0,1,0,0,0,60,0,4,127,0,0,1};
    std::copy(answer.begin(),answer.end(),buffer.begin()+n); n+=answer.size();
    if (f.mode == 1) {
        buffer[2] |= 2;
        auto [err,sent] = co_await f.upstream.send_to(capy::const_buffer(buffer.data(),n),source);
        f.server_done = !err && sent == n;
        co_return;
    }
    if (f.mode == 2) {
        buffer[1] ^= 1;
        for (int i=0; i<32; ++i) {
            auto [err,sent] = co_await f.upstream.send_to(capy::const_buffer(buffer.data(),n),source);
            if (err || sent != n) co_return;
        }
        f.server_done = true;
        co_return;
    }
    buffer[n-4]=203;
    auto [rogue_error,rogue_n]=co_await f.rogue.send_to(capy::const_buffer(buffer.data(),n),source);
    if (rogue_error || rogue_n!=n) co_return;
    buffer[1]^=1; buffer[n-4]=198;
    auto [bad_error,bad_n]=co_await f.upstream.send_to(capy::const_buffer(buffer.data(),n),source);
    if (bad_error || bad_n!=n) co_return;
    buffer[1]^=1; buffer[n-4]=127;
    // A truncated response with a mismatched question must not end the query.
    buffer[2]|=2; buffer[13]='x';
    auto [tc_error,tc_n]=co_await f.upstream.send_to(capy::const_buffer(buffer.data(),n),source);
    if (tc_error || tc_n!=n) co_return;
    buffer[2]&=static_cast<std::uint8_t>(~2); buffer[13]='e';
    auto [ok_error,ok_n]=co_await f.upstream.send_to(capy::const_buffer(buffer.data(),n),source);
    f.server_done=!ok_error && ok_n==n;
}
auto init(Fixture& f) -> bool {
    auto endpoint=io::endpoint(io::ipv4_address::loopback(),0);
    return !f.upstream.open() && !f.rogue.open() && !f.upstream.bind(endpoint) && !f.rogue.bind(endpoint);
}
auto success() -> bool {
    Fixture f; if (!init(f)) return false;
    capy::run_async(f.context.get_executor())(reply(f));
    capy::run_async(f.context.get_executor())(query(f,2s));
    f.context.restart(); (void)f.context.run_for(3s);
    if (!f.result || !*f.result || !f.server_done) return false;
    auto decoded=dns::parse_addresses((*f.result)->wire,0x1234,{"example.com",1});
    return decoded && decoded->addresses.size()==1 && decoded->addresses[0].bytes[0]==127;
}
auto failure_test(int mode, dns::detail::UdpError expected) -> bool {
    Fixture f; if (!init(f)) return false;
    f.mode = mode;
    capy::run_async(f.context.get_executor())(reply(f));
    capy::run_async(f.context.get_executor())(query(f,2s));
    f.context.restart(); (void)f.context.run_for(3s);
    return f.server_done && f.result && !*f.result && f.result->error()==expected;
}
auto timeout_test(bool cancel) -> bool {
    Fixture f; if (!init(f)) return false;
    capy::run_async(f.context.get_executor())(query(f,cancel ? 2s : 100ms));
    f.context.restart(); (void)f.context.run_for(cancel ? 20ms : 500ms);
    if (cancel) { if (f.result) return false; f.client.cancel(); f.context.restart(); (void)f.context.run_for(1s); }
    return f.result && !*f.result && f.result->error()==(cancel ? dns::detail::UdpError::canceled : dns::detail::UdpError::timeout);
}
auto main() -> int {
    if (!success() || !timeout_test(false) || !timeout_test(true) ||
        !failure_test(1,dns::detail::UdpError::truncated) ||
        !failure_test(2,dns::detail::UdpError::response_limit)) return 1;
    std::println("DNS UDP source, transaction, timeout and cancellation passed");
}
