#include <boost/capy/buffers.hpp>
#include <boost/capy/ex/run_async.hpp>
#include <boost/capy/task.hpp>
#include <boost/corosio/backend.hpp>
#include <boost/corosio/io_context.hpp>
#include <boost/corosio/ipv4_address.hpp>
#include <boost/corosio/tcp_acceptor.hpp>
#include <boost/corosio/tcp_socket.hpp>
import std;
import nexus.dns.fakeip;
import nexus.dns.fakeip_registry;
import nexus.dns.fakeip_response;
import nexus.dns.fakeip_shared;
import nexus.dns.fakeip_request;
import nexus.dns.message;
import nexus.socks5;
#include "../src/dns/corosio_fakeip_listener.hpp"
#include "../src/dns/corosio_udp.hpp"
namespace capy=boost::capy;
namespace io=boost::corosio;
namespace d=nexus::dns;
namespace s=nexus::socks5;
using namespace std::chrono_literals;
constexpr std::uint32_t base=0xc6120000;
struct Fixture {
#if BOOST_COROSIO_HAVE_LIBURING
    io::io_context context{io::uring};
#else
    io::io_context context;
#endif
    d::FakeIpShared owner{1};
    d::detail::FakeIpListener dns{context,owner,base,7};
    d::detail::UdpQuery client{context};
    io::udp_socket upstream{context};
    d::detail::UdpQuery upstream_client{context};
    io::tcp_acceptor listener{context};
    io::tcp_socket outbound{context};
    std::optional<std::expected<void,d::detail::FakeIpListenerError>> dns_result;
    bool chain_ok=false, peer_ok=false, rejected_loop=false, upstream_done=false;
    Fixture() : listener(context,io::endpoint(io::ipv4_address::loopback(),0)) {}
    ~Fixture() {
        dns.stop(); client.cancel(); upstream_client.cancel(); upstream.close(); listener.close(); outbound.close();
        context.restart(); (void)context.run();
    }
};
auto dns_loop(Fixture& f) -> capy::task<> { f.dns_result=co_await f.dns.run(); }
auto upstream_dns(Fixture& f) -> capy::task<> {
    std::array<std::uint8_t,512> buffer{};
    io::endpoint source;
    auto [error,n]=co_await f.upstream.recv_from(capy::mutable_buffer(buffer.data(),buffer.size()),source);
    if (error || n<12 || n+32>buffer.size()) co_return;
    buffer[2]=0x81; buffer[3]=0x80; buffer[7]=2;
    std::array<std::uint8_t,32> records{0xc0,0x0c,0,1,0,1,0,0,0,30,0,4,198,18,0,1,
                                        0xc0,0x0c,0,1,0,1,0,0,0,30,0,4,127,0,0,1};
    std::ranges::copy(records,buffer.begin()+n);
    auto [send_error,sent]=co_await f.upstream.send_to(capy::const_buffer(buffer.data(),n+records.size()),source);
    f.upstream_done=!send_error && sent==n+records.size();
}
auto serve(Fixture& f) -> capy::task<> {
    auto [error, peer]=co_await f.listener.accept();
    if (error) co_return;
    std::array<char,4> data{}; std::size_t pos=0;
    while (pos<data.size()) {
        auto [err,n]=co_await peer.read_some(capy::mutable_buffer(data.data()+pos,data.size()-pos));
        if (err || !n) co_return;
        pos+=n;
    }
    if (std::string_view(data.data(),data.size())!="ping") co_return;
    auto [err,n]=co_await peer.write_some(capy::const_buffer("ok",2));
    f.peer_ok=!err && n==2;
}
auto chain(Fixture& f) -> capy::task<> {
    auto answer=co_await f.client.query(f.dns.local_endpoint(),0x1234,{"localhost",1},
                                        std::chrono::steady_clock::now()+2s,true);
    if (!answer) co_return;
    auto parsed=d::parse_addresses(answer->wire,0x1234,{"localhost",1},true);
    if (!parsed || parsed->addresses.size()!=1 || parsed->addresses[0].size!=4) co_return;
    auto bytes=parsed->addresses[0].bytes;
    s::Request request; request.status=s::Status::accepted; request.address_type=1;
    request.address_length=4; request.port=f.listener.local_endpoint().port();
    std::ranges::copy(std::span(bytes).first(4),request.address.begin());
    auto translated=d::translate_fakeip_request(f.owner,request,7);
    if (!translated || !translated->target || translated->request.address_type!=3) co_return;
    std::string domain(reinterpret_cast<char const*>(translated->request.address.data()),translated->request.address_length);
    if (domain!="localhost") co_return;
    auto resolved=co_await f.upstream_client.query(f.upstream.local_endpoint(),0x5678,{domain,1},
                                                   std::chrono::steady_clock::now()+2s);
    if (!resolved) co_return;
    auto candidates=d::parse_addresses(resolved->wire,0x5678,{domain,1});
    if (!candidates || candidates->addresses.size()!=2) co_return;
    bool connected=false;
    for (auto const& candidate:candidates->addresses) {
        if (candidate.size!=4) continue;
        auto ip=std::array<std::uint8_t,4>{candidate.bytes[0],candidate.bytes[1],candidate.bytes[2],candidate.bytes[3]};
        auto checked=d::validate_fakeip_resolution(f.owner,ip);
        if (!checked) {
            if (checked.error()!=d::FakeIpRegistryError::unknown) co_return;
            f.rejected_loop=true;
            continue;
        }
        if (ip!=std::array<std::uint8_t,4>{127,0,0,1}) continue;
        auto [connect_error]=co_await f.outbound.connect(io::endpoint(io::ipv4_address(ip),request.port));
        if (!connect_error) { connected=true; break; }
    }
    if (!connected) co_return;
    auto [write_error,written]=co_await f.outbound.write_some(capy::const_buffer("ping",4));
    if (write_error || written!=4) co_return;
    std::array<char,2> result{}; std::size_t pos=0;
    while (pos<result.size()) {
        auto [error,n]=co_await f.outbound.read_some(capy::mutable_buffer(result.data()+pos,result.size()-pos));
        if (error || !n) co_return;
        pos+=n;
    }
    f.outbound.close();
    f.chain_ok=std::string_view(result.data(),result.size())=="ok" && translated->target->release().has_value();
}
auto main() -> int {
    Fixture f;
    if (!f.owner.add(base,base+3,base+1,base+1,10s,2s) || !f.owner.seal() || !f.dns.open(0) ||
        f.outbound.open() || f.upstream.open() || f.upstream.bind(io::endpoint(io::ipv4_address::loopback(),0))) return 1;
    capy::run_async(f.context.get_executor())(dns_loop(f));
    capy::run_async(f.context.get_executor())(serve(f));
    capy::run_async(f.context.get_executor())(upstream_dns(f));
    capy::run_async(f.context.get_executor())(chain(f));
    f.context.restart(); (void)f.context.run_for(3s);
    f.dns.stop();
    f.context.restart(); (void)f.context.run_for(1s);
    if (!f.chain_ok || !f.peer_ok || !f.rejected_loop || !f.upstream_done || !f.dns_result || !*f.dns_result) return 2;
    std::println("FakeIP UDP to domain resolution and TCP loopback passed");
}
