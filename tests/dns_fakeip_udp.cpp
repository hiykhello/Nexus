#include <boost/capy/buffers.hpp>
#include <boost/capy/cond.hpp>
#include <boost/capy/ex/run_async.hpp>
#include <boost/capy/task.hpp>
#include <boost/corosio/backend.hpp>
#include <boost/corosio/io_context.hpp>
#include <boost/corosio/ipv4_address.hpp>
#include <boost/corosio/udp_socket.hpp>
import std;
import dns.fakeip;
import dns.fakeip_registry;
import dns.fakeip_response;
import dns.fakeip_target;
import dns.fakeip_shared;
import dns.message;
import dns.corosio_query;
#include "../src/dns/corosio_fakeip_listener.hpp"
namespace capy=boost::capy;
namespace io=nex::corosio;
namespace d=dns;
using namespace std::chrono_literals;
constexpr std::uint32_t base=0xc6120000;
struct Fixture {
#if BOOST_COROSIO_HAVE_LIBURING
    io::io_context context{io::uring};
#else
    io::io_context context;
#endif
    io::udp_socket server{context},client{context};
    d::FakeIpRegistry registry{1};
    std::chrono::steady_clock::time_point t{};
    std::vector<std::uint8_t> query, received;
    bool retiring=false, server_done=false, client_done=false;
    bool pre_done=false, pre_released=false, receive_done=false;
    std::error_code pre_error, receive_error;
    std::size_t pre_size=0;
    ~Fixture() { server.close(); client.close(); context.restart(); (void)context.run(); }
};
auto canceled_send(Fixture& f,std::unique_ptr<d::FakeIpResponse> response) -> capy::task<> {
    auto wire=response->wire();
    auto [error,n]=co_await f.server.send_to(capy::const_buffer(wire.data(),wire.size()),f.client.local_endpoint());
    f.pre_error=error; f.pre_size=n;
    // The stop token was already canceled before this operation was started.
    f.pre_released=response->finish(!(error==capy::cond::canceled && n==0),f.t+20s).has_value();
    f.pre_done=true;
}
auto await_datagram(Fixture& f) -> capy::task<> {
    std::array<std::uint8_t,512> bytes{};
    io::endpoint source;
    auto [error,n]=co_await f.client.recv_from(capy::mutable_buffer(bytes.data(),bytes.size()),source);
    (void)n;
    f.receive_error=error; f.receive_done=true;
}
auto pre_cancel() -> bool {
    Fixture f;
    auto pool=d::FakeIpPool::create(base+1,base+1,10s,2s);
    auto query=d::make_query(1,{"example.com",1});
    auto other=d::make_query(2,{"other.example",1});
    if (!pool || !query || !other || !f.registry.add(base,base+3,std::move(*pool))) return false;
    auto endpoint=io::endpoint(io::ipv4_address::loopback(),0);
    if (f.server.open() || f.client.open() || f.server.bind(endpoint) || f.client.bind(endpoint)) return false;
    auto response=f.registry.respond(base,*query,7,f.t);
    if (!response) return false;
    std::stop_source stop;
    stop.request_stop();
    capy::run_async(f.context.get_executor())(await_datagram(f));
    capy::run_async(f.context.get_executor(),stop.get_token())(canceled_send(f,std::move(*response)));
    f.context.restart(); (void)f.context.run_for(50ms);
    if (!f.pre_done || !f.pre_released || f.pre_error!=capy::cond::canceled || f.pre_size || f.receive_done) return false;
    auto replacement=f.registry.respond(base,*other,7,f.t+20s);
    if (!replacement || !(*replacement)->finish(false,f.t+20s)) return false;
    f.client.close();
    f.context.restart(); (void)f.context.run_for(1s);
    return f.receive_done && f.receive_error==capy::cond::canceled && f.context.stopped();
}
auto serve(Fixture& f) -> capy::task<> {
    std::array<std::uint8_t,512> buffer{};
    io::endpoint source;
    auto [error,n]=co_await f.server.recv_from(capy::mutable_buffer(buffer.data(),buffer.size()),source);
    if (error) co_return;
    auto response=f.registry.respond(base,std::span(buffer).first(n),7,f.t);
    if (!response) co_return;
    auto different=d::make_query(2,{"other.example",1});
    if (!different) co_return;
    auto pending=f.registry.respond(base,*different,7,f.t+20s);
    if (pending || pending.error()!=std::variant<d::FakeIpRegistryError,d::FakeIpDnsError>{d::FakeIpDnsError::full}) co_return;
    if (f.retiring && !f.registry.retire(base)) co_return;
    auto wire=(*response)->wire();
    auto [send_error,sent]=co_await f.server.send_to(capy::const_buffer(wire.data(),wire.size()),source);
    // A failed or partial send is treated as possibly sent, conservatively.
    if (!(*response)->finish(true,f.t+20s) || send_error || sent!=wire.size()) co_return;
    f.server_done=true;
}
auto exchange(Fixture& f) -> capy::task<> {
    auto [error,n]=co_await f.client.send_to(capy::const_buffer(f.query.data(),f.query.size()),f.server.local_endpoint());
    if (error || n!=f.query.size()) co_return;
    std::array<std::uint8_t,512> buffer{};
    io::endpoint source;
    auto [recv_error,count]=co_await f.client.recv_from(capy::mutable_buffer(buffer.data(),buffer.size()),source);
    if (recv_error || source!=f.server.local_endpoint()) co_return;
    f.received.assign(buffer.begin(),buffer.begin()+count);
    f.client_done=true;
}
auto run(bool retiring) -> bool {
    Fixture f;
    f.retiring=retiring;
    auto pool=d::FakeIpPool::create(base+1,base+1,10s,2s);
    auto query=d::make_query(1,{"example.com",1});
    if (!pool || !query || !f.registry.add(base,base+3,std::move(*pool))) return false;
    f.query=std::move(*query);
    auto endpoint=io::endpoint(io::ipv4_address::loopback(),0);
    if (f.server.open() || f.client.open() || f.server.bind(endpoint) || f.client.bind(endpoint)) return false;
    capy::run_async(f.context.get_executor())(serve(f));
    capy::run_async(f.context.get_executor())(exchange(f));
    f.context.restart(); (void)f.context.run_for(2s);
    if (!f.server_done || !f.client_done) return false;
    auto parsed=d::parse_addresses(f.received,1,{"example.com",1});
    if (!parsed || parsed->ttl!=10 || parsed->addresses.size()!=1 ||
        parsed->addresses[0].bytes!=std::array<std::uint8_t,16>{198,18,0,1}) return false;
    auto target=f.registry.acquire(base+1,7,f.t+20s);
    if (retiring) return !target && target.error()==d::FakeIpRegistryError::unknown;
    if (!target || !*target || (*target)->mapping().domain!="example.com") return false;
    auto query2=d::make_query(2,{"other.example",1});
    if (!query2) return false;
    auto blocked=f.registry.respond(base,*query2,7,f.t+32s);
    if (blocked || blocked.error()!=std::variant<d::FakeIpRegistryError,d::FakeIpDnsError>{d::FakeIpDnsError::full} ||
        !(*target)->release(f.t+32s)) return false;
    auto reused=f.registry.respond(base,*query2,7,f.t+32s);
    return reused && (*reused)->finish(false,f.t+32s).has_value();
}
struct ListenerFixture {
#if BOOST_COROSIO_HAVE_LIBURING
    io::io_context context{io::uring};
#else
    io::io_context context;
#endif
    d::FakeIpShared registry{1};
    d::detail::FakeIpListener listener{context,registry,base,7};
    d::detail::UdpQuery client{context};
    d::detail::UdpQuery client2{context};
    std::optional<std::expected<void,d::detail::FakeIpListenerError>> result;
    std::optional<std::expected<d::Response,d::detail::UdpError>> answer;
    std::optional<std::expected<d::Response,d::detail::UdpError>> failure;
    ~ListenerFixture() { listener.stop(); client.cancel(); client2.cancel(); context.restart(); (void)context.run(); }
};
auto listen(ListenerFixture& f) -> capy::task<> { f.result=co_await f.listener.run(); }
auto ask(ListenerFixture& f) -> capy::task<> {
    io::udp_socket junk{f.context};
    auto endpoint=io::endpoint(io::ipv4_address::loopback(),0);
    if (junk.open() || junk.bind(endpoint)) co_return;
    std::array<std::uint8_t,513> oversized{};
    auto [error,n]=co_await junk.send_to(capy::const_buffer(oversized.data(),oversized.size()),f.listener.local_endpoint());
    if (error || n!=oversized.size()) co_return;
    std::array<std::uint8_t,12> malformed{};
    auto [error2,n2]=co_await junk.send_to(capy::const_buffer(malformed.data(),malformed.size()),f.listener.local_endpoint());
    if (error2 || n2!=malformed.size()) co_return;
    f.answer=co_await f.client.query(f.listener.local_endpoint(),17,{"example.com",1},
                                    std::chrono::steady_clock::now()+1s,true);
    f.failure=co_await f.client2.query(f.listener.local_endpoint(),18,{"other.example",1},
                                      std::chrono::steady_clock::now()+1s,true);
}
auto listener_test(bool quarantine) -> bool {
    ListenerFixture f;
    if (quarantine) {
        if (!f.registry.add_quarantined(base,base+3,base+1,base+1,10s,2s,60s)) return false;
    } else {
        if (!f.registry.add(base,base+3,base+1,base+1,10s,2s)) return false;
    }
    if (!f.registry.seal() || !f.listener.open(0)) return false;
    std::atomic<bool> worker_failed=false;
    std::atomic<bool> stop_workers=false;
    std::barrier worker_start(5);
    std::vector<std::jthread> workers;
    auto worker_query=d::make_query(19,{"example.com",1});
    if (!worker_query) return false;
    if (!quarantine) for (int i=0;i<4;++i) workers.emplace_back([&] {
        worker_start.arrive_and_wait();
        for (int j=0;j<500 || !stop_workers;++j) {
            auto response=f.registry.respond(base,*worker_query,7);
            if (!response || !(*response)->finish(true)) { worker_failed=true; return; }
            auto target=f.registry.acquire(base+1,7);
            if (!target || !*target || !(*target)->release()) { worker_failed=true; return; }
        }
    });
    if (!quarantine) worker_start.arrive_and_wait();
    capy::run_async(f.context.get_executor())(listen(f));
    capy::run_async(f.context.get_executor())(ask(f));
    f.context.restart(); (void)f.context.run_for(150ms);
    stop_workers=true;
    workers.clear();
    if (worker_failed || !f.answer || !*f.answer || !f.failure || !*f.failure || (*f.failure)->rcode!=2 ||
        !(*f.failure)->edns || (*f.failure)->edns->udp_payload_size!=1232 || f.result) return false;
    if (quarantine) {
        auto target=f.registry.acquire(base+1,7);
        if ((*f.answer)->rcode!=2 || target || target.error()!=d::FakeIpRegistryError::unknown) return false;
        f.listener.stop();
        f.context.restart(); (void)f.context.run_for(1s);
        return f.result && *f.result && f.context.stopped();
    }
    auto parsed=d::parse_addresses((*f.answer)->wire,17,{"example.com",1},true);
    if (!parsed || parsed->addresses.size()!=1 || parsed->addresses[0].bytes[0]!=198 ||
        parsed->addresses[0].bytes[1]!=18 || parsed->addresses[0].bytes[3]!=1) return false;
    auto target=f.registry.acquire(base+1,7);
    if (!target || !*target || (*target)->mapping().domain!="example.com") return false;
    f.listener.stop();
    f.context.restart(); (void)f.context.run_for(1s);
    return f.result && *f.result && f.context.stopped() &&
           (*target)->release().has_value();
}
auto main() -> int {
    if (!run(false) || !run(true) || !pre_cancel() || !listener_test(false) || !listener_test(true)) return 1;
    std::println("FakeIP UDP listener, pre-cancellation, retirement and target pin passed");
}
