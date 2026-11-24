import std;
import dns.message;
import dns.corosio_query;
import capy;
import corosio;

namespace io = ::corosio;
using namespace std::chrono_literals;

#ifdef NEXUS_TEST_FAKEIP
extern "C" void nexus_test_set_fakeip_receive_hook(bool);
extern "C" unsigned nexus_test_fakeip_receive_hook_count();
#endif

struct Fixture {
    io::io_context context;
    io::udp_socket upstream{context}, rogue{context};
    dns::detail::UdpQuery client{context};
    std::optional<std::expected<dns::Response, dns::detail::UdpError>> result;
    bool server_done = false;
    int mode = 0;
    std::optional<std::uint16_t> advertised;
#ifdef NEXUS_TEST_FAKEIP
    bool hook_threw = false;
#endif
    explicit Fixture(bool uring) : context(io::make_io_context(uring)) {}
    ~Fixture() { client.cancel(); upstream.close(); rogue.close(); context.restart(); (void)context.run(); }
};
auto query(Fixture& f, std::chrono::milliseconds time) -> capy::task<> {
#ifdef NEXUS_TEST_FAKEIP
    try {
#endif
    auto edns=f.advertised ? std::optional{dns::QueryEdns{*f.advertised,0,false,{}}} : std::nullopt;
    f.result = co_await f.client.query(f.upstream.local_endpoint(), dns::QueryMessage{0x1234,0x0100,{"example.com",1},edns},
                                        std::chrono::steady_clock::now()+time);
#ifdef NEXUS_TEST_FAKEIP
    } catch (int) { f.hook_threw = true; }
#endif
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
auto success(bool uring) -> bool {
    Fixture f(uring); if (!init(f)) return false;
    capy::run_async(f.context.get_executor())(reply(f));
    capy::run_async(f.context.get_executor())(query(f,2s));
    f.context.restart(); (void)f.context.run_for(3s);
    if (!f.result || !*f.result || !f.server_done) return false;
    auto decoded=dns::parse_addresses((*f.result)->wire,0x1234,{"example.com",1});
    return decoded && decoded->addresses.size()==1 && decoded->addresses[0].bytes[0]==127;
}
auto failure_test(bool uring, int mode, dns::detail::UdpError expected) -> bool {
    Fixture f(uring); if (!init(f)) return false;
    f.mode = mode;
    capy::run_async(f.context.get_executor())(reply(f));
    capy::run_async(f.context.get_executor())(query(f,2s));
    f.context.restart(); (void)f.context.run_for(3s);
    return f.server_done && f.result && !*f.result && f.result->error()==expected;
}
auto timeout_test(bool uring, bool cancel) -> bool {
    Fixture f(uring); if (!init(f)) return false;
    capy::run_async(f.context.get_executor())(query(f,cancel ? 2s : 100ms));
    f.context.restart(); (void)f.context.run_for(cancel ? 20ms : 500ms);
    if (cancel) { if (f.result) return false; f.client.cancel(); f.context.restart(); (void)f.context.run_for(1s); }
    return f.result && !*f.result && f.result->error()==(cancel ? dns::detail::UdpError::canceled : dns::detail::UdpError::timeout);
}
auto capacity_reply(Fixture& f) -> capy::task<> {
    std::array<std::uint8_t,512> request{}; io::endpoint source;
    auto [error,n]=co_await f.upstream.recv_from(capy::mutable_buffer(request.data(),request.size()),source);
    if(error || n<29)co_return;
    auto accepted=f.advertised ? std::max<std::size_t>(*f.advertised,512) : 512u;
    // 65507 is the largest ordinary IPv4 UDP payload; 65535 is the EDNS
    // advertised limit and remains valid even though this socket cannot fill it.
    auto size=std::min<std::size_t>(accepted,65507);
    dns::Bytes response(request.begin(),request.begin()+29);
    response[2]=0x81;response[3]=0x80;response[7]=2;response[11]=0;
    response.insert(response.end(),{0xc0,0x0c,0,1,0,1,0,0,0,60,0,4,127,0,0,1});
    auto data_size=size-response.size()-12;
    response.insert(response.end(),{0xc0,0x0c,0xfd,0xe8,0,1,0,0,0,60,
        static_cast<std::uint8_t>(data_size>>8),static_cast<std::uint8_t>(data_size)});
    response.resize(size,0x5a);
    if(accepted<65507) {
        // A valid response prefix plus trailing data must be discarded even
        // when recvmsg silently clips it to the supplied receive capacity.
        auto oversized=response;oversized[41]=198;oversized.resize(size+1,0xa5);
        auto [first_error,first_n]=co_await f.upstream.send_to(capy::const_buffer(oversized.data(),oversized.size()),source);
        if(first_error || first_n!=oversized.size())co_return;
        // TC is parsed before resource records. A much larger matching TC
        // datagram must also be discarded, not surfaced as UdpError::truncated.
        oversized[2]|=2;oversized.resize(size+100,0xa5);
        auto [tc_error,tc_n]=co_await f.upstream.send_to(capy::const_buffer(oversized.data(),oversized.size()),source);
        if(tc_error || tc_n!=oversized.size())co_return;
    }
    auto [sent_error,sent]=co_await f.upstream.send_to(capy::const_buffer(response.data(),response.size()),source);
    f.server_done=!sent_error && sent==response.size();
}
auto capacity_test(bool uring,std::optional<std::uint16_t> advertised) -> bool {
    Fixture f(uring);if(!init(f))return false;f.advertised=advertised;
    capy::run_async(f.context.get_executor())(capacity_reply(f));
    capy::run_async(f.context.get_executor())(query(f,2s));
    f.context.restart();(void)f.context.run_for(3s);
    auto accepted=advertised ? std::max<std::size_t>(*advertised,512) : 512u;
    if(!f.result || !*f.result || !f.server_done || (*f.result)->wire.size()!=std::min<std::size_t>(accepted,65507))return false;
    auto decoded=dns::parse_addresses((*f.result)->wire,0x1234,{"example.com",1});
    return decoded && decoded->addresses.size()==1 && decoded->addresses[0].bytes[0]==127;
}
#ifdef NEXUS_TEST_FAKEIP
auto receive_hook_test(bool uring) -> bool {
    Fixture f(uring); if (!init(f)) return false;
    nexus_test_set_fakeip_receive_hook(true);
    capy::run_async(f.context.get_executor())(reply(f));
    capy::run_async(f.context.get_executor())(query(f,2s));
    f.context.restart(); (void)f.context.run_for(1s);
    auto passed=f.hook_threw && !f.result && nexus_test_fakeip_receive_hook_count()==1;
    nexus_test_set_fakeip_receive_hook(false);
    return passed;
}
#endif
auto main() -> int {
    for (bool uring : {false, true}) {
        if (uring && !io::has_uring) continue;
        if (!success(uring) || !timeout_test(uring,false) || !timeout_test(uring,true) ||
            !failure_test(uring,1,dns::detail::UdpError::truncated) ||
            !failure_test(uring,2,dns::detail::UdpError::response_limit)) return 1;
        for(auto advertised:{std::optional<std::uint16_t>{},std::optional<std::uint16_t>{1},
            std::optional<std::uint16_t>{512},std::optional<std::uint16_t>{4096},std::optional<std::uint16_t>{65535}})
            if(!capacity_test(uring,advertised))return 3;
#ifdef NEXUS_TEST_FAKEIP
        if (!receive_hook_test(uring)) return 2;
#endif
        std::println("DNS UDP source, transaction, timeout, cancellation, advertised capacity and oversized prefixes passed ({})",
                     uring ? "io_uring" : "epoll");
    }
}
