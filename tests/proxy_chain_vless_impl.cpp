module relay;
import std;
import proxy.v4;
import capy;
import corosio;
import dns.local_config;
import xudp;
import xudp.client_sessions;
import xudp.client_io;
namespace relay {
    namespace {
        struct Stream {
            pro::proxy<TunnelFacade>& tunnel;
            auto write(std::span<std::uint8_t const> bytes) { return tunnel->send(bytes); }
            auto read(std::span<std::uint8_t> bytes) { return tunnel->read(bytes); }
            auto cancel() noexcept -> void { tunnel->cancel(); }
        };
        auto run(Session& session,corosio::io_context& context,TunnelFactory const& outer,unsigned inner,unsigned target,
                 TunnelLayerFactory const& layer_factory,unsigned mode,int& result) -> capy::task<> {
            auto deadline=Clock::now()+std::chrono::seconds(8);
            auto begin=Clock::now();
            std::array steps{TunnelChainStep{&layer_factory,corosio::endpoint(corosio::ipv4_address::loopback(),inner)}};
            auto connected=co_await connect_tunnel_chain(session,context,outer,steps,
                corosio::endpoint(corosio::ipv4_address::loopback(),target),mode==3 ? TunnelChainMode::xudp : TunnelChainMode::tcp,
                mode==1 ? begin+std::chrono::milliseconds(250) : deadline);
            if (mode==1 || mode==2) {
                auto elapsed=Clock::now()-begin;
                result=(mode==1 ? connected==TunnelConnectResult::timeout : session.closed && connected==TunnelConnectResult::failed) &&
                    elapsed>=std::chrono::milliseconds(100) && elapsed<std::chrono::seconds(3) ? 0 : 11;
                co_return;
            }
            if (connected!=TunnelConnectResult::connected) { result=4; co_return; }
            if (mode==3) {
                Stream stream{session.tunnel}; xudp::ClientIo client(stream,2);
                xudp::Address address; address.length=4; address.bytes[0]=127; address.bytes[3]=1; address.port=target;
                std::array<std::uint8_t,5> payload{'p','r','o','b','e'};
                auto id=co_await client.open(address,payload); if (!id) { result=12; co_return; }
                std::array<std::uint8_t,3> second{1,2,3};
                auto id2=co_await client.open(address,second); if (!id2 || *id2==*id) { result=15; co_return; }
                std::array<bool,2> received{};
                for (unsigned i=0;i<2;++i) {
                    auto reply=co_await client.read();
                    if (!reply || reply->action!=xudp::Incoming::datagram || !reply->source || *reply->source!=address) { result=13; co_return; }
                    if (reply->session==*id && !received[0] && std::ranges::equal(reply->payload,payload)) received[0]=true;
                    else if (reply->session==*id2 && !received[1] && std::ranges::equal(reply->payload,second)) received[1]=true;
                    else { result=13; co_return; }
                }
                if (!co_await client.end(*id)) { result=14; co_return; }
                if (!co_await client.end(*id2)) { result=14; co_return; }
                result=0; co_return;
            }
            std::vector<std::uint8_t> message(262144); for (std::size_t i=0;i<message.size();++i) message[i]=static_cast<std::uint8_t>(i);
            if (!co_await session.tunnel->send(message) || !co_await session.tunnel->close_output()) { result=5; co_return; }
            std::vector<std::uint8_t> received; std::array<std::uint8_t,8192> bytes{};
            for (;;) {
                auto n=co_await session.tunnel->read(bytes); if (!n) { result=6; co_return; }
                if (!*n) break;
                received.insert(received.end(),bytes.begin(),bytes.begin()+*n);
                if (received.size()>message.size()) { result=7; co_return; }
            }
            result=received==message ? 0 : 8;
        }
    }
}
extern "C" int nexus_test_chain_vless(unsigned outer,unsigned inner,unsigned target,char const* uuid,char const* ca,bool vision,bool uring,unsigned mode) {
    using namespace relay;
    std::array<std::uint8_t,16> key{}; std::iota(key.begin(),key.end(),std::uint8_t{0});
    auto factory=make_shadowsocks_factory("127.0.0.1",outer,key,{},false,10000); if (!factory) return 1;
    auto layer_factory=make_vless_layer_factory(uuid,"cover.example",ca,TlsKeyExchange::x25519,{},vision,10000); if (!layer_factory) return 1;
    LocalDnsState dns; auto context=corosio::make_io_context(uring); Session session(context); session.local_dns=&dns;
    int result=9; bool stopped=false;
    capy::run_async(context.get_executor(),[] {},[&](std::exception_ptr) noexcept { stopped=true; })(run(session,context,*factory,inner,target,*layer_factory,mode,result));
    if (mode==2) { (void)context.run_for(std::chrono::milliseconds(300)); session.close(); context.restart(); }
    (void)context.run_for(std::chrono::seconds(10));
    if (!context.stopped()) { session.close(); context.restart(); (void)context.run_for(std::chrono::seconds(1)); return 10; }
    session.tunnel={}; return mode==2 && session.closed && stopped ? 0 : result;
}
