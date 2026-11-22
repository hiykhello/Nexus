module proxy;
import std;
import proxy.v4;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;
import dns.local_config;

namespace proxy {
    namespace {
        auto run(Session& session,nex::corosio::io_context& context,TunnelFactory const& ss,TunnelFactory const& vless,int& result) -> nex::capy::task<> {
            auto destination=nex::corosio::endpoint(nex::corosio::ipv4_address::loopback(),80);
            auto expired=co_await connect_tunnel_chain(session,context,ss,{},destination,TunnelChainMode::tcp,Clock::now()-std::chrono::milliseconds(1));
            std::array invalid{TunnelChainStep{nullptr,destination}};
            auto bad=co_await connect_tunnel_chain(session,context,ss,invalid,destination,TunnelChainMode::tcp,Clock::now()+std::chrono::seconds(1));
            if (expired!=TunnelConnectResult::timeout || bad!=TunnelConnectResult::failed || session.tunnel) { result=6; co_return; }
            for (auto const* factory : {&ss,&vless}) {
                session.tunnel=(*factory)(session,context);
                if (co_await session.tunnel->connect_until(destination,Clock::now()-std::chrono::milliseconds(1))!=TunnelConnectResult::timeout) {
                    result=2; co_return;
                }
                session.tunnel={};
            }
            session.tunnel=vless(session,context);
            auto begin=Clock::now();
            auto status=co_await session.tunnel->connect_until(destination,begin+std::chrono::milliseconds(250));
            auto elapsed=Clock::now()-begin;
            if (status!=TunnelConnectResult::timeout || elapsed<std::chrono::milliseconds(150) || elapsed>std::chrono::seconds(3)) {
                result=3; co_return;
            }
            session.tunnel={}; result=0;
        }
    }
}
extern "C" int nexus_test_chain_deadline(unsigned port,char const* uuid,char const* ca) {
    using namespace proxy;
    std::array<std::uint8_t,16> key{};
    auto ss=make_shadowsocks_factory("127.0.0.1",static_cast<std::uint16_t>(port),key,{},false,10000);
    auto vless=make_vless_factory("127.0.0.1",static_cast<std::uint16_t>(port),uuid,"localhost",ca,TlsKeyExchange::x25519,{}, {},false,10000);
    if (!ss || !vless) return 1;
    LocalDnsState dns; nex::corosio::io_context context=nex::corosio::make_io_context(false); Session session(context); session.local_dns=&dns;
    int result=4; nex::capy::run_async(context.get_executor())(run(session,context,*ss,*vless,result));
    (void)context.run_for(std::chrono::seconds(5));
    if (!context.stopped()) { session.close(); context.restart(); (void)context.run_for(std::chrono::seconds(1)); return 5; }
    session.tunnel={}; return result;
}
