module relay;
import std;
import proxy.v4;
import capy;
import corosio;
import xudp;
import xudp.client_sessions;
import xudp.client_io;
import dns.local_config;
namespace relay {
    namespace {
        struct Stream {
            pro::proxy<TunnelFacade>& tunnel;
            auto write(std::span<std::uint8_t const> bytes) -> capy::task<bool> { co_return co_await tunnel->send(bytes); }
            auto read(std::span<std::uint8_t> bytes) -> capy::task<std::expected<std::size_t,std::string>> { co_return co_await tunnel->read(bytes); }
            auto cancel() noexcept -> void { tunnel->cancel(); }
        };
        auto run(Session& session,corosio::io_context& context,TunnelFactory const& factory,std::array<std::uint16_t,2> ports,int& result) -> capy::task<> {
            session.tunnel=factory(session,context);
            if (!session.tunnel || !session.tunnel->has_xudp() || co_await session.tunnel->connect_xudp()!=TunnelConnectResult::connected) { result=2; co_return; }
            Stream stream{session.tunnel}; xudp::ClientIo client(stream,2);
            std::array<std::array<std::uint8_t,3>,2> messages{{{1,2,3},{4,5,6}}};
            for (std::size_t i=0;i<2;++i) {
                xudp::Address target; target.length=4; target.bytes[0]=127; target.bytes[3]=1; target.port=ports[i];
                auto id=co_await client.open(target,messages[i]); if (!id || *id!=i+1) { result=3; co_return; }
            }
            std::array<bool,2> received{};
            while (!received[0] || !received[1]) {
                auto reply=co_await client.read();
                if (!reply || reply->action!=xudp::Incoming::datagram || reply->session<1 || reply->session>2 || !reply->source || reply->source->port!=ports[reply->session-1] || !std::ranges::equal(reply->payload,messages[reply->session-1]) || received[reply->session-1]) { result=4; co_return; }
                received[reply->session-1]=true;
            }
            for (std::uint16_t id=1;id<=2;++id) if (!co_await client.end(id)) { result=5; co_return; }
            result=0;
        }
    }
}
extern "C" int nexus_test_proxy_xudp(unsigned server,unsigned a,unsigned b,char const* uuid,char const* hex,bool vision) {
    using namespace relay;
    std::string_view text(hex); if (text.size()!=64) return 64;
    Reality reality; reality.short_id={1,0x23,0x45,0x67,0x89,0xab,0xcd,0xef};
    auto nib=[](char c)->int { if(c>='0'&&c<='9') return c-'0'; if(c>='a'&&c<='f') return c-'a'+10; return -1; };
    for (std::size_t i=0;i<32;++i) { auto x=nib(text[i*2]),y=nib(text[i*2+1]); if(x<0 || y<0) return 64; reality.public_key[i]=x*16+y; }
    auto factory=make_vless_factory("127.0.0.1",server,uuid,"cover.example","",TlsKeyExchange::x25519,{},reality,vision,10000); if (!factory) return 1;
    LocalDnsState local_dns;
    corosio::io_context context(corosio::epoll); Session session(context); session.local_dns=&local_dns; int result=9;
    capy::run_async(context.get_executor())(run(session,context,*factory,{static_cast<std::uint16_t>(a),static_cast<std::uint16_t>(b)},result));
    context.restart(); (void)context.run_for(std::chrono::seconds(15));
    if (!context.stopped()) { session.close(); context.restart(); (void)context.run_for(std::chrono::seconds(1)); if (!context.stopped()) std::_Exit(10); return 10; }
    session.tunnel={}; return result;
}
