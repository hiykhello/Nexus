module proxy;
import std;
import proxy.v4;
import net.stream_relay;
import shadowsocks.corosio_client;
import shadowsocks.corosio_relay;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;
import dns.local_config;
import uot;

namespace proxy {
    namespace {
        struct TunnelStream {
            pro::proxy<TunnelFacade>& tunnel;
            auto read(std::span<std::uint8_t> bytes) { return tunnel->read(bytes); }
            auto send(std::span<std::uint8_t const> bytes) { return tunnel->send(bytes); }
            auto close_output() { return tunnel->close_output(); }
            auto cancel() noexcept -> void { tunnel->cancel(); }
        };
        auto run(Session& session,nex::corosio::io_context& context,TunnelFactory const& outer,
                 TunnelLayerFactory const& intermediate_factory,TunnelLayerFactory const& layer_factory,unsigned inner,unsigned third,unsigned target,unsigned mode,int& result) -> nex::capy::task<> {
            auto deadline=Clock::now()+std::chrono::seconds(8);
            auto endpoint=nex::corosio::endpoint(nex::corosio::ipv4_address::loopback(),static_cast<std::uint16_t>(inner));
            auto third_endpoint=nex::corosio::endpoint(nex::corosio::ipv4_address::loopback(),static_cast<std::uint16_t>(third));
            std::array steps{TunnelChainStep{third ? &intermediate_factory : &layer_factory,endpoint},TunnelChainStep{&layer_factory,third_endpoint}};
            auto connected=co_await connect_tunnel_chain(session,context,outer,std::span(steps).first(third ? 2 : 1),
                nex::corosio::endpoint(nex::corosio::ipv4_address::loopback(),static_cast<std::uint16_t>(target)),mode==3 ? TunnelChainMode::uot : TunnelChainMode::tcp,deadline);
            if (connected!=TunnelConnectResult::connected) { result=3; co_return; }
            if (mode==3) {
                uot::Address address{}; address.length=4; address.bytes[0]=127; address.bytes[3]=1; address.port=static_cast<std::uint16_t>(target);
                auto request=uot::encode_request({false,address});
                std::array<std::uint8_t,5> payload{'p','r','o','b','e'};
                auto packet=uot::encode_packet(false,address,payload);
                if (!request || !packet || !co_await session.tunnel->send(*request) || !co_await session.tunnel->send(*packet)) { result=11; co_return; }
                uot::PacketDecoder decoder(false); std::array<std::uint8_t,256> input{};
                for (;;) {
                    auto n=co_await session.tunnel->read(input);
                    if (!n || !*n) { result=12; co_return; }
                    auto step=decoder.feed(std::span(input).first(*n));
                    if (step.status==uot::Status::incomplete && step.consumed==*n) continue;
                    auto reply=decoder.packet();
                    std::array<std::uint8_t,4> expected{'g','o','o','d'};
                    result=step.status==uot::Status::accepted && step.consumed==*n && reply && reply->destination==address && std::ranges::equal(reply->payload,expected) ? 0 : 13;
                    co_return;
                }
            }
            std::vector<std::uint8_t> message;
            if (mode==2) { message.resize(262144); for (std::size_t i=0;i<message.size();++i) message[i]=static_cast<std::uint8_t>(i); }
            else message={'h','e','l','l','o','a','g','a','i','n'};
            if (!co_await session.tunnel->send(message) || !co_await session.tunnel->close_output()) { result=4; co_return; }
            std::array<std::uint8_t,64> bytes{}; std::vector<std::uint8_t> received;
            if (mode==1 || mode==4) {
                auto begin=Clock::now();
                TunnelStream stream{session.tunnel}; net::ByteStreamAdapter socket(stream);
                auto [error,n]=co_await nex::corosio::timeout(socket.read_some(nex::capy::mutable_buffer(bytes.data(),bytes.size())),begin+std::chrono::seconds(mode==4 ? 5 : 0)+std::chrono::milliseconds(mode==4 ? 0 : 250));
                auto elapsed=Clock::now()-begin;
                result=(mode==4 ? session.closed && bool(error) : nex::capy::is_timeout(error)) && !n && elapsed>=std::chrono::milliseconds(150) && elapsed<std::chrono::seconds(3) ? 0 : 10;
                co_return;
            }
            for (;;) {
                auto n=co_await session.tunnel->read(bytes);
                if (!n) { result=5; co_return; }
                if (!*n) break;
                received.insert(received.end(),bytes.begin(),bytes.begin()+*n);
                if (received.size()>(mode==2 ? message.size() : 10)) { result=6; co_return; }
            }
            std::array<std::uint8_t,10> expected{'w','o','r','l','d','a','g','a','i','n'};
            result=(mode==2 ? received==message : std::ranges::equal(received,expected)) ? 0 : 7;
        }
    }
}
extern "C" int nexus_test_chain_ss(unsigned outer,unsigned inner,unsigned third,unsigned target,bool uring,unsigned mode) {
    using namespace proxy;
    std::array<std::uint8_t,16> key{}; std::iota(key.begin(),key.end(),std::uint8_t{0});
    auto factory=make_shadowsocks_factory("127.0.0.1",static_cast<std::uint16_t>(outer),key,{},false,10000);
    if (!factory) return 1;
    auto layer_factory=make_shadowsocks_layer_factory(key,mode==3,10000); if (!layer_factory) return 1;
    auto intermediate_factory=make_shadowsocks_layer_factory(key,false,10000); if (!intermediate_factory) return 1;
    LocalDnsState dns; auto context=nex::corosio::make_io_context(uring); Session session(context); session.local_dns=&dns;
    int result=8; nex::capy::run_async(context.get_executor())(run(session,context,*factory,*intermediate_factory,*layer_factory,inner,third,target,mode,result));
    if (mode==4) { (void)context.run_for(std::chrono::milliseconds(300)); session.close(); context.restart(); }
    (void)context.run_for(std::chrono::seconds(10));
    if (!context.stopped()) { session.close(); context.restart(); (void)context.run_for(std::chrono::seconds(1)); return 9; }
    session.tunnel={}; return result;
}
