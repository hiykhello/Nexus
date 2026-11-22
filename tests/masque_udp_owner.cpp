import std;
import masque.udp_owner;
import masque.connect_udp;
import masque.target;
import masque.udp_session;
import net.udp_socket;
import http.header;
namespace m=masque;
namespace net=net;
namespace http=http;
using namespace std::chrono_literals;
struct Policy {
    using Identity=std::uint32_t;
    unsigned calls=0;
    auto authenticate(std::span<http::HeaderField const> headers) -> std::optional<Identity> {
        for(auto const& h:headers)if(h.name=="proxy-authorization" && h.value=="Bearer test-only")return 7;
        return {};
    }
    auto allow(Identity identity,m::UdpTarget const& target,net::UdpEndpoint endpoint) -> bool {
        ++calls;return identity==7 && target.host=="localhost" && endpoint.port==target.port && endpoint.address[0]==127 && endpoint.address[3]==1;
    }
};
auto main() -> int {
    for(auto path:{"/.well-known/masque/udp/","/.well-known/masque/udp/a/0/","/.well-known/masque/udp/a/65536/","/.well-known/masque/udp/%2F/9/","/.well-known/masque/udp/a../9/","/.well-known/masque/udp/::1/9/","/.well-known/masque/udp/a/9/?q"})if(m::parse_well_known_udp_target(path))return 1;
    auto v6=m::parse_well_known_udp_target("/.well-known/masque/udp/%3A%3A1/53/");if(!v6 || v6->host!="::1" || v6->port!=53)return 2;
    net::UdpSocket echo;net::UdpEndpoint local{4,{127,0,0,1},0};if(!echo.bind(local))return 3;auto endpoint=echo.local_endpoint();if(!endpoint)return 4;
    std::string path=std::format("/.well-known/masque/udp/localhost/{}/",endpoint->port);
    std::vector<http::HeaderField> headers{{":method","CONNECT"},{":protocol","connect-udp"},{":scheme","https"},{":authority","proxy.example"},{":path",path}};
    Policy policy;m::UdpOwner<Policy,2> owner(policy,"proxy.example");
    if(owner.begin(0,headers).error()!=m::OwnerError::identity)return 5;
    headers.push_back({"proxy-authorization","Bearer test-only"});
    auto pending=owner.begin(0,headers);if(!pending || pending->host!="localhost" || pending->port!=endpoint->port || owner.ready(pending->handle))return 6;
    auto mapped=*endpoint;mapped.family=6;mapped.address={};mapped.address[10]=mapped.address[11]=255;mapped.address[12]=127;mapped.address[15]=1;
    auto prior_calls=policy.calls;
    if(owner.finish_resolve(pending->handle,mapped).error()!=m::OwnerError::resolution || policy.calls!=prior_calls)return 21;
    auto denied=*endpoint;denied.address[3]=2;
    if(owner.finish_resolve(pending->handle,denied).error()!=m::OwnerError::policy || owner.ready(pending->handle))return 7;
    if(!owner.finish_resolve(pending->handle,*endpoint) || !owner.ready(pending->handle))return 8;
    std::array<std::uint8_t,3> payload{1,2,3};if(owner.send(pending->handle,payload)!=m::OwnerSend::sent)return 9;
    std::array<std::uint8_t,32> input{};std::optional<net::UdpPacket> received;
    for(unsigned i=0;i<100 && !received;++i) {auto p=echo.receive(input);if(!p)return 10;received=*p;if(!received)std::this_thread::sleep_for(1ms);}
    if(!received || !received->valid || received->size!=payload.size() || !std::ranges::equal(payload,std::span(input).first(3)))return 11;
    net::UdpSocket attacker;if(!attacker.bind(local))return 17;
    std::array<std::uint8_t,1> forgery{99};if(!attacker.send(received->source,forgery))return 18;
    bool discarded=false;
    for(unsigned i=0;i<100 && !discarded;++i) {auto p=owner.receive(pending->handle,input);if(!p || *p)return 19;discarded=input[0]==99;if(!discarded)std::this_thread::sleep_for(1ms);}
    if(!discarded)return 20;
    if(!echo.send(received->source,payload))return 12;
    std::optional<std::size_t> reply;
    for(unsigned i=0;i<100 && !reply;++i) {auto p=owner.receive(pending->handle,input);if(!p)return 13;reply=*p;if(!reply)std::this_thread::sleep_for(1ms);}
    if(reply!=3 || !std::ranges::equal(payload,std::span(input).first(3)))return 14;
    auto first=pending->handle;owner.close(first);
    auto next=owner.begin(4,headers);if(!next || owner.finish_resolve(first,*endpoint).error()!=m::OwnerError::stale)return 15;
    owner.stop();if(!owner.drained() || owner.finish_resolve(next->handle,*endpoint).error()!=m::OwnerError::stopped || owner.begin(8,headers).error()!=m::OwnerError::stopped)return 16;
    std::println("CONNECT-UDP auth, target policy, UDP echo and stop passed");
}
