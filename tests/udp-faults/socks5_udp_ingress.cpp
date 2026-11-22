#include <arpa/inet.h>
#include <cerrno>
#include <sys/socket.h>
#include <unistd.h>
import std;
import rules;
import socks5.udp_ingress;
namespace s=socks5; namespace r = ::rules;
static bool fail_reply=false;
static int reply_error=0;
static int receive_error=0;
extern "C" ssize_t __real_sendto(int,const void*,size_t,int,const sockaddr*,socklen_t);
extern "C" ssize_t __real_recvfrom(int,void*,size_t,int,sockaddr*,socklen_t*);
extern "C" ssize_t __wrap_recvfrom(int fd,void* data,size_t size,int flags,sockaddr* source,socklen_t* length) {
    if (receive_error) { errno=std::exchange(receive_error,0); return -1; }
    return __real_recvfrom(fd,data,size,flags,source,length);
}
extern "C" ssize_t __wrap_sendto(int fd,const void* data,size_t size,int flags,const sockaddr* dest,socklen_t length) {
    if (fail_reply) { fail_reply=false; errno=EAGAIN; return -1; }
    if (reply_error) { errno=std::exchange(reply_error,0); return -1; }
    return __real_sendto(fd,data,size,flags,dest,length);
}
struct Socket { int fd; ~Socket() { if(fd>=0) ::close(fd); } };
auto lookahead_test(int client,r::RouteMatcher const& policy,std::vector<std::uint8_t> wire) -> int {
    using Clock=std::chrono::steady_clock;
    auto association=s::UdpAssociation::create({1,{127,0,0,1},1234},{1,{},0});
    if(!association)return 100;
    s::UdpIngress driver(*association,policy,true,true,{},nullptr,true);
    auto local=driver.open({1,{127,0,0,1},0});if(!local)return 101;
    sockaddr_in relay{};relay.sin_family=AF_INET;relay.sin_addr.s_addr=htonl(INADDR_LOOPBACK);relay.sin_port=htons(local->port);
    auto send=[&](unsigned id) {
        wire.back()=static_cast<std::uint8_t>(id);
        return ::sendto(client,wire.data(),wire.size(),0,reinterpret_cast<sockaddr*>(&relay),sizeof(relay))==static_cast<ssize_t>(wire.size());
    };
    std::array<Clock::time_point,10> deadlines{};
    std::array<std::optional<std::string>,10> names{};
    names[3]="three.example";names[8]="eight.example";
    auto matches=[&](unsigned id) {
        auto packet=driver.pending_route();auto metadata=driver.route_metadata();
        return packet && packet->data.size()==2 && packet->data[1]==id && metadata &&
            metadata->deadline==deadlines[id] && metadata->quic_inspected && metadata->quic_domain==names[id];
    };
    if(!send(0))return 102;
    auto step=driver.step();auto head=driver.pending_route();auto metadata=driver.route_metadata();
    if(!step || !step->route_pending || !head || !metadata || metadata->quic_inspected || metadata->quic_domain)return 103;
    deadlines[0]=metadata->deadline;
    if(deadlines[0]<=Clock::now() || !driver.remember_route_sniff({}) || !driver.begin_route_lookahead())return 104;
    auto source=driver.pending_route_source();if(!source)return 105;
    // The fixed head's borrowed bytes remain stable while seven tail entries
    // and the one overflow packet arrive through the same authenticated socket.
    for(unsigned id=1;id<=8;++id) {
        if(!send(id))return 106;
        step=driver.step();auto tail=driver.lookahead_route(id-1);
        if(!step || !step->input || !step->route_pending || step->input_error || !tail ||
            tail->packet.data.size()!=2 || tail->packet.data[1]!=id || tail->source!=*source ||
            tail->deadline<deadlines[id-1] || head->data[1]!=0 || !matches(0))return 107;
        deadlines[id]=tail->deadline;
        if(!driver.remember_lookahead_sniff(id-1,names[id]))return 108;
    }
    if(!driver.route_lookahead_full() || driver.deferred_count()!=7 || driver.lookahead_route(8) ||
        driver.remember_lookahead_sniff(8,{}) || driver.replay_deferred())return 109;
    if(!send(9))return 110;
    step=driver.step();
    if(!step || step->input || !matches(0) || driver.lookahead_route(8))return 111;
    driver.end_route_lookahead();driver.discard_route();
    if(!driver.replay_deferred() || !matches(1))return 112;
    // Re-enter sniff collection from an already replayed head. The previous
    // overflow moves into the tail and the unread ninth packet can now enter.
    if(!driver.begin_route_lookahead())return 113;
    step=driver.step();auto last=driver.lookahead_route(7);
    if(!step || !step->input || step->input_error || !matches(1) || !last ||
        last->packet.data[1]!=9 || last->source!=*source || !driver.route_lookahead_full())return 114;
    deadlines[9]=last->deadline;
    if(!driver.remember_lookahead_sniff(7,{}) || driver.deferred_count()!=7)return 115;
    for(unsigned id=2;id<=8;++id) {
        auto tail=driver.lookahead_route(id-2);
        if(!tail || tail->packet.data[1]!=id || tail->deadline!=deadlines[id])return 116;
    }
    driver.end_route_lookahead();
    auto packet=driver.pending_route();if(!packet)return 117;
    s::UdpPeer destination{1,{127,0,0,1},packet->port};
    if(!driver.send_selected(destination,2))return 118;
    auto tunnel=driver.pending_tunnel();
    if(!tunnel || tunnel->deadline!=deadlines[1] || driver.route_metadata() ||
        association->accepts_reply(destination))return 119;
    driver.complete_tunnel();
    for(unsigned id=2;id<=9;++id) {
        if(!driver.replay_deferred() || !matches(id))return 120;
        driver.discard_route();
    }
    if(driver.replay_deferred() || driver.deferred_count() || driver.deferred_bytes())return 121;
    // Finish replay, admit a fresh head, then close with an annotated tail
    // still retained. Neither payloads nor sniff/deadline metadata may survive.
    if(!send(10))return 122;
    step=driver.step();metadata=driver.route_metadata();
    if(!step || !step->route_pending || !metadata || metadata->quic_inspected ||
        metadata->quic_domain || !driver.begin_route_lookahead() || !send(11))return 123;
    step=driver.step();
    if(!step || !step->input || !driver.lookahead_route(0) ||
        !driver.remember_route_sniff("head.example") || !driver.remember_lookahead_sniff(0,{}))return 124;
    driver.close();
    if(driver.pending_route() || driver.route_metadata() || driver.lookahead_route(0) ||
        driver.pending_tunnel() || driver.deferred_count() || driver.deferred_bytes() ||
        driver.replay_deferred() || driver.begin_route_lookahead() || driver.remember_route_sniff({}) ||
        driver.remember_lookahead_sniff(0,{}))return 125;
    step=driver.step();
    if(step || step.error()!=s::UdpDirectError{s::Status::association_closed})return 126;
    return 0;
}
int main() {
    Socket client{::socket(AF_INET,SOCK_DGRAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0)},
           attacker{::socket(AF_INET,SOCK_DGRAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0)},
           target{::socket(AF_INET,SOCK_DGRAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0)};
    sockaddr_in addr{}; addr.sin_family=AF_INET; addr.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    if (client.fd<0 || attacker.fd<0 || target.fd<0 || ::bind(client.fd,reinterpret_cast<sockaddr*>(&addr),sizeof(addr)) ||
        ::bind(attacker.fd,reinterpret_cast<sockaddr*>(&addr),sizeof(addr)) || ::bind(target.fd,reinterpret_cast<sockaddr*>(&addr),sizeof(addr))) return 1;
    socklen_t length=sizeof(addr); if (::getsockname(target.fd,reinterpret_cast<sockaddr*>(&addr),&length)) return 2;
    auto target_port=ntohs(addr.sin_port);
    auto policy=r::RouteMatcher::compile(std::span<r::RouteRule const>{},0,2);
    auto association=s::UdpAssociation::create({1,{127,0,0,1},1234},{1,{},0});
    if (!policy || !association) return 3;
    s::UdpIngress driver(*association,*policy);
    auto local=driver.open({1,{127,0,0,1},0}); if (!local || !local->port) return 4;
    sockaddr_in relay{}; relay.sin_family=AF_INET; relay.sin_addr.s_addr=htonl(INADDR_LOOPBACK); relay.sin_port=htons(local->port);
    std::vector<std::uint8_t> wire{0,0,0,1,127,0,0,1,static_cast<std::uint8_t>(target_port>>8),static_cast<std::uint8_t>(target_port),'h','i'};
    if (::sendto(client.fd,wire.data(),wire.size(),0,reinterpret_cast<sockaddr*>(&relay),sizeof(relay))!=static_cast<ssize_t>(wire.size())) return 5;
    fail_reply=true;
    auto blocked_input=driver.step();
    if (!blocked_input || !blocked_input->input_backpressured || blocked_input->forwarded || fail_reply ||
        association->accepts_reply({1,{127,0,0,1},target_port})) return 5;
    bool sent=false; char bytes[32]{}; sockaddr_in origin{}; length=sizeof(origin); ssize_t n=-1;
    for(int i=0;i<100 && n<0;++i) {
        auto result=driver.step(); if (!result || result->input_error || result->output_error) return 6;
        sent |= result->forwarded;
        n=::recvfrom(target.fd,bytes,sizeof(bytes),0,reinterpret_cast<sockaddr*>(&origin),&length);
        if (n<0) std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    if (!sent || n!=2 || std::string_view(bytes,2)!="hi") return 7;
    if (::sendto(attacker.fd,wire.data(),wire.size(),0,reinterpret_cast<sockaddr*>(&relay),sizeof(relay))!=static_cast<ssize_t>(wire.size())) return 8;
    bool rejected=false;
    for(int i=0;i<100 && !rejected;++i) { auto result=driver.step(); if (!result) return 9;
        rejected=result->input_error && *result->input_error==s::UdpDirectError{s::Status::unauthorized_source}; }
    if (!rejected || ::sendto(target.fd,"ok",2,0,reinterpret_cast<sockaddr*>(&origin),length)!=2) return 10;
    fail_reply=true; bool blocked=false;
    for(int i=0;i<100 && !blocked;++i) { auto result=driver.step(); if (!result || result->output_error) return 11;
        blocked=result->backpressured; if (!blocked) std::this_thread::sleep_for(std::chrono::milliseconds(1)); }
    if (!blocked || fail_reply) return 11;
    std::array<std::uint8_t,64> response{}; n=-1;
    for(int i=0;i<100 && n<0;++i) { auto result=driver.step(); if (!result || result->output_error) return 11;
        n=::recv(client.fd,response.data(),response.size(),0); if (n<0) std::this_thread::sleep_for(std::chrono::milliseconds(1)); }
    if (n<0) return 12;
    auto parsed=s::parse_udp_datagram(std::span(response).first(n));
    if (!parsed || parsed->port!=target_port || !std::ranges::equal(parsed->data,std::array<std::uint8_t,2>{'o','k'})) return 13;
    for (int failure : {EMSGSIZE, ENETUNREACH, EHOSTUNREACH, ECONNREFUSED}) {
        if (::sendto(target.fd,"drop",4,0,reinterpret_cast<sockaddr*>(&origin),length)!=4) return 61;
        reply_error=failure; bool dropped=false;
        for (int i=0;i<100 && !dropped;++i) {
            auto result=driver.step(); if (!result || result->output_error) return 62;
            dropped=result->output_dropped;
            if (!dropped) std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        if (!dropped || reply_error || ::recv(client.fd,response.data(),response.size(),0)>=0) return 63;
        if (::sendto(target.fd,"next",4,0,reinterpret_cast<sockaddr*>(&origin),length)!=4) return 64;
        n=-1;
        for (int i=0;i<100 && n<0;++i) {
            auto result=driver.step(); if (!result || result->output_error) return 65;
            n=::recv(client.fd,response.data(),response.size(),0);
            if (n<0) std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        if (n<0) return 66;
        parsed=s::parse_udp_datagram(std::span(response).first(n));
        if (!parsed || !std::ranges::equal(parsed->data,std::array<std::uint8_t,4>{'n','e','x','t'})) return 67;
    }
    if (::sendto(target.fd,"error",5,0,reinterpret_cast<sockaddr*>(&origin),length)!=5) return 68;
    reply_error=EIO; bool fatal=false;
    for (int i=0;i<100 && !fatal;++i) {
        auto result=driver.step(); if (!result) return 69;
        fatal=result->output_error && *result->output_error==s::UdpDirectError{std::error_code(EIO,std::generic_category())};
        if (!fatal) std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    if (!fatal || reply_error) return 70;
    association->close(); auto stopped=driver.step();
    if (stopped || stopped.error()!=s::UdpDirectError{s::Status::association_closed}) return 14;
    Socket reuse{::socket(AF_INET,SOCK_DGRAM|SOCK_CLOEXEC,0)};
    if (reuse.fd<0 || ::bind(reuse.fd,reinterpret_cast<sockaddr*>(&relay),sizeof(relay))) return 15;
    auto second=s::UdpAssociation::create({1,{127,0,0,1},1234},{1,{},0});
    if (!second) return 16;
    s::UdpIngress faulty(*second,*policy);
    auto endpoint=faulty.open({1,{127,0,0,1},0}); if (!endpoint) return 17;
    for (int temporary : {EAGAIN,EINTR}) {
        receive_error=temporary;
        auto result=faulty.step();
        if (!result || result->input_error || receive_error) return 18;
    }
    receive_error=EIO;
    auto failed=faulty.step();
    if (failed || failed.error()!=s::UdpDirectError{std::error_code(EIO,std::generic_category())} || receive_error) return 19;
    auto closed=faulty.step();
    if (closed || closed.error()!=s::UdpDirectError{s::Status::association_closed}) return 20;
    Socket recovered{::socket(AF_INET,SOCK_DGRAM|SOCK_CLOEXEC,0)};
    relay.sin_port=htons(endpoint->port);
    if (recovered.fd<0 || ::bind(recovered.fd,reinterpret_cast<sockaddr*>(&relay),sizeof(relay))) return 21;
    auto third=s::UdpAssociation::create({1,{127,0,0,1},1234},{1,{},0});
    if (!third) return 22;
    s::UdpIngress domains(*third,*policy,true);
    auto domain_endpoint=domains.open({1,{127,0,0,1},0}); if (!domain_endpoint) return 23;
    relay.sin_port=htons(domain_endpoint->port);
    std::vector<std::uint8_t> named{0,0,0,3,4,'t','e','s','t',static_cast<std::uint8_t>(target_port>>8),static_cast<std::uint8_t>(target_port),'d'};
    if (::sendto(client.fd,named.data(),named.size(),0,reinterpret_cast<sockaddr*>(&relay),sizeof(relay))!=static_cast<ssize_t>(named.size())) return 24;
    auto waiting=domains.step(); auto request=domains.pending_domain();
    if (!waiting || !waiting->domain_pending || !request || request->address_type!=3 || request->data.size()!=1 || request->data[0]!='d') return 25;
    if (domains.send_resolved({1,{127,0,0,1},static_cast<std::uint16_t>(target_port+1)}) || !domains.pending_domain()) return 26;
    fail_reply=true;
    auto retry=domains.send_resolved({1,{127,0,0,1},target_port});
    if (retry || !domains.pending_domain() || third->accepts_reply({1,{127,0,0,1},target_port})) return 33;
    if (!domains.send_resolved({1,{127,0,0,1},target_port}) || domains.pending_domain()) return 27;
    length=sizeof(origin); n=::recvfrom(target.fd,bytes,sizeof(bytes),0,reinterpret_cast<sockaddr*>(&origin),&length);
    if (n!=1 || bytes[0]!='d') return 28;
    if (::sendto(client.fd,named.data(),named.size(),0,reinterpret_cast<sockaddr*>(&relay),sizeof(relay))!=static_cast<ssize_t>(named.size()) ||
        ::sendto(target.fd,"r",1,0,reinterpret_cast<sockaddr*>(&origin),length)!=1) return 29;
    bool delivered=false;
    for (int i=0;i<100 && !delivered;++i) {
        auto result=domains.step(); if (!result || !result->domain_pending || result->output_error) return 30;
        delivered=result->delivered;
        if (!delivered) std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    if (!delivered || !domains.pending_domain() || ::recv(client.fd,response.data(),response.size(),0)<0) return 31;
    domains.discard_domain();
    if (domains.pending_domain() || domains.send_resolved({1,{127,0,0,1},target_port})) return 32;
    r::RuleSet blocked_name{{{"domain-suffix","test"}}};
    auto deny=r::RouteMatcher::compile(std::array{r::RouteRule{blocked_name,1}},0,2);
    auto fourth=s::UdpAssociation::create({1,{127,0,0,1},1234},{1,{},0});
    if (!deny || !fourth) return 34;
    s::UdpIngress blocked_driver(*fourth,*deny,true);
    auto block_endpoint=blocked_driver.open({1,{127,0,0,1},0}); if (!block_endpoint) return 35;
    relay.sin_port=htons(block_endpoint->port);
    if (::sendto(client.fd,named.data(),named.size(),0,reinterpret_cast<sockaddr*>(&relay),sizeof(relay))!=static_cast<ssize_t>(named.size())) return 36;
    auto denied=blocked_driver.step();
    if (!denied || denied->domain_pending || blocked_driver.pending_domain() ||
        !denied->input_error || *denied->input_error!=s::UdpDirectError{s::UdpRouteError::blocked}) return 37;
    s::UdpPeer loopback6{4,{},0}; loopback6.address[15]=1;
    auto fifth=s::UdpAssociation::create(loopback6,{4,{},0});
    if (!fifth) return 38;
    s::UdpIngress invalid6(*fifth,*policy);
    auto wildcard6=loopback6; wildcard6.address[15]=0;
    auto mapped6=wildcard6; mapped6.address[10]=255; mapped6.address[11]=255; mapped6.address[12]=127; mapped6.address[15]=1;
    if (invalid6.open(wildcard6) || invalid6.open(mapped6)) return 60;
    s::UdpIngress ipv6(*fifth,*policy);
    auto endpoint6=ipv6.open(loopback6); if (!endpoint6) return 39;
    Socket client6{::socket(AF_INET6,SOCK_DGRAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0)};
    Socket attacker6{::socket(AF_INET6,SOCK_DGRAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0)};
    sockaddr_in6 addr6{}; addr6.sin6_family=AF_INET6; addr6.sin6_addr=in6addr_loopback;
    if (client6.fd<0 || attacker6.fd<0 || ::bind(client6.fd,reinterpret_cast<sockaddr*>(&addr6),sizeof(addr6)) ||
        ::bind(attacker6.fd,reinterpret_cast<sockaddr*>(&addr6),sizeof(addr6))) return 40;
    addr6.sin6_port=htons(endpoint6->port);
    if (::sendto(client6.fd,wire.data(),wire.size(),0,reinterpret_cast<sockaddr*>(&addr6),sizeof(addr6))!=static_cast<ssize_t>(wire.size())) return 41;
    bool forwarded6=false; n=-1;
    for (int i=0;i<100 && n<0;++i) {
        auto result=ipv6.step(); if (!result || result->input_error || result->output_error) return 42;
        forwarded6 |= result->forwarded; length=sizeof(origin);
        n=::recvfrom(target.fd,bytes,sizeof(bytes),0,reinterpret_cast<sockaddr*>(&origin),&length);
        if (n<0) std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    if (!forwarded6 || n!=2 || std::string_view(bytes,2)!="hi") return 43;
    if (::sendto(attacker6.fd,wire.data(),wire.size(),0,reinterpret_cast<sockaddr*>(&addr6),sizeof(addr6))!=static_cast<ssize_t>(wire.size())) return 44;
    auto rejected6=ipv6.step();
    if (!rejected6 || !rejected6->input_error || *rejected6->input_error!=s::UdpDirectError{s::Status::unauthorized_source}) return 45;
    if (::sendto(target.fd,"v6",2,0,reinterpret_cast<sockaddr*>(&origin),length)!=2) return 46;
    n=-1;
    for (int i=0;i<100 && n<0;++i) {
        auto result=ipv6.step(); if (!result || result->output_error) return 47;
        n=::recv(client6.fd,response.data(),response.size(),0);
        if (n<0) std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    if (n<0) return 48;
    parsed=s::parse_udp_datagram(std::span(response).first(n));
    if (!parsed || !std::ranges::equal(parsed->data,std::array<std::uint8_t,2>{'v','6'})) return 49;
    Socket target6{::socket(AF_INET6,SOCK_DGRAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0)};
    sockaddr_in6 upstream6{}; upstream6.sin6_family=AF_INET6; upstream6.sin6_addr=in6addr_loopback;
    if (target6.fd<0 || ::bind(target6.fd,reinterpret_cast<sockaddr*>(&upstream6),sizeof(upstream6))) return 51;
    length=sizeof(upstream6);
    if (::getsockname(target6.fd,reinterpret_cast<sockaddr*>(&upstream6),&length)) return 52;
    s::UdpDatagram packet6; packet6.address_type=4; packet6.address_length=16; packet6.address[15]=1;
    packet6.port=ntohs(upstream6.sin6_port); std::array<std::uint8_t,1> payload6{'6'}; packet6.data=payload6;
    auto wire6=s::encode_udp_datagram(packet6); if (!wire6) return 53;
    if (::sendto(client6.fd,wire6->data(),wire6->size(),0,reinterpret_cast<sockaddr*>(&addr6),sizeof(addr6))!=static_cast<ssize_t>(wire6->size())) return 54;
    sockaddr_in6 origin6{}; n=-1;
    for (int i=0;i<100 && n<0;++i) {
        auto result=ipv6.step(); if (!result || result->input_error || result->output_error) return 55;
        length=sizeof(origin6); n=::recvfrom(target6.fd,bytes,sizeof(bytes),0,reinterpret_cast<sockaddr*>(&origin6),&length);
        if (n<0) std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    if (n!=1 || bytes[0]!='6' || ::sendto(target6.fd,"z",1,0,reinterpret_cast<sockaddr*>(&origin6),length)!=1) return 56;
    n=-1;
    for (int i=0;i<100 && n<0;++i) {
        auto result=ipv6.step(); if (!result || result->output_error) return 57;
        n=::recv(client6.fd,response.data(),response.size(),0);
        if (n<0) std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    if (n<0) return 58;
    parsed=s::parse_udp_datagram(std::span(response).first(n));
    if (!parsed || parsed->address_type!=4 || parsed->port!=packet6.port || parsed->data.size()!=1 || parsed->data[0]!='z') return 59;
    ipv6.close();
    Socket reuse6{::socket(AF_INET6,SOCK_DGRAM|SOCK_CLOEXEC,0)};
    if (reuse6.fd<0 || ::bind(reuse6.fd,reinterpret_cast<sockaddr*>(&addr6),sizeof(addr6))) return 50;
    auto tunnel_policy=r::RouteMatcher::compile(std::span<r::RouteRule const>{},2,3);
    auto tunnel_assoc=s::UdpAssociation::create({1,{127,0,0,1},1234},{1,{},0});
    if (!tunnel_policy || !tunnel_assoc) return 71;
    s::UdpIngress tunnels(*tunnel_assoc,*tunnel_policy,true,true);
    auto tunnel_endpoint=tunnels.open({1,{127,0,0,1},0}); if (!tunnel_endpoint) return 72;
    relay.sin_port=htons(tunnel_endpoint->port);
    if (::sendto(client.fd,wire.data(),wire.size(),0,reinterpret_cast<sockaddr*>(&relay),sizeof(relay))!=static_cast<ssize_t>(wire.size())) return 73;
    auto step=tunnels.step(); auto pending=tunnels.pending_tunnel();
    if (!step || !step->tunnel_pending || !pending || pending->outbound!=2 || pending->target!=s::UdpPeer{1,{127,0,0,1},target_port} ||
        !std::ranges::equal(pending->packet.data,std::array<std::uint8_t,2>{'h','i'}) ||
        tunnel_assoc->accepts_reply(pending->target) || ::recv(target.fd,bytes,sizeof(bytes),0)>=0) return 74;
    if (::sendto(attacker.fd,wire.data(),wire.size(),0,reinterpret_cast<sockaddr*>(&relay),sizeof(relay))!=static_cast<ssize_t>(wire.size())) return 75;
    step=tunnels.step(); if (!step || !step->tunnel_pending || !tunnels.pending_tunnel()) return 76;
    tunnels.complete_tunnel();
    step=tunnels.step(); if (!step || !step->input_error || *step->input_error!=s::UdpDirectError{s::Status::unauthorized_source}) return 77;
    if (::sendto(client.fd,named.data(),named.size(),0,reinterpret_cast<sockaddr*>(&relay),sizeof(relay))!=static_cast<ssize_t>(named.size())) return 78;
    step=tunnels.step(); if (!step || !step->domain_pending || !tunnels.pending_domain()) return 79;
    if (tunnels.send_resolved({1,{127,0,0,1},static_cast<std::uint16_t>(target_port+1)}) || !tunnels.pending_domain()) return 80;
    if (!tunnels.send_resolved({1,{127,0,0,1},target_port}) || tunnels.pending_domain()) return 81;
    pending=tunnels.pending_tunnel();
    if (!pending || pending->outbound!=2 || pending->packet.address_type!=3 || pending->packet.data.size()!=1 ||
        pending->packet.data[0]!='d' || tunnel_assoc->accepts_reply(pending->target)) return 82;
    tunnels.complete_tunnel();
    auto queued=tunnels.queue_tunnel_reply({1,{127,0,0,1},target_port},std::array<std::uint8_t,1>{'r'});
    if (!queued || *queued!=s::UdpReplyStatus::queued || tunnels.queue_tunnel_reply({1,{127,0,0,1},target_port},{}).value()!=s::UdpReplyStatus::busy) return 83;
    fail_reply=true; step=tunnels.step(); if (!step || !step->backpressured || fail_reply) return 84;
    step=tunnels.step(); if (!step || !step->delivered) return 85;
    n=::recv(client.fd,response.data(),response.size(),0); if (n<0) return 86;
    parsed=s::parse_udp_datagram(std::span(response).first(n));
    if (!parsed || parsed->port!=target_port || parsed->data.size()!=1 || parsed->data[0]!='r') return 87;
    std::vector<std::uint8_t> too_big(65507);
    if (tunnels.queue_tunnel_reply({1,{127,0,0,1},target_port},too_big).value()!=s::UdpReplyStatus::dropped ||
        tunnels.queue_tunnel_reply({3,{},target_port},{})) return 88;
    tunnels.close(); if (tunnels.pending_tunnel() || tunnels.queue_tunnel_reply({1,{127,0,0,1},target_port},{})) return 89;
    auto ordered_assoc=s::UdpAssociation::create({1,{127,0,0,1},1234},{1,{},0});
    if(!ordered_assoc)return 90;
    s::UdpIngress ordered(*ordered_assoc,*policy,true,true,{},nullptr,true);
    auto ordered_endpoint=ordered.open({1,{127,0,0,1},0});if(!ordered_endpoint)return 91;
    relay.sin_port=htons(ordered_endpoint->port);
    std::array<std::chrono::steady_clock::time_point,9> deferred_deadlines{};
    for(unsigned i=0;i<9;++i) {
        wire.back()=static_cast<std::uint8_t>('0'+i);
        if(::sendto(client.fd,wire.data(),wire.size(),0,reinterpret_cast<sockaddr*>(&relay),sizeof(relay))!=static_cast<ssize_t>(wire.size()))return 92;
        step=ordered.step();if(!step || !step->route_pending || !ordered.pending_route())return 93;
        auto metadata=ordered.route_metadata();if(!metadata || metadata->quic_inspected)return 127;
        deferred_deadlines[i]=metadata->deadline;
        if(!ordered.remember_route_sniff({}))return 128;
        if(i<8) {if(!ordered.defer_route())return 94;}
        else if(ordered.defer_route() || ordered.deferred_count()!=8 || !ordered.pending_route())return 95;
    }
    if(!ordered.begin_deferred_replay())return 96;
    for(unsigned i=0;i<9;++i) {
        if(!ordered.replay_deferred())return 97;
        auto item=ordered.pending_route();auto source=ordered.pending_route_source();
        if(!item || !source || !source->port || item->data.size()!=2 || item->data[1]!='0'+i)return 98;
        auto metadata=ordered.route_metadata();
        if(!metadata || metadata->deadline!=deferred_deadlines[i] || !metadata->quic_inspected || metadata->quic_domain)return 129;
        ordered.discard_route();
    }
    if(ordered.replay_deferred() || ordered.deferred_count() || ordered.deferred_bytes())return 99;
    ordered.close();
    if(auto error=lookahead_test(client.fd,*policy,wire))return error;
    std::println("SOCKS UDP ingress forwards and filters real datagrams");
}
