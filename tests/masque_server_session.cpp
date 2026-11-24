module;
#include <poll.h>
#include <unistd.h>
import std;
import crypto;
import masque.session;
import masque.server;
import masque.bearer;
import masque.udp_owner;
import net.udp_socket;
import http.header;
import masque.target;
import masque.http3;
import quic.connection;
import quic.http3;
import masque.datagram;
import masque.udp_session;
import quic.tls_client;
import quic.tls_server;
import tls.server_credential;
import ngtcp2;
import nghttp3;
import test.quic_tls_link;
namespace m=masque;
namespace n = ::ngtcp2;
namespace h = ::nghttp3;
namespace q=quic;
namespace t=tls;
namespace support=test::quic_tls;
using View=std::span<std::uint8_t const>;
extern "C" int nghttp3_conn_set_client_stream_priority(h::nghttp3_conn*,std::int64_t,std::uint8_t const*,std::size_t);
struct Packet {std::uint64_t stream=0;View payload;};
struct Hooks {
    bool server=false,ready=false,ready_second=false,headers_done=false,second_headers=false,shutdown_seen=false;
    std::vector<std::pair<std::string,std::string>> fields;
    std::vector<std::uint8_t> outbound,received,received_second,capsule_out,capsule_received;
    m::UdpCapsules<1200> capsules;
    bool capsule_submitted=false,close_output=false;std::uint64_t capsule_acked=0;
    std::optional<std::pair<std::int64_t,std::uint64_t>> abort;
    auto changed() noexcept -> void {}
    auto h3_closed() noexcept -> void {}
    auto transport_closed() noexcept -> void {ready=false;}
    auto stream_capacity() const noexcept -> std::size_t {return 16;}
    auto stream_state(std::uint64_t id) noexcept -> m::Http3StreamState {
        return ((id==0 && ready) || (id==4 && ready_second)) ? m::Http3StreamState{m::Http3StreamKind::datagram,true,true} : m::Http3StreamState{};
    }
    auto datagram(std::uint64_t id,View packet) -> int {
        if((id==0 && !ready) || (id==4 && !ready_second) || (id!=0 && id!=4))return n::err_callback_failure;
        auto parsed=m::parse_proxy_datagram(packet,true);if(!parsed) {if(id==0)ready=false;else ready_second=false;abort=std::pair{static_cast<std::int64_t>(id),std::uint64_t{0x33}};return 0;}
        if(parsed->context_id)return 0;
        auto& target=id==0 ? received : received_second;target.assign(parsed->payload.begin(),parsed->payload.end());return 0;
    }
    auto datagram_output() -> std::optional<Packet> {if(outbound.empty())return {};return Packet{0,outbound};}
    auto datagram_accepted() -> void {outbound.clear();}
    auto datagram_rejected() -> void {outbound.clear();}
    auto datagram_budget() const noexcept -> std::size_t {return 1150;}
    auto closed(std::int64_t id,std::uint64_t,std::uint64_t) noexcept -> void {if(id==0)ready=false;else ready_second=false;}
    auto receive_closed(std::int64_t id,std::uint64_t) noexcept -> void {if(id==0)ready=false;else ready_second=false;}
    auto send_closed(std::int64_t id,std::uint64_t) noexcept -> void {if(id==0)ready=false;else ready_second=false;}
    auto begin_headers(std::int64_t id,bool trailers) -> int {if(id<0 || (id&3) || trailers)return h::err_callback_failure;fields.clear();return 0;}
    auto header(std::int64_t,h::nghttp3_rcbuf* key,h::nghttp3_rcbuf* value,bool) -> int {
        auto a=h::nghttp3_rcbuf_get_buf(key),b=h::nghttp3_rcbuf_get_buf(value);
        if(fields.size()>=16 || a.len+b.len>1024)return h::err_callback_failure;
        fields.emplace_back(std::string(reinterpret_cast<char const*>(a.base),a.len),std::string(reinterpret_cast<char const*>(b.base),b.len));return 0;
    }
    auto end_headers(std::int64_t id,bool fin,bool trailers) -> int {
        if(fin || trailers)return h::err_callback_failure;
        if(id==0)headers_done=true;else second_headers=true;
        if(!server)for(auto const& [key,value]:fields)if(key==":status" && value=="200") {if(id==0)ready=true;else ready_second=true;}
        return 0;
    }
    auto data(std::int64_t id,View bytes) -> int {
        auto result=capsules.feed(bytes,[&](auto packet){if(ready)capsule_received.assign(packet.begin(),packet.end());});
        if(result==m::UdpInput::malformed || result==m::UdpInput::too_large) {ready=false;abort=std::pair{id,std::uint64_t{0x10e}};}
        return 0;
    }
    auto take_abort() noexcept -> std::optional<std::pair<std::int64_t,std::uint64_t>> {return std::exchange(abort,{});}
    auto data_acked(std::int64_t,std::uint64_t count) -> int {capsule_acked+=count;return 0;}
    auto end_stream(std::int64_t id) -> int {
        if(id!=0) {ready_second=false;return 0;}
        auto result=capsules.finish([&](auto packet){if(ready)capsule_received.assign(packet.begin(),packet.end());});ready=false;
        if(result==m::UdpInput::malformed || result==m::UdpInput::too_large)abort=std::pair{id,std::uint64_t{0x10e}};
        return 0;
    }
    auto shutdown(std::int64_t) -> int {shutdown_seen=true;return 0;}
    auto read_data(std::int64_t,std::span<h::nghttp3_vec> output,std::uint32_t& flags) -> h::nghttp3_ssize {
        if(close_output && capsule_out.empty()) {flags=h::data_flag_eof;return 0;}
        if(capsule_submitted || capsule_out.empty() || output.empty())return h::err_wouldblock;
        output[0]={capsule_out.data(),capsule_out.size()};capsule_submitted=true;flags=h::data_flag_none;return 1;
    }
};
static h::nghttp3_mem const h3_memory{nullptr,
    [](std::size_t size,void*) -> void* {return std::malloc(size);},
    [](void* p,void*) {std::free(p);},
    [](std::size_t n,std::size_t s,void*) -> void* {return std::calloc(n,s);},
    [](void* p,std::size_t size,void*) -> void* {return std::realloc(p,size);}};
template<class Tls> struct Peer {
    support::Memory memory;support::Path path;Hooks hooks;
    m::Session<Tls,Hooks> app;q::Connection<Tls,m::Session<Tls,Hooks>> connection;
    Peer(Tls& tls,bool server):path(server),hooks{.server=server},app(tls,hooks,server,h3_memory),connection(tls,app) {app.attach(connection);}
    ~Peer(){stop();}
    auto stop() noexcept -> void {app.request_stop();app.joined();connection.stop();app.drain();}
};
template<class Sender,class Receiver> auto transfer(Sender& sender,Receiver& receiver,std::uint64_t& now) -> int {
    std::array<std::uint8_t,1500> output{};
    auto result=sender.app.output(output,now);if(!result)return result.error();
    if(*result) {receiver.app.time(now+=1000000);auto e=receiver.connection.read(receiver.path.value,nullptr,std::span(output).first(*result),now);if(e)std::println("receive server={} e={} h3={} abort={}",receiver.hooks.server,e,receiver.app.h3().terminal_error(),receiver.hooks.abort.has_value());return e;}
    return 0;
}
template<class Client,class Server> auto pump(Client& client,Server& server,std::uint64_t& now,unsigned rounds) -> int {
    for(unsigned i=0;i<rounds;++i) {
        now+=1000000;
        if(auto error=transfer(client,server,now))return error;
        if(auto error=transfer(server,client,now))return error;
        for(auto* connection:{client.connection.native(),server.connection.native()})if(n::ngtcp2_conn_get_expiry2(connection)<=now)
            if(auto error=n::ngtcp2_conn_handle_expiry(connection,now))return error;
    }
    return 0;
}
auto field(std::string_view name,std::string_view value) -> h::nghttp3_nv {
    return {reinterpret_cast<std::uint8_t const*>(name.data()),reinterpret_cast<std::uint8_t const*>(value.data()),name.size(),value.size(),h::nv_flag_none};
}

struct TargetPolicy {
    unsigned wakes=0;
    auto changed() noexcept -> void {++wakes;}
    auto allow(m::UdpTarget const& target,net::UdpEndpoint endpoint) noexcept -> bool {
        return target.host=="localhost" && target.port==endpoint.port && endpoint.family==4 && endpoint.address[0]==127 && endpoint.address[3]==1;
    }
};
template<class Tls> struct ServerPeer {
    support::Memory memory;support::Path path{true};TargetPolicy target;
    m::BearerPolicy<TargetPolicy> policy;
    m::UdpServer<Tls,m::BearerPolicy<TargetPolicy>> server;
    q::Connection<Tls,typename m::UdpServer<Tls,m::BearerPolicy<TargetPolicy>>::Application> connection;
    static auto credential() -> m::BearerCredential {
        constexpr std::string_view value="approved";
        return std::move(*m::BearerCredential::create({reinterpret_cast<std::uint8_t const*>(value.data()),value.size()}));
    }
    ServerPeer(Tls& tls):policy(credential(),target),server(tls,policy,"localhost",h3_memory),connection(tls,server.application()){server.attach(connection);}
    ~ServerPeer(){stop();}
    auto stop() noexcept -> void {server.stop();server.joined();connection.stop();server.drain();}
};
template<class Server> auto pump_sockets(Server& server) -> bool {
    for(auto const& entry:server.sockets()) {
        if(!entry)continue;
        pollfd pfd{entry->second,POLLIN,0};
        if(::poll(&pfd,1,0)<=0)continue;
        if(pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {if(!server.socket_failed(entry->first,entry->second))return false;}
        else if(pfd.revents & POLLIN) {if(!server.ready_socket(entry->first,entry->second))return false;}
    }
    return true;
}
template<class Server> auto next_pending(Server& server) -> std::optional<typename Server::Route> {
    for(std::size_t slot=0;slot<server.stream_capacity();++slot)if(auto route=server.pending(slot))return route;
    return {};
}
template<class Client,class Server> auto pump_server(Client& client,Server& server,std::uint64_t& now,unsigned rounds) -> int {
    for(unsigned i=0;i<rounds;++i) {
        now+=1000000;std::array<std::uint8_t,1500> bytes{};
        auto a=client.app.output(bytes,now);if(!a)return a.error();
        if(*a){server.server.application().time(now+=1000000);if(auto e=server.connection.read(server.path.value,nullptr,std::span(bytes).first(*a),now))return e;}
        if(!pump_sockets(server.server))return -999;auto b=server.server.application().output(bytes,now);if(!b)return b.error();
        if(*b){client.app.time(now+=1000000);if(auto e=client.connection.read(client.path.value,nullptr,std::span(bytes).first(*b),now))return e;}
        for(auto* c:{client.connection.native(),server.connection.native()})if(n::ngtcp2_conn_get_expiry2(c)<=now)if(auto e=n::ngtcp2_conn_handle_expiry(c,now))return e;
    }
    return 0;
}
auto scenario(t::ServerCredential const& credential,View cert) -> int {
    net::UdpSocket echo;net::UdpEndpoint local{4,{127,0,0,1},0};if(!echo.bind(local))return 1;auto target=echo.local_endpoint();if(!target)return 2;
    q::TlsClient client_tls(support::hello(*credential.scheme()),29,support::Pki{cert},"h3");q::TlsServer server_tls(credential,"h3");
    Peer client(client_tls,false);ServerPeer server(server_tls);
    auto cp=support::parameters(false),sp=support::parameters(true);cp.max_datagram_frame_size=sp.max_datagram_frame_size=1200;
    if(client.connection.start(false,support::cid(0x83),support::cid(0),client.path.value,support::settings(),cp,client.memory.transport()) ||
       server.connection.start(true,support::cid(0),support::cid(0xf0),server.path.value,support::settings(),sp,server.memory.transport()))return 3;
    std::uint64_t now=2;for(unsigned i=0;i<300 && !client.app.can_open();++i)if(pump_server(client,server,now,1))return 4;
    if(!client.app.can_open())return 5;
    std::int64_t id=-1;if(n::ngtcp2_conn_open_bidi_stream(client.connection.native(),&id,nullptr) || id)return 6;
    std::string path=std::format("/.well-known/masque/udp/localhost/{}/",target->port);
    std::array request{field(":method","CONNECT"),field(":protocol","connect-udp"),field(":scheme","https"),field(":authority","localhost"),field(":path",path),field("proxy-authorization","Bearer approved")};
    if(client.app.h3().request(id,request,true))return 7;
    std::optional<typename decltype(server.server)::Route> route;
    for(unsigned i=0;i<300 && !route;++i){if(pump_server(client,server,now,1))return 8;route=next_pending(server.server);}
    if(!route || route->host!="localhost" || route->port!=target->port || client.hooks.ready)return 9;
    if(!server.server.resolved(route->handle,*target))return 10;
    for(unsigned i=0;i<300 && !client.hooks.ready;++i)if(pump_server(client,server,now,1))return 11;
    if(!client.hooks.ready)return 12;
    client.hooks.outbound={0,3,4,5};std::array<std::uint8_t,100> input{};std::optional<net::UdpPacket> incoming;
    for(unsigned i=0;i<500 && !incoming;++i){if(pump_server(client,server,now,1))return 13;auto value=echo.receive(input);if(!value)return 14;incoming=*value;}
    if(!incoming || incoming->size!=3 || !incoming->valid || input[0]!=3 || input[2]!=5)return 15;
    if(!echo.send(incoming->source,std::span(input).first(3)))return 16;
    for(unsigned i=0;i<500 && client.hooks.capsule_received.empty();++i)if(pump_server(client,server,now,1))return 17;
    if(client.hooks.capsule_received!=std::vector<std::uint8_t>{3,4,5})return 18;
    // The request's clean FIN closes only client-to-proxy transmission.
    // The same socket must still forward a later UDP reply via H3 DATA.
    client.hooks.close_output=true;if(client.app.h3().resume(id))return 21;
    for(unsigned i=0;i<300 && server.server.stream_state(0).receive_open;++i)if(pump_server(client,server,now,1))return 22;
    auto half=server.server.stream_state(0);if(half.receive_open || !half.send_open || !server.server.socket_handle(route->handle))return 23;
    client.hooks.capsule_received.clear();std::array<std::uint8_t,2> late{8,9};if(!echo.send(incoming->source,late))return 24;
    for(unsigned i=0;i<500 && client.hooks.capsule_received.empty();++i)if(pump_server(client,server,now,1))return 25;
    if(client.hooks.capsule_received!=std::vector<std::uint8_t>{8,9})return 26;
    // Dead socket fault with no new incoming application data: poll must
    // flush RESET, release the failed stream, and allow a new request.
    auto fd=server.server.socket_handle(route->handle);if(!fd || ::close(*fd))return 27;
    if(!pump_sockets(server.server))return 28;
    for(unsigned i=0;i<300 && client.hooks.ready;++i)if(pump_server(client,server,now,1))return 29;
    if(client.hooks.ready || !client.connection.active() || !server.connection.active())return 30;
    client.hooks.close_output=false;
    std::int64_t next=-1;if(n::ngtcp2_conn_open_bidi_stream(client.connection.native(),&next,nullptr) || next!=4)return 31;
    if(client.app.h3().request(next,request,true))return 32;
    std::optional<typename decltype(server.server)::Route> route2;
    for(unsigned i=0;i<300 && !route2;++i){if(pump_server(client,server,now,1))return 33;route2=next_pending(server.server);}
    if(!route2 || !server.server.resolved(route2->handle,*target))return 34;
    for(unsigned i=0;i<300 && !client.hooks.ready_second;++i)if(pump_server(client,server,now,1))return 35;
    if(!client.hooks.ready_second)return 36;
    // Cycle enough client-initiated streams to exceed the initial window of
    // 16, then send PRIORITY_UPDATE for the next legal stream. H3 and QUIC
    // must agree on the cumulative client stream limit after every close.
    for(unsigned index=2;index<19;++index) {
        if(n::ngtcp2_conn_shutdown_stream(client.connection.native(),0,next,0x10c))return 37;
        for(unsigned k=0;k<80;++k)if(pump_server(client,server,now,1))return 38;
        next=-1;if(n::ngtcp2_conn_open_bidi_stream(client.connection.native(),&next,nullptr) || next!=static_cast<std::int64_t>(index*4))return 39;
        client.hooks.ready_second=false;
        if(client.app.h3().request(next,request,true))return 40;
        if(index>=16) {
            constexpr std::array<std::uint8_t,3> priority{'u','=','3'};
            if(nghttp3_conn_set_client_stream_priority(client.app.h3().native(),next,priority.data(),priority.size()))return 41;
        }
        route2.reset();
        for(unsigned k=0;k<300 && !route2;++k){if(pump_server(client,server,now,1))return 42;route2=next_pending(server.server);}
        if(!route2 || !server.server.resolved(route2->handle,*target))return 43;
        for(unsigned k=0;k<300 && !client.hooks.ready_second;++k)if(pump_server(client,server,now,1))return 44;
        if(!client.hooks.ready_second || !server.connection.active())return 45;
    }
    server.stop();if(server.server.resolved(route->handle,*target))return 19;
    client.stop();server.stop();if(!client.app.clean() || !server.server.clean() || client.memory.used || server.memory.used)return 20;
    return 0;
}
auto main(int argc,char** argv) -> int {
    if(argc!=3)return 1;auto cert=support::read(argv[1]),key=support::read(argv[2]);
    auto credential=t::ServerCredential::create(cert,key);::crypto::cleanse(key);if(!credential)return 2;
    if(auto result=scenario(*credential,cert)){std::println("server owner failure {}",result);return 3;}
    std::println("authenticated CONNECT-UDP server owner and echo passed");
}
