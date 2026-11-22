import std;
import crypto;
import masque.session;
import masque.http3;
import quic.connection;
import quic.http3;
import masque.datagram;
import masque.udp_session;
import masque.ip_receiver;
import masque.ip_control;
import masque.ip_packet;
import masque.connect_ip;
import http.header;
import quic.tls_client;
import quic.tls_server;
import tls.server_credential;
import nexus.thirdparty.ngtcp2;
import nexus.thirdparty.nghttp3;
import nexus.test.quic_tls_link;
namespace m=masque;
namespace n=nex::ngtcp2;
namespace h=nex::nghttp3;
namespace q=quic;
namespace t=tls;
namespace support=nexus::test::quic_tls;
using View=std::span<std::uint8_t const>;
struct Packet {std::uint64_t stream=0;View payload;};
struct IpSink {
    unsigned assignments=0,requests=0,packets=0,dropped=0;std::size_t address_count=0;std::uint8_t packet_byte=0;bool validate_packets=false;
    m::AddressEntry source{0,4,24,{192,0,2,0}};
    m::AddressEntry target{0,4,24,{198,51,100,0}};
    m::RouteEntry route{4,17,{198,51,0,0},{198,51,255,255}};
    std::optional<std::uint8_t> scope_protocol=17;
    auto assigned(std::span<m::AddressEntry const> addresses) noexcept -> bool {++assignments;address_count=addresses.size();return true;}
    auto routes(std::span<m::RouteEntry const>) noexcept -> bool {return true;}
    auto requested(std::span<m::AddressEntry const>) noexcept -> bool {++requests;return true;}
    auto packet(View packet) noexcept -> void {
        if(validate_packets) {
            auto view=m::inspect_ip_packet(packet);
            m::IpRequestScope scope{std::span(&target,1),false,scope_protocol};
            m::IpAdvertisedPolicy policy{std::span(&source,1),std::span(&route,1),scope};
            if(!view || !m::ip_permitted_by_advertisements(*view,policy)) {++dropped;return;}
        }
        ++packets;packet_byte=packet.empty() ? 0 : packet.back();
    }
};
struct Hooks {
    bool server=false,ready=false,ready_second=false,headers_done=false,second_headers=false,shutdown_seen=false;
    bool ip_mode=false;IpSink ip_sink;m::IpReceiver<IpSink,1200,8,8,8> ip{ip_sink};
    std::vector<std::pair<std::string,std::string>> fields;
    std::vector<std::uint8_t> outbound,received,received_second,capsule_out,capsule_received;
    m::UdpCapsules<1200> capsules;
    bool capsule_submitted=false;std::uint64_t capsule_acked=0;
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
        if(ip_mode) {if(ip.datagram(packet)!=m::IpReceiveStatus::active) {ready=false;abort=std::pair{static_cast<std::int64_t>(id),std::uint64_t{0x33}};}return 0;}
        auto parsed=m::parse_proxy_datagram(packet,true);if(!parsed) {if(id==0)ready=false;else ready_second=false;abort=std::pair{static_cast<std::int64_t>(id),std::uint64_t{0x33}};return 0;}
        if(parsed->context_id)return 0;
        auto& target=id==0 ? received : received_second;target.assign(parsed->payload.begin(),parsed->payload.end());return 0;
    }
    auto datagram_output() -> std::optional<Packet> {if(outbound.empty())return {};return Packet{0,outbound};}
    auto datagram_accepted() -> void {outbound.clear();}
    auto datagram_rejected() -> void {outbound.clear();}
    auto datagram_budget() const noexcept -> std::size_t {return 1150;}
    auto closed(std::int64_t id,std::uint64_t,std::uint64_t) noexcept -> void {if(id==0)ready=false;else if(id==4)ready_second=false;}
    auto receive_closed(std::int64_t id,std::uint64_t) noexcept -> void {if(id==0)ready=false;else if(id==4)ready_second=false;}
    auto send_closed(std::int64_t id,std::uint64_t) noexcept -> void {if(id==0)ready=false;else if(id==4)ready_second=false;}
    auto begin_headers(std::int64_t id,bool trailers) -> int {if((id!=0 && id!=4) || trailers)return h::err_callback_failure;fields.clear();return 0;}
    auto header(std::int64_t,h::nghttp3_rcbuf* key,h::nghttp3_rcbuf* value,bool) -> int {
        auto a=h::nghttp3_rcbuf_get_buf(key),b=h::nghttp3_rcbuf_get_buf(value);
        if(fields.size()>=16 || a.len+b.len>1024)return h::err_callback_failure;
        fields.emplace_back(std::string(reinterpret_cast<char const*>(a.base),a.len),std::string(reinterpret_cast<char const*>(b.base),b.len));return 0;
    }
    auto end_headers(std::int64_t id,bool fin,bool trailers) -> int {
        if(fin || trailers)return h::err_callback_failure;
        if(ip_mode) {
            std::array<http::HeaderField,16> decoded{};
            for(std::size_t i=0;i<fields.size();++i)decoded[i]={fields[i].first,fields[i].second};
            auto headers=std::span(decoded).first(fields.size());
            if(server) {
                auto request=m::parse_connect_ip_request(headers);
                if(!request || request->scheme!="https" || request->authority!="localhost")return h::err_callback_failure;
                auto scope=m::parse_default_ip_path(request->path);
                if(!scope || scope->kind!=m::IpTargetKind::prefix)return h::err_callback_failure;
                ip_sink.target=scope->prefix;ip_sink.scope_protocol=scope->protocol;
            } else if(!m::parse_connect_ip_response(headers))return h::err_callback_failure;
        }
        if(id==0)headers_done=true;else second_headers=true;
        if(!server)for(auto const& [key,value]:fields)if(key==":status" && value=="200") {if(id==0)ready=true;else ready_second=true;}
        return 0;
    }
    auto data(std::int64_t id,View bytes) -> int {
        if(ip_mode) {if(ip.feed(bytes).status!=m::IpReceiveStatus::active) {ready=false;abort=std::pair{id,std::uint64_t{0x10e}};}return 0;}
        auto result=capsules.feed(bytes,[&](auto packet){if(ready)capsule_received.assign(packet.begin(),packet.end());});
        if(result==m::UdpInput::malformed || result==m::UdpInput::too_large) {ready=false;abort=std::pair{id,std::uint64_t{0x10e}};}
        return 0;
    }
    auto take_abort() noexcept -> std::optional<std::pair<std::int64_t,std::uint64_t>> {return std::exchange(abort,{});}
    auto data_acked(std::int64_t,std::uint64_t count) -> int {capsule_acked+=count;return 0;}
    auto end_stream(std::int64_t id) -> int {
        if(ip_mode) {auto status=ip.finish();ready=false;if(status!=m::IpReceiveStatus::closed)abort=std::pair{id,std::uint64_t{0x10e}};return 0;}
        auto result=capsules.finish([&](auto packet){if(ready)capsule_received.assign(packet.begin(),packet.end());});ready=false;
        if(result==m::UdpInput::malformed || result==m::UdpInput::too_large)abort=std::pair{id,std::uint64_t{0x10e}};
        return 0;
    }
    auto shutdown(std::int64_t) -> int {shutdown_seen=true;return 0;}
    auto read_data(std::int64_t,std::span<h::nghttp3_vec> output,std::uint32_t& flags) -> h::nghttp3_ssize {
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
auto scenario(t::ServerCredential const& credential,View cert,bool bad_datagram) -> int {
    q::TlsClient client_tls(support::hello(*credential.scheme()),29,support::Pki{cert},"h3");
    q::TlsServer server_tls(credential,"h3");Peer client(client_tls,false);Peer server(server_tls,true);
    auto client_params=support::parameters(false),server_params=support::parameters(true);
    client_params.max_datagram_frame_size=server_params.max_datagram_frame_size=1200;
    auto error=client.connection.start(false,support::cid(0x83),support::cid(0),client.path.value,support::settings(),client_params,client.memory.transport());
    if(!error)error=server.connection.start(true,support::cid(0),support::cid(0xf0),server.path.value,support::settings(),server_params,server.memory.transport());
    if(error)return 1;std::uint64_t now=2;
    for(unsigned i=0;i<200 && !client.app.can_open();++i)if(pump(client,server,now,1))return 2;
    if(!client.app.can_open())return 3;
    std::int64_t id=-1;if(n::ngtcp2_conn_open_bidi_stream(client.connection.native(),&id,nullptr) || id)return 4;
    std::array request{field(":method","CONNECT"),field(":protocol","connect-udp"),field(":scheme","https"),field(":authority","localhost"),field(":path","/.well-known/masque/udp/127.0.0.1/443/"),field("capsule-protocol","?1")};
    if(client.app.h3().request(id,request,true))return 5;
    for(unsigned i=0;i<200 && !server.hooks.headers_done;++i)if(pump(client,server,now,1))return 6;
    if(!server.hooks.headers_done)return 7;
    // Fixture policy admits only this fixed request; this is not a real UDP endpoint.
    bool method=false,path=false;
    for(auto const& [key,value]:server.hooks.fields){method|=key==":protocol" && value=="connect-udp";path|=key==":path" && value=="/.well-known/masque/udp/127.0.0.1/443/";}
    if(!method || !path)return 8;server.hooks.ready=true;
    std::array response{field(":status","200"),field("capsule-protocol","?1")};
    if(server.app.h3().response(id,response,true))return 9;
    for(unsigned i=0;i<200 && !client.hooks.ready;++i)if(pump(client,server,now,1))return 10;
    if(!client.hooks.ready)return 11;
    client.hooks.outbound={0,1,2,3};
    for(unsigned i=0;i<300 && server.hooks.received.empty();++i)if(pump(client,server,now,1))return 12;
    if(server.hooks.received!=std::vector<std::uint8_t>{1,2,3})return 13;
    server.hooks.outbound={0,4,5};
    for(unsigned i=0;i<300 && client.hooks.received.empty();++i)if(pump(client,server,now,1))return 14;
    if(client.hooks.received!=std::vector<std::uint8_t>{4,5})return 15;
    client.hooks.capsule_out={0,4,0,7,8,9};
    if(client.app.h3().resume(id))return 17;
    for(unsigned i=0;i<300 && (server.hooks.capsule_received.empty() || !client.hooks.capsule_acked);++i)if(pump(client,server,now,1))return 18;
    if(server.hooks.capsule_received!=std::vector<std::uint8_t>{7,8,9} || client.hooks.capsule_acked!=6)return 19;
    server.hooks.capsule_out={0,3,0,42,43};
    if(server.app.h3().resume(id))return 20;
    for(unsigned i=0;i<300 && (client.hooks.capsule_received.empty() || !server.hooks.capsule_acked);++i)if(pump(client,server,now,1))return 21;
    if(client.hooks.capsule_received!=std::vector<std::uint8_t>{42,43} || server.hooks.capsule_acked!=5) {std::println("reverse capsule bytes={} ack={} submitted={} ready={}",client.hooks.capsule_received.size(),server.hooks.capsule_acked,server.hooks.capsule_submitted,client.hooks.ready);return 22;}
    if(bad_datagram) {
        std::int64_t second=-1;if(n::ngtcp2_conn_open_bidi_stream(client.connection.native(),&second,nullptr) || second!=4)return 27;
        if(client.app.h3().request(second,request,true))return 28;
        for(unsigned i=0;i<200 && !server.hooks.second_headers;++i)if(pump(client,server,now,1))return 29;
        if(!server.hooks.second_headers)return 30;
        server.hooks.ready_second=true;if(server.app.h3().response(second,response,true))return 31;
        for(unsigned i=0;i<200 && !client.hooks.ready_second;++i)if(pump(client,server,now,1))return 32;
        if(!client.hooks.ready_second)return 33;
        // ngtcp2 MORE produces one actual encrypted QUIC packet with three
        // DATAGRAM frames: bad context on stream 0, then valid stream 0,
        // then valid stream 4. The first must revoke stream 0 synchronously.
        std::array<std::uint8_t,1500> packet{};
        std::array<std::array<std::uint8_t,3>,3> frames{{{{0,0xc0,0}},{{0,0,99}},{{1,0,77}}}};
        std::array<std::size_t,3> sizes{2,3,3};std::ptrdiff_t written=0;
        for(std::size_t i=0;i<frames.size();++i) {
            n::ngtcp2_vec vec{frames[i].data(),sizes[i]};int accepted=0;
            written=n::ngtcp2_conn_writev_datagram_versioned(client.connection.native(),nullptr,n::pkt_info_version,nullptr,packet.data(),packet.size(),&accepted,i<2 ? 1u : 0u,0,&vec,1,now);
            if(!accepted || (i<2 ? written!=-230 : written<=0))return 34;
        }
        server.app.time(now+=1000000);
        if(auto error=server.connection.read(server.path.value,nullptr,std::span(packet).first(written),now)) {std::println("coalesced packet read error {}",error);return 35;}
        if(server.hooks.ready || !server.hooks.ready_second || server.hooks.received!=std::vector<std::uint8_t>{1,2,3} || server.hooks.received_second!=std::vector<std::uint8_t>{77})return 36;
        if(pump(client,server,now,30) || !client.connection.active() || !server.connection.active() || !server.hooks.ready_second)return 37;
        client.stop();server.stop();
        if(!client.app.clean() || !server.app.clean() || client.memory.used || server.memory.used)return 38;
        return 0;
    }
    // An empty DATAGRAM Capsule lacks its required Context ID. Only its
    // request stream is aborted; the enclosing QUIC connection stays live.
    client.hooks.capsule_out={0,0};client.hooks.capsule_submitted=false;if(client.app.h3().resume(id))return 23;
    for(unsigned i=0;i<300 && server.hooks.ready;++i)if(auto e=pump(client,server,now,1)) {std::println("malformed datagram={} pump={} client-app={} server-app={}",bad_datagram,e,client.app.application_error(),server.app.application_error());return 24;}
    if(server.hooks.ready || !client.connection.active() || !server.connection.active())return 25;
    if(pump(client,server,now,30) || !client.connection.active() || !server.connection.active())return 26;
    client.stop();server.stop();
    if(!client.app.clean() || !server.app.clean() || client.memory.used || server.memory.used)return 16;
    return 0;
}
auto ip_checksum(std::span<std::uint8_t> packet) -> void {
    packet[10]=packet[11]=0;
    std::uint32_t sum=0;for(std::size_t i=0;i<20;i+=2)sum+=(std::uint32_t(packet[i])<<8)|packet[i+1];
    while(sum>>16)sum=(sum&0xffff)+(sum>>16);auto check=static_cast<std::uint16_t>(~sum);packet[10]=check>>8;packet[11]=check;
}
auto ip_packet(std::uint8_t source_octet,std::uint8_t payload) -> std::vector<std::uint8_t> {
    std::vector<std::uint8_t> packet(29);packet[0]=0x45;packet[3]=packet.size();packet[8]=64;packet[9]=17;
    packet[12]=192;packet[14]=source_octet;packet[15]=1;packet[16]=198;packet[17]=51;packet[18]=100;packet[19]=42;
    packet[20]=0x12;packet[21]=0x34;packet[23]=53;packet[25]=9;packet[28]=payload;
    ip_checksum(packet);
    return packet;
}
auto append_ip_capsule(std::vector<std::uint8_t>& output,View packet) -> void {
    output.push_back(0);output.push_back(static_cast<std::uint8_t>(packet.size()+1));output.push_back(0);
    output.insert(output.end(),packet.begin(),packet.end());
}
auto ip_scenario(t::ServerCredential const& credential,View cert) -> int {
    q::TlsClient client_tls(support::hello(*credential.scheme()),29,support::Pki{cert},"h3");
    q::TlsServer server_tls(credential,"h3");Peer client(client_tls,false);Peer server(server_tls,true);
    client.hooks.ip_mode=server.hooks.ip_mode=true;server.hooks.ip_sink.validate_packets=true;
    auto cp=support::parameters(false),sp=support::parameters(true);
    cp.max_datagram_frame_size=sp.max_datagram_frame_size=1200;
    auto error=client.connection.start(false,support::cid(0x83),support::cid(0),client.path.value,support::settings(),cp,client.memory.transport());
    if(!error)error=server.connection.start(true,support::cid(0),support::cid(0xf0),server.path.value,support::settings(),sp,server.memory.transport());
    if(error)return 1;std::uint64_t now=2;
    for(unsigned i=0;i<200 && !client.app.can_open();++i)if(pump(client,server,now,1))return 2;
    if(!client.app.can_open())return 3;
    std::int64_t id=-1;if(n::ngtcp2_conn_open_bidi_stream(client.connection.native(),&id,nullptr) || id)return 4;
    m::ConnectIpScope scope;scope.kind=m::IpTargetKind::prefix;scope.prefix={0,4,24,{198,51,100,0}};scope.protocol=17;
    auto path=m::write_default_ip_path(scope);if(!path)return 27;
    std::array request{field(":method","CONNECT"),field(":protocol","connect-ip"),field(":scheme","https"),field(":authority","localhost"),field(":path",*path),field("capsule-protocol","?1")};
    if(client.app.h3().request(id,request,true))return 5;
    for(unsigned i=0;i<200 && !server.hooks.headers_done;++i)if(pump(client,server,now,1))return 6;
    if(!server.hooks.headers_done)return 7;
    // This fixture admits a fixed request; it does not install routes.
    server.hooks.ready=true;
    std::array response{field(":status","200"),field("capsule-protocol","?1")};
    if(server.app.h3().response(id,response,true))return 8;
    for(unsigned i=0;i<200 && !client.hooks.ready;++i)if(pump(client,server,now,1))return 9;
    if(!client.hooks.ready)return 10;
    auto valid=ip_packet(2,55);client.hooks.capsule_out={2,7,1,4,192,0,2,0,24};append_ip_capsule(client.hooks.capsule_out,valid);
    if(client.app.h3().resume(id))return 11;
    for(unsigned i=0;i<300 && (server.hooks.ip_sink.requests!=1 || server.hooks.ip_sink.packets!=1 || client.hooks.capsule_acked<41);++i)if(pump(client,server,now,1))return 12;
    if(server.hooks.ip_sink.requests!=1 || server.hooks.ip_sink.packets!=1 || server.hooks.ip_sink.packet_byte!=55 || client.hooks.capsule_acked!=41)return 13;
    server.hooks.capsule_out={1,7,1,4,192,0,2,0,24};
    if(server.app.h3().resume(id))return 14;
    for(unsigned i=0;i<300 && (client.hooks.ip_sink.assignments!=1 || server.hooks.capsule_acked<9);++i)if(pump(client,server,now,1))return 15;
    if(client.hooks.ip_sink.assignments!=1 || client.hooks.ip_sink.address_count!=1 || server.hooks.capsule_acked!=9)return 16;
    valid=ip_packet(2,77);client.hooks.outbound={0};client.hooks.outbound.insert(client.hooks.outbound.end(),valid.begin(),valid.end());
    for(unsigned i=0;i<300 && server.hooks.ip_sink.packets<2;++i)if(pump(client,server,now,1))return 17;
    if(server.hooks.ip_sink.packets!=2 || server.hooks.ip_sink.packet_byte!=77)return 18;
    auto outside=ip_packet(2,78);outside[18]=101;ip_checksum(outside);
    client.hooks.outbound={0};client.hooks.outbound.insert(client.hooks.outbound.end(),outside.begin(),outside.end());
    for(unsigned i=0;i<300 && !server.hooks.ip_sink.dropped;++i)if(pump(client,server,now,1))return 28;
    if(server.hooks.ip_sink.dropped!=1 || server.hooks.ip_sink.packets!=2)return 29;
    auto denied=ip_packet(3,88);client.hooks.capsule_out.clear();append_ip_capsule(client.hooks.capsule_out,denied);client.hooks.capsule_submitted=false;
    if(client.app.h3().resume(id))return 19;
    for(unsigned i=0;i<300 && (server.hooks.ip_sink.dropped!=2 || client.hooks.capsule_acked<73);++i)if(pump(client,server,now,1))return 24;
    if(server.hooks.ip_sink.dropped!=2 || server.hooks.ip_sink.packets!=2 || client.hooks.capsule_acked!=73)return 25;
    // Duplicate request ID aborts this request before a subsequent capsule.
    valid=ip_packet(2,99);client.hooks.capsule_out={2,7,1,4,192,0,2,0,24};append_ip_capsule(client.hooks.capsule_out,valid);client.hooks.capsule_submitted=false;
    if(client.app.h3().resume(id))return 26;
    for(unsigned i=0;i<300 && server.hooks.ready;++i)if(pump(client,server,now,1))return 20;
    if(server.hooks.ready || server.hooks.ip_sink.requests!=1 || server.hooks.ip_sink.packets!=2 || !client.connection.active() || !server.connection.active())return 21;
    if(pump(client,server,now,30) || !client.connection.active() || !server.connection.active())return 22;
    client.stop();server.stop();
    if(!client.app.clean() || !server.app.clean() || client.memory.used || server.memory.used)return 23;
    return 0;
}
auto main(int argc,char** argv) -> int {
    if(argc!=3)return 1;
    auto cert=support::read(argv[1]),key=support::read(argv[2]);auto credential=t::ServerCredential::create(cert,key);::crypto::cleanse(key);if(!credential)return 2;
    for(bool bad_datagram:{false,true})if(auto result=scenario(*credential,cert,bad_datagram)) {std::println("MASQUE session scenario bad_datagram={} failed {}",bad_datagram,result);return 3;}
    if(auto result=ip_scenario(*credential,cert)) {std::println("CONNECT-IP control scenario failed {}",result);return 4;}
    std::println("TLS QUIC H3 CONNECT-UDP and CONNECT-IP control sessions passed");
}
