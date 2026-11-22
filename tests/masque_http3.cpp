import std;
import masque.http3;
import quic.http3;
import nexus.thirdparty.nghttp3;
namespace m=masque;
namespace n=nex::nghttp3;
namespace q=quic;
using Bytes=std::span<std::uint8_t const>;

// nghttp3 controls QPACK and SETTINGS; this fixture transfers its actual H3
// bytes in fragments and reports accepted offsets and ACKs independently.
struct Hooks {
    using H3=q::Http3<Hooks>;
    bool server=false,seen_request=false,seen_response=false,invalid=false;
    unsigned method=0,protocol=0,scheme=0,path=0,authority=0;
    m::Http3DatagramBoundary gate;
    explicit Hooks(bool is_server):server(is_server),gate(*m::Http3DatagramBoundary::create(is_server,is_server ? 3 : 2)) {}
    auto closing(H3&,int) noexcept -> bool {return true;}
    auto connection_closed(H3&,int) noexcept -> void {gate.stop();}
    auto begin_headers(H3&,std::int64_t,bool,void*) -> int {method=protocol=scheme=path=authority=0;return 0;}
    auto header(H3&,std::int64_t,std::int32_t,n::nghttp3_rcbuf* name,n::nghttp3_rcbuf* value,std::uint8_t,bool,void*) -> int {
        auto a=n::nghttp3_rcbuf_get_buf(name),b=n::nghttp3_rcbuf_get_buf(value);
        auto key=std::string_view(reinterpret_cast<char const*>(a.base),a.len);
        auto text=std::string_view(reinterpret_cast<char const*>(b.base),b.len);
        if(key==":method")method+=text=="CONNECT";
        if(key==":protocol")protocol+=text=="connect-udp";
        if(key==":scheme")scheme+=text=="https";
        if(key==":path")path+=text=="/.well-known/masque/udp/192.0.2.6/443/";
        if(key==":authority")authority+=text=="proxy.example";
        if(key==":status")seen_response=text=="200";
        return 0;
    }
    auto end_headers(H3& h,std::int64_t id,bool,bool trailers,void*) -> int {
        if(trailers)return n::err_callback_failure;
        if(!server)return 0;
        seen_request=method==1 && protocol==1 && scheme==1 && path==1 && authority==1;
        if(!seen_request)return n::err_callback_failure;
        static std::uint8_t status[] = ":status",value[]="200";
        n::nghttp3_nv field{status,value,7,3,n::nv_flag_none};
        return h.response(id,std::span(&field,1),true);
    }
    auto data(H3&,std::int64_t,Bytes,void*) -> int {return 0;}
    auto deferred_consume(H3&,std::int64_t,std::size_t,void*) -> int {return 0;}
    auto data_acked(H3&,std::int64_t,std::uint64_t,void*) -> int {return 0;}
    auto end_stream(H3&,std::int64_t,void*) -> int {return 0;}
    auto stream_closed(H3&,std::uint32_t,std::int64_t,std::uint64_t,std::uint64_t,void*) -> int {return 0;}
    auto stop_sending(H3&,std::int64_t,std::uint64_t,void*) -> int {return 0;}
    auto reset_stream(H3&,std::int64_t,std::uint64_t,void*) -> int {return 0;}
    auto shutdown(H3&,std::int64_t) -> int {return 0;}
    auto settings(H3&,n::nghttp3_settings const& settings) -> int {
        if(!gate.peer_settings(settings.h3_datagram,settings.enable_connect_protocol))return n::err_callback_failure;
        return 0;
    }
    auto read_data(H3&,std::int64_t,std::span<n::nghttp3_vec>,std::uint32_t&,void*) -> n::nghttp3_ssize {return n::err_wouldblock;}
};
struct Peer {
    Hooks hooks;
    q::Http3<Hooks> h3;
    std::uint64_t control,control_ack=0;
    explicit Peer(bool server):hooks(server),h3(hooks),control(server ? 3 : 2) {}
    auto start() -> int {
        n::nghttp3_settings settings{};n::nghttp3_settings_default_versioned(n::settings_version,&settings);
        settings.h3_datagram=1;settings.enable_connect_protocol=hooks.server;
        static n::nghttp3_mem const mem{nullptr,
            [](std::size_t size,void*) -> void* {return std::malloc(size);},
            [](void* ptr,void*) {std::free(ptr);},
            [](std::size_t count,std::size_t size,void*) -> void* {return std::calloc(count,size);},
            [](void* ptr,std::size_t size,void*) -> void* {return std::realloc(ptr,size);}};
        auto error=h3.start(hooks.server,settings,mem);if(error)return error;
        if(hooks.server)n::nghttp3_conn_set_max_client_streams_bidi(h3.native(),16);
        return h3.bind(control,control+4,control+8);
    }
};
struct Frame {std::int64_t stream;std::vector<std::uint8_t> bytes;bool fin;};
auto capture(Peer& p,std::size_t partial) -> std::expected<std::vector<Frame>,int> {
    std::vector<Frame> result;
    for(unsigned i=0;i<10000;++i) {
        std::array<n::nghttp3_vec,16> vec{};auto write=p.h3.write(vec);if(!write)return std::unexpected(write.error());
        if(write->stream<0)return result;
        Frame frame{write->stream,{},write->fin};std::size_t remaining=partial,total=0;
        for(auto const& v:std::span(vec).first(write->vectors)) {
            total+=v.len;auto count=std::min(v.len,remaining);
            if(count)frame.bytes.insert(frame.bytes.end(),v.base,v.base+count);remaining-=count;
        }
        frame.fin=frame.fin && frame.bytes.size()==total;
        if(!p.hooks.gate.accepted_stream(frame.stream,frame.bytes))return std::unexpected(-999);
        if(auto error=p.h3.accepted(frame.stream,frame.bytes.size()))return std::unexpected(error);
        result.push_back(std::move(frame));
    }
    return std::unexpected(-998);
}
auto deliver(Peer& sender,Peer& receiver,Frame const& f,std::size_t chunk,bool ack) -> int {
    for(std::size_t i=0;i<f.bytes.size();) {
        auto len=std::min(chunk,f.bytes.size()-i);
        auto result=receiver.h3.read(f.stream,std::span(f.bytes).subspan(i,len),f.fin && i+len==f.bytes.size(),1);
        if(!result)return result.error();i+=len;
    }
    if(f.bytes.empty() && f.fin) {auto result=receiver.h3.read(f.stream,{},true,1);if(!result)return result.error();}
    if(ack) {
        if(f.stream==static_cast<std::int64_t>(sender.control)) {
            if(!sender.hooks.gate.acknowledged_stream(f.stream,sender.control_ack,f.bytes.size()))return -997;
            sender.control_ack+=f.bytes.size();
        }
        return sender.h3.acknowledged(f.stream,f.bytes.size());
    }
    return 0;
}
auto pump(Peer& client,Peer& server,std::size_t chunk) -> int {
    for(unsigned i=0;i<128;++i) {
        auto a=capture(client,5);if(!a)return a.error();
        for(auto const& frame:*a)if(auto error=deliver(client,server,frame,chunk,true))return error;
        auto b=capture(server,7);if(!b)return b.error();
        for(auto const& frame:*b)if(auto error=deliver(server,client,frame,chunk,true))return error;
        if(a->empty() && b->empty())return 0;
    }
    return -996;
}
auto settings_boundaries() -> int {
    std::array<std::uint8_t,7> data{0,4,4,8,1,0x33,1};
    for(std::size_t split=0;split<=data.size();++split) {
        m::LocalSettings s;
        if(!s.accepted(std::span(data).first(split)) || !s.accepted(std::span(data).subspan(split)) || !s.complete() || !s.datagram() || !s.extended_connect())return 1;
        if(!s.acknowledged(0,3) || s.sent_and_acked() || !s.acknowledged(3,4) || !s.sent_and_acked())return 2;
        if(s.acknowledged(2,1) || s.acknowledged(7,1))return 3;
        s.close();if(s.accepted(data) || s.acknowledged(7,0))return 4;
    }
    for(auto data:std::array<std::vector<std::uint8_t>,5>{{{1},{0,5},{0,4,1,0x33},{0,4,2,0x33,2},{0,4,4,0x33,1,0x33,1}}}) {
        m::LocalSettings s;auto result=s.accepted(data);
        if(result || result.error()!=m::SettingsError::invalid)return 5;
    }
    auto invalid=m::Http3DatagramBoundary::create(false,3);
    if(invalid)return 6;
    auto gate=m::Http3DatagramBoundary::create(false,2);if(!gate)return 7;
    if(!gate->peer_settings(1,1) || gate->peer_settings(1,1) || !gate->can_open_extended_connect())return 8;
    if(!gate->peer_transport(0) || gate->peer_transport(1200) || !gate->accepted_stream(2,data) ||
       !gate->acknowledged_stream(2,0,data.size()) || gate->can_send_datagram())return 9;
    gate->stop();if(gate->can_open_extended_connect() || gate->peer_settings(1,1) || gate->accepted_stream(2,data))return 28;
    auto open=m::Http3StreamState{m::Http3StreamKind::datagram,true,true};
    for(std::uint64_t limit=1;limit<=3;++limit) {
        auto bounded=m::Http3DatagramBoundary::create(false,2);
        if(!bounded || !bounded->peer_settings(1,1) || !bounded->peer_transport(limit) ||
           !bounded->accepted_stream(2,data) || !bounded->acknowledged_stream(2,0,data.size()))return 29;
        auto prefix=bounded->send_prefix(0,open,0,1);
        if(bool(prefix)!=(limit==3))return 30;
    }
    return 0;
}
auto native_http3(std::size_t chunk) -> int {
    Peer client(false),server(true);
    if(client.start() || server.start())return 10;
    if(!client.hooks.gate.peer_transport(1200) || !server.hooks.gate.peer_transport(1200))return 11;
    if(client.hooks.gate.can_send_datagram() || client.hooks.gate.can_open_extended_connect())return 12;
    // SETTINGS reaching peer is insufficient for send until local control ACK.
    auto frames=capture(client,5);if(!frames)return 13;
    for(auto const& frame:*frames)if(auto e=deliver(client,server,frame,chunk,false))return e;
    auto server_frames=capture(server,7);if(!server_frames)return 14;
    for(auto const& frame:*server_frames)if(auto e=deliver(server,client,frame,chunk,true))return e;
    if(!client.hooks.gate.can_open_extended_connect() || client.hooks.gate.can_send_datagram())return 15;
    for(auto const& frame:*frames) {
        if(frame.stream==static_cast<std::int64_t>(client.control)) {
            if(!client.hooks.gate.acknowledged_stream(frame.stream,client.control_ack,frame.bytes.size()))return 16;
            client.control_ack+=frame.bytes.size();
        }
        if(auto error=client.h3.acknowledged(frame.stream,frame.bytes.size()))return error;
    }
    if(auto error=pump(client,server,chunk))return error;
    if(!client.hooks.gate.can_send_datagram() || !server.hooks.gate.can_send_datagram() || server.hooks.gate.can_open_extended_connect())return 17;
    std::array<std::string_view,6> keys{":method",":protocol",":scheme",":authority",":path","capsule-protocol"};
    std::array<std::string_view,6> values{"CONNECT","connect-udp","https","proxy.example","/.well-known/masque/udp/192.0.2.6/443/","?1"};
    std::array<n::nghttp3_nv,6> fields{};
    for(std::size_t i=0;i<fields.size();++i)fields[i]={reinterpret_cast<std::uint8_t const*>(keys[i].data()),reinterpret_cast<std::uint8_t const*>(values[i].data()),keys[i].size(),values[i].size(),n::nv_flag_none};
    if(auto error=client.h3.request(0,fields,true))return error;
    if(auto error=pump(client,server,chunk))return error;
    if(!server.hooks.seen_request || !client.hooks.seen_response)return 18;
    auto open=m::Http3StreamState{m::Http3StreamKind::datagram,true,true};
    auto prefix=client.hooks.gate.send_prefix(0,open,2,3);if(!prefix || prefix->size!=1)return 19;
    std::array<std::uint8_t,3> packet{prefix->bytes[0],0,0xa5};
    auto received=server.hooks.gate.receive(packet,[&](auto id){return id==0 ? open : m::Http3StreamState{};});
    if(received.action!=m::Http3DatagramAction::deliver || received.payload.size()!=2 || received.payload[1]!=0xa5)return 20;
    auto send_only=open;send_only.receive_open=false;
    if(!client.hooks.gate.send_prefix(0,send_only,0,1))return 21;
    auto receive_only=open;receive_only.send_open=false;
    if(client.hooks.gate.send_prefix(0,receive_only,0,1))return 22;
    auto other=server.hooks.gate.receive(packet,[](auto){return m::Http3StreamState{m::Http3StreamKind::no_datagram,true,true};});
    if(other.action!=m::Http3DatagramAction::stream_error)return 23;
    auto closed=server.hooks.gate.receive(packet,[&](auto){return send_only;});if(closed.action!=m::Http3DatagramAction::drop)return 24;
    if(server.hooks.gate.receive({},[&](auto){return open;}).action!=m::Http3DatagramAction::connection_error)return 25;
    if(client.hooks.gate.send_prefix(0,open,3,3) || client.hooks.gate.send_prefix(2,open,0,1))return 26;
    client.h3.stop();server.h3.stop();
    if(client.hooks.gate.can_send_datagram() || server.hooks.gate.can_send_datagram())return 27;
    return 0;
}
auto main() -> int {
    if(auto error=settings_boundaries()){std::println("settings boundary {}",error);return 1;}
    for(auto chunk:{1u,7u,1024u})if(auto error=native_http3(chunk)){std::println("native HTTP3 chunk {} error {}",chunk,error);return 2;}
    std::println("HTTP3 settings/ACK gating, extended CONNECT, datagram demultiplex and half-close passed");
}
