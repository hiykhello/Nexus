import std;
import crypto;
import net.udp_socket;
import masque.session;
import masque.http3;
import quic.connection;
import quic.http3;
import masque.datagram;
import masque.udp_session;
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
struct Hooks {
    bool server=false,ready=false,rejected=false,headers_done=false,shutdown_seen=false;
    std::uint64_t stream=0;
    std::vector<std::pair<std::string,std::string>> fields;
    std::vector<std::uint8_t> outbound,received,capsule_out,capsule_received;
    m::UdpCapsules<1200> capsules;
    bool capsule_submitted=false;std::uint64_t capsule_acked=0;
    std::optional<std::pair<std::int64_t,std::uint64_t>> abort;
    auto changed() noexcept -> void {}
    auto h3_closed() noexcept -> void {}
    auto transport_closed() noexcept -> void {ready=false;}
    auto stream_capacity() const noexcept -> std::size_t {return 16;}
    auto stream_state(std::uint64_t id) noexcept -> m::Http3StreamState {
        return id==stream && ready ? m::Http3StreamState{m::Http3StreamKind::datagram,true,true} : m::Http3StreamState{};
    }
    auto datagram(std::uint64_t id,View packet) -> int {
        if(id!=stream || !ready)return n::err_callback_failure;
        auto parsed=m::parse_proxy_datagram(packet,true);if(!parsed) {ready=false;abort=std::pair{static_cast<std::int64_t>(id),std::uint64_t{0x33}};return 0;}
        if(parsed->context_id)return 0;
        received.assign(parsed->payload.begin(),parsed->payload.end());return 0;
    }
    auto datagram_output() -> std::optional<Packet> {if(outbound.empty())return {};return Packet{stream,outbound};}
    auto datagram_accepted() -> void {outbound.clear();}
    auto datagram_rejected() -> void {outbound.clear();}
    auto datagram_budget() const noexcept -> std::size_t {return 1150;}
    auto closed(std::int64_t id,std::uint64_t,std::uint64_t) noexcept -> void {if(id==stream)ready=false;}
    auto receive_closed(std::int64_t id,std::uint64_t) noexcept -> void {if(id==stream)ready=false;}
    auto send_closed(std::int64_t id,std::uint64_t) noexcept -> void {if(id==stream)ready=false;}
    auto begin_headers(std::int64_t id,bool trailers) -> int {if(id!=static_cast<std::int64_t>(stream) || trailers)return h::err_callback_failure;fields.clear();return 0;}
    auto header(std::int64_t,h::nghttp3_rcbuf* key,h::nghttp3_rcbuf* value,bool) -> int {
        auto a=h::nghttp3_rcbuf_get_buf(key),b=h::nghttp3_rcbuf_get_buf(value);
        if(fields.size()>=16 || a.len+b.len>1024)return h::err_callback_failure;
        fields.emplace_back(std::string(reinterpret_cast<char const*>(a.base),a.len),std::string(reinterpret_cast<char const*>(b.base),b.len));return 0;
    }
    auto end_headers(std::int64_t,bool fin,bool trailers) -> int {
        if(trailers)return h::err_callback_failure;
        headers_done=true;
        if(!server)for(auto const& [key,value]:fields)if(key==":status") {if(value=="200")ready=true;else rejected=true;}
        if(fin && !rejected)return h::err_callback_failure;
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
        if(id!=static_cast<std::int64_t>(stream) || rejected)return 0;
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

using Clock=std::chrono::steady_clock;
using namespace std::chrono_literals;
auto clock_now() noexcept -> std::uint64_t {return std::chrono::duration_cast<std::chrono::nanoseconds>(Clock::now().time_since_epoch()).count();}
struct Path {
    n::ngtcp2_sockaddr_union local{},remote{};n::ngtcp2_path value{};
    auto assign(net::UdpEndpoint source,net::UdpEndpoint target) -> void {
        auto convert=[](auto& out,net::UdpEndpoint in) -> n::ngtcp2_addr {
            auto port=std::bit_cast<std::uint16_t>(std::array<std::uint8_t,2>{static_cast<std::uint8_t>(in.port>>8),static_cast<std::uint8_t>(in.port)});
            if(in.family==4) {out.in.sin_family=n::af_inet;out.in.sin_port=port;std::memcpy(&out.in.sin_addr.s_addr,in.address.data(),4);return {reinterpret_cast<n::ngtcp2_sockaddr*>(&out.in),sizeof(out.in)};}
            out.in6.sin6_family=n::af_inet6;out.in6.sin6_port=port;std::memcpy(out.in6.sin6_addr.s6_addr,in.address.data(),16);return {reinterpret_cast<n::ngtcp2_sockaddr*>(&out.in6),sizeof(out.in6)};
        };
        value={convert(local,source),convert(remote,target),nullptr};
    }
};
auto random_cid() -> n::ngtcp2_cid {std::array<std::uint8_t,8> bytes{};if(!::crypto::random_bytes(bytes))throw std::runtime_error("entropy");n::ngtcp2_cid id{};n::ngtcp2_cid_init(&id,bytes.data(),bytes.size());return id;}
template<class Tls> struct Peer {
    support::Memory memory;Hooks hooks;m::Session<Tls,Hooks> app;q::Connection<Tls,m::Session<Tls,Hooks>> connection;
    Peer(Tls& tls,bool server):hooks{.server=server},app(tls,hooks,server,h3_memory),connection(tls,app){app.attach(connection);}
    ~Peer(){stop();}
    auto stop() noexcept -> void {app.request_stop();app.joined();connection.stop();app.drain();}
};
auto field(std::string_view name,std::string_view value) -> h::nghttp3_nv {return {reinterpret_cast<std::uint8_t const*>(name.data()),reinterpret_cast<std::uint8_t const*>(value.data()),name.size(),value.size(),h::nv_flag_none};}
template<class Tls> auto run(Tls& tls,bool ipv6,unsigned port,unsigned echo_port,std::string_view target) -> int {
    net::UdpSocket socket;net::UdpEndpoint local{ipv6 ? std::uint8_t{6} : std::uint8_t{4},{},0};
    if(ipv6)local.address[15]=1;else{local.address[0]=127;local.address[3]=1;}
    if(!socket.bind(local))return 1;auto bound=socket.local_endpoint();if(!bound)return 2;local=*bound;auto remote=local;remote.port=port;
    Peer peer(tls,false);Path path;path.assign(local,remote);auto parameters=support::parameters(false);parameters.max_datagram_frame_size=1200;
    auto settings=support::settings();settings.initial_ts=clock_now();
    if(peer.connection.start(false,random_cid(),random_cid(),path.value,settings,parameters,peer.memory.transport()))return 3;
    std::array<std::uint8_t,65535> input{};std::array<std::uint8_t,1500> output{};
    std::size_t pending=0;bool requested=false,denied_sent=false,forwarded=false,second=false;auto deadline=Clock::now()+10s;
    auto request_path=std::format("/.well-known/masque/udp/{}/{}/",target,echo_port);
    while(Clock::now()<deadline) {
        if(pending){auto sent=socket.send(remote,std::span(output).first(pending));if(sent)pending=0;else if(sent.error()!=std::errc::resource_unavailable_try_again && sent.error()!=std::errc::operation_would_block)return 4;}
        auto packet=socket.receive(input);if(!packet)return 5;
        if(*packet && (**packet).valid && (**packet).source==remote){auto now=clock_now();peer.app.time(now);if(peer.connection.read(path.value,nullptr,std::span(input).first((**packet).size),now))return 6;}
        auto now=clock_now();if(auto expiry=peer.connection.expiry();expiry && *expiry<=now)if(peer.connection.expire(now))return 7;
        if(!requested && peer.app.can_open()) {
            std::int64_t id=-1;if(n::ngtcp2_conn_open_bidi_stream(peer.connection.native(),&id,nullptr) || id)return 8;
            std::array request{field(":method","CONNECT"),field(":protocol","connect-udp"),field(":scheme","https"),field(":authority","localhost"),field(":path",request_path),field("proxy-authorization","Bearer rejected")};
            if(peer.app.h3().request(id,request,true))return 9;requested=true;denied_sent=true;
        }
        if(denied_sent && peer.hooks.rejected && peer.hooks.stream==0) {
            std::int64_t id=-1;if(n::ngtcp2_conn_open_bidi_stream(peer.connection.native(),&id,nullptr) || id!=4)return 13;
            peer.hooks.stream=4;peer.hooks.rejected=false;peer.hooks.headers_done=false;
            std::array request{field(":method","CONNECT"),field(":protocol","connect-udp"),field(":scheme","https"),field(":authority","localhost"),field(":path",request_path),field("proxy-authorization","Bearer approved")};
            if(peer.app.h3().request(id,request,true))return 14;
        }
        if(peer.hooks.ready && !forwarded){peer.hooks.outbound={0,11,22,33};forwarded=true;}
        if(!second && peer.hooks.capsule_received==std::vector<std::uint8_t>{11,22,33}) {
            peer.hooks.capsule_received.clear();peer.hooks.outbound={0,44,55,66};second=true;
        }
        if(second && peer.hooks.capsule_received==std::vector<std::uint8_t>{44,55,66}) {peer.stop();socket.close();return peer.app.clean() && !peer.memory.used ? 0 : 10;}
        if(!pending){auto written=peer.app.output(output,now);if(!written)return 11;pending=*written;}
        if(!pending && !*packet)std::this_thread::sleep_for(1ms);
    }
    return 12;
}
auto main(int argc,char** argv) -> int {
    if(argc!=7)return 1;bool ipv6=std::string_view(argv[1])=="6";auto port=std::stoul(argv[2]),echo=std::stoul(argv[3]);auto cert=support::read(argv[4]);auto scheme=static_cast<std::uint16_t>(std::stoul(argv[5],nullptr,0));
    q::TlsClient tls(support::hello(scheme),29,support::Pki{cert},"h3");auto result=run(tls,ipv6,port,echo,argv[6]);std::println("MASQUE real listener client result={}",result);return result;
}
