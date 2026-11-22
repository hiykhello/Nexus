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
    bool server=false,ready=false,headers_done=false,shutdown_seen=false;
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
        return id==0 && ready ? m::Http3StreamState{m::Http3StreamKind::datagram,true,true} : m::Http3StreamState{};
    }
    auto datagram(std::uint64_t id,View packet) -> int {
        if(id!=0 || !ready)return n::err_callback_failure;
        auto parsed=m::parse_proxy_datagram(packet,true);if(!parsed) {ready=false;abort=std::pair{static_cast<std::int64_t>(id),std::uint64_t{0x33}};return 0;}
        if(parsed->context_id)return 0;
        received.assign(parsed->payload.begin(),parsed->payload.end());return 0;
    }
    auto datagram_output() -> std::optional<Packet> {if(outbound.empty())return {};return Packet{0,outbound};}
    auto datagram_accepted() -> void {outbound.clear();}
    auto datagram_rejected() -> void {outbound.clear();}
    auto datagram_budget() const noexcept -> std::size_t {return 1150;}
    auto closed(std::int64_t,std::uint64_t,std::uint64_t) noexcept -> void {ready=false;}
    auto receive_closed(std::int64_t,std::uint64_t) noexcept -> void {ready=false;}
    auto send_closed(std::int64_t,std::uint64_t) noexcept -> void {ready=false;}
    auto begin_headers(std::int64_t id,bool trailers) -> int {if(id || trailers)return h::err_callback_failure;fields.clear();return 0;}
    auto header(std::int64_t,h::nghttp3_rcbuf* key,h::nghttp3_rcbuf* value,bool) -> int {
        auto a=h::nghttp3_rcbuf_get_buf(key),b=h::nghttp3_rcbuf_get_buf(value);
        if(fields.size()>=16 || a.len+b.len>1024)return h::err_callback_failure;
        fields.emplace_back(std::string(reinterpret_cast<char const*>(a.base),a.len),std::string(reinterpret_cast<char const*>(b.base),b.len));return 0;
    }
    auto end_headers(std::int64_t,bool fin,bool trailers) -> int {
        if(fin || trailers)return h::err_callback_failure;
        headers_done=true;
        if(!server)for(auto const& [key,value]:fields)if(key==":status" && value=="200")ready=true;
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
template<class Tls> auto run(Tls& tls,bool server,bool ipv6,unsigned port,unsigned echo_port,bool capsule) -> int {
    net::UdpSocket socket,udp;
    net::UdpEndpoint local{ipv6 ? std::uint8_t{6} : std::uint8_t{4},{},0};
    if(ipv6)local.address[15]=1;else{local.address[0]=127;local.address[3]=1;}
    if(!socket.bind(local))return 1;auto bound=socket.local_endpoint();if(!bound)return 2;local=*bound;
    auto remote=local;remote.port=port;auto echo=local;echo.port=echo_port;
    if(server && !udp.bind(net::UdpEndpoint{local.family,local.address,0}))return 3;
    Peer peer(tls,server);Path path;std::array<std::uint8_t,65535> input{},udp_input{};std::array<std::uint8_t,1500> output{};
    std::size_t pending=0;bool started=false,requested=false,responded=false,forwarded=false,replied=false,passed=false;unsigned sent_after_reply=0;
    std::optional<Clock::time_point> client_received;
    std::string request_path=std::format("/.well-known/masque/udp/{}/{}/",ipv6 ? "%3A%3A1" : "127.0.0.1",echo_port);
    auto start=[&](n::ngtcp2_cid const& dest,n::ngtcp2_cid const& source,n::ngtcp2_transport_params params) -> int {
        params.max_datagram_frame_size=1200;path.assign(local,remote);auto settings=support::settings();settings.initial_ts=clock_now();
        auto error=peer.connection.start(server,dest,source,path.value,settings,params,peer.memory.transport());started=!error;return error;
    };
    if(!server)if(auto error=start(random_cid(),random_cid(),support::parameters(false)))return error;
    std::cout<<"READY "<<local.port<<std::endl;
    auto deadline=Clock::now()+10s;
    while(Clock::now()<deadline) {
        if(pending) {auto result=socket.send(remote,std::span(output).first(pending));if(result){pending=0;if(replied)++sent_after_reply;}
            else if(result.error()!=std::errc::resource_unavailable_try_again && result.error()!=std::errc::operation_would_block)return 4;}
        auto packet=socket.receive(input);if(!packet)return 5;
        if(*packet && (**packet).valid) {
            auto source=(**packet).source;auto bytes=std::span(input).first((**packet).size);
            if(!started) {n::ngtcp2_pkt_hd first{};if(n::ngtcp2_accept(&first,bytes.data(),bytes.size()) || first.version!=1)continue;
                remote=source;auto params=support::parameters(true);params.original_dcid=first.dcid;if(start(first.scid,random_cid(),params))return 6;}
            if(source==remote){auto now=clock_now();peer.app.time(now);if(peer.connection.read(path.value,nullptr,bytes,now))return 7;}
        }
        if(!started){std::this_thread::sleep_for(1ms);continue;}
        auto now=clock_now();if(auto expiry=peer.connection.expiry();expiry && *expiry<=now)if(peer.connection.expire(now))return 8;
        if(!server && !requested && peer.app.can_open()) {
            std::int64_t id=-1;if(n::ngtcp2_conn_open_bidi_stream(peer.connection.native(),&id,nullptr) || id)return 9;
            std::array request{field(":method","CONNECT"),field(":protocol","connect-udp"),field(":scheme","https"),field(":authority","localhost"),field(":path",request_path),field("capsule-protocol","?1")};
            if(peer.app.h3().request(id,request,true))return 10;requested=true;
        }
        if(server && peer.hooks.headers_done && !responded) {
            bool method=false,target=false;
            for(auto const& [key,value]:peer.hooks.fields){method|=key==":protocol" && value=="connect-udp";target|=key==":path" && value==request_path;}
            if(!method || !target)return 11;peer.hooks.ready=true;
            std::array response{field(":status","200"),field("capsule-protocol","?1")};
            if(peer.app.h3().response(0,response,true))return 12;responded=true;
        }
        if(!server && peer.hooks.ready && !forwarded) {
            if(capsule) {peer.hooks.capsule_out={0,4,0,11,22,33};if(peer.app.h3().resume(0))return 19;}
            else peer.hooks.outbound={0,11,22,33};
            forwarded=true;
        }
        auto& incoming=capsule ? peer.hooks.capsule_received : peer.hooks.received;
        if(server && !forwarded && !incoming.empty()) {
            if(incoming!=std::vector<std::uint8_t>{11,22,33})return 13;
            if(!udp.send(echo,incoming))return 14;forwarded=true;
        }
        if(server && forwarded && !replied) {
            auto result=udp.receive(udp_input);if(!result)return 15;
            if(*result && (**result).valid && (**result).source==echo) {
                auto bytes=std::span(udp_input).first((**result).size);
                if(capsule) {
                    if(bytes.size()>63)return 20;
                    peer.hooks.capsule_out={0,static_cast<std::uint8_t>(bytes.size()+1),0};
                    peer.hooks.capsule_out.insert(peer.hooks.capsule_out.end(),bytes.begin(),bytes.end());
                    if(peer.app.h3().resume(0))return 21;
                } else {peer.hooks.outbound={0};peer.hooks.outbound.insert(peer.hooks.outbound.end(),bytes.begin(),bytes.end());}
                replied=true;
            }
        }
        if(!server && incoming==std::vector<std::uint8_t>{11,22,33}) {
            if(!capsule){passed=true;break;}
            if(!client_received)client_received=Clock::now();
            if(Clock::now()-*client_received>=100ms){passed=true;break;}
        }
        if(server && replied && (capsule ? peer.hooks.capsule_acked==peer.hooks.capsule_out.size() : peer.hooks.outbound.empty() && sent_after_reply)) {passed=true;break;}
        if(!pending){auto result=peer.app.output(output,now);if(!result)return 16;pending=*result;}
        if(!pending && !*packet)std::this_thread::sleep_for(1ms);
    }
    peer.stop();socket.close();udp.close();
    if(!peer.app.clean() || peer.memory.used)return 17;
    std::println("MASQUE UDP {} passed={} forwarded={} replied={}",server ? "server" : "client",passed,forwarded,replied);
    return passed ? 0 : 18;
}
auto main(int argc,char** argv) -> int {
    if(argc!=9)return 1;bool capsule=std::string_view(argv[8])=="capsule";bool server=std::string_view(argv[1])=="server",ipv6=std::string_view(argv[2])=="6";
    auto port=std::stoul(argv[3]),echo_port=std::stoul(argv[4]);auto cert=support::read(argv[5]);auto scheme=static_cast<std::uint16_t>(std::stoul(argv[7],nullptr,0));
    if(server){auto key=support::read(argv[6]);auto credential=t::ServerCredential::create(cert,key);::crypto::cleanse(key);if(!credential)return 2;q::TlsServer tls(*credential,"h3");return run(tls,true,ipv6,port,echo_port,capsule);}
    q::TlsClient tls(support::hello(scheme),29,support::Pki{cert},"h3");return run(tls,false,ipv6,port,echo_port,capsule);
}
