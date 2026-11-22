import std;
import crypto;
import net.udp_socket;
import quic.connection;
import quic.tls_client;
import quic.tls_server;
import nexus.thirdparty.ngtcp2;
import nexus.thirdparty.nghttp3;
import tls.server_credential;
import nexus.test.quic_tls_link;
import nexus.test.http3_link;

namespace q=quic;
namespace t=tls;
namespace n=nex::ngtcp2;
namespace h3=nex::nghttp3;
namespace support=nexus::test::quic_tls;
namespace app=nexus::test::http3_link;
using Clock=std::chrono::steady_clock;
using namespace std::chrono_literals;
namespace {
    auto now() noexcept -> std::uint64_t { return std::chrono::duration_cast<std::chrono::nanoseconds>(Clock::now().time_since_epoch()).count(); }
    struct Path {
        n::ngtcp2_sockaddr_union local{},remote{};
        n::ngtcp2_path value{};
        auto assign(net::UdpEndpoint source,net::UdpEndpoint target) -> void {
            auto convert=[](auto& output,net::UdpEndpoint input) -> n::ngtcp2_addr {
                auto port=std::bit_cast<std::uint16_t>(std::array<std::uint8_t,2>{static_cast<std::uint8_t>(input.port>>8),static_cast<std::uint8_t>(input.port)});
                if (input.family==4) {
                    output.in.sin_family=n::af_inet; output.in.sin_port=port; std::memcpy(&output.in.sin_addr.s_addr,input.address.data(),4);
                    return {reinterpret_cast<n::ngtcp2_sockaddr*>(&output.in),sizeof(output.in)};
                }
                output.in6.sin6_family=n::af_inet6; output.in6.sin6_port=port; std::memcpy(output.in6.sin6_addr.s6_addr,input.address.data(),16);
                return {reinterpret_cast<n::ngtcp2_sockaddr*>(&output.in6),sizeof(output.in6)};
            };
            value={convert(local,source),convert(remote,target),nullptr};
        }
    };
    auto random_cid() -> n::ngtcp2_cid {
        std::array<std::uint8_t,8> bytes{}; if (!::crypto::random_bytes(bytes)) throw std::runtime_error("CID entropy");
        n::ngtcp2_cid id{}; n::ngtcp2_cid_init(&id,bytes.data(),bytes.size()); return id;
    }
    template<class Tls> struct Peer {
        support::Memory memory;
        app::Application<Tls> app;
        q::Connection<Tls,app::Application<Tls>> connection;
        Peer(Tls& tls,bool server):app(tls),connection(tls,app) { app.server=server; app.transport=&connection; }
        ~Peer() { stop(); }
        auto stop() noexcept -> void { connection.stop(); app.drain(); }
    };
    template<class Tls> auto run(Tls& tls,bool server,bool ipv6,unsigned port,bool loss) -> int {
        net::UdpSocket socket;
        net::UdpEndpoint local{ipv6 ? std::uint8_t{6} : std::uint8_t{4},{},0};
        if (ipv6) local.address[15]=1; else { local.address[0]=127; local.address[3]=1; }
        if (!socket.bind(local)) return 1;
        auto bound=socket.local_endpoint(); if (!bound) return 2; local=*bound;
        auto remote=local; remote.port=port;
        Peer peer(tls,server); Path path;
        std::array<std::uint8_t,65535> input{}; std::array<std::uint8_t,1500> output{};
        std::size_t pending=0; bool started=false,auth_sent=false,get_sent=false,passed=false;
        unsigned sent=0,received=0,dropped=0; int failure=0;
        auto start=[&](n::ngtcp2_cid const& destination,n::ngtcp2_cid const& source,n::ngtcp2_transport_params const& parameters) -> int {
            path.assign(local,remote); auto settings=support::settings(); settings.initial_ts=now();
            auto error=peer.connection.start(server,destination,source,path.value,settings,parameters,peer.memory.transport()); started=!error; return error;
        };
        if (!server) if (auto error=start(random_cid(),random_cid(),support::parameters(false))) return error;
        std::cout<<"READY "<<local.port<<std::endl;
        auto deadline=Clock::now()+10s;
        while (Clock::now()<deadline) {
            if (pending) {
                auto result=socket.send(remote,std::span(output).first(pending));
                if (result) { pending=0; ++sent; }
                else if (result.error()!=std::errc::resource_unavailable_try_again && result.error()!=std::errc::operation_would_block) { failure=3; break; }
            }
            auto packet=socket.receive(input); if (!packet) { failure=4; break; }
            if (*packet && (**packet).valid) {
                auto source=(**packet).source; auto bytes=std::span(input).first((**packet).size); ++received;
                if (!started) {
                    n::ngtcp2_pkt_hd first{}; if (n::ngtcp2_accept(&first,bytes.data(),bytes.size()) || first.version!=1) continue;
                    remote=source; auto parameters=support::parameters(true); parameters.original_dcid=first.dcid;
                    if (auto error=start(first.scid,random_cid(),parameters)) { failure=5; break; }
                }
                if (source!=remote) continue;
                peer.app.time=now(); auto error=peer.connection.read(path.value,nullptr,bytes,peer.app.time); peer.app.drain();
                if (error) { std::println("H3 QUIC read error={} H3={} TLSalert={}",error,peer.app.http3_error,tls.alert()); failure=6; break; }
            }
            if (!started) { std::this_thread::sleep_for(1ms); continue; }
            auto time=now(); if (auto expiry=peer.connection.expiry(); expiry && *expiry<=time) if (auto error=peer.connection.expire(time)) { failure=7; break; }
            if (!server && peer.app.completed && !auth_sent) { if (auto error=app::request(peer,true)) { failure=8; break; } auth_sent=true; }
            if (!server && peer.app.authenticated && !get_sent) { if (auto error=app::request(peer,false)) { failure=9; break; } get_sent=true; }
            if (peer.app.authenticated && (server ? peer.app.slot(4).acked==12000 : peer.app.slot(4).fin && peer.app.slot(4).received==12000)) { passed=true; break; }
            if (!pending) {
                auto time=now(); auto written=app::write(peer,output,time,false,0); peer.app.drain();
                if (!written) { std::println("H3 write error {} H3={}",written.error(),peer.app.http3_error); failure=10; break; }
                pending=written->bytes;
                // Drop an actual H3 stream packet after QUIC has borrowed its
                // frame vectors, then rely on native retransmit and ACK.
                if (loss && !dropped && pending && written->accepted) { pending=0; ++dropped; }
            }
            if (!pending && !*packet) std::this_thread::sleep_for(1ms);
        }
        if (passed && !server) {
            auto& state=peer.app.slot(4); for (std::size_t i=0;i<state.received;++i) if (state.body[i]!=static_cast<std::uint8_t>(i*73)) passed=false;
        }
        passed&=peer.app.input==peer.app.framing+peer.app.payload && peer.app.refs_valid() && (!loss || dropped==1);
        if (passed && peer.connection.native()) {
            n::ngtcp2_ccerr error{}; n::ngtcp2_ccerr_default(&error); n::ngtcp2_ccerr_set_application_error(&error,h3::h3_no_error,nullptr,0);
            auto result=peer.connection.write_close(output,nullptr,nullptr,error,now()); if (result && *result) (void)socket.send(remote,std::span(output).first(*result));
        }
        peer.stop(); socket.close();
        if (peer.connection.key_slots() || peer.memory.used || peer.app.memory.used || peer.app.broken || peer.app.quic_closed!=1 || peer.app.http3_closed!=1 || tls.pending_handshake_bytes()) return 11;
        std::println("HTTP3 UDP Nexus {} passed={} auth233={} payload={} DATAacked={} sent={} received={} H3loss={} native_peak={} H3peak={} failure={}",server ? "server" : "client",passed,peer.app.authenticated,peer.app.payload,peer.app.slot(4).acked,sent,received,dropped,peer.memory.peak,peer.app.memory.peak,failure);
        return passed && !failure ? 0 : 20+failure;
    }
}
auto main(int argc,char** argv) -> int {
    if (argc!=8) { std::println("usage: quic-http3-udp client|server 4|6 PORT CERT.der KEY.der SCHEME normal|loss"); return 1; }
    try {
        bool server=std::string_view(argv[1])=="server",ipv6=std::string_view(argv[2])=="6";
        auto cert=support::read(argv[4]); auto scheme=static_cast<std::uint16_t>(std::stoul(argv[6],nullptr,0));
        auto port=static_cast<unsigned>(std::stoul(argv[3])); bool loss=std::string_view(argv[7])=="loss";
        if (server) {
            auto key=support::read(argv[5]); auto credential=t::ServerCredential::create(cert,key); ::crypto::cleanse(key); if (!credential) return 2;
            q::TlsServer tls(*credential,"h3"); return run(tls,true,ipv6,port,loss);
        }
        q::TlsClient tls(support::hello(scheme),29,support::Pki{cert},"h3"); return run(tls,false,ipv6,port,loss);
    } catch (std::exception const& error) { std::println("H3 UDP exception {}",error.what()); return 99; }
}
