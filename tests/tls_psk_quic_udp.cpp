import std;
import crypto;
import net.udp_socket;
import quic.connection;
import quic.tls_client;
import quic.resumption;
import quic.tls_server;
import nexus.thirdparty.ngtcp2;
import tls.certificate_trust;
import tls.handshake;
import tls.hello;
import tls.record;
import tls.fingerprint;
import tls.hybrid;
import tls.server_credential;
import tls.server_hello;

namespace q=quic;
namespace n=nex::ngtcp2;
namespace t=tls;
namespace c = ::crypto;
using View=std::span<std::uint8_t const>;
using Clock=std::chrono::steady_clock;
using namespace std::chrono_literals;
namespace {
    std::size_t record_contexts=0;
    auto now() noexcept -> std::uint64_t { return std::chrono::duration_cast<std::chrono::nanoseconds>(Clock::now().time_since_epoch()).count(); }
    auto read(std::string_view path) -> c::Bytes { std::ifstream input(std::string(path),std::ios::binary); return {std::istreambuf_iterator<char>(input),{}}; }
    auto bytes(std::string_view input) noexcept -> View { return {reinterpret_cast<std::uint8_t const*>(input.data()),input.size()}; }
    auto payload() -> c::Bytes { c::Bytes out(12000); for (std::size_t i=0;i<out.size();++i) out[i]=static_cast<std::uint8_t>(i*73); return out; }
    constexpr std::array<std::uint8_t,5> datagram{0,1,255,127,0};
    struct Memory {
        struct alignas(std::max_align_t) Header { std::size_t size; };
        std::size_t live=0,peak=0,calls=0;
        static auto allocate(std::size_t size,void* context) noexcept -> void* {
            auto& self=*static_cast<Memory*>(context);
            if (size>4*1024*1024-self.live-sizeof(Header)) return nullptr;
            auto* out=static_cast<Header*>(std::malloc(size+sizeof(Header))); if (!out) return nullptr;
            out->size=size+sizeof(Header); self.live+=out->size; self.peak=std::max(self.peak,self.live); ++self.calls; return out+1;
        }
        static auto release(void* pointer,void* context) noexcept -> void {
            if (!pointer) return;
            auto& self=*static_cast<Memory*>(context); auto* out=static_cast<Header*>(pointer)-1; auto size=out->size;
            c::cleanse({reinterpret_cast<std::uint8_t*>(out),size}); self.live-=size; std::free(out);
        }
        static auto zero(std::size_t count,std::size_t size,void* context) noexcept -> void* {
            if (size && count>std::numeric_limits<std::size_t>::max()/size) return nullptr;
            auto* out=allocate(count*size,context); if (out) std::memset(out,0,count*size); return out;
        }
        static auto resize(void* pointer,std::size_t size,void* context) noexcept -> void* {
            if (!pointer) return allocate(size,context);
            if (!size) { release(pointer,context); return nullptr; }
            auto* out=allocate(size,context); if (!out) return nullptr;
            auto old=(static_cast<Header*>(pointer)-1)->size-sizeof(Header); std::memcpy(out,pointer,std::min(old,size)); release(pointer,context); return out;
        }
        auto callbacks() noexcept -> n::ngtcp2_mem { return {this,allocate,release,zero,resize}; }
    };
    struct Path {
        n::ngtcp2_sockaddr_union local{},remote{};
        n::ngtcp2_path value{};
        auto assign(net::UdpEndpoint source,net::UdpEndpoint target) -> void {
            auto address=[](auto& out,net::UdpEndpoint input) -> n::ngtcp2_addr {
                auto port=std::bit_cast<std::uint16_t>(std::array<std::uint8_t,2>{static_cast<std::uint8_t>(input.port>>8),static_cast<std::uint8_t>(input.port)});
                if (input.family==4) {
                    out.in.sin_family=n::af_inet; out.in.sin_port=port;
                    std::memcpy(&out.in.sin_addr.s_addr,input.address.data(),4);
                    return {reinterpret_cast<n::ngtcp2_sockaddr*>(&out.in),sizeof(out.in)};
                }
                out.in6.sin6_family=n::af_inet6; out.in6.sin6_port=port;
                std::memcpy(out.in6.sin6_addr.s6_addr,input.address.data(),16);
                return {reinterpret_cast<n::ngtcp2_sockaddr*>(&out.in6),sizeof(out.in6)};
            };
            value={address(local,source),address(remote,target),nullptr};
        }
    };
    template<class Connection> struct ObservedConnection {
        Connection& connection;unsigned& hellos;unsigned& retries;
        template<class... Args>auto install_secret(Args&&... args){return connection.install_secret(std::forward<Args>(args)...);}
        auto complete_handshake(){return connection.complete_handshake();}
        auto remote_transport_parameters(View b){return connection.remote_transport_parameters(b);}
        auto local_transport_parameters(std::span<std::uint8_t> b){return connection.local_transport_parameters(b);}
        auto tls_alert(std::uint8_t a) noexcept->void {connection.tls_alert(a);}
        auto submit_crypto(n::ngtcp2_encryption_level level,View data)->int{
            if(level==n::NGTCP2_ENCRYPTION_LEVEL_INITIAL&&!data.empty()){
                if(data[0]==1)++hellos;
                if(data[0]==2){auto h=t::ServerHello::parse(data.subspan(4));if(h&&h->is_retry())++retries;}
            }
            return connection.submit_crypto(level,data);
        }
    };
    template<class Core>struct ObservedTls:Core{
        unsigned hellos=0,retries=0;
        template<class Setup>explicit ObservedTls(Setup&& setup):Core(std::forward<Setup>(setup)){}
        template<class Connection,class... Recovery>auto start(Connection& c,Recovery&... recovery)->int{
            ObservedConnection view{c,hellos,retries};return Core::start(view,recovery...);
        }
        template<class Connection,class... Recovery>auto receive(Connection& c,n::ngtcp2_encryption_level l,std::uint64_t offset,View data,Recovery&... recovery)->int{
            ObservedConnection view{c,hellos,retries};return Core::receive(view,l,offset,data,recovery...);
        }
    };
    template<class Tls> struct Application {
        Tls& tls;
        c::Bytes data;
        std::array<std::uint8_t,1200> received_datagram{};
        std::size_t datagram_size=0,acked=0;
        std::int64_t stream=-1;
        unsigned completed=0,closed=0,datagrams=0;
        bool fin=false,datagram_pending=false,before_auth=false;
        explicit Application(Tls& value):tls(value) { data.reserve(65536); }
        template<class Connection> auto connection_closed(Connection& connection,int) noexcept -> void { if (connection.native()) std::terminate(); ++closed; if constexpr(!requires {tls.resumption_policy();})tls.cancel(); }
        template<class Connection> auto handshake_complete(Connection&) -> int { if (!tls.complete()) return n::err_callback_failure; ++completed; return 0; }
        template<class... Args> auto handshake_confirmed(Args&&...) -> int { return 0; }
        template<class Connection> auto stream_data(Connection& connection,std::uint32_t flags,std::int64_t id,std::uint64_t offset,View input,void*) -> int {
            before_auth|=!tls.complete();
            if (before_auth || (stream!=-1 && stream!=id) || offset!=data.size() || input.size()>65536-data.size()) return n::err_callback_failure;
            stream=id; data.insert(data.end(),input.begin(),input.end()); fin|=bool(flags&n::stream_data_flag_fin);
            auto error=n::ngtcp2_conn_extend_max_stream_offset(connection.native(),id,input.size());
            if (!error) n::ngtcp2_conn_extend_max_offset(connection.native(),input.size());
            return error;
        }
        template<class Connection> auto stream_acked(Connection&,std::int64_t,std::uint64_t,std::uint64_t size,void*) -> int { acked+=size; return 0; }
        template<class Connection> auto datagram(Connection&,View input) -> int {
            before_auth|=!tls.complete(); if (before_auth || input.size()>received_datagram.size()) return n::err_callback_failure;
            std::ranges::copy(input,received_datagram.begin()); datagram_size=input.size(); datagram_pending=true; ++datagrams; return 0;
        }
        template<class... Args> auto stream_close(Args&&...) -> int { return 0; }
        template<class... Args> auto stream_reset(Args&&...) -> int { return 0; }
        template<class... Args> auto stop_sending(Args&&...) -> int { return 0; }
        template<class... Args> auto stream_limit(Args&&...) -> int { return 0; }
        template<class... Args> auto add_connection_id(Args&&...) -> int { return 0; }
        template<class... Args> auto remove_connection_id(Args&&...) -> int { return 0; }
    };
    auto settings(std::uint64_t time) -> n::ngtcp2_settings {
        n::ngtcp2_settings out{}; n::ngtcp2_settings_default_versioned(n::settings_version,&out); out.initial_ts=time; out.handshake_timeout=10*n::seconds; return out;
    }
    auto parameters() -> n::ngtcp2_transport_params {
        n::ngtcp2_transport_params out{}; n::ngtcp2_transport_params_default_versioned(n::transport_params_version,&out);
        out.initial_max_data=65536; out.initial_max_stream_data_bidi_local=out.initial_max_stream_data_bidi_remote=out.initial_max_stream_data_uni=4096;
        out.initial_max_streams_bidi=16; out.initial_max_streams_uni=3; out.max_datagram_frame_size=1200; out.disable_active_migration=1; return out;
    }
    auto random_cid() -> n::ngtcp2_cid {
        std::array<std::uint8_t,8> bytes{}; if (!c::random_bytes(bytes)) throw std::runtime_error("CID entropy");
        n::ngtcp2_cid out{}; n::ngtcp2_cid_init(&out,bytes.data(),bytes.size()); return out;
    }
    template<class Tls>
    auto run(Tls& tls,bool server,bool ipv6,unsigned port,std::string_view mode,bool retry,t::ResumptionCache<8>* cache,t::ServerTicketStore<8>* store,unsigned round,bool expected_resume) -> int {
        net::UdpSocket socket;
        net::UdpEndpoint local{ipv6 ? std::uint8_t{6} : std::uint8_t{4},{},0},peer=local;
        if (ipv6) local.address[15]=1; else { local.address[0]=127; local.address[3]=1; }
        if(server)local.port=port;
        peer=local; peer.port=port;
        if (!socket.bind(local)) return 1;
        auto bound=socket.local_endpoint(); if (!bound) return 2; local=*bound;
        Memory memory; Application application(tls); q::Connection connection(tls,application); Path path;
        std::array<std::uint8_t,65535> input{}; std::array<std::uint8_t,1500> output{};
        std::size_t pending=0,offset=0; bool started=false,sent_fin=false,passed=false;
        unsigned sent_packets=0,received_packets=0,dropped=0;
        std::optional<t::PendingServerTicket> ticket;
        bool ticket_submitted=false,published=false;
        auto cache_before=cache ? cache->size() : 0;
        auto deadline=Clock::now()+(mode=="timeout" ? 1200ms : 10s),last_datagram=Clock::time_point{};
        auto original=payload();
        if (!server) {
            path.assign(local,peer);
            auto error=connection.start(false,random_cid(),random_cid(),path.value,settings(now()),parameters(),memory.callbacks()); if (error) return 3;
            started=true;
        }
        std::cout<<"READY "<<local.port<<std::endl;
        int failure=0;
        while (Clock::now()<deadline) {
            if (pending) {
                auto sent=socket.send(peer,std::span(output).first(pending));
                if (sent) { pending=0; ++sent_packets; }
                else if (sent.error()!=std::errc::resource_unavailable_try_again && sent.error()!=std::errc::operation_would_block) { failure=4; break; }
            }
            auto packet=socket.receive(input); if (!packet) { failure=5; break; }
            if (*packet) {
                if (!(**packet).valid) continue;
                auto from=(**packet).source; auto wire=std::span(input).first((**packet).size); ++received_packets;
                if (mode=="loss" && !dropped) { ++dropped; continue; }
                if (!started) {
                    n::ngtcp2_pkt_hd first{};
                    if (n::ngtcp2_accept(&first,wire.data(),wire.size()) || first.version!=1) continue;
                    peer=from; path.assign(local,peer); auto params=parameters(); params.original_dcid=first.dcid; params.original_dcid_present=1;
                    auto error=connection.start(true,first.scid,random_cid(),path.value,settings(now()),params,memory.callbacks()); if (error) { failure=6; break; }
                    started=true;
                }
                if (from!=peer) continue;
                if (mode=="stop") { passed=true; break; }
                auto error=connection.read(path.value,nullptr,wire,now());
                if (error) {
                    if (mode=="reject" && !application.completed && application.data.empty() &&
                        (server ? error==n::err_draining : error==n::err_crypto && tls.alert()==42)) { passed=true; break; }
                    std::println("QUIC read error {} TLS alert {} bytes {}",error,tls.alert(),wire.size()); failure=7; break;
                }
            }
            if (started) {
                auto time=now(); if (auto expiry=connection.expiry(); expiry && *expiry<=time) { auto error=connection.expire(time); if (error) { failure=8; break; } }
                if (tls.complete() && application.completed && !pending) {
                    if constexpr(requires {tls.take_issuer();}) if (!ticket_submitted) {
                        auto issuer=tls.take_issuer();if (!issuer){failure=30;break;}
                        auto pending_ticket=issuer->prepare();if(!pending_ticket){failure=31;break;}
                        auto wire=t::HandshakeDecoder::encode(4,pending_ticket->body());if(!wire||connection.submit_crypto(n::NGTCP2_ENCRYPTION_LEVEL_1RTT,*wire)){failure=32;break;}
                        ticket.emplace(std::move(*pending_ticket));ticket_submitted=true;
                    }
                    if constexpr(requires {tls.take_issuer();}) if (ticket && !published && !application.data.empty()) {
                        // Go sends its first stream only after its session cache
                        // has admitted the complete authenticated ticket.
                        published=ticket->publish(*store,t::PskSteadyClock::now());if(!published){failure=33;break;}
                    }

                    if (!server && cache && cache->size()>cache_before && application.stream==-1 && n::ngtcp2_conn_open_bidi_stream(connection.native(),&application.stream,nullptr)) { failure=9; break; }
                    auto& outgoing=server ? application.data : original;
                    bool ready_fin=!server || application.fin;
                    if (application.stream!=-1 && !sent_fin && (offset<outgoing.size() || ready_fin)) {
                        n::ngtcp2_vec view{outgoing.data()+offset,outgoing.size()-offset};
                        auto written=connection.write_stream(output,nullptr,nullptr,application.stream,std::span(&view,1),ready_fin,now());
                        if (!written && written.error()!=n::err_stream_data_blocked) { std::println("QUIC stream write error {}",written.error()); failure=10; break; }
                        if (written) {
                            if (written->stream_bytes>=0) { offset+=written->stream_bytes; sent_fin=ready_fin && offset==outgoing.size(); }
                            pending=written->packet_bytes;
                        }
                    }
                    if (!pending && (server ? application.datagram_pending : application.datagrams==0 && Clock::now()-last_datagram>50ms)) {
                        auto content=server ? std::span(application.received_datagram).first(application.datagram_size) : std::span<std::uint8_t const>(datagram);
                        n::ngtcp2_vec view{const_cast<std::uint8_t*>(content.data()),content.size()};
                        auto written=connection.write_datagram(output,nullptr,nullptr,1,std::span(&view,1),now());
                        if (!written) { failure=11; break; }
                        pending=written->packet_bytes;
                        if (written->accepted) { application.datagram_pending=false; last_datagram=Clock::now(); }
                    }
                    if (application.fin && application.data==original && sent_fin && application.acked==outgoing.size() && application.datagrams &&
                        std::ranges::equal(std::span(application.received_datagram).first(application.datagram_size),datagram) && (server ? published : cache && cache->size()>cache_before)) { passed=true; break; }
                }
                if (!pending) {
                    auto written=connection.write_packet(output,nullptr,nullptr,now());
                    if (!written) { failure=12; break; } pending=*written;
                }
            }
            if (!pending && !*packet) std::this_thread::sleep_for(1ms);
        }
        if (mode=="timeout") passed=!application.completed && application.data.empty() && Clock::now()>=deadline;
        if (passed && connection.native() && mode!="stop" && mode!="timeout") {
            n::ngtcp2_ccerr error{}; n::ngtcp2_ccerr_default(&error); n::ngtcp2_ccerr_set_application_error(&error,0,nullptr,0);
            if (mode=="reject" && tls.alert()) {
                n::ngtcp2_ccerr_default(&error);
                error.error_code=0x100u+tls.alert(); // RFC9000 CRYPTO_ERROR carries the TLS alert.
            }
            auto closed=connection.write_close(output,nullptr,nullptr,error,now());
            if (mode=="reject") std::println("QUIC rejection close size={} error={} alert={}",closed ? *closed : 0,closed ? 0 : closed.error(),tls.alert());
            if (closed && *closed) (void)socket.send(peer,std::span(output).first(*closed));
        }
        auto actual_resume=tls.resumed();
        if(passed&&(server?tls.retries!=(retry?1u:0u):tls.hellos!=(retry?2u:1u))){failure=35;passed=false;}
        if (passed && actual_resume!=expected_resume) {failure=34;passed=false;}
        connection.stop(); socket.close();
        if (record_contexts) return 15;
        std::cerr<<"TCP RecordLayer contexts="<<record_contexts<<"\n";
        if (memory.live || connection.key_slots() || application.before_auth || application.closed!=(started ? 1u : 0u) || tls.pending_handshake_bytes()) return 13;
        std::println("QUIC PSK UDP round={} resumed={} {}={} sent={} received={} dropped={} acked={} native_peak={} started={} authenticated={} client_hellos={} hrr={} failure={}",round,actual_resume,server ? "server" : "client",passed,sent_packets,received_packets,dropped,application.acked,memory.peak,started,application.completed,tls.hellos,tls.retries,failure);
        return passed && !failure ? 0 : 20+failure;
    }
}
auto track_record(t::RecordDirection,c::Aead,View,View,std::uint64_t) -> std::expected<t::RecordLayer,t::RecordError>
    asm("__wrap__ZN5nexus3tlsW5nexusW3tlsW6record11RecordLayer6createENS0_S3_15RecordDirectionENS_6cryptoS1_W6crypto4AeadESt4spanIKhLm18446744073709551615EESB_m");
auto track_record(t::RecordDirection,c::Aead,View,View,std::uint64_t) -> std::expected<t::RecordLayer,t::RecordError> {
    ++record_contexts; return std::unexpected(t::RecordError::invalid_state);
}
int main(int argc,char** argv){
 if(argc!=10){std::println("usage: quic-psk client|server 4|6 PORT CERT.der KEY.der GROUP CIPHER direct|hrr|fallback NAME");return 1;}
 try{
  if(std::getenv("NEXUS_FINGERPRINT_WRAPPED")){
   auto calibrated=t::RecordLayer::create(t::RecordDirection::send,c::Aead::aes_128_gcm,std::array<std::uint8_t,16>{},std::array<std::uint8_t,12>{});
   if(calibrated||record_contexts!=1)return 40;record_contexts=0;
  }
  bool server=std::string_view(argv[1])=="server",ipv6=std::string_view(argv[2])=="6";
  auto port=static_cast<unsigned>(std::stoul(argv[3]));auto cert=read(argv[4]);auto group=static_cast<std::uint16_t>(std::stoul(argv[6],nullptr,0));auto suite=static_cast<std::uint16_t>(std::stoul(argv[7],nullptr,0));auto mode=std::string_view(argv[8]);
  bool retry=mode.starts_with("hrr"),fallback=mode.ends_with("fallback");t::ResumptionCache<8> cache;t::ServerTicketStore<8> store;
  std::optional<t::ServerCredential> credential;if(server){auto key=read(argv[5]);auto value=t::ServerCredential::create(cert,key);c::cleanse(key);if(!value)return 2;credential.emplace(std::move(*value));}
  for(unsigned round=0;round<3;++round){
   int result;
   if(server){if(round==1&&fallback)store.clear();auto setup=q::ServerResumptionSetup<t::ServerTicketStore<8>>::create(*credential,"h3",store);if(!setup)return 3;ObservedTls<q::ResumingTlsServer<t::ServerTicketStore<8>>> tls(std::move(*setup));result=run(tls,true,ipv6,port,mode,retry&&group!=4588,nullptr,&store,round,round!=0&&!(round==1&&fallback));}
   else{std::array<View,1> anchors{cert};std::array<std::uint16_t,1> groups{group};std::array<std::string_view,1> protocols{"h3"};auto hello=t::make_client_hello("localhost",protocols,groups);if(!hello)return 4;hello->cipher_suites={suite};
    auto time=std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();auto setup=q::ClientResumptionSetup<t::ResumptionCache<8>>::create(std::move(*hello),retry?std::span<std::uint16_t const>{}:std::span<std::uint16_t const>(groups),anchors,t::PeerNameKind::dns,bytes(argv[9]),time,"h3",cache);if(!setup)return 5;ObservedTls<q::ResumingTlsClient<t::ResumptionCache<8>>> tls(std::move(*setup));result=run(tls,false,ipv6,port,mode,retry,&cache,nullptr,round,round!=0&&!(round==1&&fallback));}
   if(result)return result;
  }
  std::println("QUIC PSK UDP three authenticated connections and ticket renewal passed");
 }catch(std::exception const& e){std::println("QUIC PSK UDP exception {}",e.what());return 99;}
}
