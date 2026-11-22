import std;
import crypto;
import net.udp_socket;
import quic.connection;
import quic.tls_client;
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
    struct Pki {
        View anchor; std::string_view name;
        auto operator()(std::span<View const> chain) const -> bool {
            std::array<View,1> anchors{anchor};
            auto seconds=std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
            return t::verify_server_certificate_chain(chain,anchors,t::PeerNameKind::dns,bytes(name),seconds).has_value();
        }
    };
    template<class Connection> struct ObservedConnection {
        Connection& connection; unsigned& hellos; unsigned& retries;
        template<class... Args> auto install_secret(Args&&... args) { return connection.install_secret(std::forward<Args>(args)...); }
        auto complete_handshake() { return connection.complete_handshake(); }
        auto remote_transport_parameters(View input) { return connection.remote_transport_parameters(input); }
        auto local_transport_parameters(std::span<std::uint8_t> output) { return connection.local_transport_parameters(output); }
        auto tls_alert(std::uint8_t alert) noexcept { connection.tls_alert(alert); }
        auto submit_crypto(n::ngtcp2_encryption_level level,View input) -> int {
            if (level==n::NGTCP2_ENCRYPTION_LEVEL_INITIAL && input.size()>=4) {
                if (input[0]==1) {
                    ++hellos;
                    auto parsed=t::ClientHello::parse(input.subspan(4));
                    if (!parsed || input.size()!=1600 || !parsed->session_id.empty() || !t::is_grease(parsed->cipher_suites.front()) ||
                        !t::is_grease(parsed->extensions.front().type) || !parsed->extension(0x39) || !parsed->extension(21)) return n::err_callback_failure;
                    auto shares=t::KeyShare::parse_client(parsed->extension(51)->data); if (!shares) return n::err_callback_failure;
                    auto group_count=std::ranges::count_if(*shares,[](auto const& entry) {return !t::is_grease(entry.group);});
                    std::cerr<<"FINGERPRINT hello="<<hellos<<" wire="<<input.size()<<" groups="<<group_count<<" grease=true empty_session=true\n";
                }
                if (input[0]==2) { auto parsed=t::ServerHello::parse(input.subspan(4)); if (parsed && parsed->is_retry()) ++retries; }
            }
            return connection.submit_crypto(level,input);
        }
    };
    template<class Core> struct ObservedTls {
        Core& core; unsigned hellos=0,retries=0;
        auto complete() const noexcept { return core.complete(); }
        auto alert() const noexcept { return core.alert(); }
        auto pending_handshake_bytes() const noexcept { return core.pending_handshake_bytes(); }
        auto cancel() noexcept -> void { core.cancel(); }
        template<class Connection> auto start(Connection& connection) { ObservedConnection view{connection,hellos,retries}; return core.start(view); }
        template<class Connection> auto receive(Connection& connection,n::ngtcp2_encryption_level level,std::uint64_t offset,View input) {
            ObservedConnection view{connection,hellos,retries}; return core.receive(view,level,offset,input);
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
        template<class Connection> auto connection_closed(Connection& connection,int) noexcept -> void { if (connection.native()) std::terminate(); ++closed; tls.cancel(); }
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
    auto run(Tls& tls,bool server,bool ipv6,unsigned port,std::string_view mode,bool retry) -> int {
        net::UdpSocket socket;
        net::UdpEndpoint local{ipv6 ? std::uint8_t{6} : std::uint8_t{4},{},0},peer=local;
        if (ipv6) local.address[15]=1; else { local.address[0]=127; local.address[3]=1; }
        peer=local; peer.port=port;
        if (!socket.bind(local)) return 1;
        auto bound=socket.local_endpoint(); if (!bound) return 2; local=*bound;
        Memory memory; Application application(tls); q::Connection connection(tls,application); Path path;
        std::array<std::uint8_t,65535> input{}; std::array<std::uint8_t,1500> output{};
        std::size_t pending=0,offset=0; bool started=false,sent_fin=false,passed=false;
        unsigned sent_packets=0,received_packets=0,dropped=0;
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
                    if (!server && application.stream==-1 && n::ngtcp2_conn_open_bidi_stream(connection.native(),&application.stream,nullptr)) { failure=9; break; }
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
                        std::ranges::equal(std::span(application.received_datagram).first(application.datagram_size),datagram)) { passed=true; break; }
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
        if (passed && (mode=="normal" || mode=="loss") && (server ? tls.retries!=(retry ? 1u : 0u) : tls.hellos!=(retry ? 2u : 1u))) { passed=false; failure=14; }
        connection.stop(); socket.close();
        if (record_contexts) return 15;
        std::cerr<<"TCP RecordLayer contexts="<<record_contexts<<"\n";
        if (memory.live || connection.key_slots() || application.before_auth || application.closed!=(started ? 1u : 0u) || tls.pending_handshake_bytes()) return 13;
        std::println("QUIC UDP {}={} sent={} received={} dropped={} acked={} native_peak={} started={} authenticated={} client_hellos={} hrr={} failure={}",server ? "server" : "client",passed,sent_packets,received_packets,dropped,application.acked,memory.peak,started,application.completed,tls.hellos,tls.retries,failure);
        return passed && !failure ? 0 : 20+failure;
    }
}
auto track_record(t::RecordDirection,c::Aead,View,View,std::uint64_t) -> std::expected<t::RecordLayer,t::RecordError>
    asm("__wrap__ZN5nexus3tlsW5nexusW3tlsW6record11RecordLayer6createENS0_S3_15RecordDirectionENS_6cryptoS1_W6crypto4AeadESt4spanIKhLm18446744073709551615EESB_m");
auto track_record(t::RecordDirection,c::Aead,View,View,std::uint64_t) -> std::expected<t::RecordLayer,t::RecordError> {
    ++record_contexts; return std::unexpected(t::RecordError::invalid_state);
}
auto main(int argc,char** argv) -> int {
    if (argc!=10 && argc!=11 && argc!=12) { std::println("usage: quic-udp-fixture client|server 4|6 PORT CERT.der KEY.der SCHEME x|hybrid|retry MODE NAME [CIPHER [SIGNATURE]]"); return 1; }
    try {
        if (std::getenv("NEXUS_FINGERPRINT_WRAPPED")) {
            auto calibrated=t::RecordLayer::create(t::RecordDirection::send,c::Aead::aes_128_gcm,std::array<std::uint8_t,16>{},std::array<std::uint8_t,12>{});
            if (calibrated || record_contexts!=1) return 4;
            record_contexts=0;
        }
        bool server=std::string_view(argv[1])=="server",ipv6=std::string_view(argv[2])=="6";
        auto port=static_cast<unsigned>(std::stoul(argv[3])); auto scheme=static_cast<std::uint16_t>(std::stoul(argv[6],nullptr,0));
        auto cert=read(argv[4]); auto kind=std::string_view(argv[7]),mode=std::string_view(argv[8]);
        bool hybrid=kind=="hybrid",retry=kind=="retry" || kind.ends_with("-retry");
        if (server) {
            auto key=read(argv[5]); auto credential=t::ServerCredential::create(cert,key); c::cleanse(key); if (!credential) return 2;
            q::TlsServer core(*credential,"h3"); ObservedTls tls{core}; return run(tls,true,ipv6,port,mode,retry);
        }
        auto cipher=argc>=11 ? static_cast<std::uint16_t>(std::stoul(argv[10],nullptr,0)) : std::uint16_t{0};
        t::FingerprintConfig policy;
        policy.profile=t::Fingerprint::tls13_randomized;
        policy.shares=retry ? t::FingerprintShares::retry : hybrid ? t::FingerprintShares::hybrid : t::FingerprintShares::dual;
        policy.cipher_count=cipher ? 1 : 2;
        if (cipher) policy.cipher_order[0]=cipher;
        if (kind.starts_with("p256") || kind.starts_with("p384") || kind.starts_with("p521")) {
            policy.group_count=1;policy.group_order[0]=kind.starts_with("p256") ? 23 : kind.starts_with("p384") ? 24 : 25;
            policy.key_share_count=retry ? 0 : 1;policy.key_share_groups[0]=policy.group_order[0];
        }
        policy.pad_to=1600;
        if (argc==12) { policy.signature_count=1;policy.signature_order[0]=static_cast<std::uint16_t>(std::stoul(argv[11],nullptr,0)); }
        std::array<std::string_view,1> alpn{"h3"};
        auto shape=t::make_fingerprint_hello("localhost",alpn,policy,t::HandshakeTransport::quic,std::span<std::uint8_t const>{});
        if (!shape) return 3;
        q::TlsClient core(std::move(shape->hello),shape->initial_groups(),Pki{cert,argv[9]},"h3"); ObservedTls tls{core};
        return run(tls,false,ipv6,port,mode,retry);
    } catch (std::exception const& error) { std::println("QUIC UDP exception {}",error.what()); return 99; }
}
