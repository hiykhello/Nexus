import std;
import crypto;
import quic.connection;
import quic.varint;
import quic.tls_client;
import quic.tls_server;
import nexus.thirdparty.ngtcp2;
import tls.hello;
import tls.handshake;
import tls.server_credential;
import tls.certificate_trust;
import tls.record;
import tls.hybrid;

namespace q=quic;
namespace n=nex::ngtcp2;
namespace t=tls;
namespace c = ::crypto;
namespace allocations {
    bool enabled=false,denied=false;
    std::ptrdiff_t allowance=-1;
    std::size_t live=0,calls=0;
    unsigned stage=0,denied_stage=0;
    struct Stage { unsigned previous; explicit Stage(unsigned value):previous(std::exchange(stage,value)) {} ~Stage() { stage=previous; } };
    auto allocate(std::size_t size,std::size_t alignment=alignof(std::max_align_t)) -> void* {
        if (enabled) { ++calls; if (!allowance) { denied=true; denied_stage=stage; throw std::bad_alloc(); } if (allowance>0) --allowance; }
        size=std::max<std::size_t>(size,1);
        if (size>std::numeric_limits<std::size_t>::max()-alignment) throw std::bad_alloc();
        auto* pointer=std::aligned_alloc(alignment,(size+alignment-1)/alignment*alignment);
        if (!pointer) throw std::bad_alloc();
        ++live; return pointer;
    }
    auto release(void* pointer) noexcept -> void { if (pointer) { --live; std::free(pointer); } }
}
auto operator new(std::size_t size) -> void* { return allocations::allocate(size); }
auto operator new[](std::size_t size) -> void* { return allocations::allocate(size); }
auto operator new(std::size_t size,std::align_val_t alignment) -> void* { return allocations::allocate(size,static_cast<std::size_t>(alignment)); }
auto operator new[](std::size_t size,std::align_val_t alignment) -> void* { return allocations::allocate(size,static_cast<std::size_t>(alignment)); }
auto operator delete(void* pointer) noexcept -> void { allocations::release(pointer); }
auto operator delete[](void* pointer) noexcept -> void { allocations::release(pointer); }
auto operator delete(void* pointer,std::size_t) noexcept -> void { allocations::release(pointer); }
auto operator delete[](void* pointer,std::size_t) noexcept -> void { allocations::release(pointer); }
auto operator delete(void* pointer,std::align_val_t) noexcept -> void { allocations::release(pointer); }
auto operator delete[](void* pointer,std::align_val_t) noexcept -> void { allocations::release(pointer); }
auto operator delete(void* pointer,std::size_t,std::align_val_t) noexcept -> void { allocations::release(pointer); }
auto operator delete[](void* pointer,std::size_t,std::align_val_t) noexcept -> void { allocations::release(pointer); }
namespace {
    template<std::size_t Size> auto hex(std::string_view input) -> std::array<std::uint8_t,Size> {
        if (input.size()!=2*Size) throw std::invalid_argument("hex length");
        auto digit=[](char value) -> unsigned { return value<='9' ? value-'0' : value-'a'+10; };
        std::array<std::uint8_t,Size> output{};
        for (std::size_t i=0;i<Size;++i) output[i]=static_cast<std::uint8_t>((digit(input[2*i])<<4)|digit(input[2*i+1]));
        return output;
    }
    struct Memory {
        struct alignas(std::max_align_t) Header { std::size_t bytes; };
        std::size_t used=0,peak=0,allocations=0,frees=0,denied=0,limit=4*1024*1024;
        std::ptrdiff_t allowance=-1;
        static auto allocate(std::size_t size,void* owner) noexcept -> void* {
            auto& self=*static_cast<Memory*>(owner);
            if (!self.allowance) { ++self.denied; return nullptr; }
            if (size>std::numeric_limits<std::size_t>::max()-sizeof(Header)) return nullptr;
            if (self.allowance>0) --self.allowance;
            auto total=std::max<std::size_t>(size,1)+sizeof(Header);
            if (total>self.limit-self.used) return nullptr;
            auto* pointer=static_cast<Header*>(std::malloc(total)); if (!pointer) return nullptr;
            pointer->bytes=total; self.used+=total; self.peak=std::max(self.peak,self.used); ++self.allocations; return pointer+1;
        }
        static auto release(void* pointer,void* owner) noexcept -> void {
            if (!pointer) return;
            auto& self=*static_cast<Memory*>(owner); auto* block=static_cast<Header*>(pointer)-1; auto bytes=block->bytes;
            ::crypto::cleanse({reinterpret_cast<std::uint8_t*>(block),bytes}); std::free(block); self.used-=bytes; ++self.frees;
        }
        static auto zero(std::size_t count,std::size_t size,void* owner) noexcept -> void* {
            if (size && count>std::numeric_limits<std::size_t>::max()/size) return nullptr;
            auto bytes=count*size; auto* pointer=allocate(bytes,owner); if (pointer) std::memset(pointer,0,bytes); return pointer;
        }
        static auto resize(void* pointer,std::size_t size,void* owner) noexcept -> void* {
            if (!pointer) return allocate(size,owner);
            if (!size) { release(pointer,owner); return nullptr; }
            auto* next=allocate(size,owner); if (!next) return nullptr;
            auto old=(static_cast<Header*>(pointer)-1)->bytes-sizeof(Header); std::memcpy(next,pointer,std::min(old,size)); release(pointer,owner); return next;
        }
        auto callbacks() noexcept -> n::ngtcp2_mem { return {this,allocate,release,zero,resize}; }
    };
    struct Path {
        n::ngtcp2_sockaddr_in local{},remote{};
        n::ngtcp2_path value{};
        explicit Path(bool server) {
            local.sin_family=remote.sin_family=n::af_inet;
            auto port=[](unsigned value) { return std::bit_cast<std::uint16_t>(std::array<std::uint8_t,2>{static_cast<std::uint8_t>(value>>8),static_cast<std::uint8_t>(value)}); };
            local.sin_port=port(server ? 443 : 12345); remote.sin_port=port(server ? 12345 : 443);
            local.sin_addr.s_addr=remote.sin_addr.s_addr=std::bit_cast<std::uint32_t>(std::array<std::uint8_t,4>{127,0,0,1});
            value={{reinterpret_cast<n::ngtcp2_sockaddr*>(&local),sizeof(local)},{reinterpret_cast<n::ngtcp2_sockaddr*>(&remote),sizeof(remote)},nullptr};
        }
    };
    auto cid(std::span<std::uint8_t const> bytes) -> n::ngtcp2_cid { n::ngtcp2_cid result{}; n::ngtcp2_cid_init(&result,bytes.data(),bytes.size()); return result; }
    auto settings() -> n::ngtcp2_settings {
        n::ngtcp2_settings result{}; n::ngtcp2_settings_default_versioned(n::settings_version,&result);
        result.initial_ts=1; result.handshake_timeout=10*n::seconds; return result;
    }
    auto parameters(bool server) -> n::ngtcp2_transport_params {
        n::ngtcp2_transport_params result{}; n::ngtcp2_transport_params_default_versioned(n::transport_params_version,&result);
        result.initial_max_data=65536; result.initial_max_stream_data_bidi_local=result.initial_max_stream_data_bidi_remote=result.initial_max_stream_data_uni=4096;
        result.initial_max_streams_bidi=16; result.initial_max_streams_uni=3; result.max_datagram_frame_size=1200; result.disable_active_migration=1;
        if (server) { result.original_dcid=cid(hex<8>("8394c8f03e515708")); result.original_dcid_present=1; }
        return result;
    }
    using View=std::span<std::uint8_t const>;
    auto bytes(std::string_view value) noexcept -> View { return {reinterpret_cast<std::uint8_t const*>(value.data()),value.size()}; }
    auto read(std::string_view path) -> c::Bytes { std::ifstream input(std::string(path),std::ios::binary); return {std::istreambuf_iterator<char>(input),{}}; }
    std::size_t record_contexts=0;
    std::uint16_t requested_signature=0;
    struct Pki {
        View anchor;
        std::string_view name;
        std::int64_t time;
        unsigned exception=0;
        auto operator()(std::span<View const> chain) const -> bool {
            if (exception==1) throw std::runtime_error("certificate policy exception");
            if (exception==2) throw std::bad_alloc();
            std::array<View,1> anchors{anchor};
            return t::verify_server_certificate_chain(chain,anchors,t::PeerNameKind::dns,bytes(name),time).has_value();
        }
    };
    template<class Connection> struct FaultView {
        Connection& connection;
        unsigned mode;
        bool server;
        template<class... Args> auto install_secret(Args&&... args) { return connection.install_secret(std::forward<Args>(args)...); }
        auto complete_handshake() { return connection.complete_handshake(); }
        auto remote_transport_parameters(View input) { return connection.remote_transport_parameters(input); }
        auto tls_alert(std::uint8_t value) noexcept { connection.tls_alert(value); }
        auto local_transport_parameters(std::span<std::uint8_t> output) -> std::expected<std::size_t,int> {
            if (!server || mode<10 || mode>13) return connection.local_transport_parameters(output);
            if (mode==12) return std::size_t{0}; // Signed extension, missing all required QUIC parameter values.
            auto extra=mode==11 ? 10u : mode==13 ? 4u : 0u;
            auto native=connection.local_transport_parameters(output.empty() ? output : output.first(output.size()-extra));
            if (!native || output.empty()) return native ? std::expected<std::size_t,int>(*native+extra) : native;
            std::span<std::uint8_t> source_id;
            for (std::size_t offset=0;offset<*native;) {
                auto id=q::read_varint(output.subspan(offset)); if (id.status!=q::VarintStatus::accepted) return std::unexpected(n::err_callback_failure); offset+=id.consumed;
                auto size=q::read_varint(output.subspan(offset)); if (size.status!=q::VarintStatus::accepted) return std::unexpected(n::err_callback_failure); offset+=size.consumed;
                if (size.value>*native-offset) return std::unexpected(n::err_callback_failure);
                if (id.value==0x0f) source_id=output.subspan(offset,size.value);
                offset+=size.value;
            }
            if (source_id.size()!=8) return std::unexpected(n::err_callback_failure);
            if (mode==10) source_id[0]^=1; // Signed TP identity differs from the authenticated QUIC packet SCID.
            if (mode==11) { output[*native]=0x0f; output[*native+1]=8; std::ranges::copy(source_id,output.begin()+*native+2); }
            if (mode==13) std::ranges::copy(std::array<std::uint8_t,4>{3,2,0x44,0xaf},output.begin()+*native); // max_udp_payload_size=1199.
            return *native+extra;
        }
        auto submit_crypto(n::ngtcp2_encryption_level level,View input) -> int {
            if (level==n::NGTCP2_ENCRYPTION_LEVEL_HANDSHAKE && !input.empty() &&
                ((server && ((mode==7 && input[0]==15) || (mode==8 && input[0]==20))) || (!server && (mode==9 || mode==14 || mode==15) && input[0]==20))) {
                c::Bytes changed(input.begin(),input.end());
                if (mode==14 || mode==15) changed[0]=mode==14 ? 5 : 24; else changed.back()^=1;
                return connection.submit_crypto(level,changed);
            }
            return connection.submit_crypto(level,input);
        }
    };
    template<class Core> struct FaultTls {
        Core& core;
        unsigned mode;
        bool server;
        auto complete() const noexcept -> bool { return core.complete(); }
        auto alert() const noexcept -> std::uint8_t { return core.alert(); }
        auto pending_handshake_bytes() const noexcept -> std::size_t { return core.pending_handshake_bytes(); }
        auto cancel() noexcept -> void { core.cancel(); }
        template<class Connection> auto start(Connection& connection) -> int { allocations::Stage stage(1); FaultView view{connection,mode,server}; return core.start(view); }
        template<class Connection> auto receive(Connection& connection,n::ngtcp2_encryption_level level,std::uint64_t offset,View input) -> int {
            allocations::Stage stage(2); FaultView view{connection,mode,server}; auto error=core.receive(view,level,offset,input);
            if (mode==16) connection.stop();
            return error;
        }
    };
    template<class Tls> struct Application {
        Tls& tls;
        unsigned completed=0,confirmed=0,closed=0,streams=0,datagrams=0;
        std::size_t acked=0;
        bool business_before_auth=false,fin=false;
        c::Bytes data,datagram_data;
        explicit Application(Tls& value):tls(value) {}
        template<class Connection> auto connection_closed(Connection& connection,int) noexcept -> void {
            if (connection.native()) std::terminate();
            ++closed; tls.cancel();
        }
        template<class Connection> auto handshake_complete(Connection&) -> int { if (!tls.complete()) return n::err_callback_failure; ++completed; return 0; }
        template<class Connection> auto handshake_confirmed(Connection&) -> int { if (!tls.complete()) return n::err_callback_failure; ++confirmed; return 0; }
        template<class Connection> auto stream_data(Connection& connection,std::uint32_t flags,std::int64_t id,std::uint64_t offset,View input,void*) -> int {
            business_before_auth|=!tls.complete();
            if (business_before_auth || offset!=data.size() || data.size()>65536-input.size()) return n::err_callback_failure;
            ++streams; data.insert(data.end(),input.begin(),input.end()); fin|=bool(flags&n::stream_data_flag_fin);
            auto error=n::ngtcp2_conn_extend_max_stream_offset(connection.native(),id,input.size());
            if (!error) n::ngtcp2_conn_extend_max_offset(connection.native(),input.size());
            return error;
        }
        template<class Connection> auto stream_acked(Connection&,std::int64_t,std::uint64_t,std::uint64_t size,void*) -> int { acked+=size; return 0; }
        template<class... Args> auto stream_close(Args&&...) -> int { return 0; }
        template<class... Args> auto stream_reset(Args&&...) -> int { return 0; }
        template<class... Args> auto stop_sending(Args&&...) -> int { return 0; }
        template<class... Args> auto stream_limit(Args&&...) -> int { return 0; }
        template<class Connection> auto datagram(Connection&,View input) -> int {
            business_before_auth|=!tls.complete(); if (business_before_auth) return n::err_callback_failure;
            ++datagrams; datagram_data.assign(input.begin(),input.end()); return 0;
        }
        template<class... Args> auto add_connection_id(Args&&...) -> int { return 0; }
        template<class... Args> auto remove_connection_id(Args&&...) -> int { return 0; }
    };
    auto hello(std::uint16_t suite,bool hybrid,std::uint16_t scheme) -> t::ClientHello {
        auto group=hybrid ? t::x25519_mlkem768_group : std::uint16_t{29};
        t::ClientHello value; value.random.fill(9); value.cipher_suites={suite}; value.compression_methods={0};
        value.extensions={{43,{2,3,4}},{10,{0,2,static_cast<std::uint8_t>(group>>8),static_cast<std::uint8_t>(group)}},{13,{0,2,static_cast<std::uint8_t>(scheme>>8),static_cast<std::uint8_t>(scheme)}},{51,{0,0}},{16,{0,3,2,'h','3'}}};
        return value;
    }
    struct EndpointError { int side=0,code=0; };
    template<class Sender,class Receiver>
    auto transfer(Sender& sender,Receiver& receiver,Path& destination,std::uint64_t& now,unsigned& packets,unsigned drop_at=0) -> std::expected<bool,int> {
        std::array<std::uint8_t,1500> output{};
        auto written=sender.write_packet(output,nullptr,nullptr,now+=1000000);
        if (!written) return std::unexpected(written.error());
        if (!*written) return false;
        ++packets;
        if (packets==drop_at) return true;
        auto error=receiver.read(destination.value,nullptr,std::span(output).first(*written),now+=1000000);
        if (error) return std::unexpected(error);
        return true;
    }
    template<class Client,class Server>
    auto pump(Client& client,Server& server,Path& client_path,Path& server_path,std::uint64_t& now,unsigned& client_packets,unsigned& server_packets,unsigned rounds=1,unsigned drop_client=0,unsigned drop_server=0) -> EndpointError {
        for (unsigned i=0;i<rounds;++i) {
            auto first=transfer(client,server,server_path,now,client_packets,drop_client);
            if (!first) return {1,first.error()};
            auto second=transfer(server,client,client_path,now,server_packets,drop_server);
            if (!second) return {2,second.error()};
            for (auto* connection:{client.native(),server.native()}) {
                auto expiry=n::ngtcp2_conn_get_expiry2(connection);
                if (expiry<=now) { auto error=n::ngtcp2_conn_handle_expiry(connection,now); if (error) return {3,error}; }
            }
        }
        return {};
    }
    auto authenticated_pair(t::ServerCredential const& credential,View anchor,View wrong_anchor,std::uint16_t suite,bool hybrid,bool retry,unsigned mutation,bool drop) -> int {
        auto profile=hello(suite,hybrid,requested_signature ? requested_signature : *credential.scheme());
        if (mutation==3) profile.session_id={1};
        if (mutation==4) profile.cipher_suites={0x1304}; // CCM remains unsupported; 1303 is now a real capability.
        if (mutation==5) profile.extensions.back().data={0,3,2,'h','2'};
        auto verification_time=std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
        using ClientTls=q::TlsClient<Pki>;
        ClientTls client_core(std::move(profile),retry ? 0 : hybrid ? t::x25519_mlkem768_group : 29,Pki{mutation==6 ? wrong_anchor : anchor,mutation==1 ? "wrong.example" : "localhost",verification_time},"h3");
        q::TlsServer server_core(credential,mutation==2 ? "h2" : "h3");
        FaultTls client_tls{client_core,mutation,false}; FaultTls server_tls{server_core,mutation,true};
        Memory client_memory,server_memory; Path client_path(false),server_path(true);
        Application client_app(client_tls); Application server_app(server_tls);
        q::Connection client(client_tls,client_app); q::Connection server(server_tls,server_app);
        auto initial=cid(hex<8>("8394c8f03e515708")),client_id=cid(hex<8>("0001020304050607")),server_id=cid(hex<8>("f067a5502a4262b5"));
        if (client.start(false,initial,client_id,client_path.value,settings(),parameters(false),client_memory.callbacks()) ||
            server.start(true,client_id,server_id,server_path.value,settings(),parameters(true),server_memory.callbacks())) return 1;
        std::uint64_t now=2; unsigned client_packets=0,server_packets=0; EndpointError failure;
        for (unsigned round=0;round<3000 && (!client_tls.complete() || !server_tls.complete() || !client_app.completed || !server_app.completed);++round) {
            failure=pump(client,server,client_path,server_path,now,client_packets,server_packets,1,drop ? 1 : 0,drop ? 1 : 0);
            if (failure.code) break;
        }
        if (mutation) {
            bool server_rejects=mutation==2 || mutation==9 || mutation==14 || mutation==15;
            auto alert=server_rejects ? server_tls.alert() : client_tls.alert();
            auto expected=(mutation==1 || mutation==6) ? 42 : (mutation==2 || mutation==5) ? 120 : (mutation>=7 && mutation<=9) ? 51 : mutation>=14 ? 10 : 47;
            bool client_finished_sent=mutation==9 || mutation==14 || mutation==15;
            // Exact error codes from fixed ngtcp2 v1.25.0 public header.
            auto native_error=mutation==10 || mutation==13 ? -225 : mutation==11 ? -225 : mutation==12 ? -215 : 0;
            if (!failure.code || (native_error && failure.code!=native_error) || alert!=expected || client_app.streams || server_app.streams || client_app.datagrams || server_app.datagrams || client_tls.complete()!=client_finished_sent || server_tls.complete()) {
                std::println("negative mutation={} error side/code={}/{} alerts={}/{} expected={} complete={}/{}",mutation,failure.side,failure.code,client_tls.alert(),server_tls.alert(),expected,client_tls.complete(),server_tls.complete()); return 2;
            }
        } else {
            if (failure.code || !client_tls.complete() || !server_tls.complete() || client_app.completed!=1 || server_app.completed!=1 || !n::ngtcp2_conn_get_handshake_completed2(client.native()) || !n::ngtcp2_conn_get_handshake_completed2(server.native())) {
                std::println("handshake error side/code={}/{} alerts={}/{} complete={}/{} callbacks={}/{} packets={}/{} now={}",failure.side,failure.code,client_tls.alert(),server_tls.alert(),client_tls.complete(),server_tls.complete(),client_app.completed,server_app.completed,client_packets,server_packets,now); return 3;
            }
            // Exercise actual encrypted key-phase transition, not just HKDF
            // vectors or installation calls. The following stream/ACK/DATAGRAM
            // transfer must authenticate after the client changes its keys.
            for (unsigned round=0;round<100 && !client_app.confirmed;++round) {
                failure=pump(client,server,client_path,server_path,now,client_packets,server_packets);
                if (failure.code) return 24;
            }
            if (client_app.confirmed!=1) return 25;
            auto updated=n::ngtcp2_conn_initiate_key_update(client.native(),now+=1000000);
            if (updated) { std::println("native key-phase update failed {} suite={:04x}",updated,suite); return 26; }
            c::Bytes payload(12000); for (std::size_t i=0;i<payload.size();++i) payload[i]=static_cast<std::uint8_t>(i*73);
            std::int64_t stream=-1; if (n::ngtcp2_conn_open_bidi_stream(client.native(),&stream,nullptr)) return 4;
            std::size_t offset=0; bool sent_fin=false;
            for (unsigned round=0;round<2000 && (server_app.data.size()!=payload.size() || !server_app.fin || client_app.acked!=payload.size());++round) {
                if (!sent_fin) {
                    std::array<std::uint8_t,1500> output{}; n::ngtcp2_vec input{payload.data()+offset,payload.size()-offset};
                    auto written=client.write_stream(output,nullptr,nullptr,stream,std::span(&input,1),true,now+=1000000);
                    if (!written) { std::println("stream write failed {}",written.error()); return 5; }
                    if (written->stream_bytes>=0) { offset+=static_cast<std::size_t>(written->stream_bytes); sent_fin=offset==payload.size(); }
                    if (written->packet_bytes) {
                        auto error=server.read(server_path.value,nullptr,std::span(output).first(written->packet_bytes),now+=1000000); if (error) return 6;
                    }
                }
                failure=pump(client,server,client_path,server_path,now,client_packets,server_packets);
                if (failure.code) return 7;
            }
            if (offset!=payload.size() || !sent_fin || server_app.data!=payload || !server_app.fin || client_app.acked!=payload.size() || server_app.business_before_auth) return 8;
            std::array<std::uint8_t,3> datagram{0,1,255}; bool accepted=false;
            for (unsigned round=0;round<100 && !server_app.datagrams;++round) {
                if (!accepted) {
                    std::array<std::uint8_t,1500> output{}; n::ngtcp2_vec input{datagram.data(),datagram.size()};
                    auto written=client.write_datagram(output,nullptr,nullptr,1,std::span(&input,1),now+=1000000);
                    if (!written) return 9;
                    accepted=written->accepted;
                    if (written->packet_bytes && server.read(server_path.value,nullptr,std::span(output).first(written->packet_bytes),now+=1000000)) return 10;
                }
                failure=pump(client,server,client_path,server_path,now,client_packets,server_packets);
                if (failure.code) return 11;
            }
            if (!accepted || server_app.datagrams!=1 || !std::ranges::equal(server_app.datagram_data,datagram) || server_app.business_before_auth) return 12;
            // Fragmented and coalesced post-handshake tickets are validated and
            // discarded using the same parser as TCP, without a TLS key update.
            std::array<std::uint8_t,18> ticket{4,0,0,14,0,0,0,1,0,0,0,2,0,0,1,7,0,0};
            if (server.submit_crypto(n::NGTCP2_ENCRYPTION_LEVEL_1RTT,std::span(ticket).first(3))) return 14;
            for (unsigned round=0;round<100 && client_tls.pending_handshake_bytes()!=3;++round) {
                failure=pump(client,server,client_path,server_path,now,client_packets,server_packets); if (failure.code) return 15;
            }
            if (client_tls.pending_handshake_bytes()!=3 || !client_tls.complete()) return 16;
            c::Bytes joined(ticket.begin()+3,ticket.end()); joined.insert(joined.end(),ticket.begin(),ticket.end());
            if (server.submit_crypto(n::NGTCP2_ENCRYPTION_LEVEL_1RTT,joined)) return 17;
            for (unsigned round=0;round<100 && client_tls.pending_handshake_bytes();++round) {
                failure=pump(client,server,client_path,server_path,now,client_packets,server_packets); if (failure.code) return 18;
            }
            if (client_tls.pending_handshake_bytes() || !client_tls.complete() || client_app.completed!=1) return 19;
            if (server.submit_crypto(n::NGTCP2_ENCRYPTION_LEVEL_1RTT,std::array<std::uint8_t,5>{24,0,0,1,0})) return 20;
            failure={};
            for (unsigned round=0;round<100 && !failure.code;++round) failure=pump(client,server,client_path,server_path,now,client_packets,server_packets);
            if (failure.side!=2 || failure.code!=n::err_crypto || client_tls.alert()!=10 || client_tls.complete()) return 21;

        }
        client.stop(); server.stop();
        if (client_memory.used || server_memory.used || client.key_slots() || server.key_slots() || client_app.closed!=1 || server_app.closed!=1 || record_contexts) return 13;
        return 0;
    }
    struct Trial { int error=0; bool complete=false,clean=false,denied=false,initial=false; std::size_t calls=0; };
    auto lifecycle(t::ServerCredential const& credential,View anchor,unsigned kind,std::ptrdiff_t allowance,bool retry,unsigned stop_after=0,unsigned exception=0,unsigned callback_stop=0,std::uint16_t suite=0x1301) -> Trial {
        auto before=allocations::live; Trial result;
        {
            using ClientTls=q::TlsClient<Pki>;
            auto now_seconds=std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
            ClientTls client_core(hello(suite,false,requested_signature ? requested_signature : *credential.scheme()),retry ? 0 : 29,Pki{anchor,"localhost",now_seconds,exception},"h3");
            q::TlsServer server_core(credential,"h3");
            FaultTls client_tls{client_core,callback_stop==2 ? 16u : 0u,false}; FaultTls server_tls{server_core,callback_stop==1 ? 16u : 0u,true};
            Memory client_memory,server_memory; Path client_path(false),server_path(true);
            Application client_app(client_tls); Application server_app(server_tls);
            q::Connection client(client_tls,client_app); q::Connection server(server_tls,server_app);
            auto initial=cid(hex<8>("8394c8f03e515708")),client_id=cid(hex<8>("0001020304050607")),server_id=cid(hex<8>("f067a5502a4262b5"));
            allocations::allowance=allowance; allocations::calls=0; allocations::denied=false; allocations::enabled=kind==0;
            if (kind==1) client_memory.allowance=allowance;
            if (kind==2) server_memory.allowance=allowance;
            auto first=client.start(false,initial,client_id,client_path.value,settings(),parameters(false),client_memory.callbacks());
            auto second=server.start(true,client_id,server_id,server_path.value,settings(),parameters(true),server_memory.callbacks());
            result.error=first ? first : second;
            std::uint64_t now=2; unsigned client_packets=0,server_packets=0,phase=0;
            for (unsigned round=0;!result.error && client.active() && server.active() && round<3000;++round) {
                auto sent=transfer(client,server,server_path,now,client_packets); if (!sent) { result.error=sent.error(); break; }
                if ((stop_after && ++phase==stop_after) || !client.active() || !server.active()) break;
                sent=transfer(server,client,client_path,now,server_packets); if (!sent) { result.error=sent.error(); break; }
                if ((stop_after && ++phase==stop_after) || !client.active() || !server.active()) break;
                if (client_tls.complete() && server_tls.complete() && client_app.completed==1 && server_app.completed==1) { result.complete=true; break; }
                for (auto* connection:{client.native(),server.native()}) if (n::ngtcp2_conn_get_expiry2(connection)<=now) {
                    auto error=n::ngtcp2_conn_handle_expiry(connection,now); if (error) { result.error=error; break; }
                }
            }
            result.calls=allocations::calls; result.denied=allocations::denied || client_memory.denied || server_memory.denied; result.initial=allocations::denied_stage!=2;
            allocations::enabled=false; client.stop(); server.stop(); client.stop(); server.stop(); client_tls.cancel(); server_tls.cancel();
            result.clean=!client.native() && !server.native() && !client_memory.used && !server_memory.used && !client.key_slots() && !server.key_slots() && client_app.closed<=1 && server_app.closed<=1 &&
                !client_tls.pending_handshake_bytes() && !server_tls.pending_handshake_bytes() && !client_app.business_before_auth && !server_app.business_before_auth;
        }
        result.clean&=allocations::live==before; return result;
    }
    auto fault_matrix(t::ServerCredential const& credential,View anchor) -> int {
        unsigned failures=0;
        for (auto suite:{std::uint16_t{0x1301},std::uint16_t{0x1303}}) for (bool retry:{false,true}) for (unsigned kind=0;kind<3;++kind) {
            bool succeeded=false;
            for (std::ptrdiff_t allowance=0;allowance<1024;++allowance) {
                auto trial=lifecycle(credential,anchor,kind,allowance,retry,0,0,0,suite);
                auto expected=trial.initial ? n::err_callback_failure : n::err_nomem;
                if (!trial.clean || (trial.denied && (trial.complete || (kind==0 ? trial.error!=expected : trial.error!=n::err_nomem && trial.error!=n::err_callback_failure)))) {
                    std::println("QUIC fault kind={} retry={} allowance={} error={} initial={} complete={} clean={} denied={}",kind,retry,allowance,trial.error,trial.initial,trial.complete,trial.clean,trial.denied); return 1;
                }
                if (!trial.denied) { if (trial.error || !trial.complete) return 2; succeeded=true; break; }
                ++failures;
            }
            if (!succeeded) return 3;
        }
        for (unsigned phase:{1u,2u}) { auto trial=lifecycle(credential,anchor,3,-1,true,phase); if (!trial.clean || trial.error || trial.complete) return 4; }
        for (unsigned side:{1u,2u}) { auto trial=lifecycle(credential,anchor,3,-1,false,0,0,side); if (!trial.clean || trial.error || trial.complete) return 5; }
        for (unsigned exception:{1u,2u}) { auto trial=lifecycle(credential,anchor,3,-1,false,0,exception); if (!trial.clean || trial.complete || trial.error!=(exception==1 ? n::err_callback_failure : n::err_nomem)) return 6; }
        std::println("QUIC raw-owner {} allocation failures plus HRR, active stop, callback stop and policy exception cleanup passed; native slots/C++ live allocations return to baseline",failures);
        return 0;
    }
}
// Linker wrapping proves the raw QUIC path never calls the TCP RecordLayer
// factory when explicitly relinked with --wrap. The optional calibration below
// must succeed before that run can make an allocation-cost assertion.
auto track_record(t::RecordDirection,c::Aead,View,View,std::uint64_t) -> std::expected<t::RecordLayer,t::RecordError>
    asm("__wrap__ZN5nexus3tlsW5nexusW3tlsW6record11RecordLayer6createENS0_S3_15RecordDirectionENS_6cryptoS1_W6crypto4AeadESt4spanIKhLm18446744073709551615EESB_m");
auto track_record(t::RecordDirection,c::Aead,View,View,std::uint64_t) -> std::expected<t::RecordLayer,t::RecordError> {
    ++record_contexts; return std::unexpected(t::RecordError::invalid_state);
}
auto main(int argc,char** argv) -> int {
    bool wrapped=false,faults=false;
    if (argc<4) { std::println("usage: quic-tls CERT.der KEY.der WRONG-CA.der [--wrapped-records] [--faults]"); return 1; }
    for (int i=4;i<argc;++i) { auto option=std::string_view(argv[i]); if (option=="--wrapped-records") wrapped=true; else if (option=="--faults") faults=true; else if (option.starts_with("--signature=")) requested_signature=static_cast<std::uint16_t>(std::stoul(std::string(option.substr(12)),nullptr,0)); else return 1; }
    try {
        if (wrapped) {
            auto calibrated=t::RecordLayer::create(t::RecordDirection::send,c::Aead::aes_128_gcm,std::array<std::uint8_t,16>{},std::array<std::uint8_t,12>{});
            if (calibrated || record_contexts!=1) { std::println("RecordLayer wrapper calibration failed; relink using quic_tls_relink.py"); return 1; }
            record_contexts=0;
        }
        auto cert=read(argv[1]),key=read(argv[2]),wrong_anchor=read(argv[3]);
        if (cert.empty() || key.empty() || wrong_anchor.empty() || cert==wrong_anchor) return 2;
        auto credential=t::ServerCredential::create(cert,key); c::cleanse(key); if (!credential) return 2;
        if (faults) { auto result=fault_matrix(*credential,cert); if (result) return 70+result; }
        unsigned passed=0;
        for (auto suite:{std::uint16_t{0x1301},std::uint16_t{0x1302},std::uint16_t{0x1303}}) for (bool hybrid:{false,true}) for (bool retry:{false,true}) {
            auto result=authenticated_pair(*credential,cert,wrong_anchor,suite,hybrid,retry,0,false);
            if (result) { std::println("authenticated QUIC suite={:04x} hybrid={} retry={} case {} failed",suite,hybrid,retry,result); return 10+result; } ++passed;
        }
        for (auto suite:{std::uint16_t{0x1301},std::uint16_t{0x1303}}) for (unsigned mutation=1;mutation<=15;++mutation) {
            auto result=authenticated_pair(*credential,cert,wrong_anchor,suite,false,false,mutation,false);
            if (result) { std::println("authenticated QUIC mutation={} case {} failed",mutation,result); return 40+result; } ++passed;
        }
        for (auto suite:{std::uint16_t{0x1301},std::uint16_t{0x1303}}) {
            auto loss=authenticated_pair(*credential,cert,wrong_anchor,suite,true,true,0,true);
            if (loss) { std::println("authenticated QUIC loss case {} failed",loss); return 60+loss; } ++passed;
        }
        std::println("authenticated in-memory QUIC {} cases passed; strict PKI/ALPN/TP identity, malformed/duplicate/required/range TP rejection, signature/Finished/forbidden messages, AES128/AES256/ChaCha20 X/hybrid HRR, key-phase update, stream FIN/ACK/credit, DATAGRAM, tickets and loss recovery",passed);
        if (wrapped) std::println("calibrated linker wrapper: TCP RecordLayer contexts={}",record_contexts);
    } catch (std::exception const& error) { std::println("authenticated QUIC exception: {}",error.what()); return 99; }
}
