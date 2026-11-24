import std;
import crypto;
import quic.connection;
import quic.resumption;
import quic.varint;
import ngtcp2;
import tls.hello_config;
import tls.handshake;
namespace q=quic;namespace n = ::ngtcp2;namespace t=tls;namespace c = ::crypto;
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
    template<class Tls> struct Application {
        Tls& tls;
        unsigned completed=0,confirmed=0,closed=0,streams=0,datagrams=0;
        std::size_t acked=0;
        bool business_before_auth=false,fin=false;
        c::Bytes data,datagram_data;
        explicit Application(Tls& value):tls(value) {}
        template<class Connection> auto connection_closed(Connection& connection,int) noexcept -> void {
            if (connection.native()) std::terminate();
            ++closed; if constexpr(!requires {tls.resumption_policy();})tls.cancel();
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
    struct Clock {static auto now() noexcept -> std::uint64_t {return 100000;}};
    using Cache=t::ResumptionCache<8>;using Store=t::ServerTicketStore<8>;
    auto pair(t::ServerCredential const& credential,View anchor,Store& store,Cache& cache,std::uint16_t group,std::uint16_t suite,bool retry,unsigned round,bool expected_resume) -> int {
        std::array<std::uint16_t,1> groups{group};std::array<std::string_view,1> alpn{"h3"};std::array<View,1> anchors{anchor};
        auto hello=t::make_client_hello("localhost",alpn,groups);if (!hello)return 1;hello->cipher_suites={suite};
        auto wall=std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
        auto prepared=q::ClientResumptionSetup<Cache,Clock>::create(std::move(*hello),retry ? std::span<std::uint16_t const>{} : std::span<std::uint16_t const>(groups),anchors,t::PeerNameKind::dns,bytes("localhost"),wall,"h3",cache);
        if (!prepared)return 2;
        q::ResumingTlsClient<Cache,Clock> client_tls(std::move(*prepared));
        auto server_prepared=q::ServerResumptionSetup<Store,Clock>::create(credential,"h3",store);if (!server_prepared)return 3;
        q::ResumingTlsServer<Store,Clock> server_tls(std::move(*server_prepared));
        Memory cm,sm;Path cp(false),sp(true);Application ca(client_tls);Application sa(server_tls);
        q::Connection client(client_tls,ca);q::Connection server(server_tls,sa);
        auto initial_bytes=hex<8>("8394c8f03e515708");initial_bytes.back()^=static_cast<std::uint8_t>(round);
        auto initial=cid(initial_bytes),client_id=cid(hex<8>("0001020304050607")),server_id=cid(hex<8>("f067a5502a4262b5"));
        auto remote=parameters(true);remote.original_dcid=initial;remote.initial_max_data=65536-round*1024;
        if (client.start(false,initial,client_id,cp.value,settings(),parameters(false),cm.callbacks()) || server.start(true,client_id,server_id,sp.value,settings(),remote,sm.callbacks()))return 4;
        std::uint64_t now=2;unsigned cpackets=0,spackets=0;EndpointError failure;
        for (unsigned i=0;i<3000 && (!client_tls.complete()||!server_tls.complete()||!ca.completed||!sa.completed);++i) {
            failure=pump(client,server,cp,sp,now,cpackets,spackets);if(failure.code)break;
        }
        if(failure.code||!client_tls.complete()||!server_tls.complete()||client_tls.resumed()!=expected_resume||server_tls.resumed()!=expected_resume) {
            std::println("handshake failed group={} suite={:04x} retry={} round={} side/code={}/{} alerts={}/{} complete={}/{} resumed={}/{} expected={}",group,suite,retry,round,failure.side,failure.code,client_tls.alert(),server_tls.alert(),client_tls.complete(),server_tls.complete(),client_tls.resumed(),server_tls.resumed(),expected_resume);return 5;
        }
        auto issuer=server_tls.take_issuer();if(!issuer)return 6;
        auto first=issuer->prepare(),second=issuer->prepare();if(!first||!second)return 7;
        auto w1=t::HandshakeDecoder::encode(4,first->body()),w2=t::HandshakeDecoder::encode(4,second->body());if(!w1||!w2)return 8;
        auto cache_before=cache.size(),store_before=store.size();
        if(server.submit_crypto(n::NGTCP2_ENCRYPTION_LEVEL_1RTT,std::span(*w1).first(3)))return 9;
        for(unsigned i=0;i<200&&client_tls.pending_handshake_bytes()!=3;++i){failure=pump(client,server,cp,sp,now,cpackets,spackets);if(failure.code)return 10;}
        if(client_tls.pending_handshake_bytes()!=3||cache.size()!=cache_before||store.size()!=store_before)return 11;
        c::Bytes joined(w1->begin()+3,w1->end());joined.insert(joined.end(),w2->begin(),w2->end());
        if(server.submit_crypto(n::NGTCP2_ENCRYPTION_LEVEL_1RTT,joined))return 12;
        for(unsigned i=0;i<300&&cache.size()!=cache_before+2;++i){failure=pump(client,server,cp,sp,now,cpackets,spackets);if(failure.code)return 13;}
        // Publish only after the peer really authenticated and parsed both
        // complete ticket messages; queue submission alone does not prove it.
        if(client_tls.pending_handshake_bytes()||cache.size()!=cache_before+2||store.size()!=store_before||!first->publish(store,Clock::now())||!second->publish(store,Clock::now()))return 14;
        std::array<std::uint8_t,7> payload{1,2,3,4,5,6,7};std::int64_t stream=-1;
        if(n::ngtcp2_conn_open_bidi_stream(client.native(),&stream,nullptr))return 15;
        std::size_t offset=0;bool fin=false;
        for(unsigned i=0;i<500&&(sa.data.size()!=payload.size()||!sa.fin||ca.acked!=payload.size());++i){
            if(!fin){std::array<std::uint8_t,1500> packet{};n::ngtcp2_vec data{payload.data()+offset,payload.size()-offset};auto written=client.write_stream(packet,nullptr,nullptr,stream,std::span(&data,1),true,now+=1000000);
                if(!written)return 16;if(written->stream_bytes>=0){offset+=written->stream_bytes;fin=offset==payload.size();}
                if(written->packet_bytes&&server.read(sp.value,nullptr,std::span(packet).first(written->packet_bytes),now+=1000000))return 17;}
            failure=pump(client,server,cp,sp,now,cpackets,spackets);if(failure.code)return 18;
        }
        if(!fin||sa.data!=c::Bytes(payload.begin(),payload.end())||!sa.fin||ca.acked!=payload.size()||sa.business_before_auth)return 19;
        if(client.submit_crypto(n::NGTCP2_ENCRYPTION_LEVEL_0RTT,payload)!=n::err_invalid_argument)return 20;
        auto legal=issuer->prepare();if(!legal)return 22;
        c::Bytes early(legal->body().begin(),legal->body().end());early[early.size()-2]=0;early.back()=8;
        early.insert(early.end(),{0,42,0,4,255,255,255,255});
        auto advertised=t::HandshakeDecoder::encode(4,early);if(!advertised||server.submit_crypto(n::NGTCP2_ENCRYPTION_LEVEL_1RTT,*advertised))return 23;
        auto before_early=cache.size();
        for(unsigned i=0;i<200&&cache.size()==before_early;++i){failure=pump(client,server,cp,sp,now,cpackets,spackets);if(failure.code)return 24;}
        if(cache.size()!=before_early+1||!legal->publish(store,Clock::now()))return 25;
        // RFC9001 4.6.1: the invalid sentinel is fatal even with 0RTT off.
        auto max=round==0?0u:round==1?1u:0xfffffffeu;
        for(unsigned i=0;i<4;++i)early[early.size()-1-i]=static_cast<std::uint8_t>(max>>(8*i));
        auto invalid=t::HandshakeDecoder::encode(4,early);if(!invalid||server.submit_crypto(n::NGTCP2_ENCRYPTION_LEVEL_1RTT,*invalid))return 26;
        auto before_invalid=cache.size();failure={};
        for(unsigned i=0;i<200&&!failure.code;++i)failure=pump(client,server,cp,sp,now,cpackets,spackets);
        if(failure.side!=2||failure.code!=-203||client_tls.alert()!=0||client_tls.complete()||cache.size()!=before_invalid)return 27;
        client.stop();server.stop();if(client_tls.complete()||server_tls.complete())return 28;if(cm.used||sm.used||client.key_slots()||server.key_slots()||ca.closed!=1||sa.closed!=1)return 21;
        return 0;
    }
}
int main(int argc,char** argv){
    if(argc!=4)return 1;auto cert=read(argv[1]),key=read(argv[2]),anchor=read(argv[3]);auto credential=t::ServerCredential::create(cert,key);c::cleanse(key);if(!credential)return 2;
    unsigned authenticated=0;
    for(auto group:{23,24,25,29,4588})for(auto suite:{0x1301,0x1302,0x1303})for(bool retry:{false,true}){
        Cache cache;Store store;
        for(unsigned round=0;round<3;++round){auto result=pair(*credential,anchor,store,cache,group,suite,retry,round,round!=0);if(result){std::println("QUIC PSK case failed group={} suite={:04x} retry={} round={} result={}",group,suite,retry,round,result);return 10+result;}++authenticated;}
    }
    std::println("QUIC PSK {} authenticated native packet connections: five groups three ciphers direct/HRR full+two resumed, new transport limits, fragmented/coalesced tickets and renewal, stream FIN/ACK/credit, no0RTT, native cleanup passed",authenticated);
}
