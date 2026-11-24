import std;
import crypto;
import crypto.aead_context;
import quic.varint;
import quic.packet_keys;
import quic.packet_protection;
import quic.connection;
import ngtcp2;

namespace q=quic;
namespace n = ::ngtcp2;
namespace {
    // RFC 9001 Appendix A.2, IETF Trust 2021, Simplified BSD code license.
    inline constexpr std::string_view client_payload=
        "060040f1010000ed0303ebf8fa56f12939b9584a3896472ec40bb863cfd3e86804fe3a47f06a2b69484c000004130113"
        "02010000c000000010000e00000b6578616d706c652e636f6dff01000100000a00080006001d00170018001000070005"
        "04616c706e000500050100000000003300260024001d00209370b2c9caa47fbabaf4559fedba753de171fa71f50f1ce1"
        "5d43e994ec74d748002b0003020304000d0010000e0403050306030203080408050806002d00020101001c0002400100"
        "3900320408ffffffffffffffff05048000ffff07048000ffff0801100104800075300901100f088394c8f03e51570806"
        "048000ffff";
    inline constexpr std::string_view client_packet=
        "c000000001088394c8f03e5157080000449e7b9aec34d1b1c98dd7689fb8ec11d242b123dc9bd8bab936b47d92ec356c"
        "0bab7df5976d27cd449f63300099f3991c260ec4c60d17b31f8429157bb35a1282a643a8d2262cad67500cadb8e7378c"
        "8eb7539ec4d4905fed1bee1fc8aafba17c750e2c7ace01e6005f80fcb7df621230c83711b39343fa028cea7f7fb5ff89"
        "eac2308249a02252155e2347b63d58c5457afd84d05dfffdb20392844ae812154682e9cf012f9021a6f0be17ddd0c208"
        "4dce25ff9b06cde535d0f920a2db1bf362c23e596d11a4f5a6cf3948838a3aec4e15daf8500a6ef69ec4e3feb6b1d98e"
        "610ac8b7ec3faf6ad760b7bad1db4ba3485e8a94dc250ae3fdb41ed15fb6a8e5eba0fc3dd60bc8e30c5c4287e53805db"
        "059ae0648db2f64264ed5e39be2e20d82df566da8dd5998ccabdae053060ae6c7b4378e846d29f37ed7b4ea9ec5d82e7"
        "961b7f25a9323851f681d582363aa5f89937f5a67258bf63ad6f1a0b1d96dbd4faddfcefc5266ba6611722395c906556"
        "be52afe3f565636ad1b17d508b73d8743eeb524be22b3dcbc2c7468d54119c7468449a13d8e3b95811a198f3491de3e7"
        "fe942b330407abf82a4ed7c1b311663ac69890f4157015853d91e923037c227a33cdd5ec281ca3f79c44546b9d90ca00"
        "f064c99e3dd97911d39fe9c5d0b23a229a234cb36186c4819e8b9c5927726632291d6a418211cc2962e20fe47feb3edf"
        "330f2c603a9d48c0fcb5699dbfe5896425c5bac4aee82e57a85aaf4e2513e4f05796b07ba2ee47d80506f8d2c25e50fd"
        "14de71e6c418559302f939b0e1abd576f279c4b2e0feb85c1f28ff18f58891ffef132eef2fa09346aee33c28eb130ff2"
        "8f5b766953334113211996d20011a198e3fc433f9f2541010ae17c1bf202580f6047472fb36857fe843b19f5984009dd"
        "c324044e847a4f4a0ab34f719595de37252d6235365e9b84392b061085349d73203a4a13e96f5432ec0fd4a1ee65accd"
        "d5e3904df54c1da510b0ff20dcc0c77fcb2c0e0eb605cb0504db87632cf3d8b4dae6e705769d1de354270123cb11450e"
        "fc60ac47683d7b8d0f811365565fd98c4c8eb936bcab8d069fc33bd801b03adea2e1fbc5aa463d08ca19896d2bf59a07"
        "1b851e6c239052172f296bfb5e72404790a2181014f3b94a4e97d117b438130368cc39dbb2d198065ae3986547926cd2"
        "162f40a29f0c3c8745c0f50fba3852e566d44575c29d39a03f0cda721984b6f440591f355e12d439ff150aab7613499d"
        "bd49adabc8676eef023b15b65bfc5ca06948109f23f350db82123535eb8a7433bdabcb909271a6ecbcb58b936a88cd4e"
        "8f2e6ff5800175f113253d8fa9ca8885c2f552e657dc603f252e1a8e308f76f0be79e2fb8f5d5fbbe2e30ecadd220723"
        "c8c0aea8078cdfcb3868263ff8f0940054da48781893a7e49ad5aff4af300cd804a6b6279ab3ff3afb64491c85194aab"
        "760d58a606654f9f4400e8b38591356fbf6425aca26dc85244259ff2b19c41b9f96f3ca9ec1dde434da7d2d392b905dd"
        "f3d1f9af93d1af5950bd493f5aa731b4056df31bd267b6b90a079831aaf579be0a39013137aac6d404f518cfd4684064"
        "7e78bfe706ca4cf5e9c5453e9f7cfd2b8b4c8d169a44e55c88d4a9a7f9474241e221af44860018ab0856972e194cd934";
    template<std::size_t Size> auto hex(std::string_view input) -> std::array<std::uint8_t,Size> {
        if (input.size()!=2*Size) throw std::invalid_argument("hex length");
        auto digit=[](char value) -> unsigned { return value<='9' ? value-'0' : value-'a'+10; };
        std::array<std::uint8_t,Size> output{};
        for (std::size_t i=0;i<Size;++i) output[i]=static_cast<std::uint8_t>((digit(input[2*i])<<4)|digit(input[2*i+1]));
        return output;
    }
    struct Memory {
        struct alignas(std::max_align_t) Header { std::size_t bytes; };
        std::size_t used=0,peak=0,allocations=0,frees=0,limit=4*1024*1024;
        std::ptrdiff_t allowance=-1;
        static auto allocate(std::size_t size,void* owner) noexcept -> void* {
            auto& self=*static_cast<Memory*>(owner);
            if (!self.allowance || size>std::numeric_limits<std::size_t>::max()-sizeof(Header)) return nullptr;
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
    struct Application {
        unsigned handshake_calls=0,business_calls=0,closed_calls=0;
        int close_error=0;
        template<class Connection> auto connection_closed(Connection& connection,int error) noexcept -> void {
            if (connection.native()) std::terminate();
            ++closed_calls; close_error=error;
        }
        template<class Connection> auto handshake_complete(Connection&) -> int { ++handshake_calls; return 0; }
        template<class Connection> auto handshake_confirmed(Connection&) -> int { ++handshake_calls; return 0; }
        template<class... Args> auto stream_data(Args&&...) -> int { ++business_calls; return 0; }
        template<class... Args> auto stream_acked(Args&&...) -> int { return 0; }
        template<class... Args> auto stream_close(Args&&...) -> int { return 0; }
        template<class... Args> auto stream_reset(Args&&...) -> int { return 0; }
        template<class... Args> auto stop_sending(Args&&...) -> int { return 0; }
        template<class... Args> auto stream_limit(Args&&...) -> int { return 0; }
        template<class... Args> auto datagram(Args&&...) -> int { ++business_calls; return 0; }
        template<class... Args> auto add_connection_id(Args&&...) -> int { return 0; }
        template<class... Args> auto remove_connection_id(Args&&...) -> int { return 0; }
    };
    // This collector deliberately performs no TLS handshake or identity check.
    // It tests ngtcp2 CRYPTO delivery only, and never completes authentication.
    struct Collector {
        std::array<std::uint8_t,512> bytes{};
        std::size_t size=0;
        unsigned calls=0,starts=0;
        bool reentrant_rejected=false,complete_rejected=false,request_stop=false;
        int exception=0;
        template<class Connection> auto start(Connection& connection) -> int {
            ++starts;
            std::array<std::uint8_t,1500> scratch{};
            auto reentrant=connection.write_packet(scratch,nullptr,nullptr,2);
            reentrant_rejected=!reentrant && reentrant.error()==n::err_invalid_argument;
            auto payload=hex<245>(client_payload);
            return connection.submit_crypto(n::NGTCP2_ENCRYPTION_LEVEL_INITIAL,std::span(payload).subspan(4));
        }
        template<class Connection> auto receive(Connection& connection,n::ngtcp2_encryption_level level,std::uint64_t offset,std::span<std::uint8_t const> input) -> int {
            ++calls;
            if (exception==1) throw std::bad_alloc();
            if (exception==2) throw std::runtime_error("collector failure");
            if (level!=n::NGTCP2_ENCRYPTION_LEVEL_INITIAL || offset!=size || input.size()>bytes.size()-size) return n::err_crypto;
            std::ranges::copy(input,bytes.begin()+size); size+=input.size();
            complete_rejected=connection.complete_handshake()==n::err_invalid_argument;
            if (request_stop) connection.stop();
            return 0;
        }
    };
    using Connection=q::Connection<Collector,Application>;
    auto start(Connection& connection,Memory& memory,Path& path,bool server) -> int {
        auto destination=server ? cid({}) : cid(hex<8>("8394c8f03e515708"));
        auto source=server ? cid(hex<8>("f067a5502a4262b5")) : cid({});
        return connection.start(server,destination,source,path.value,settings(),parameters(server),memory.callbacks());
    }
    auto reference_initial() -> int {
        Memory memory; Path path(true); Collector collector; Application app; Connection connection(collector,app);
        if (start(connection,memory,path,true) || !connection.active() || connection.key_slots()) return 1;
        auto packet=hex<1200>(client_packet);
        if (connection.read(path.value,nullptr,packet,2) || collector.calls!=1 || collector.size!=241 || !collector.complete_rejected ||
            app.business_calls || app.handshake_calls || connection.key_slots()!=2) return 2;
        auto expected=hex<245>(client_payload);
        if (!std::ranges::equal(std::span(collector.bytes).first(collector.size),std::span(expected).subspan(4))) return 3;
        if (connection.read(path.value,nullptr,packet,3) || collector.calls!=1) return 4;
        auto before=memory.used;
        if (connection.read(path.value,nullptr,packet,2)!=n::err_invalid_argument || memory.used!=before || collector.calls!=1 || !connection.active()) return 5;
        if (start(connection,memory,path,true)!=n::err_invalid_argument || connection.complete_handshake()!=n::err_invalid_argument) return 6;
        connection.stop();
        connection.stop();
        if (connection.native() || connection.active() || connection.key_slots() || memory.used || memory.allocations!=memory.frees || app.closed_calls!=1 || app.close_error) return 7;
        std::println("ngtcp2 reference Initial native allocations={} peak={} bytes; sizeof connection={} protection={}",memory.allocations,memory.peak,sizeof(Connection),sizeof(q::PacketProtection<>));
        return 0;
    }
    auto retry_integrity() -> int {
        Memory memory; Path path(false); Collector collector; Application app; Connection connection(collector,app);
        if (start(connection,memory,path,false)) return 1;
        std::array<std::uint8_t,1500> packet{};
        auto first=connection.write_packet(packet,nullptr,nullptr,2);
        if (!first || *first<1200 || collector.starts!=1 || !collector.reentrant_rejected || connection.key_slots()!=2) return 2;
        // RFC 9001 A.4: token "token", ODCID 8394c8f03e515708.
        auto retry=hex<36>("ff000000010008f067a5502a4262b5746f6b656e04a265ba2eff4d829058fb3f0f2496ba");
        auto bad=retry; bad.back()^=1;
        if (connection.read(path.value,nullptr,bad,3) || !std::ranges::equal(std::span(n::ngtcp2_conn_get_dcid2(connection.native())->data).first(8),hex<8>("8394c8f03e515708"))) return 3;
        if (connection.read(path.value,nullptr,retry,4) || !connection.active() || connection.key_slots()!=2) return 4;
        auto const* destination=n::ngtcp2_conn_get_dcid2(connection.native());
        if (destination->datalen!=8 || !std::ranges::equal(std::span(destination->data).first(8),hex<8>("f067a5502a4262b5"))) return 5;
        auto second=connection.write_packet(packet,nullptr,nullptr,5);
        if (!second || *second<1200 || collector.starts!=1 || app.handshake_calls) return 6;
        connection.stop();
        if (memory.used || memory.allocations!=memory.frees || connection.key_slots() || app.closed_calls!=1 || app.close_error) return 7;
        return 0;
    }
    auto callback_lifetimes() -> int {
        auto packet=hex<1200>(client_packet);
        for (int mode:{0,1,2}) {
            Memory memory; Path path(true); Collector collector; Application app; Connection connection(collector,app);
            collector.request_stop=mode==0; collector.exception=mode;
            if (start(connection,memory,path,true)) return 1;
            auto error=connection.read(path.value,nullptr,packet,2);
            if (collector.calls!=1 || app.business_calls || app.handshake_calls) return 2;
            if (!mode) { if (error || connection.native() || connection.key_slots() || memory.used) return 3; }
            else {
                if (error!=(mode==1 ? n::err_nomem : n::err_callback_failure) || connection.active()) return 4;
                std::array<std::uint8_t,1500> output{};
                if (connection.write_packet(output,nullptr,nullptr,3) || connection.read(path.value,nullptr,packet,3)!=n::err_invalid_argument) return 5;
                connection.stop();
            }
            if (memory.used || memory.allocations!=memory.frees || connection.key_slots() || app.closed_calls!=1 || app.close_error!=error) return 6;
        }
        return 0;
    }
    struct KeyOwner {
        q::PacketProtection<6> keys;
        n::ngtcp2_mem memory;
        n::ngtcp2_conn* connection=nullptr;
        bool split_retirement=false,retired_ciphers_invalid=true;
        KeyOwner(Memory& allocations,Path& path):memory(allocations.callbacks()) {
            n::ngtcp2_callbacks events{};
            events.client_initial=[](n::ngtcp2_conn*,void*) noexcept -> int { return 0; };
            events.recv_retry=[](n::ngtcp2_conn*,n::ngtcp2_pkt_hd const*,void*) noexcept -> int { return n::err_callback_failure; };
            events.recv_crypto_data=[](n::ngtcp2_conn*,n::ngtcp2_encryption_level,std::uint64_t,std::uint8_t const*,std::size_t,void*) noexcept -> int { return 0; };
            events.encrypt=q::PacketProtection<6>::encrypt; events.decrypt=q::PacketProtection<6>::decrypt; events.hp_mask=q::PacketProtection<6>::hp_mask;
            events.rand=[](std::uint8_t* out,std::size_t size,n::ngtcp2_rand_ctx const*) noexcept { if (!::crypto::random_bytes({out,size})) std::terminate(); };
            events.get_new_connection_id2=[](n::ngtcp2_conn*,n::ngtcp2_cid*,n::ngtcp2_stateless_reset_token*,std::size_t,void*) noexcept -> int { return n::err_callback_failure; };
            events.get_path_challenge_data2=[](n::ngtcp2_conn*,n::ngtcp2_path_challenge_data*,void*) noexcept -> int { return n::err_callback_failure; };
            events.version_negotiation=[](n::ngtcp2_conn*,std::uint32_t,n::ngtcp2_cid const*,void*) noexcept -> int { return n::err_callback_failure; };
            events.update_key=[](n::ngtcp2_conn*,std::uint8_t*,std::uint8_t*,n::ngtcp2_crypto_aead_ctx*,std::uint8_t*,n::ngtcp2_crypto_aead_ctx*,std::uint8_t*,std::uint8_t const*,std::uint8_t const*,std::size_t,void*) noexcept -> int { return n::err_callback_failure; };
            events.delete_crypto_aead_ctx=[](n::ngtcp2_conn*,n::ngtcp2_crypto_aead_ctx* context,void* owner) noexcept {
                auto& self=*static_cast<KeyOwner*>(owner); auto* cipher=static_cast<::crypto::AeadContext*>(context->native_handle); auto valid=cipher!=nullptr; auto before=self.keys.active_slots();
                self.keys.release_aead(*context);
                if (valid && before && self.keys.active_slots()==before) self.split_retirement=true;
                if (valid) self.retired_ciphers_invalid&=!cipher->valid();
            };
            events.delete_crypto_cipher_ctx=[](n::ngtcp2_conn*,n::ngtcp2_crypto_cipher_ctx* context,void* owner) noexcept { static_cast<KeyOwner*>(owner)->keys.release_header(*context); };
            auto destination=cid(hex<8>("8394c8f03e515708")),source=cid({}); auto config=settings(); auto params=parameters(false);
            auto error=n::ngtcp2_conn_client_new_versioned(&connection,&destination,&source,&path.value,n::proto_ver_v1,n::callbacks_version,&events,n::settings_version,&config,n::transport_params_version,&params,&memory,this);
            if (error) throw std::runtime_error(n::ngtcp2_strerror(error));
        }
        ~KeyOwner() { stop(); }
        auto stop() noexcept -> void { if (auto* current=std::exchange(connection,nullptr)) n::ngtcp2_conn_del(current); }
    };
    auto key_slot_lifetimes(q::PacketSuite suite) -> int {
        Memory memory; Path path(false); KeyOwner owner(memory,path);
        auto secret=hex<32>("c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea");
        auto& keys=owner.keys;
        if (keys.install_secret(*owner.connection,n::NGTCP2_ENCRYPTION_LEVEL_INITIAL,false,suite,secret)!=n::err_invalid_argument || keys.active_slots()) return 1;
        memory.allowance=0;
        auto error=keys.install_secret(*owner.connection,n::NGTCP2_ENCRYPTION_LEVEL_HANDSHAKE,false,suite,secret);
        memory.allowance=-1;
        if (error!=n::err_nomem || keys.active_slots() || keys.application_keys_ready()) return 2;
        if (keys.install_secret(*owner.connection,n::NGTCP2_ENCRYPTION_LEVEL_HANDSHAKE,false,suite,secret) || keys.active_slots()!=1 ||
            keys.install_secret(*owner.connection,n::NGTCP2_ENCRYPTION_LEVEL_HANDSHAKE,false,suite,secret)!=n::err_invalid_argument) return 3;
        auto* description=n::ngtcp2_conn_get_crypto_ctx2(owner.connection);
        auto chacha=suite==q::PacketSuite::chacha20_poly1305_sha256;
        if (!description || description->aead.max_overhead!=16 || description->max_encryption!=(chacha ? q::max_varint : std::uint64_t{1}<<23) ||
            description->max_decryption_failure!=(std::uint64_t{1}<<(chacha ? 36 : 52))) return 15;
        n::ngtcp2_crypto_aead_ctx rx{},tx{}; std::array<std::uint8_t,32> rx_secret{},tx_secret{}; std::array<std::uint8_t,12> rx_iv{},tx_iv{};
        if (keys.update(rx_secret.data(),tx_secret.data(),rx,rx_iv.data(),tx,tx_iv.data(),secret,secret)!=n::err_crypto || keys.active_slots()!=1) return 4;
        if (keys.install_secret(*owner.connection,n::NGTCP2_ENCRYPTION_LEVEL_1RTT,false,suite,secret) ||
            keys.install_secret(*owner.connection,n::NGTCP2_ENCRYPTION_LEVEL_1RTT,true,suite,secret) || !keys.application_keys_ready() || keys.active_slots()!=3) return 5;
        if (keys.update(rx_secret.data(),tx_secret.data(),rx,rx_iv.data(),tx,tx_iv.data(),secret,secret) || keys.active_slots()!=5) return 6;
        // Independent Python HMAC/SHA256 HKDF-Expand-Label reference.
        if (rx_secret!=hex<32>("4428ffa195ad665b9ebf9456945b99e8ff848512cab93d0426436409047d666c") || rx_secret!=tx_secret ||
            rx_iv!=hex<12>("994107a30fb5ed593e8976f2") || rx_iv!=tx_iv) return 7;
        n::ngtcp2_crypto_aead_ctx failed_rx{reinterpret_cast<void*>(std::uintptr_t{0x1234})},failed_tx{reinterpret_cast<void*>(std::uintptr_t{0x5678})};
        std::array<std::uint8_t,32> failed_secret{}; failed_secret.fill(0xa5); auto before=failed_secret;
        if (keys.update(failed_secret.data(),failed_secret.data(),failed_rx,rx_iv.data(),failed_tx,tx_iv.data(),secret,secret)!=n::err_nomem ||
            keys.active_slots()!=5 || failed_secret!=before || failed_rx.native_handle!=reinterpret_cast<void*>(std::uintptr_t{0x1234}) || failed_tx.native_handle!=reinterpret_cast<void*>(std::uintptr_t{0x5678})) return 8;
        std::array<std::uint8_t,3> input{1,2,3},output{}; std::array<std::uint8_t,19> ciphertext{};
        if (q::PacketProtection<6>::encrypt(ciphertext.data(),nullptr,&rx,input.data(),input.size(),rx_iv.data(),rx_iv.size(),nullptr,0) ||
            q::PacketProtection<6>::decrypt(output.data(),nullptr,&tx,ciphertext.data(),ciphertext.size(),rx_iv.data(),rx_iv.size(),nullptr,0) || output!=input) return 9;
        ciphertext.back()^=1;
        if (q::PacketProtection<6>::decrypt(output.data(),nullptr,&tx,ciphertext.data(),ciphertext.size(),rx_iv.data(),rx_iv.size(),nullptr,0)!=n::err_decrypt || output!=std::array<std::uint8_t,3>{}) return 10;
        if (q::PacketProtection<6>::decrypt(output.data(),nullptr,&tx,ciphertext.data(),ciphertext.size(),rx_iv.data(),11,nullptr,0)!=n::err_callback_failure) return 11;
        keys.release_aead(rx);
        if (rx.native_handle || keys.active_slots()!=4 || q::PacketProtection<6>::encrypt(ciphertext.data(),nullptr,&rx,input.data(),input.size(),rx_iv.data(),rx_iv.size(),nullptr,0)!=n::err_callback_failure) return 12;
        keys.release_aead(rx); keys.release_aead(tx);
        if (keys.active_slots()!=3) return 13;
        owner.stop();
        if (keys.active_slots() || memory.used || memory.allocations!=memory.frees || !owner.split_retirement || !owner.retired_ciphers_invalid) return 14;
        return 0;
    }
    auto allocation_failures() -> int {
        bool created=false,read=false;
        for (std::ptrdiff_t allowance=0;allowance<128;++allowance) {
            Memory memory; Path path(false); Collector collector; Application app; Connection connection(collector,app);
            memory.allowance=allowance; auto error=start(connection,memory,path,false); memory.allowance=-1;
            connection.stop();
            if (memory.used || memory.allocations!=memory.frees || connection.key_slots() || (error && error!=n::err_nomem)) return 1;
            if (!error) { created=true; break; }
        }
        auto packet=hex<1200>(client_packet);
        for (std::ptrdiff_t allowance=0;allowance<128;++allowance) {
            Memory memory; Path path(true); Collector collector; Application app; Connection connection(collector,app);
            if (start(connection,memory,path,true)) return 2;
            memory.allowance=allowance; auto error=connection.read(path.value,nullptr,packet,2); memory.allowance=-1;
            connection.stop();
            // Fixed ngtcp2 conn_call_recv_client_initial maps all nonzero
            // callback returns to CALLBACK_FAILURE. The first two native
            // allocations install Initial RX/TX key metadata in that callback.
            auto expected_error=allowance<2 ? n::err_callback_failure : n::err_nomem;
            if (memory.used || memory.allocations!=memory.frees || connection.key_slots() || (error && error!=expected_error)) {
                std::println("QUIC read allocation allowance={} error={} used={} alloc/free={}/{} slots={} callbacks={}",allowance,error,memory.used,memory.allocations,memory.frees,connection.key_slots(),collector.calls); return 3;
            }
            if (!error) { read=true; break; }
        }
        return created && read ? 0 : 4;
    }
    auto write_thresh() -> int {
        Memory memory; Path server_path(true), client_path(false);
        Collector client_collector; Application client_app; Connection client(client_collector,client_app);
        if (start(client,memory,client_path,false)) return 1;
        std::array<std::uint8_t,512> params_buf{};
        auto encoded=client.local_transport_parameters(params_buf);
        if (!encoded) return 2;
        auto params=std::span(params_buf).first(*encoded);
        auto packet=hex<1200>(client_packet);
        auto check=[&](std::size_t thresh,std::uint64_t expected) -> int {
            Collector collector; Application app; Connection server(collector,app);
            auto s=settings(); s.write_stream_data_thresh=thresh;
            if (server.start(true,cid({}),cid(hex<8>("f067a5502a4262b5")),server_path.value,s,parameters(true),memory.callbacks())) return 3;
            if (server.read(server_path.value,nullptr,packet,2)) return 4;
            if (server.max_data_left()!=0) return 5;
            std::array<std::uint8_t,32> tx_secret{};
            if (server.install_secret(n::NGTCP2_ENCRYPTION_LEVEL_1RTT,true,q::PacketSuite::aes128_gcm_sha256,tx_secret)) return 8;
            if (auto err=server.remote_transport_parameters(params)) { std::println("remote_transport_parameters err={}",err); return 6; }
            if (server.max_data_left()!=expected) return 7;
            server.stop(); return 0;
        };
        if (auto rc=check(65536,0)) return rc;
        if (auto rc=check(65535,65536)) return 10+rc;
        client.stop();
        return memory.used || memory.allocations!=memory.frees ? 9 : 0;
    }
}
auto main() -> int {
    try {
        if (auto result=reference_initial()) { std::println("QUIC reference Initial case {} failed",result); return result; }
        if (auto result=retry_integrity()) { std::println("QUIC Retry case {} failed",result); return 20+result; }
        if (auto result=callback_lifetimes()) { std::println("QUIC callback lifetime case {} failed",result); return 40+result; }
        for (auto suite:{q::PacketSuite::aes128_gcm_sha256,q::PacketSuite::chacha20_poly1305_sha256}) if (auto result=key_slot_lifetimes(suite)) { std::println("QUIC key slot case {} failed",result); return 80+result; }
        if (auto result=allocation_failures()) { std::println("QUIC native allocation case {} failed",result); return 60+result; }
        if (auto result=write_thresh()) { std::println("QUIC write_stream_data_thresh case {} failed",result); return 100+result; }
    } catch (std::exception const& error) { std::println("QUIC core exception: {}",error.what()); return 99; }
    std::println("QUIC core RFC Initial CRYPTO delivery, Retry integrity, KU/independent key retirement, callback stop/throw, exact close notification and native allocation rollback passed; no TLS handshake or peer authentication asserted");
}
