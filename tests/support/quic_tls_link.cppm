export module nexus.test.quic_tls_link;
import std;
import crypto;
import nexus.thirdparty.ngtcp2;
import nexus.thirdparty.nghttp3;
import tls.certificate_trust;
import tls.hello;
import tls.hybrid;

export namespace nexus::test::quic_tls {
    using View=std::span<std::uint8_t const>;
    inline auto bytes(std::string_view value) noexcept -> View { return {reinterpret_cast<std::uint8_t const*>(value.data()),value.size()}; }
    inline auto read(std::string_view path) -> crypto::Bytes { std::ifstream input(std::string(path),std::ios::binary); return {std::istreambuf_iterator<char>(input),{}}; }
    struct Memory {
        struct alignas(std::max_align_t) Header { std::size_t bytes; };
        std::size_t used=0,peak=0,allocations=0,frees=0,limit=4*1024*1024;
        static auto allocate(std::size_t size,void* owner) noexcept -> void* {
            auto& self=*static_cast<Memory*>(owner);
            if (size>self.limit-sizeof(Header) || self.used>self.limit-size-sizeof(Header)) return nullptr;
            auto* block=static_cast<Header*>(std::malloc(size+sizeof(Header))); if (!block) return nullptr;
            block->bytes=size+sizeof(Header); self.used+=block->bytes; self.peak=std::max(self.peak,self.used); ++self.allocations; return block+1;
        }
        static auto release(void* pointer,void* owner) noexcept -> void {
            if (!pointer) return;
            auto& self=*static_cast<Memory*>(owner); auto* block=static_cast<Header*>(pointer)-1; auto size=block->bytes;
            crypto::cleanse({reinterpret_cast<std::uint8_t*>(block),size}); self.used-=size; ++self.frees; std::free(block);
        }
        static auto zero(std::size_t count,std::size_t size,void* owner) noexcept -> void* {
            if (size && count>std::numeric_limits<std::size_t>::max()/size) return nullptr;
            auto total=count*size; auto* out=allocate(total,owner); if (out) std::memset(out,0,total); return out;
        }
        static auto resize(void* pointer,std::size_t size,void* owner) noexcept -> void* {
            if (!pointer) return allocate(size,owner);
            if (!size) { release(pointer,owner); return nullptr; }
            auto* out=allocate(size,owner); if (!out) return nullptr;
            auto old=(static_cast<Header*>(pointer)-1)->bytes-sizeof(Header); std::memcpy(out,pointer,std::min(old,size)); release(pointer,owner); return out;
        }
        auto transport() noexcept -> nex::ngtcp2::ngtcp2_mem { return {this,allocate,release,zero,resize}; }
        auto http3() noexcept -> nex::nghttp3::nghttp3_mem { return {this,allocate,release,zero,resize}; }
    };
    struct Path {
        nex::ngtcp2::ngtcp2_sockaddr_in local{},remote{};
        nex::ngtcp2::ngtcp2_path value{};
        explicit Path(bool server) {
            namespace n=nex::ngtcp2;
            auto port=[](unsigned value) { return std::bit_cast<std::uint16_t>(std::array<std::uint8_t,2>{static_cast<std::uint8_t>(value>>8),static_cast<std::uint8_t>(value)}); };
            local.sin_family=remote.sin_family=n::af_inet;
            local.sin_port=port(server ? 443 : 12345); remote.sin_port=port(server ? 12345 : 443);
            local.sin_addr.s_addr=remote.sin_addr.s_addr=std::bit_cast<std::uint32_t>(std::array<std::uint8_t,4>{127,0,0,1});
            value={{reinterpret_cast<n::ngtcp2_sockaddr*>(&local),sizeof(local)},{reinterpret_cast<n::ngtcp2_sockaddr*>(&remote),sizeof(remote)},nullptr};
        }
    };
    inline auto cid(std::uint8_t seed) -> nex::ngtcp2::ngtcp2_cid {
        std::array<std::uint8_t,8> bytes{}; for (auto& byte:bytes) byte=seed++;
        nex::ngtcp2::ngtcp2_cid out{}; nex::ngtcp2::ngtcp2_cid_init(&out,bytes.data(),bytes.size()); return out;
    }
    inline auto settings() -> nex::ngtcp2::ngtcp2_settings {
        namespace n=nex::ngtcp2;
        n::ngtcp2_settings out{}; n::ngtcp2_settings_default_versioned(n::settings_version,&out);
        out.initial_ts=1; out.handshake_timeout=10*n::seconds; return out;
    }
    inline auto parameters(bool server) -> nex::ngtcp2::ngtcp2_transport_params {
        namespace n=nex::ngtcp2;
        n::ngtcp2_transport_params out{}; n::ngtcp2_transport_params_default_versioned(n::transport_params_version,&out);
        out.initial_max_data=65536; out.initial_max_stream_data_bidi_local=out.initial_max_stream_data_bidi_remote=out.initial_max_stream_data_uni=4096;
        out.initial_max_streams_bidi=16; out.initial_max_streams_uni=3; out.disable_active_migration=1;
        if (server) { out.original_dcid=cid(0x83); out.original_dcid_present=1; }
        return out;
    }
    struct Pki {
        View anchor;
        auto operator()(std::span<View const> chain) const -> bool {
            std::array<View,1> anchors{anchor};
            auto now=std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
            return tls::verify_server_certificate_chain(chain,anchors,tls::PeerNameKind::dns,bytes("localhost"),now).has_value();
        }
    };
    inline auto hello(std::uint16_t scheme,bool hybrid=false,std::uint16_t suite=0x1301) -> tls::ClientHello {
        auto group=hybrid ? tls::x25519_mlkem768_group : std::uint16_t{29};
        tls::ClientHello out; if (!crypto::random_bytes(out.random)) throw std::runtime_error("TLS entropy");
        out.cipher_suites={suite}; out.compression_methods={0};
        out.extensions={{43,{2,3,4}},{10,{0,2,static_cast<std::uint8_t>(group>>8),static_cast<std::uint8_t>(group)}},
            {13,{0,2,static_cast<std::uint8_t>(scheme>>8),static_cast<std::uint8_t>(scheme)}},{51,{0,0}},{16,{0,3,2,'h','3'}}};
        return out;
    }
}
