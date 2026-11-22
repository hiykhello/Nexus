module tls.fingerprint;
import std;
import crypto;
import tls.hybrid;
import tls.signature;
import tls.certificate_compression;
import crypto.ecdh;

namespace tls {
    namespace {
        class Random {
            std::array<std::uint8_t,64> bytes_{};
            std::size_t offset_=64;
        public:
            auto sample(std::uint16_t bound) -> std::optional<std::uint16_t> {
                if (!bound) return {};
                auto limit=65536u-(65536u%bound);
                for (;;) {
                    if (offset_==bytes_.size()) {
                        if (!crypto::random_bytes(bytes_)) return {};
                        offset_=0;
                    }
                    auto value=(std::uint32_t{bytes_[offset_]}<<8)|bytes_[offset_+1]; offset_+=2;
                    if (value<limit) return static_cast<std::uint16_t>(value%bound);
                }
            }
            auto grease() -> std::optional<std::uint16_t> {
                auto value=sample(16); if (!value) return {};
                return static_cast<std::uint16_t>(0x0a0a+0x1010*(*value));
            }
        };
        auto prepend(Extension& extension,std::uint16_t value,bool vector8=false) -> void {
            auto header=vector8 ? 1u : 2u;
            extension.data.insert(extension.data.begin()+header,{static_cast<std::uint8_t>(value>>8),static_cast<std::uint8_t>(value)});
            auto size=extension.data.size()-header;
            if (vector8) extension.data[0]=static_cast<std::uint8_t>(size);
            else { extension.data[0]=static_cast<std::uint8_t>(size>>8); extension.data[1]=static_cast<std::uint8_t>(size); }
        }
        struct PresetSpec {
            bool valid=false;
            bool grease=false;
            bool permute=false;
            bool psk_kex_modes=false;
            bool compat_sid=false;
            std::uint16_t tcp_min_pad=0;
            std::optional<std::uint16_t> default_rsl{};
            std::array<std::uint16_t,3> ciphers{0x1301,0x1302,0x1303};
            std::uint8_t cipher_count=3;
            std::array<std::uint16_t,7> signatures{0x0804,0x0403,0x0807,0x0805,0x0806,0x0503,0x0603};
            std::uint8_t sig_count=3;
            std::array<std::uint16_t,20> ext_order{};
            std::uint8_t ext_count=0;
        };
        auto preset_spec(Fingerprint profile) noexcept -> PresetSpec {
            switch (profile) {
            case Fingerprint::native:
                return {true,false,false,false,false,0,{}};
            case Fingerprint::tls13_grease:
                return {true,true,false,false,true,0,{}};
            case Fingerprint::tls13_randomized:
                return {true,true,true,false,true,0,{}};
            case Fingerprint::chrome:
                return {true,true,true,true,true,517,{},{0x1301,0x1302,0x1303},3,
                    {0x0403,0x0804,0x0503,0x0805,0x0806,0x0807},6};
            case Fingerprint::edge:
                return {true,true,true,true,true,517,{},{0x1301,0x1302,0x1303},3,
                    {0x0403,0x0804,0x0503,0x0805,0x0806},5};
            case Fingerprint::firefox:
                return {true,false,false,true,true,0,16385,{0x1301,0x1303,0x1302},3,
                    {0x0403,0x0503,0x0603,0x0804,0x0805,0x0806,0x0807},7,
                    {0,23,0xff01,10,11,35,16,5,34,51,43,13,45,28,18,0x39,0xfe0d},17};
            case Fingerprint::safari:
                return {true,true,false,true,true,517,{},{0x1301,0x1302,0x1303},3,
                    {0x0403,0x0804,0x0805,0x0503,0x0806,0x0603},6,
                    {0,10,51,16,13,45,43,0x39},8};
            case Fingerprint::ios:
                return {true,true,false,true,true,517,{},{0x1302,0x1303,0x1301},3,
                    {0x0403,0x0804,0x0503,0x0805,0x0603,0x0806},6,
                    {0,51,10,13,16,45,43,0x39},8};
            case Fingerprint::android:
                return {true,false,false,true,true,0,{},{0x1301,0x1302,0x1303},3,
                    {0x0403,0x0503,0x0804,0x0805,0x0806},5,
                    {0,10,51,13,16,45,43,0x39},8};
            default:
                return {};
            }
        }
        auto is_browser_preset(Fingerprint profile) noexcept -> bool {
            return profile==Fingerprint::chrome || profile==Fingerprint::firefox || profile==Fingerprint::safari ||
                profile==Fingerprint::ios || profile==Fingerprint::android || profile==Fingerprint::edge;
        }
        auto order_extensions(std::vector<Extension>& extensions,std::span<std::uint16_t const> order) -> void {
            std::vector<Extension> reordered;
            reordered.reserve(extensions.size());
            auto take=[&](std::uint16_t type) {
                for (auto& ext:extensions) {
                    if (ext.type==type && ext.type!=0xffffu) {
                        reordered.push_back(std::move(ext));
                        ext.type=0xffffu;
                    }
                }
            };
            for (auto type:order) take(type);
            for (auto& ext:extensions) if (ext.type!=0xffffu) reordered.push_back(std::move(ext));
            extensions=std::move(reordered);
        }
    }
}

#include "browser_extensions.hpp"

namespace tls {
    auto make_fingerprint_hello(std::optional<std::string_view> name,std::span<std::string_view const> alpn,
        FingerprintConfig const& input_config,HandshakeTransport transport,
        std::optional<std::span<std::uint8_t const>> parameters,std::optional<std::uint16_t> required_signature,bool real_ech)
        -> std::expected<FingerprintHello,FingerprintError> {
        using E=FingerprintError;
        Random random;
        FingerprintConfig config=input_config;
        if (config.profile==Fingerprint::random) {
            static constexpr std::array<Fingerprint,7> pool{
                Fingerprint::chrome,Fingerprint::firefox,Fingerprint::safari,
                Fingerprint::ios,Fingerprint::android,Fingerprint::edge,Fingerprint::tls13_randomized
            };
            auto picked=random.sample(static_cast<std::uint16_t>(pool.size()));
            if (!picked) return std::unexpected(E::random_error);
            config.profile=pool[*picked];
        }
        auto spec=preset_spec(config.profile);
        if (!spec.valid) return std::unexpected(E::invalid_policy);
        if ((config.shares!=FingerprintShares::x25519 && config.shares!=FingerprintShares::hybrid && config.shares!=FingerprintShares::dual && config.shares!=FingerprintShares::retry) ||
            (transport!=HandshakeTransport::tcp && transport!=HandshakeTransport::quic) ||
            (transport==HandshakeTransport::tcp && parameters) || (transport==HandshakeTransport::quic && (!parameters || alpn.empty())) ||
            (parameters && parameters->size()>12000) || config.pad_to>16000) return std::unexpected(E::invalid_policy);
        if (config.record_size_limit && (transport!=HandshakeTransport::tcp || *config.record_size_limit<64 || *config.record_size_limit>16385)) return std::unexpected(E::invalid_policy);
        auto browser=is_browser_preset(config.profile);
        if (browser) {
            if (config.cipher_count==3 && config.cipher_order==std::array<std::uint16_t,3>{0x1301,0x1302,0x1303}) {
                config.cipher_order=spec.ciphers; config.cipher_count=spec.cipher_count;
            }
            if (config.signature_count==3 && config.signature_order==std::array<std::uint16_t,7>{0x0804,0x0403,0x0807,0x0805,0x0806,0x0503,0x0603}) {
                config.signature_order=spec.signatures; config.signature_count=spec.sig_count;
            }
            if (!config.record_size_limit && transport==HandshakeTransport::tcp && spec.default_rsl)
                config.record_size_limit=spec.default_rsl;
        }
        if (!config.cipher_count || config.cipher_count>config.cipher_order.size()) return std::unexpected(E::invalid_policy);
        auto suites=std::span(config.cipher_order).first(config.cipher_count);
        for (std::size_t index=0;index<suites.size();++index) {
            auto suite=suites[index];
            if ((suite!=0x1301 && suite!=0x1302 && suite!=0x1303) ||
                std::ranges::contains(suites.first(index),suite)) return std::unexpected(E::invalid_policy);
        }
        if (!config.signature_count || config.signature_count>config.signature_order.size()) return std::unexpected(E::invalid_policy);
        if (required_signature &&
            !std::ranges::contains(std::span(config.signature_order).first(config.signature_count),*required_signature)) {
            if (config.signature_count==config.signature_order.size()) return std::unexpected(E::invalid_policy);
            config.signature_order[config.signature_count++]=*required_signature;
        }
        auto signatures=std::span(config.signature_order).first(config.signature_count);
        for (std::size_t index=0;index<signatures.size();++index)
            if (!signature_parameters(signatures[index]) || std::ranges::contains(signatures.first(index),signatures[index])) return std::unexpected(E::invalid_policy);
        FingerprintHello result;
        auto x=config.shares==FingerprintShares::x25519;
        std::array<std::uint16_t,2> groups=x ? std::array<std::uint16_t,2>{29,x25519_mlkem768_group} : std::array<std::uint16_t,2>{x25519_mlkem768_group,29};
        if (config.group_count>config.group_order.size() || config.key_share_count>config.key_share_groups.size()) return std::unexpected(E::invalid_policy);
        auto offered_groups=config.group_count ? std::span(config.group_order).first(config.group_count) : std::span<std::uint16_t const>(groups);
        auto hello=make_client_hello(name,alpn,offered_groups);
        if (!hello) return std::unexpected(hello.error()==ClientHelloConfigError::random_error ? E::random_error : E::invalid_hello);
        result.hello=std::move(*hello);
        auto& h=result.hello;
        if (spec.psk_kex_modes) h.extensions.push_back({45,{1,1}});
        if constexpr (certificate_compression_enabled()) {
            // Auto profile offers from the fixed uTLS reference.
            if (config.profile==Fingerprint::chrome || config.profile==Fingerprint::edge)
                h.extensions.push_back({certificate_compression_extension,{2,0,static_cast<std::uint8_t>(CertificateCompression::brotli)}});
            if (config.profile==Fingerprint::safari)
                h.extensions.push_back({certificate_compression_extension,{2,0,static_cast<std::uint8_t>(CertificateCompression::zlib)}});
            if (config.profile==Fingerprint::tls13_randomized)
                h.extensions.push_back({certificate_compression_extension,{6,0,1,0,2,0,3}});
        }
        if (config.record_size_limit) {
            auto value=*config.record_size_limit;
            h.extensions.push_back({28,{static_cast<std::uint8_t>(value>>8),static_cast<std::uint8_t>(value)}});
        }
        h.cipher_suites.assign(suites.begin(),suites.end());
        if (browser && !add_browser_extensions(h,config.profile,alpn,transport,real_ech,
                config.legacy_alps,config.allow_tls12,random)) return std::unexpected(E::random_error);
        auto legacy_signatures=browser && transport==HandshakeTransport::tcp && config.allow_tls12;
        for (auto& extension:h.extensions) if (extension.type==13) {
            extension.data={0,static_cast<std::uint8_t>(2*signatures.size()+(legacy_signatures ? 6 : 0))};
            for (auto signature:signatures) {
                extension.data.push_back(static_cast<std::uint8_t>(signature>>8)); extension.data.push_back(static_cast<std::uint8_t>(signature));
            }
            if (legacy_signatures)
                extension.data.append_range(std::array<std::uint8_t,6>{4,1,5,1,6,1});
        }
        if (parameters) h.extensions.push_back({0x39,{parameters->begin(),parameters->end()}});
        if (config.group_count) {
            std::size_t position=0;
            for (std::size_t i=0;i<config.key_share_count;++i) {
                auto value=config.key_share_groups[i];
                while(position<offered_groups.size() && offered_groups[position]!=value) ++position;
                if (position==offered_groups.size()) return std::unexpected(E::invalid_policy);
                result.groups[i]=value; ++position;
            }
            result.group_count=config.key_share_count;
        } else if (config.shares!=FingerprintShares::retry) {
            result.groups[0]=groups[0]; result.group_count=1;
            if (config.shares==FingerprintShares::dual) { result.groups[1]=groups[1]; result.group_count=2; }
        }
        std::vector<KeyShareEntry> shares;
        if (spec.compat_sid && transport==HandshakeTransport::tcp) {
            h.session_id.resize(32);
            if (!crypto::random_bytes(h.session_id)) return std::unexpected(E::random_error);
        }
        if (spec.ext_count) order_extensions(h.extensions,std::span(spec.ext_order).first(spec.ext_count));
        if (spec.grease) {
            std::array<std::uint16_t,6> grease{};
            for (auto& value:grease) { auto sampled=random.grease(); if (!sampled) return std::unexpected(E::random_error); value=*sampled; }
            // Draw uniformly conditioned on distinct extension types. The
            // two extension slots are not independent under this constraint.
            while (grease[4]==grease[5]) {
                auto sampled=random.grease(); if (!sampled) return std::unexpected(E::random_error); grease[5]=*sampled;
            }
            h.cipher_suites.insert(h.cipher_suites.begin(),grease[0]);
            for (auto& extension:h.extensions) {
                if (extension.type==10) prepend(extension,grease[1]);
                if (extension.type==43 && (transport==HandshakeTransport::tcp || browser)) prepend(extension,grease[2],true);
                if (extension.type==13 && !browser) prepend(extension,grease[3]);
            }
            shares.push_back({grease[1],{0}});
            h.extensions.insert(h.extensions.begin(),{grease[4],{}});
            h.extensions.push_back({grease[5],{0}});
        }
        for (auto group:result.initial_groups()) shares.push_back({group,std::vector<std::uint8_t>(group==29 ? 32 : group==0x11ec ? 1216 : crypto::nist_curve(group)->public_size())});
        auto encoded=KeyShare::encode_client(shares); if (!encoded) return std::unexpected(E::too_large);
        for (auto& extension:h.extensions) if (extension.type==51) extension.data=std::move(*encoded);
        if (spec.permute) {
            // Fisher-Yates with rejection sampling; no deterministic PRNG seed.
            // Leading and trailing GREASE extension markers retain their bookend slots.
            for (std::size_t index=h.extensions.size()-2;index>1;--index) {
                auto sample=random.sample(static_cast<std::uint16_t>(index)); if (!sample) return std::unexpected(E::random_error);
                std::swap(h.extensions[index],h.extensions[1+*sample]);
            }
        }
        if (config.pad_to && (transport==HandshakeTransport::tcp || !browser)) {
            auto overhead=4+(transport==HandshakeTransport::tcp ? 5 : 0);
            if (config.pad_to<=overhead || !repad_client_hello(h,config.pad_to-overhead,16000)) return std::unexpected(E::invalid_policy);
        } else if (spec.tcp_min_pad && transport==HandshakeTransport::tcp) {
            auto current=h.encoding_size(16000);
            if (!current) return std::unexpected(E::too_large);
            constexpr std::size_t tcp_overhead=9;
            if (*current+tcp_overhead<spec.tcp_min_pad) {
                auto target=std::max(spec.tcp_min_pad-tcp_overhead,*current+4);
                if (!repad_client_hello(h,target,16000)) return std::unexpected(E::too_large);
            }
        }
        if (!h.validate_encoding(16000) || !h.validate_tls13() || !validate_handshake_transport(h,transport)) return std::unexpected(E::too_large);
        return result;
    }
}
