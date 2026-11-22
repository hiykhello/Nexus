export module shadowsocks.identity;
import std;
import crypto;
import nexus.thirdparty.blake3;
import shadowsocks.key;

export namespace shadowsocks {
    using IdentityBlock=std::array<std::uint8_t,16>;

    [[nodiscard]] auto identity_hash(std::span<std::uint8_t const> psk) noexcept -> IdentityBlock;
    // SIP023 places this encrypted block between the TCP salt and AEAD chunks.
    [[nodiscard]] auto tcp_identity(std::span<std::uint8_t const> identity_key,
        std::span<std::uint8_t const> salt,std::span<std::uint8_t const,16> block,bool encrypt) noexcept
        -> std::optional<IdentityBlock>;
    struct UdpIdentity {
        IdentityBlock header;
        IdentityBlock user_hash;
    };
    // The caller must authenticate the remaining ciphertext with the
    // selected user's key before changing any session state.
    [[nodiscard]] auto open_udp_identity(std::span<std::uint8_t const> identity_key,
        std::span<std::uint8_t const> packet) noexcept -> std::optional<UdpIdentity>;
}

namespace shadowsocks {
    namespace {
        struct Hasher {
            nex::blake3::blake3_hasher value{};
            ~Hasher() { crypto::cleanse(std::span{reinterpret_cast<std::uint8_t*>(&value),sizeof(value)}); }
        };
    }

    auto identity_hash(std::span<std::uint8_t const> psk) noexcept -> IdentityBlock {
        Hasher hash;
        nex::blake3::blake3_hasher_init(&hash.value);
        nex::blake3::blake3_hasher_update(&hash.value,psk.data(),psk.size());
        IdentityBlock result;
        nex::blake3::blake3_hasher_finalize(&hash.value,result.data(),result.size());
        return result;
    }

    auto tcp_identity(std::span<std::uint8_t const> identity_key,
        std::span<std::uint8_t const> salt,std::span<std::uint8_t const,16> block,bool encrypt) noexcept
        -> std::optional<IdentityBlock> {
        if ((identity_key.size()!=16 && identity_key.size()!=32) || salt.size()!=identity_key.size()) return {};
        constexpr std::string_view context="shadowsocks 2022 identity subkey";
        Hasher hash;
        nex::blake3::blake3_hasher_init_derive_key_raw(&hash.value,context.data(),context.size());
        nex::blake3::blake3_hasher_update(&hash.value,identity_key.data(),identity_key.size());
        nex::blake3::blake3_hasher_update(&hash.value,salt.data(),salt.size());
        struct Secret {
            std::array<std::uint8_t,32> value{};
            ~Secret() { crypto::cleanse(value); }
        } key;
        auto subkey=std::span(key.value).first(identity_key.size());
        nex::blake3::blake3_hasher_finalize(&hash.value,subkey.data(),subkey.size());
        return transform_aes_block(subkey,block,encrypt);
    }

    auto open_udp_identity(std::span<std::uint8_t const> identity_key,
        std::span<std::uint8_t const> packet) noexcept -> std::optional<UdpIdentity> {
        if (packet.size()<48) return {};
        auto header=transform_aes_block(identity_key,packet.first<16>(),false);
        auto hash=transform_aes_block(identity_key,packet.subspan<16,16>(),false);
        if (!header || !hash) return {};
        for (std::size_t index=0;index<hash->size();++index) (*hash)[index]^=(*header)[index];
        return UdpIdentity{*header,*hash};
    }
}
