module nexus.shadowsocks.key;
import std;
import nexus.crypto;
import nexus.thirdparty.blake3;
namespace nexus::shadowsocks {
    SessionKey::~SessionKey() { crypto::cleanse(bytes_); }
    SessionKey::SessionKey(SessionKey&& other) noexcept : bytes_(other.bytes_),size_(std::exchange(other.size_,0)) { crypto::cleanse(other.bytes_); }
    auto SessionKey::operator=(SessionKey&& other) noexcept -> SessionKey& {
        if (this!=&other) { crypto::cleanse(bytes_); bytes_=other.bytes_; size_=std::exchange(other.size_,0); crypto::cleanse(other.bytes_); }
        return *this;
    }
    auto SessionKey::derive(std::span<std::uint8_t const> key, std::span<std::uint8_t const> salt) -> std::expected<SessionKey,KeyError> {
        if (key.size()!=16 && key.size()!=32) return std::unexpected(KeyError::invalid_key_length);
        if (salt.size()!=key.size()) return std::unexpected(KeyError::invalid_salt_length);
        return derive_material(key,salt);
    }
    auto SessionKey::derive_udp(std::span<std::uint8_t const> key, std::span<std::uint8_t const,8> session_id) -> std::expected<SessionKey,KeyError> {
        if (key.size()!=16 && key.size()!=32) return std::unexpected(KeyError::invalid_key_length);
        return derive_material(key,session_id);
    }
    auto SessionKey::derive_material(std::span<std::uint8_t const> key, std::span<std::uint8_t const> salt) -> std::expected<SessionKey,KeyError> {
        constexpr std::string_view context="shadowsocks 2022 session subkey";
        nex::blake3::blake3_hasher hasher{};
        nex::blake3::blake3_hasher_init_derive_key_raw(&hasher,context.data(),context.size());
        nex::blake3::blake3_hasher_update(&hasher,key.data(),key.size());
        nex::blake3::blake3_hasher_update(&hasher,salt.data(),salt.size());
        SessionKey result; result.size_=key.size();
        nex::blake3::blake3_hasher_finalize(&hasher,result.bytes_.data(),result.size_);
        crypto::cleanse(std::span{reinterpret_cast<std::uint8_t*>(&hasher),sizeof(hasher)});
        return result;
    }
}
