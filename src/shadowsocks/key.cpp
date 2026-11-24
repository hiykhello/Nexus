module shadowsocks.key;
import std;
import crypto;
import blake3;
import boringssl;
namespace shadowsocks {
    auto transform_aes_block(std::span<std::uint8_t const> key,
        std::span<std::uint8_t const,16> block,bool encrypt) noexcept -> std::optional<std::array<std::uint8_t,16>> {
        if (key.size()!=16 && key.size()!=32) return {};
        using namespace boringssl;
        struct Schedule {
            AES_KEY value{};
            ~Schedule() {crypto::cleanse(std::span{reinterpret_cast<std::uint8_t*>(&value),sizeof(value)});}
        } schedule;
        auto bits=static_cast<unsigned>(key.size()*8);
        auto status=encrypt ? AES_set_encrypt_key(key.data(),bits,&schedule.value)
                            : AES_set_decrypt_key(key.data(),bits,&schedule.value);
        if (status) return {};
        std::array<std::uint8_t,16> result;
        if (encrypt) AES_encrypt(block.data(),result.data(),&schedule.value);
        else AES_decrypt(block.data(),result.data(),&schedule.value);
        return result;
    }
    SessionKey::~SessionKey() { crypto::cleanse(bytes_); }
    SessionKey::SessionKey(SessionKey&& other) noexcept
        : bytes_(other.bytes_),size_(std::exchange(other.size_,0)),method_(other.method_) { crypto::cleanse(other.bytes_); }
    auto SessionKey::operator=(SessionKey&& other) noexcept -> SessionKey& {
        if (this!=&other) {
            crypto::cleanse(bytes_); bytes_=other.bytes_; size_=std::exchange(other.size_,0); method_=other.method_;
            crypto::cleanse(other.bytes_);
        }
        return *this;
    }
    auto SessionKey::derive(std::span<std::uint8_t const> key, std::span<std::uint8_t const> salt,CipherMethod method)
        -> std::expected<SessionKey,KeyError> {
        if (key.size()!=32 && (key.size()!=16 || method!=CipherMethod::aes)) return std::unexpected(KeyError::invalid_key_length);
        if (salt.size()!=key.size()) return std::unexpected(KeyError::invalid_salt_length);
        return derive_material(key,salt,method);
    }
    auto SessionKey::derive_udp(std::span<std::uint8_t const> key, std::span<std::uint8_t const,8> session_id) -> std::expected<SessionKey,KeyError> {
        if (key.size()!=16 && key.size()!=32) return std::unexpected(KeyError::invalid_key_length);
        return derive_material(key,session_id,CipherMethod::aes);
    }
    auto SessionKey::derive_material(std::span<std::uint8_t const> key, std::span<std::uint8_t const> salt,CipherMethod method)
        -> std::expected<SessionKey,KeyError> {
        constexpr std::string_view context="shadowsocks 2022 session subkey";
        blake3::blake3_hasher hasher{};
        blake3::blake3_hasher_init_derive_key_raw(&hasher,context.data(),context.size());
        blake3::blake3_hasher_update(&hasher,key.data(),key.size());
        blake3::blake3_hasher_update(&hasher,salt.data(),salt.size());
        SessionKey result; result.size_=key.size(); result.method_=method;
        blake3::blake3_hasher_finalize(&hasher,result.bytes_.data(),result.size_);
        crypto::cleanse(std::span{reinterpret_cast<std::uint8_t*>(&hasher),sizeof(hasher)});
        return result;
    }
}
