module;
#include <openssl/mlkem.h>
#include <openssl/bytestring.h>
#include <openssl/crypto.h>
module nexus.crypto.mlkem;
import std;

namespace nexus::crypto {
    MlkemSecret::~MlkemSecret() { OPENSSL_cleanse(bytes_.data(),bytes_.size()); }
    MlkemSecret::MlkemSecret(MlkemSecret&& other) noexcept : bytes_(other.bytes_) { OPENSSL_cleanse(other.bytes_.data(),other.bytes_.size()); }
    auto MlkemSecret::operator=(MlkemSecret&& other) noexcept -> MlkemSecret& {
        if (this!=&other) { OPENSSL_cleanse(bytes_.data(),bytes_.size()); bytes_=other.bytes_; OPENSSL_cleanse(other.bytes_.data(),other.bytes_.size()); } return *this;
    }
    Mlkem768Private::~Mlkem768Private() { OPENSSL_cleanse(&key_,sizeof(key_)); }
    Mlkem768Private::Mlkem768Private(Mlkem768Private&& other) noexcept
        : key_(other.key_), valid_(std::exchange(other.valid_,false)) { OPENSSL_cleanse(&other.key_,sizeof(other.key_)); }
    auto Mlkem768Private::operator=(Mlkem768Private&& other) noexcept -> Mlkem768Private& {
        if (this!=&other) {
            OPENSSL_cleanse(&key_,sizeof(key_)); key_=other.key_; valid_=std::exchange(other.valid_,false);
            OPENSSL_cleanse(&other.key_,sizeof(other.key_));
        }
        return *this;
    }
    auto Mlkem768Private::generate() -> std::expected<Mlkem768Private,MlkemError> {
        Mlkem768Private result; std::array<std::uint8_t,1184> public_key{};
        MLKEM768_generate_key(public_key.data(),nullptr,&result.key_); return result;
    }
    auto Mlkem768Private::from_seed(std::span<std::uint8_t const> seed) -> std::expected<Mlkem768Private,MlkemError> {
        if (seed.size()!=64) return std::unexpected(MlkemError::invalid_key);
        Mlkem768Private result;
        if (MLKEM768_private_key_from_seed(&result.key_,seed.data(),seed.size())!=1) return std::unexpected(MlkemError::backend_failure);
        return result;
    }
    auto Mlkem768Private::public_key() const -> std::expected<std::array<std::uint8_t,1184>,MlkemError> {
        if (!valid_) return std::unexpected(MlkemError::invalid_state);
        MLKEM768_public_key key{}; MLKEM768_public_from_private(&key,&key_);
        CBB cbb; if (!CBB_init(&cbb,1184)) return std::unexpected(MlkemError::backend_failure);
        if (!MLKEM768_marshal_public_key(&cbb,&key) || CBB_len(&cbb)!=1184) { CBB_cleanup(&cbb); return std::unexpected(MlkemError::backend_failure); }
        std::array<std::uint8_t,1184> out{}; std::copy_n(CBB_data(&cbb),out.size(),out.begin()); CBB_cleanup(&cbb); return out;
    }
    auto Mlkem768Private::decapsulate(std::span<std::uint8_t const> ciphertext) const -> std::expected<MlkemSecret,MlkemError> {
        if (!valid_) return std::unexpected(MlkemError::invalid_state);
        if (ciphertext.size()!=1088) return std::unexpected(MlkemError::invalid_ciphertext);
        MlkemSecret secret; if (!MLKEM768_decap(secret.bytes_.data(),ciphertext.data(),ciphertext.size(),&key_)) return std::unexpected(MlkemError::backend_failure);
        return secret;
    }
    auto mlkem768_encapsulate(std::span<std::uint8_t const> encoded) -> std::expected<MlkemEncapsulation,MlkemError> {
        if (encoded.size()!=1184) return std::unexpected(MlkemError::invalid_key);
        CBS input; CBS_init(&input,encoded.data(),encoded.size()); MLKEM768_public_key key{};
        if (!MLKEM768_parse_public_key(&key,&input)) return std::unexpected(MlkemError::invalid_key);
        MlkemEncapsulation result; MLKEM768_encap(result.ciphertext.data(),result.secret.bytes_.data(),&key); return result;
    }
}
