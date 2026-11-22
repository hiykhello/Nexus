module shadowsocks.chunk;
import std;
import crypto;
namespace shadowsocks {
    ChunkCipher::ChunkCipher(SessionKey&& key, bool encrypt) noexcept : key_(std::move(key)), active_(true), encrypt_(encrypt) {}
    ChunkCipher::ChunkCipher(ChunkCipher&& other) noexcept
        : key_(std::move(other.key_)), nonce_(other.nonce_), active_(std::exchange(other.active_,false)), encrypt_(other.encrypt_) {}
    auto ChunkCipher::operator=(ChunkCipher&& other) noexcept -> ChunkCipher& {
        if (this!=&other) { key_=std::move(other.key_); nonce_=other.nonce_; active_=std::exchange(other.active_,false); encrypt_=other.encrypt_; }
        return *this;
    }
    auto ChunkCipher::create(SessionKey&& key, bool encrypt) -> std::expected<ChunkCipher,ChunkError> {
        if (key.view().size()!=16 && key.view().size()!=32) return std::unexpected(ChunkError::invalid_key);
        return ChunkCipher(std::move(key),encrypt);
    }
    auto ChunkCipher::advance() noexcept -> void {
        for (auto& byte:nonce_) { if (++byte!=0) { active_=true; return; } }
    }
    auto ChunkCipher::process(std::span<std::uint8_t const> input) -> std::expected<std::vector<std::uint8_t>,ChunkError> {
        if (!active_) return std::unexpected(ChunkError::closed);
        active_=false; // An exception or any error must never leave a nonce reusable.
        if (encrypt_ ? input.size()>65535 : input.size()<16 || input.size()>65535+16)
            return std::unexpected(ChunkError::invalid_length);
        auto algorithm=key_.method()==CipherMethod::chacha20 ? crypto::Aead::chacha20_poly1305 :
            key_.view().size()==16 ? crypto::Aead::aes_128_gcm : crypto::Aead::aes_256_gcm;
        auto result=encrypt_ ? crypto::seal(algorithm,key_.view(),nonce_,input) : crypto::open(algorithm,key_.view(),nonce_,input);
        if (!result) return std::unexpected(result.error()==crypto::Error::authentication_failed ? ChunkError::authentication_failed : ChunkError::backend_failure);
        advance();
        return std::move(*result);
    }
}
