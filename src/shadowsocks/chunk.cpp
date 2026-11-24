module shadowsocks.chunk;
import std;
import crypto;
import crypto.aead_context;
namespace shadowsocks {
    ChunkCipher::ChunkCipher(SessionKey&& key, std::unique_ptr<crypto::AeadContext> aead, bool encrypt) noexcept
        : key_(std::move(key)), aead_(std::move(aead)), active_(true), encrypt_(encrypt) {}
    ChunkCipher::~ChunkCipher() = default;
    ChunkCipher::ChunkCipher(ChunkCipher&& other) noexcept
        : key_(std::move(other.key_)), aead_(std::move(other.aead_)), nonce_(other.nonce_), active_(std::exchange(other.active_,false)), encrypt_(other.encrypt_) {}
    auto ChunkCipher::operator=(ChunkCipher&& other) noexcept -> ChunkCipher& {
        if (this!=&other) { key_=std::move(other.key_); aead_=std::move(other.aead_); nonce_=other.nonce_; active_=std::exchange(other.active_,false); encrypt_=other.encrypt_; }
        return *this;
    }
    auto ChunkCipher::create(SessionKey&& key, bool encrypt) -> std::expected<ChunkCipher,ChunkError> {
        if (key.view().size()!=16 && key.view().size()!=32) return std::unexpected(ChunkError::invalid_key);
        auto algorithm=key.method()==CipherMethod::chacha20 ? crypto::Aead::chacha20_poly1305 :
            key.view().size()==16 ? crypto::Aead::aes_128_gcm : crypto::Aead::aes_256_gcm;
        auto aead=std::make_unique<crypto::AeadContext>();
        if (auto ok=aead->reset(algorithm,key.view()); !ok) {
            return std::unexpected(ok.error()==crypto::Error::invalid_key ? ChunkError::invalid_key : ChunkError::backend_failure);
        }
        return ChunkCipher(std::move(key),std::move(aead),encrypt);
    }
    auto ChunkCipher::advance() noexcept -> void {
        for (auto& byte:nonce_) { if (++byte!=0) { active_=true; return; } }
    }
    auto ChunkCipher::process_to(std::span<std::uint8_t const> input, std::span<std::uint8_t> output)
        -> std::expected<std::size_t,ChunkError> {
        if (!active_ || !aead_) return std::unexpected(ChunkError::closed);
        active_=false; // An exception or any error must never leave a nonce reusable.
        if (encrypt_ ? input.size()>65535 : input.size()<16 || input.size()>65535+16)
            return std::unexpected(ChunkError::invalid_length);
        auto const expected = encrypt_ ? input.size()+16 : input.size()-16;
        if (output.size() < expected) return std::unexpected(ChunkError::invalid_length);
        auto written=encrypt_ ? aead_->seal_to(output.first(expected),nonce_,input)
                              : aead_->open_to(output.first(expected),nonce_,input);
        if (!written) return std::unexpected(written.error()==crypto::Error::authentication_failed ? ChunkError::authentication_failed : ChunkError::backend_failure);
        advance();
        return *written;
    }
    auto ChunkCipher::process(std::span<std::uint8_t const> input) -> std::expected<std::vector<std::uint8_t>,ChunkError> {
        if (!active_ || !aead_) return std::unexpected(ChunkError::closed);
        if (encrypt_ ? input.size()>65535 : input.size()<16 || input.size()>65535+16) {
            active_=false;
            return std::unexpected(ChunkError::invalid_length);
        }
        std::vector<std::uint8_t> output(encrypt_ ? input.size()+16 : input.size()-16);
        auto written=process_to(input,output);
        if (!written) return std::unexpected(written.error());
        output.resize(*written);
        return output;
    }
}
