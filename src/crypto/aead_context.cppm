export module crypto.aead_context;
import std;
import crypto;
import nexus.thirdparty.boringssl;

export namespace crypto {
    // Stable-address key slot for packet protocols. The selected backend's
    // concrete context is owned directly; no allocation or dispatch wrapper
    // is added for per-packet encryption. It is intentionally non-movable.
    class AeadContext {
        nex::boringssl::EVP_AEAD_CTX context_{};
        bool valid_=false;
        static auto algorithm(Aead value) noexcept -> nex::boringssl::EVP_AEAD const* {
            using namespace nex::boringssl;
            switch (value) {
            case Aead::aes_128_gcm: return EVP_aead_aes_128_gcm();
            case Aead::aes_256_gcm: return EVP_aead_aes_256_gcm();
            case Aead::chacha20_poly1305: return EVP_aead_chacha20_poly1305();
            case Aead::xchacha20_poly1305: return EVP_aead_xchacha20_poly1305();
            }
            return nullptr;
        }
        static auto overlaps(std::span<std::uint8_t> output,std::span<std::uint8_t const> input) noexcept -> bool {
            if (output.empty() || input.empty()) return false;
            auto first=reinterpret_cast<std::uintptr_t>(output.data()),second=reinterpret_cast<std::uintptr_t>(input.data());
            return first<=second ? second-first<output.size() : first-second<input.size();
        }
        auto apply(bool encrypt,std::span<std::uint8_t> output,std::span<std::uint8_t const> nonce,
            std::span<std::uint8_t const> input,std::span<std::uint8_t const> aad) const noexcept -> std::expected<std::size_t,Error> {
            using namespace nex::boringssl;
            if (!valid_) return std::unexpected(Error::invalid_state);
            if (nonce.size()!=EVP_AEAD_nonce_length(context_.aead)) return std::unexpected(Error::invalid_nonce);
            if ((!encrypt && input.size()<16) || (encrypt && input.size()>std::numeric_limits<std::size_t>::max()-16))
                return std::unexpected(Error::invalid_length);
            auto size=encrypt ? input.size()+16 : input.size()-16;
            if (output.size()<size) return std::unexpected(Error::invalid_length);
            auto destination=output.first(size);
            if ((destination.data()!=input.data() && overlaps(destination,input)) || overlaps(destination,nonce) || overlaps(destination,aad))
                return std::unexpected(Error::invalid_length);
            std::uint8_t empty=0;
            auto* bytes=destination.empty() ? &empty : destination.data();
            std::size_t written=0;
            ERR_clear_error();
            auto success=encrypt ? EVP_AEAD_CTX_seal(&context_,bytes,&written,size,nonce.data(),nonce.size(),input.data(),input.size(),aad.data(),aad.size()) :
                EVP_AEAD_CTX_open(&context_,bytes,&written,size,nonce.data(),nonce.size(),input.data(),input.size(),aad.data(),aad.size());
            if (!success || written!=size) {
                cleanse(destination);
                if (!encrypt && is_bad_decrypt(ERR_peek_last_error())) return std::unexpected(Error::authentication_failed);
                return std::unexpected(Error::backend_failure);
            }
            return written;
        }
    public:
        AeadContext() noexcept=default;
        ~AeadContext() { clear(); }
        AeadContext(AeadContext const&)=delete;
        auto operator=(AeadContext const&) -> AeadContext& = delete;
        AeadContext(AeadContext&&)=delete;
        auto operator=(AeadContext&&) -> AeadContext& = delete;
        auto valid() const noexcept -> bool { return valid_; }
        auto clear() noexcept -> void {
            nex::boringssl::EVP_AEAD_CTX_cleanup(&context_);
            nex::boringssl::OPENSSL_cleanse(&context_,sizeof(context_)); valid_=false;
        }
        // Validation errors preserve the previous slot; backend setup failure
        // leaves it invalid. Every supported algorithm has the full 16B tag.
        auto reset(Aead selected,std::span<std::uint8_t const> key) noexcept -> std::expected<void,Error> {
            auto* cipher=algorithm(selected);
            if (!cipher) return std::unexpected(Error::unsupported_algorithm);
            if (key.size()!=nex::boringssl::EVP_AEAD_key_length(cipher)) return std::unexpected(Error::invalid_key);
            clear();
            if (!nex::boringssl::EVP_AEAD_CTX_init(&context_,cipher,key.data(),key.size(),16,nullptr)) {
                clear(); return std::unexpected(Error::backend_failure);
            }
            valid_=true; return {};
        }
        // Only exact-start input/output overlap is supported. Validation
        // errors do not write; backend/auth failure cleans the output prefix.
        // Nonces and usage limits belong to the protocol owner.
        auto seal_to(std::span<std::uint8_t> output,std::span<std::uint8_t const> nonce,std::span<std::uint8_t const> plaintext,
            std::span<std::uint8_t const> aad={}) const noexcept -> std::expected<std::size_t,Error> {
            return apply(true,output,nonce,plaintext,aad);
        }
        auto open_to(std::span<std::uint8_t> output,std::span<std::uint8_t const> nonce,std::span<std::uint8_t const> ciphertext,
            std::span<std::uint8_t const> aad={}) const noexcept -> std::expected<std::size_t,Error> {
            return apply(false,output,nonce,ciphertext,aad);
        }
    };
}
