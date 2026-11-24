export module crypto.aead_context;
import std;
import crypto;
import boringssl;

export namespace crypto {
    // Stable-address key slot for packet protocols. The selected backend's
    // concrete context is owned directly; no allocation or dispatch wrapper
    // is added for per-packet encryption. It is intentionally non-movable.
    class AeadContext {
        boringssl::EVP_AEAD_CTX context_{};
        bool valid_=false;
        static auto algorithm(Aead value) noexcept -> boringssl::EVP_AEAD const* {
            using namespace boringssl;
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
            using namespace boringssl;
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
            auto success=encrypt ? EVP_AEAD_CTX_seal(&context_,bytes,&written,size,nonce.data(),nonce.size(),input.data(),input.size(),aad.data(),aad.size()) :
                EVP_AEAD_CTX_open(&context_,bytes,&written,size,nonce.data(),nonce.size(),input.data(),input.size(),aad.data(),aad.size());
            if (!success || written!=size) {
                cleanse(destination);
                auto const err=ERR_peek_last_error();
                ERR_clear_error();
                if (!encrypt && is_bad_decrypt(err)) return std::unexpected(Error::authentication_failed);
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
            boringssl::EVP_AEAD_CTX_cleanup(&context_);
            boringssl::OPENSSL_cleanse(&context_,sizeof(context_)); valid_=false;
        }
        // Validation errors preserve the previous slot; backend setup failure
        // leaves it invalid. Every supported algorithm has the full 16B tag.
        auto reset(Aead selected,std::span<std::uint8_t const> key) noexcept -> std::expected<void,Error> {
            auto* cipher=algorithm(selected);
            if (!cipher) return std::unexpected(Error::unsupported_algorithm);
            if (key.size()!=boringssl::EVP_AEAD_key_length(cipher)) return std::unexpected(Error::invalid_key);
            clear();
            if (!boringssl::EVP_AEAD_CTX_init(&context_,cipher,key.data(),key.size(),16,nullptr)) {
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
        auto seal_scatter_to(std::span<std::uint8_t> output,std::span<std::uint8_t const> nonce,
            std::span<std::uint8_t const> plaintext,std::span<std::uint8_t const> extra_plaintext,
            std::span<std::uint8_t const> aad={}) const noexcept -> std::expected<std::size_t,Error> {
            using namespace boringssl;
            if (!valid_) return std::unexpected(Error::invalid_state);
            if (nonce.size()!=EVP_AEAD_nonce_length(context_.aead)) return std::unexpected(Error::invalid_nonce);
            constexpr auto max_sz=std::numeric_limits<std::size_t>::max();
            if (plaintext.size()>max_sz-16 || extra_plaintext.size()>max_sz-16-plaintext.size())
                return std::unexpected(Error::invalid_length);
            auto const extra_total=extra_plaintext.size()+16;
            auto const total=plaintext.size()+extra_total;
            if (output.size()<total) return std::unexpected(Error::invalid_length);
            auto destination=output.first(total);
            auto cipher_dst=destination.first(plaintext.size());
            auto tag_dst=destination.subspan(plaintext.size());
            if ((cipher_dst.data()!=plaintext.data() && overlaps(cipher_dst,plaintext)) ||
                overlaps(tag_dst,plaintext) || overlaps(destination,extra_plaintext) ||
                overlaps(destination,nonce) || overlaps(destination,aad))
                return std::unexpected(Error::invalid_length);
            std::uint8_t empty=0;
            auto* out_ptr=cipher_dst.empty() ? &empty : cipher_dst.data();
            std::size_t tag_written=0;
            auto success=EVP_AEAD_CTX_seal_scatter(&context_,out_ptr,tag_dst.data(),&tag_written,extra_total,
                nonce.data(),nonce.size(),plaintext.data(),plaintext.size(),
                extra_plaintext.data(),extra_plaintext.size(),aad.data(),aad.size());
            if (!success || tag_written!=extra_total) {
                ERR_clear_error();
                cleanse(destination);
                return std::unexpected(Error::backend_failure);
            }
            return total;
        }
    };
}
