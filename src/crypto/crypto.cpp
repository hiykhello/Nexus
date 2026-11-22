module crypto;
import nexus.thirdparty.boringssl;
import std;
using namespace nex::boringssl;

namespace crypto {
    namespace {
        auto md(Hash hash) noexcept -> EVP_MD const* {
            switch (hash) { case Hash::sha256: return EVP_sha256(); case Hash::sha384: return EVP_sha384(); case Hash::sha512: return EVP_sha512(); case Hash::sha224: return EVP_sha224(); }
            return nullptr;
        }
        auto aead(Aead algorithm) noexcept -> EVP_AEAD const* {
            switch (algorithm) {
                case Aead::aes_128_gcm: return EVP_aead_aes_128_gcm();
                case Aead::aes_256_gcm: return EVP_aead_aes_256_gcm();
                case Aead::chacha20_poly1305: return EVP_aead_chacha20_poly1305();
                case Aead::xchacha20_poly1305: return EVP_aead_xchacha20_poly1305();
            }
            return nullptr;
        }
        auto crypt(bool encrypt, Aead algorithm, std::span<std::uint8_t const> key,
                   std::span<std::uint8_t const> nonce, std::span<std::uint8_t const> input,
                   std::span<std::uint8_t const> aad) -> std::expected<Bytes, Error> {
            auto* cipher=aead(algorithm);
            if (!cipher) return std::unexpected(Error::unsupported_algorithm);
            if (key.size()!=EVP_AEAD_key_length(cipher)) return std::unexpected(Error::invalid_key);
            if (nonce.size()!=EVP_AEAD_nonce_length(cipher)) return std::unexpected(Error::invalid_nonce);
            auto overhead=EVP_AEAD_max_overhead(cipher);
            if ((!encrypt && input.size()<overhead) || (encrypt && input.size()>Bytes{}.max_size()-overhead))
                return std::unexpected(Error::invalid_length);
            std::unique_ptr<EVP_AEAD_CTX, decltype(&EVP_AEAD_CTX_free)> ctx(
                EVP_AEAD_CTX_new(cipher,key.data(),key.size(),evp_aead_default_tag_length), EVP_AEAD_CTX_free);
            if (!ctx) return std::unexpected(Error::backend_failure);
            Bytes output(encrypt ? input.size()+overhead : input.size());
            std::size_t length=0;
            int ok=encrypt ? EVP_AEAD_CTX_seal(ctx.get(),output.data(),&length,output.size(),nonce.data(),nonce.size(),
                                               input.data(),input.size(),aad.data(),aad.size())
                           : EVP_AEAD_CTX_open(ctx.get(),output.data(),&length,output.size(),nonce.data(),nonce.size(),
                                               input.data(),input.size(),aad.data(),aad.size());
            if (!ok) { cleanse(output); return std::unexpected(encrypt ? Error::backend_failure : Error::authentication_failed); }
            output.resize(length); return output;
        }
    }
    Secret32::~Secret32() { cleanse(bytes_); }
    Secret32::Secret32(Secret32&& other) noexcept : bytes_(other.bytes_) { cleanse(other.bytes_); }
    auto Secret32::operator=(Secret32&& other) noexcept -> Secret32& {
        if (this != &other) { cleanse(bytes_); bytes_ = other.bytes_; cleanse(other.bytes_); }
        return *this;
    }
    X25519Private::X25519Private(Secret32&& key) noexcept : key_(std::move(key)) {}
    X25519Private::X25519Private(X25519Private&& other) noexcept
        : key_(std::move(other.key_)), valid_(std::exchange(other.valid_,false)) {}
    auto X25519Private::operator=(X25519Private&& other) noexcept -> X25519Private& {
        if (this != &other) { key_=std::move(other.key_); valid_=std::exchange(other.valid_,false); }
        return *this;
    }
    auto random_bytes(std::span<std::uint8_t> output) -> std::expected<void, Error> {
        if (!output.empty() && RAND_bytes(output.data(),output.size()) != 1) return std::unexpected(Error::backend_failure);
        return {};
    }
    auto X25519Private::generate() -> std::expected<X25519Private, Error> {
        Secret32 key;
        if (auto result=random_bytes(key.bytes_); !result) return std::unexpected(result.error());
        return X25519Private(std::move(key));
    }
    auto X25519Private::from_bytes(std::span<std::uint8_t const> key) -> std::expected<X25519Private, Error> {
        if (key.size()!=32) return std::unexpected(Error::invalid_key);
        Secret32 secret; std::ranges::copy(key,secret.bytes_.begin());
        return X25519Private(std::move(secret));
    }
    auto X25519Private::public_key() const -> std::expected<std::array<std::uint8_t,32>, Error> {
        if (!valid_) return std::unexpected(Error::invalid_key);
        std::array<std::uint8_t,32> result{};
        X25519_public_from_private(result.data(),key_.bytes_.data());
        return result;
    }
    auto X25519Private::agree(std::span<std::uint8_t const> peer) const -> std::expected<Secret32, Error> {
        if (!valid_) return std::unexpected(Error::invalid_key);
        if (peer.size()!=32) return std::unexpected(Error::invalid_peer);
        Secret32 result;
        if (!X25519(result.bytes_.data(),key_.bytes_.data(),peer.data())) return std::unexpected(Error::invalid_peer);
        return result;
    }
    auto cleanse(std::span<std::uint8_t> data) noexcept -> void { if (!data.empty()) OPENSSL_cleanse(data.data(),data.size()); }
    auto blake2b_256_parts(std::span<std::uint8_t,32> output,
        std::span<std::uint8_t const> first,std::span<std::uint8_t const> second) noexcept -> void {
        BLAKE2B_CTX context;
        BLAKE2B256_Init(&context);
        if (!first.empty()) BLAKE2B256_Update(&context,first.data(),first.size());
        if (!second.empty()) BLAKE2B256_Update(&context,second.data(),second.size());
        BLAKE2B256_Final(output.data(),&context);
        OPENSSL_cleanse(&context,sizeof(context));
    }
    DigestContext::DigestContext(EVP_MD_CTX* context, std::size_t size) noexcept : context_(context), size_(size) {}
    DigestContext::~DigestContext() { EVP_MD_CTX_free(context_); }
    DigestContext::DigestContext(DigestContext&& other) noexcept
        : context_(std::exchange(other.context_,nullptr)), size_(other.size_), failed_(other.failed_) {}
    auto DigestContext::operator=(DigestContext&& other) noexcept -> DigestContext& {
        if (this!=&other) {
            EVP_MD_CTX_free(context_); context_=std::exchange(other.context_,nullptr);
            size_=other.size_; failed_=other.failed_;
        }
        return *this;
    }
    auto DigestContext::create(Hash hash) -> std::expected<DigestContext, Error> {
        auto* type=md(hash); if (!type) return std::unexpected(Error::unsupported_algorithm);
        std::unique_ptr<EVP_MD_CTX,decltype(&EVP_MD_CTX_free)> context(EVP_MD_CTX_new(),EVP_MD_CTX_free);
        if (!context || !EVP_DigestInit_ex(context.get(),type,nullptr)) return std::unexpected(Error::backend_failure);
        return DigestContext(context.release(),EVP_MD_size(type));
    }
    auto DigestContext::update(std::span<std::uint8_t const> input) -> std::expected<void, Error> {
        if (!context_ || failed_) return std::unexpected(Error::invalid_state);
        if (!input.empty() && !EVP_DigestUpdate(context_,input.data(),input.size())) {
            failed_=true; return std::unexpected(Error::backend_failure);
        }
        return {};
    }
    auto DigestContext::snapshot() const -> std::expected<Bytes, Error> {
        if (!context_ || failed_) return std::unexpected(Error::invalid_state);
        std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> copy(EVP_MD_CTX_new(),EVP_MD_CTX_free);
        if (!copy || !EVP_MD_CTX_copy_ex(copy.get(),context_)) return std::unexpected(Error::backend_failure);
        Bytes output(size_); unsigned int length=0;
        if (!EVP_DigestFinal_ex(copy.get(),output.data(),&length) || length!=output.size()) return std::unexpected(Error::backend_failure);
        return output;
    }
    auto digest(Hash hash, std::span<std::uint8_t const> input) -> std::expected<Bytes, Error> {
        auto* type=md(hash); if (!type) return std::unexpected(Error::unsupported_algorithm);
        Bytes result(EVP_MD_size(type)); unsigned int length=0;
        if (!EVP_Digest(input.data(),input.size(),result.data(),&length,type,nullptr) || length!=result.size())
            return std::unexpected(Error::backend_failure);
        return result;
    }
    auto md5_fingerprint(std::span<std::uint8_t const> input) -> std::expected<std::array<std::uint8_t,16>,Error> {
        std::array<std::uint8_t,16> result{};
        unsigned int length=0;
        if (!EVP_Digest(input.data(),input.size(),result.data(),&length,EVP_md5(),nullptr) || length!=result.size())
            return std::unexpected(Error::backend_failure);
        return result;
    }
    HmacSha1Context::HmacSha1Context(HMAC_CTX* context) noexcept : context_(context) {}
    HmacSha1Context::~HmacSha1Context() { HMAC_CTX_free(context_); }
    HmacSha1Context::HmacSha1Context(HmacSha1Context&& other) noexcept
        : context_(std::exchange(other.context_,nullptr)), failed_(other.failed_) {}
    auto HmacSha1Context::operator=(HmacSha1Context&& other) noexcept -> HmacSha1Context& {
        if (this!=&other) {
            HMAC_CTX_free(context_); context_=std::exchange(other.context_,nullptr); failed_=other.failed_;
        }
        return *this;
    }
    auto HmacSha1Context::create(std::span<std::uint8_t const> key) -> std::expected<HmacSha1Context, Error> {
        std::unique_ptr<HMAC_CTX,decltype(&HMAC_CTX_free)> context(HMAC_CTX_new(),HMAC_CTX_free);
        if (!context || !HMAC_Init_ex(context.get(),key.data(),key.size(),EVP_sha1(),nullptr))
            return std::unexpected(Error::backend_failure);
        return HmacSha1Context(context.release());
    }
    auto HmacSha1Context::reset(std::span<std::uint8_t const> key) -> std::expected<void, Error> {
        if (!context_) return std::unexpected(Error::invalid_state);
        if (!HMAC_Init_ex(context_,key.data(),key.size(),EVP_sha1(),nullptr)) {
            failed_=true; return std::unexpected(Error::backend_failure);
        }
        failed_=false;
        return {};
    }
    auto HmacSha1Context::update(std::span<std::uint8_t const> input) -> std::expected<void, Error> {
        if (!context_ || failed_) return std::unexpected(Error::invalid_state);
        if (!input.empty() && !HMAC_Update(context_,input.data(),input.size())) {
            failed_=true; return std::unexpected(Error::backend_failure);
        }
        return {};
    }
    auto HmacSha1Context::snapshot() const -> std::expected<std::array<std::uint8_t, 20>, Error> {
        if (!context_ || failed_) return std::unexpected(Error::invalid_state);
        std::unique_ptr<HMAC_CTX,decltype(&HMAC_CTX_free)> copy(HMAC_CTX_new(),HMAC_CTX_free);
        if (!copy || !HMAC_CTX_copy(copy.get(),context_)) return std::unexpected(Error::backend_failure);
        std::array<std::uint8_t,20> output{}; unsigned int length=0;
        if (!HMAC_Final(copy.get(),output.data(),&length) || length!=output.size())
            return std::unexpected(Error::backend_failure);
        return output;
    }
    auto HmacSha1Context::clone() const -> std::expected<HmacSha1Context, Error> {
        if (!context_ || failed_) return std::unexpected(Error::invalid_state);
        std::unique_ptr<HMAC_CTX,decltype(&HMAC_CTX_free)> copy(HMAC_CTX_new(),HMAC_CTX_free);
        if (!copy || !HMAC_CTX_copy(copy.get(),context_)) return std::unexpected(Error::backend_failure);
        return HmacSha1Context(copy.release());
    }
    auto hmac(Hash hash, std::span<std::uint8_t const> key, std::span<std::uint8_t const> input) -> std::expected<Bytes, Error> {
        auto* type=md(hash); if (!type) return std::unexpected(Error::unsupported_algorithm);
        Bytes result(EVP_MD_size(type)); unsigned int length=0;
        if (!HMAC(type,key.data(),key.size(),input.data(),input.size(),result.data(),&length) || length!=result.size()) {
            cleanse(result); return std::unexpected(Error::backend_failure);
        }
        return result;
    }
    auto constant_time_equal(std::span<std::uint8_t const> a, std::span<std::uint8_t const> b) noexcept -> bool {
        if (a.size()!=b.size()) return false;
        return a.empty() || CRYPTO_memcmp(a.data(),b.data(),a.size())==0;
    }
    auto hkdf_extract(Hash hash, std::span<std::uint8_t const> salt, std::span<std::uint8_t const> secret)
        -> std::expected<Bytes, Error> {
        auto* type=md(hash); if (!type) return std::unexpected(Error::unsupported_algorithm);
        Bytes result(EVP_MD_size(type)); std::size_t length=0;
        if (!HKDF_extract(result.data(),&length,type,secret.data(),secret.size(),salt.data(),salt.size()) || length!=result.size()) {
            cleanse(result); return std::unexpected(Error::backend_failure);
        }
        return result;
    }
    auto hkdf_expand(Hash hash, std::span<std::uint8_t const> prk, std::span<std::uint8_t const> info, std::size_t length)
        -> std::expected<Bytes, Error> {
        auto* type=md(hash); if (!type) return std::unexpected(Error::unsupported_algorithm);
        auto size=static_cast<std::size_t>(EVP_MD_size(type));
        if (prk.size()<size || length>255*size) return std::unexpected(Error::invalid_length);
        Bytes result(length);
        if (length && !HKDF_expand(result.data(),length,type,prk.data(),prk.size(),info.data(),info.size())) {
            cleanse(result); return std::unexpected(Error::backend_failure);
        }
        return result;
    }
    auto seal(Aead algorithm, std::span<std::uint8_t const> key, std::span<std::uint8_t const> nonce,
              std::span<std::uint8_t const> plaintext, std::span<std::uint8_t const> aad) -> std::expected<Bytes, Error> {
        return crypt(true,algorithm,key,nonce,plaintext,aad);
    }
    auto open(Aead algorithm, std::span<std::uint8_t const> key, std::span<std::uint8_t const> nonce,
              std::span<std::uint8_t const> ciphertext, std::span<std::uint8_t const> aad) -> std::expected<Bytes, Error> {
        return crypt(false,algorithm,key,nonce,ciphertext,aad);
    }
}
