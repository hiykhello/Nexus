export module crypto;
export import nexus.thirdparty.boringssl;
import std;
using namespace nex::boringssl;

export namespace crypto {
    using Bytes = std::vector<std::uint8_t>;
    enum class Hash { sha256, sha384, sha512, sha224 };
    enum class Aead { aes_128_gcm, aes_256_gcm, chacha20_poly1305, xchacha20_poly1305 };
    enum class Error { unsupported_algorithm, invalid_key, invalid_nonce, invalid_length, authentication_failed, invalid_peer, invalid_state, backend_failure };
    // RAND_bytes aborts if the operating system cannot supply randomness.
    [[nodiscard]] auto random_bytes(std::span<std::uint8_t> output) -> std::expected<void, Error>;
    class X25519Private;
    class Secret32 {
        std::array<std::uint8_t,32> bytes_{};
        friend class X25519Private;
    public:
        Secret32() = default;
        ~Secret32();
        Secret32(Secret32 const&) = delete;
        auto operator=(Secret32 const&) -> Secret32& = delete;
        Secret32(Secret32&& other) noexcept;
        auto operator=(Secret32&& other) noexcept -> Secret32&;
        [[nodiscard]] auto view() const noexcept -> std::span<std::uint8_t const,32> { return bytes_; }
    };
    class X25519Private {
        Secret32 key_;
        bool valid_ = true;
        explicit X25519Private(Secret32&& key) noexcept;
    public:
        X25519Private(X25519Private const&) = delete;
        auto operator=(X25519Private const&) -> X25519Private& = delete;
        X25519Private(X25519Private&& other) noexcept;
        auto operator=(X25519Private&& other) noexcept -> X25519Private&;
        [[nodiscard]] static auto generate() -> std::expected<X25519Private, Error>;
        [[nodiscard]] static auto from_bytes(std::span<std::uint8_t const> key) -> std::expected<X25519Private, Error>;
        [[nodiscard]] auto public_key() const -> std::expected<std::array<std::uint8_t,32>, Error>;
        // Rejects low-order public values; feed the shared secret into a protocol-specific KDF.
        [[nodiscard]] auto agree(std::span<std::uint8_t const> peer) const -> std::expected<Secret32, Error>;
    };
    // Returned byte vectors and input keys are caller-owned and are not automatically erased.
    auto cleanse(std::span<std::uint8_t> data) noexcept -> void;
    // Hash two contiguous logical segments without allocating or copying them.
    auto blake2b_256_parts(std::span<std::uint8_t,32> output,
        std::span<std::uint8_t const> first,std::span<std::uint8_t const> second) noexcept -> void;
    class DigestContext {
        env_md_ctx_st* context_;
        std::size_t size_;
        bool failed_ = false;
        explicit DigestContext(env_md_ctx_st* context, std::size_t size) noexcept;
    public:
        ~DigestContext();
        DigestContext(DigestContext&&) noexcept;
        auto operator=(DigestContext&&) noexcept -> DigestContext&;
        DigestContext(DigestContext const&) = delete;
        auto operator=(DigestContext const&) -> DigestContext& = delete;
        [[nodiscard]] static auto create(Hash hash) -> std::expected<DigestContext, Error>;
        [[nodiscard]] auto update(std::span<std::uint8_t const> input) -> std::expected<void, Error>;
        // Takes a snapshot without finalizing the live context.
        [[nodiscard]] auto snapshot() const -> std::expected<Bytes, Error>;
    };
    [[nodiscard]] auto digest(Hash hash, std::span<std::uint8_t const> input) -> std::expected<Bytes, Error>;
    // Compatibility fingerprints only, e.g. AnyTLS padding scheme IDs. This
    // is deliberately absent from Hash so it cannot select HMAC/HKDF/TLS.
    [[nodiscard]] auto md5_fingerprint(std::span<std::uint8_t const> input) -> std::expected<std::array<std::uint8_t,16>,Error>;
    // Legacy HMAC-SHA1 stream state for compatibility protocols such as ShadowTLS v3.
    class HmacSha1Context {
        hmac_ctx_st* context_;
        bool failed_ = false;
        explicit HmacSha1Context(hmac_ctx_st* context) noexcept;
    public:
        ~HmacSha1Context();
        HmacSha1Context(HmacSha1Context&&) noexcept;
        auto operator=(HmacSha1Context&&) noexcept -> HmacSha1Context&;
        HmacSha1Context(HmacSha1Context const&) = delete;
        auto operator=(HmacSha1Context const&) -> HmacSha1Context& = delete;
        [[nodiscard]] static auto create(std::span<std::uint8_t const> key) -> std::expected<HmacSha1Context, Error>;
        [[nodiscard]] auto reset(std::span<std::uint8_t const> key) -> std::expected<void, Error>;
        [[nodiscard]] auto update(std::span<std::uint8_t const> input) -> std::expected<void, Error>;
        [[nodiscard]] auto snapshot() const -> std::expected<std::array<std::uint8_t, 20>, Error>;
        [[nodiscard]] auto clone() const -> std::expected<HmacSha1Context, Error>;
    };
    [[nodiscard]] auto hmac(Hash hash, std::span<std::uint8_t const> key,
                            std::span<std::uint8_t const> input) -> std::expected<Bytes, Error>;
    [[nodiscard]] auto constant_time_equal(std::span<std::uint8_t const> a, std::span<std::uint8_t const> b) noexcept -> bool;
    // NaCl-compatible one-time authenticator. The key must never authenticate
    // two messages; protocols derive a fresh key from their unique nonce.
    auto poly1305_to(std::span<std::uint8_t,16> tag,std::span<std::uint8_t const,32> one_time_key,
        std::span<std::uint8_t const> message) noexcept -> void;
    [[nodiscard]] auto hkdf_extract(Hash hash, std::span<std::uint8_t const> salt,
                                    std::span<std::uint8_t const> secret) -> std::expected<Bytes, Error>;
    [[nodiscard]] auto hkdf_expand(Hash hash, std::span<std::uint8_t const> prk,
                                   std::span<std::uint8_t const> info, std::size_t length) -> std::expected<Bytes, Error>;
    // Nonces must be unique per key. The caller owns nonce generation and usage limits.
    [[nodiscard]] auto seal(Aead algorithm, std::span<std::uint8_t const> key, std::span<std::uint8_t const> nonce,
                            std::span<std::uint8_t const> plaintext, std::span<std::uint8_t const> aad = {})
        -> std::expected<Bytes, Error>;
    [[nodiscard]] auto open(Aead algorithm, std::span<std::uint8_t const> key, std::span<std::uint8_t const> nonce,
                            std::span<std::uint8_t const> ciphertext, std::span<std::uint8_t const> aad = {})
        -> std::expected<Bytes, Error>;
}
