export module tls.hybrid;
export import crypto;
export import crypto.mlkem;
import std;

export namespace tls {
    inline constexpr std::uint16_t x25519_mlkem768_group = 0x11ec;
    enum class HybridError { invalid_share, invalid_public_key, invalid_state, crypto_error };
    class HybridSecret {
        std::array<std::uint8_t,64> bytes_{};
        friend class HybridClient;
        friend struct HybridServerResult;
        friend auto hybrid_server_accept(std::span<std::uint8_t const>,crypto::X25519Private&&) -> std::expected<struct HybridServerResult,HybridError>;
    public:
        HybridSecret() = default;
        ~HybridSecret();
        HybridSecret(HybridSecret const&) = delete;
        auto operator=(HybridSecret const&) -> HybridSecret& = delete;
        HybridSecret(HybridSecret&&) noexcept;
        auto operator=(HybridSecret&&) noexcept -> HybridSecret&;
        [[nodiscard]] auto view() const noexcept -> std::span<std::uint8_t const,64> { return bytes_; }
    };
    struct HybridServerResult { std::array<std::uint8_t,1120> share{}; HybridSecret secret; };
    class HybridClient {
        std::optional<crypto::Mlkem768Private> kem_;
        std::optional<crypto::X25519Private> x25519_;
        HybridClient(crypto::Mlkem768Private&& kem, crypto::X25519Private&& x25519) noexcept;
    public:
        ~HybridClient();
        HybridClient(HybridClient const&) = delete;
        auto operator=(HybridClient const&) -> HybridClient& = delete;
        HybridClient(HybridClient&& other) noexcept;
        auto operator=(HybridClient&& other) noexcept -> HybridClient&;
        [[nodiscard]] static auto generate() -> std::expected<HybridClient,HybridError>;
        // Consumes independent ephemeral keys. Do not reuse them for another handshake.
        [[nodiscard]] static auto from_keys(crypto::Mlkem768Private&& kem, crypto::X25519Private&& x25519) -> HybridClient;
        [[nodiscard]] auto share() const -> std::expected<std::array<std::uint8_t,1216>,HybridError>;
        // Borrowed for first-Hello authentication while this handshake owns the key.
        [[nodiscard]] auto x25519_key() const noexcept -> crypto::X25519Private const* { return x25519_ ? &*x25519_ : nullptr; }
        // One attempt consumes both private keys, including on failure. Successful decapsulation does not authenticate ciphertext.
        [[nodiscard]] auto finish(std::span<std::uint8_t const> server_share) -> std::expected<HybridSecret,HybridError>;
    };
    // Consumes an independently generated ephemeral X25519 key.
    [[nodiscard]] auto hybrid_server_accept(std::span<std::uint8_t const> client_share,crypto::X25519Private&& private_key)
        -> std::expected<HybridServerResult,HybridError>;
}
