export module shadowsocks.chunk;
import std;
import crypto.aead_context;
import shadowsocks.key;
export namespace shadowsocks {
    enum class ChunkError { invalid_key, invalid_length, authentication_failed, backend_failure, closed };
    // One instance is one direction of one stream. Use a fresh session key per stream.
    // Each successful call consumes one nonce; never reuse a key and nonce across instances.
    class ChunkCipher {
        SessionKey key_;
        std::unique_ptr<crypto::AeadContext> aead_;
        std::array<std::uint8_t,12> nonce_{};
        bool active_=false;
        bool encrypt_=false;
        ChunkCipher(SessionKey&& key, std::unique_ptr<crypto::AeadContext> aead, bool encrypt) noexcept;
        auto advance() noexcept -> void;
    public:
        ~ChunkCipher();
        ChunkCipher(ChunkCipher const&) = delete;
        auto operator=(ChunkCipher const&) -> ChunkCipher& = delete;
        ChunkCipher(ChunkCipher&&) noexcept;
        auto operator=(ChunkCipher&&) noexcept -> ChunkCipher&;
        [[nodiscard]] static auto create(SessionKey&& key, bool encrypt) -> std::expected<ChunkCipher,ChunkError>;
        [[nodiscard]] auto method() const noexcept -> CipherMethod {return key_.method();}
        // Ciphertext includes the 16-byte tag. Failure permanently closes the stream.
        [[nodiscard]] auto process(std::span<std::uint8_t const> input)
            -> std::expected<std::vector<std::uint8_t>,ChunkError>;
        // Zero-allocation variant writing directly into caller-provided output buffer.
        [[nodiscard]] auto process_to(std::span<std::uint8_t const> input, std::span<std::uint8_t> output)
            -> std::expected<std::size_t,ChunkError>;
    };
}
