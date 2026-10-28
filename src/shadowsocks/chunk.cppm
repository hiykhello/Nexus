export module nexus.shadowsocks.chunk;
import std;
import nexus.shadowsocks.key;
export namespace nexus::shadowsocks {
    enum class ChunkError { invalid_key, invalid_length, authentication_failed, backend_failure, closed };
    // One instance is one direction of one stream. Use a fresh session key per stream.
    // Each successful call consumes one nonce; never reuse a key and nonce across instances.
    class ChunkCipher {
        SessionKey key_;
        std::array<std::uint8_t,12> nonce_{};
        bool active_=false;
        bool encrypt_=false;
        ChunkCipher(SessionKey&& key, bool encrypt) noexcept;
        auto advance() noexcept -> void;
    public:
        ChunkCipher(ChunkCipher const&) = delete;
        auto operator=(ChunkCipher const&) -> ChunkCipher& = delete;
        ChunkCipher(ChunkCipher&&) noexcept;
        auto operator=(ChunkCipher&&) noexcept -> ChunkCipher&;
        [[nodiscard]] static auto create(SessionKey&& key, bool encrypt) -> std::expected<ChunkCipher,ChunkError>;
        // Ciphertext includes the 16-byte tag. Failure permanently closes the stream.
        [[nodiscard]] auto process(std::span<std::uint8_t const> input)
            -> std::expected<std::vector<std::uint8_t>,ChunkError>;
    };
}
