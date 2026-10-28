export module nexus.shadowsocks.frame;
import std;
import nexus.shadowsocks.chunk;
export namespace nexus::shadowsocks {
    enum class FrameError { invalid_length, authentication, crypto, truncated, closed };
    struct FrameStep { std::size_t consumed; std::optional<std::vector<std::uint8_t>> payload; };
    // Each instance owns a cipher already positioned after the stream header.
    class FrameEncoder {
        ChunkCipher cipher_;
        bool active_=true;
    public:
        explicit FrameEncoder(ChunkCipher cipher) noexcept : cipher_(std::move(cipher)) {}
        FrameEncoder(FrameEncoder const&) = delete;
        auto operator=(FrameEncoder const&) -> FrameEncoder& = delete;
        [[nodiscard]] auto encode(std::span<std::uint8_t const> payload) -> std::expected<std::vector<std::uint8_t>,FrameError>;
        auto close() noexcept -> void { active_=false; }
    };
    class FrameDecoder {
        ChunkCipher cipher_;
        std::vector<std::uint8_t> buffer_;
        std::size_t needed_=18;
        bool length_=true;
        bool active_=true;
    public:
        explicit FrameDecoder(ChunkCipher cipher) noexcept : cipher_(std::move(cipher)) {}
        FrameDecoder(FrameDecoder const&) = delete;
        auto operator=(FrameDecoder const&) -> FrameDecoder& = delete;
        // Returns at most one authenticated payload. Caller retains input after consumed.
        [[nodiscard]] auto feed(std::span<std::uint8_t const> input) -> std::expected<FrameStep,FrameError>;
        // Signal EOF; succeeds only between complete frames and closes the decoder.
        [[nodiscard]] auto finish() -> std::expected<void,FrameError>;
    };
}
