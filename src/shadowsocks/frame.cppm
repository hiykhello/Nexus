export module shadowsocks.frame;
import std;
import shadowsocks.chunk;
export namespace shadowsocks {
    enum class FrameError { invalid_length, authentication, crypto, truncated, closed };
    struct FrameStep { std::size_t consumed; std::optional<std::vector<std::uint8_t>> payload; };
    struct FrameIntoStep { std::size_t consumed; bool has_payload; };
    struct FrameSpanStep { std::size_t consumed; std::size_t direct_written; bool has_frame; bool has_overflow; };
    // Each instance owns a cipher already positioned after the stream header.
    class FrameEncoder {
        ChunkCipher cipher_;
        std::unique_ptr<std::uint8_t[]> wire_;
        std::size_t wire_cap_=0;
        bool active_=true;
    public:
        explicit FrameEncoder(ChunkCipher cipher) noexcept : cipher_(std::move(cipher)) {}
        FrameEncoder(FrameEncoder const&) = delete;
        auto operator=(FrameEncoder const&) -> FrameEncoder& = delete;
        [[nodiscard]] auto encode(std::span<std::uint8_t const> payload) -> std::expected<std::vector<std::uint8_t>,FrameError>;
        // Reusable-buffer variant returning a view into internal wire_ storage (valid until next encode_wire/close).
        [[nodiscard]] auto encode_wire(std::span<std::uint8_t const> payload) -> std::expected<std::span<std::uint8_t const>,FrameError>;
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
        // Reusable-buffer variant writing decoded payload directly into out without reallocating capacity.
        [[nodiscard]] auto feed_into(std::span<std::uint8_t const> input, std::vector<std::uint8_t>& out) -> std::expected<FrameIntoStep,FrameError>;
        // Zero-copy variant: decrypts directly into direct_out when payload fits, else writes to overflow_out.
        [[nodiscard]] auto feed_span(std::span<std::uint8_t const> input, std::span<std::uint8_t> direct_out,
            std::vector<std::uint8_t>& overflow_out) -> std::expected<FrameSpanStep,FrameError>;
        // Signal EOF; succeeds only between complete frames and closes the decoder.
        [[nodiscard]] auto finish() -> std::expected<void,FrameError>;
    };
}
