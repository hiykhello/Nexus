export module nexus.shadowsocks.request;
import std;
import nexus.shadowsocks.chunk;
import nexus.shadowsocks.header;
import nexus.shadowsocks.replay;
export namespace nexus::shadowsocks {
    enum class RequestError { invalid_key_or_salt, invalid_header, short_read, authentication, replay, capacity, clock, crypto };
    struct EncodedRequest {
        std::vector<std::uint8_t> wire;
        ChunkCipher cipher; // Next nonce follows the two header chunks.
    };
    struct RequestPrefix {
        ChunkCipher cipher; // Fixed header has consumed the first nonce.
        std::vector<std::uint8_t> salt;
        std::size_t header_length;
        std::size_t consumed;
    };
    struct DecodedRequest {
        ChunkCipher cipher;
        std::vector<std::uint8_t> salt;
        RequestHeader header;
    };
    // Caller must generate a fresh random salt and send the returned wire in one socket write.
    [[nodiscard]] auto encode_request(std::span<std::uint8_t const> psk, std::span<std::uint8_t const> salt,
        std::uint64_t timestamp, std::span<std::uint8_t const> address, std::span<std::uint8_t const> padding,
        std::span<std::uint8_t const> payload) -> std::expected<EncodedRequest,RequestError>;
    // input must be the result of the single initial socket read; retain bytes after consumed.
    // Failure handling and coordination of the shared replay table belong to the socket owner.
    [[nodiscard]] auto decode_request_prefix(std::span<std::uint8_t const> psk, std::span<std::uint8_t const> input,
        std::uint64_t now, std::chrono::steady_clock::time_point monotonic_now, ReplayTable& replay)
        -> std::expected<RequestPrefix,RequestError>;
    // Production variant samples the replay table clocks under its lock.
    [[nodiscard]] auto decode_request_prefix_current(std::span<std::uint8_t const> psk, std::span<std::uint8_t const> input,
        ReplayTable& replay) -> std::expected<RequestPrefix,RequestError>;
    // Pass exactly header_length + 16 bytes. Consumes the prefix even on failure.
    [[nodiscard]] auto decode_request_header(RequestPrefix prefix, std::span<std::uint8_t const> ciphertext)
        -> std::expected<DecodedRequest,RequestError>;
}
