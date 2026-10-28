export module nexus.shadowsocks.response;
import std;
import nexus.shadowsocks.chunk;
export namespace nexus::shadowsocks {
    enum class ResponseError { invalid_key_or_salt, invalid_payload, invalid_header, short_read, authentication, crypto };
    struct EncodedResponse { std::vector<std::uint8_t> wire; ChunkCipher cipher; };
    struct ResponsePrefix { ChunkCipher cipher; std::size_t payload_length; std::size_t consumed; };
    struct DecodedResponse { ChunkCipher cipher; std::vector<std::uint8_t> payload; };
    // Salt must be fresh and random; send wire in one socket write.
    [[nodiscard]] auto encode_response(std::span<std::uint8_t const> psk, std::span<std::uint8_t const> salt,
        std::span<std::uint8_t const> request_salt, std::uint64_t timestamp, std::span<std::uint8_t const> payload)
        -> std::expected<EncodedResponse,ResponseError>;
    // input is the result of the one initial socket read; retain bytes after consumed.
    [[nodiscard]] auto decode_response_prefix(std::span<std::uint8_t const> psk, std::span<std::uint8_t const> request_salt,
        std::span<std::uint8_t const> input, std::uint64_t now) -> std::expected<ResponsePrefix,ResponseError>;
    // Pass exactly payload_length + 16 bytes; consumes prefix on success or failure.
    [[nodiscard]] auto decode_response_payload(ResponsePrefix prefix, std::span<std::uint8_t const> ciphertext)
        -> std::expected<DecodedResponse,ResponseError>;
}
