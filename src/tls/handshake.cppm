export module nexus.tls.handshake;
import std;

export namespace nexus::tls {
    enum class HandshakeError { invalid_type, message_too_large, input_too_large, truncated, invalid_state };
    struct HandshakeMessage {
        std::uint8_t type = 0;
        std::vector<std::uint8_t> body;
        auto operator==(HandshakeMessage const&) const -> bool = default;
    };

    // Reassembles TLS Handshake messages from arbitrary record payload fragments.
    // It owns at most max_message_size + four bytes of incomplete input.
    class HandshakeDecoder {
        std::vector<std::uint8_t> pending_;
        std::size_t expected_ = 0;
        std::size_t max_message_size_;
        bool failed_ = false;
        explicit HandshakeDecoder(std::size_t max_message_size);
        auto fail(HandshakeError error) -> std::expected<std::vector<HandshakeMessage>, HandshakeError>;
    public:
        [[nodiscard]] static auto create(std::size_t max_message_size = 1u << 20)
            -> std::expected<HandshakeDecoder, HandshakeError>;
        HandshakeDecoder(HandshakeDecoder&&) noexcept = default;
        auto operator=(HandshakeDecoder&&) noexcept -> HandshakeDecoder& = default;
        HandshakeDecoder(HandshakeDecoder const&) = delete;
        auto operator=(HandshakeDecoder const&) -> HandshakeDecoder& = delete;
        // Each input is at most 2^14 bytes: a TLS plaintext record payload.
        // A call may contain part of a header, one message, or several messages.
        // On error the decoder fails and any completed messages from that call are discarded.
        [[nodiscard]] auto feed(std::span<std::uint8_t const> input)
            -> std::expected<std::vector<HandshakeMessage>, HandshakeError>;
        // End of the enclosing byte stream. A partial message permanently fails the decoder.
        [[nodiscard]] auto finish() -> std::expected<void, HandshakeError>;
        [[nodiscard]] auto failed() const noexcept -> bool { return failed_; }
        [[nodiscard]] auto pending_bytes() const noexcept -> std::size_t { return pending_.size(); }
        [[nodiscard]] static auto encode(std::uint8_t type, std::span<std::uint8_t const> body,
                                         std::size_t max_message_size = 1u << 20)
            -> std::expected<std::vector<std::uint8_t>, HandshakeError>;
    };
}
