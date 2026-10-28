export module nexus.shadowsocks.udp_cipher;
import std;

export namespace nexus::shadowsocks {
    enum class UdpCipherError { invalid_key, invalid_length, authentication, crypto };
    struct UdpPlaintext {
        std::array<std::uint8_t,16> separate_header;
        std::vector<std::uint8_t> body;
    };
    // Low-level AES UDP construction only. The owner must generate unique
    // session IDs, never reuse a packet ID within a session, and authenticate
    // and validate all main-header fields before changing replay/session state.
    [[nodiscard]] auto seal_udp(std::span<std::uint8_t const> psk,
        std::span<std::uint8_t const,16> separate_header, std::span<std::uint8_t const> body)
        -> std::expected<std::vector<std::uint8_t>,UdpCipherError>;
    // No decrypted header or body is returned if AEAD authentication fails.
    [[nodiscard]] auto open_udp(std::span<std::uint8_t const> psk, std::span<std::uint8_t const> packet)
        -> std::expected<UdpPlaintext,UdpCipherError>;
}
