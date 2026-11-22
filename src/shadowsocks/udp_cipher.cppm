export module shadowsocks.udp_cipher;
import std;
import shadowsocks.key;

export namespace shadowsocks {
    enum class UdpCipherError { invalid_key, invalid_length, authentication, crypto };
    struct UdpPlaintext {
        std::array<std::uint8_t,16> separate_header;
        std::vector<std::uint8_t> body;
    };
    inline constexpr auto udp_cipher_overhead(CipherMethod method) noexcept -> std::size_t {
        return method==CipherMethod::chacha20 ? 56 : 32;
    }
    // The owner enforces unique session/packet IDs and authenticates all
    // fields before changing replay or session state.
    [[nodiscard]] auto seal_udp(std::span<std::uint8_t const> psk,
        std::span<std::uint8_t const,16> separate_header, std::span<std::uint8_t const> body,
        CipherMethod method=CipherMethod::aes,
        std::span<std::array<std::uint8_t,32> const> identities={}) -> std::expected<std::vector<std::uint8_t>,UdpCipherError>;
    // No decrypted header or body is returned if AEAD authentication fails.
    [[nodiscard]] auto open_udp(std::span<std::uint8_t const> psk, std::span<std::uint8_t const> packet,
                               CipherMethod method=CipherMethod::aes)
        -> std::expected<UdpPlaintext,UdpCipherError>;
    [[nodiscard]] auto open_udp_aes_body(std::span<std::uint8_t const> psk,
        std::array<std::uint8_t,16> header,std::span<std::uint8_t const> ciphertext)
        -> std::expected<UdpPlaintext,UdpCipherError>;
}
