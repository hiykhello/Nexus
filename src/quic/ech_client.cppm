export module quic.ech_client;
import std;
import crypto.hpke_sender;
import quic.ech_config;
import tls.server_hello;

export namespace quic {
    enum class EchHandshakeError { malformed, rejected, crypto };
    inline constexpr std::uint16_t ech_extension = 0xfe0d;

    class EchClient {
        std::string public_name_;
        std::uint8_t config_id_, maximum_name_length_;
        std::uint16_t aead_;
        crypto::HpkeSender sender_;
        std::array<std::uint8_t,32> outer_random_{};
        EchClient(EchConfig const& config, crypto::HpkeSender sender);
    public:
        [[nodiscard]] static auto create(EchConfig const& config) -> std::optional<EchClient>;
        // `inner` already contains the final generated key shares. The caller
        // retains its uncompressed encoding for TLS transcript processing.
        [[nodiscard]] auto seal(tls::ClientHello const& inner, bool retry = false)
            -> std::expected<std::vector<std::uint8_t>, EchHandshakeError>;
    };

    // For a final ServerHello after HRR, pass the exact HRR and second inner
    // ClientHello. For HRR itself those two arguments must be empty.
    [[nodiscard]] auto verify_ech_acceptance(std::span<const std::uint8_t> first_inner,
        std::span<const std::uint8_t> server_hello, std::span<const std::uint8_t> retry = {},
        std::span<const std::uint8_t> second_inner = {}) -> std::expected<void, EchHandshakeError>;
}
