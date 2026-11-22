export module tls.schedule;
export import crypto;
import std;

export namespace tls {
    // Move-only, owns and erases its bytes; views remain valid only while this object is alive and unmoved.
    class Secret {
        crypto::Bytes bytes_;
    public:
        explicit Secret(crypto::Bytes&& bytes) noexcept : bytes_(std::move(bytes)) {}
        ~Secret();
        Secret(Secret const&) = delete;
        auto operator=(Secret const&) -> Secret& = delete;
        Secret(Secret&&) noexcept;
        auto operator=(Secret&&) noexcept -> Secret&;
        [[nodiscard]] auto view() const noexcept -> std::span<std::uint8_t const> { return bytes_; }
    };
    [[nodiscard]] auto expand_label(crypto::Hash hash, std::span<std::uint8_t const> secret,
                                    std::string_view label, std::span<std::uint8_t const> context,
                                    std::size_t length) -> std::expected<Secret, crypto::Error>;
    // transcript_hash is the digest of the exact handshake transcript at the specified stage.
    [[nodiscard]] auto derive_secret(crypto::Hash hash, std::span<std::uint8_t const> secret,
                                     std::string_view label, std::span<std::uint8_t const> transcript_hash)
        -> std::expected<Secret, crypto::Error>;
    [[nodiscard]] auto early_secret(crypto::Hash hash, std::optional<std::span<std::uint8_t const>> psk = {})
        -> std::expected<Secret, crypto::Error>;
    [[nodiscard]] auto handshake_secret(crypto::Hash hash, std::span<std::uint8_t const> early,
                                        std::span<std::uint8_t const> shared) -> std::expected<Secret, crypto::Error>;
    [[nodiscard]] auto master_secret(crypto::Hash hash, std::span<std::uint8_t const> handshake)
        -> std::expected<Secret, crypto::Error>;
    [[nodiscard]] auto finished_verify_data(crypto::Hash hash, std::span<std::uint8_t const> traffic_secret,
                                            std::span<std::uint8_t const> transcript_hash)
        -> std::expected<Secret, crypto::Error>;
    [[nodiscard]] auto exporter_master_secret(crypto::Hash hash, std::span<std::uint8_t const> master,
                                              std::span<std::uint8_t const> server_finished_transcript)
        -> std::expected<Secret, crypto::Error>;
    // RFC 8446 Section 7.5 exporter using exporter_master_secret.
    [[nodiscard]] auto export_keying_material(crypto::Hash hash, std::span<std::uint8_t const> exporter_master,
                                              std::string_view label, std::span<std::uint8_t const> context,
                                              std::size_t length) -> std::expected<Secret, crypto::Error>;
}
