export module tls.certificate_compression;
import std;

export namespace tls {
    inline constexpr std::uint16_t certificate_compression_extension=27;
    inline constexpr std::uint8_t compressed_certificate_message=25;
    enum class CertificateCompression : std::uint16_t { zlib=1,brotli=2,zstd=3 };
    enum class CertificateCompressionError { malformed,unoffered,decompression };
    inline constexpr auto certificate_compression_enabled() noexcept -> bool {
#ifdef NEXUS_ENABLE_TLS_CERT_COMPRESSION
        return true;
#else
        return false;
#endif
    }

    // Returns an ordinary Certificate handshake message for chain parsing.
    // The caller authenticates the original compressed wire in the transcript.
    [[nodiscard]] auto expand_certificate(std::span<std::uint8_t const> message,
        std::span<std::uint8_t const> offer,std::size_t maximum_body)
        -> std::expected<std::vector<std::uint8_t>,CertificateCompressionError>;
}
