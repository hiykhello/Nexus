export module tls.fingerprint;
export import tls.hello_config;
export import tls.handshake_policy;
export import tls.key_share;
import std;

export namespace tls {
    // Native Nexus TLS 1.3 profiles plus named browser uTLS shapes built strictly from verified capabilities.
    enum class Fingerprint : std::uint8_t {
        native, tls13_grease, tls13_randomized,
        chrome, firefox, safari, ios, android, edge, random, tls12
    };
    enum class FingerprintShares : std::uint8_t { x25519,hybrid,dual,retry };
    enum class FingerprintError { invalid_policy,invalid_hello,random_error,too_large };
    struct FingerprintConfig {
        Fingerprint profile=Fingerprint::native;
        FingerprintShares shares=FingerprintShares::x25519;
        // Total raw Handshake bytes, or TCP record+Handshake bytes. Zero disables padding.
        std::uint16_t pad_to=0;
        std::array<std::uint16_t,3> cipher_order{0x1301,0x1302,0x1303};
        std::uint8_t cipher_count=3;
        std::array<std::uint16_t,7> signature_order{0x0804,0x0403,0x0807,0x0805,0x0806,0x0503,0x0603};
        std::uint8_t signature_count=3;
        // A nonzero count selects explicit implemented groups and initial shares.
        // Zero preserves the legacy shares policy above.
        std::array<std::uint16_t,5> group_order{29,0x11ec,23,24,25};
        std::array<std::uint16_t,2> key_share_groups{29,0x11ec};
        std::uint8_t group_count=0;
        std::uint8_t key_share_count=1;
        // TCP-only RFC 8449 receive limit; absent preserves the original Hello.
        std::optional<std::uint16_t> record_size_limit;
        bool legacy_alps=false;
        bool allow_tls12=true;
        auto operator==(FingerprintConfig const&) const -> bool = default;
    };
    struct FingerprintHello {
        ClientHello hello;
        std::array<std::uint16_t,2> groups{};
        std::uint8_t group_count=0;
        [[nodiscard]] auto initial_groups() const noexcept -> std::span<std::uint16_t const> {
            return std::span(groups).first(group_count);
        }
    };
    [[nodiscard]] auto parse_fingerprint(std::string_view name) noexcept -> std::optional<Fingerprint>;
    [[nodiscard]] auto fingerprint_name(Fingerprint profile) noexcept -> std::string_view;
    [[nodiscard]] auto make_profile_fingerprint_config(Fingerprint profile,
        std::uint16_t primary_group=0x001d,bool hybrid_only=false,
        HandshakeTransport transport=HandshakeTransport::tcp,
        std::optional<std::uint16_t> record_size_limit={}) -> FingerprintConfig;
    // Protocol IDs are supplied by the actual caller. QUIC additionally supplies
    // its validated transport parameters; a present empty span remains present.
    [[nodiscard]] auto make_fingerprint_hello(std::optional<std::string_view> server_name,
        std::span<std::string_view const> alpn,FingerprintConfig const& config,
        HandshakeTransport transport=HandshakeTransport::tcp,
        std::optional<std::span<std::uint8_t const>> quic_parameters={},
        std::optional<std::uint16_t> required_signature={},bool real_ech=false)
        -> std::expected<FingerprintHello,FingerprintError>;
}
