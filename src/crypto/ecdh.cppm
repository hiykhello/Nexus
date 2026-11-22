export module crypto.ecdh;
export import crypto;
import std;

export namespace crypto {
    struct NistCurve {
        std::uint16_t group;
        int nid;
        std::uint8_t coordinate_size;
        [[nodiscard]] auto public_size() const noexcept -> std::size_t { return 1+2*coordinate_size; }
    };
    [[nodiscard]] constexpr auto nist_curve(std::uint16_t group) noexcept -> std::optional<NistCurve> {
        switch(group) {
        case 23: return NistCurve{23,nex::boringssl::nid_x9_62_prime256v1,32};
        case 24: return NistCurve{24,nex::boringssl::nid_secp384r1,48};
        case 25: return NistCurve{25,nex::boringssl::nid_secp521r1,66};
        default: return {};
        }
    }
    struct EcPublic {
        std::array<std::uint8_t,133> bytes{};
        std::uint8_t size=0;
        [[nodiscard]] auto view() const noexcept -> std::span<std::uint8_t const> { return std::span(bytes).first(size); }
    };
    class EcSecret {
        std::array<std::uint8_t,66> bytes_{};
        std::uint8_t size_=0;
        friend class EcPrivate;
    public:
        EcSecret() = default;
        ~EcSecret();
        EcSecret(EcSecret const&)=delete;
        auto operator=(EcSecret const&) -> EcSecret& = delete;
        EcSecret(EcSecret&&) noexcept;
        auto operator=(EcSecret&&) noexcept -> EcSecret&;
        [[nodiscard]] auto view() const noexcept -> std::span<std::uint8_t const> { return std::span(bytes_).first(size_); }
    };
    // Direct owner of the native ephemeral key. No heap-allocated C++ wrapper.
    class EcPrivate {
        nex::boringssl::EC_KEY* key_;
        explicit EcPrivate(nex::boringssl::EC_KEY* key) noexcept : key_(key) {}
    public:
        ~EcPrivate();
        EcPrivate(EcPrivate const&)=delete;
        auto operator=(EcPrivate const&) -> EcPrivate& = delete;
        EcPrivate(EcPrivate&&) noexcept;
        auto operator=(EcPrivate&&) noexcept -> EcPrivate&;
        [[nodiscard]] static auto generate(std::uint16_t group) -> std::expected<EcPrivate,Error>;
        [[nodiscard]] auto group() const noexcept -> std::uint16_t;
        [[nodiscard]] auto public_key() const -> std::expected<EcPublic,Error>;
        // RFC8446 uncompressed encoding only; validates length, curve, infinity.
        [[nodiscard]] auto agree(std::span<std::uint8_t const> peer) const -> std::expected<EcSecret,Error>;
    };
}
