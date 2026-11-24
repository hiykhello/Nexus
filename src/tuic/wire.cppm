export module tuic.wire;
import std;
import crypto;
import tls.schedule;

export namespace tuic {
    inline constexpr std::uint8_t version = 5;
    inline constexpr std::size_t authenticate_size = 50;
    inline constexpr std::size_t dissociate_size = 4;
    inline constexpr std::size_t heartbeat_size = 2;
    inline constexpr std::size_t max_defrag_entries = 64;
    inline constexpr std::size_t max_defrag_packet_bytes = 65535;
    inline constexpr std::size_t max_defrag_fragments = 64;
    inline constexpr std::uint64_t defrag_entry_ttl_ns = 5'000'000'000ULL;

    enum class Command : std::uint8_t {
        authenticate = 0,
        connect = 1,
        packet = 2,
        dissociate = 3,
        heartbeat = 4,
    };

    enum class AddressType : std::uint8_t {
        domain = 0x00,
        ipv4 = 0x01,
        ipv6 = 0x02,
        none = 0xff,
    };

    struct TargetAddress {
        AddressType type = AddressType::none;
        std::string domain;
        std::array<std::uint8_t, 16> address{};
        std::uint16_t port = 0;
        auto operator==(TargetAddress const&) const -> bool = default;
    };

    enum class WireError { incomplete, invalid, unsupported_version, unsupported_command, too_large, duplicate, conflict };

    struct Authenticate {
        std::array<std::uint8_t, 16> uuid{};
        std::array<std::uint8_t, 32> token{};
        auto operator==(Authenticate const&) const -> bool = default;
    };

    struct PacketHeader {
        std::uint16_t assoc_id = 0;
        std::uint16_t packet_id = 0;
        std::uint8_t frag_total = 1;
        std::uint8_t frag_id = 0;
        std::uint16_t payload_size = 0;
        TargetAddress destination;
    };

    struct PacketView {
        PacketHeader header;
        std::span<std::uint8_t const> payload;
    };

    [[nodiscard]] auto parse_uuid(std::string_view text) noexcept -> std::optional<std::array<std::uint8_t, 16>>;
    [[nodiscard]] auto encoded_address_size(TargetAddress const& addr) noexcept -> std::optional<std::size_t>;
    [[nodiscard]] auto encode_address(TargetAddress const& addr, std::vector<std::uint8_t>& out) -> bool;
    [[nodiscard]] auto decode_address(std::span<std::uint8_t const> input)
        -> std::expected<std::pair<TargetAddress, std::size_t>, WireError>;

    // Compute TUIC v5 32-byte auth token using RFC 8446 TLS exporter:
    // ExportKeyingMaterial(label = uuid_bytes, context = password_bytes, length = 32).
    [[nodiscard]] auto derive_auth_token(
        crypto::Hash hash,
        std::span<std::uint8_t const> exporter_master,
        std::span<std::uint8_t const, 16> uuid,
        std::string_view password) -> std::expected<std::array<std::uint8_t, 32>, crypto::Error>;

    [[nodiscard]] auto encode_authenticate(Authenticate const& msg) -> std::array<std::uint8_t, authenticate_size>;
    [[nodiscard]] auto decode_authenticate(std::span<std::uint8_t const> input)
        -> std::expected<Authenticate, WireError>;

    [[nodiscard]] auto encode_connect(TargetAddress const& target) -> std::expected<std::vector<std::uint8_t>, WireError>;
    [[nodiscard]] auto decode_connect(std::span<std::uint8_t const> input)
        -> std::expected<std::pair<TargetAddress, std::size_t>, WireError>;

    [[nodiscard]] auto encode_dissociate(std::uint16_t assoc_id) noexcept -> std::array<std::uint8_t, dissociate_size>;
    [[nodiscard]] auto decode_dissociate(std::span<std::uint8_t const> input) noexcept
        -> std::expected<std::uint16_t, WireError>;

    [[nodiscard]] auto encode_heartbeat() noexcept -> std::array<std::uint8_t, heartbeat_size>;
    [[nodiscard]] auto decode_heartbeat(std::span<std::uint8_t const> input) noexcept
        -> std::expected<void, WireError>;

    [[nodiscard]] auto encode_packet(
        std::uint16_t assoc_id,
        std::uint16_t packet_id,
        std::uint8_t frag_total,
        std::uint8_t frag_id,
        TargetAddress const& destination,
        std::span<std::uint8_t const> payload) -> std::expected<std::vector<std::uint8_t>, WireError>;

    [[nodiscard]] auto decode_packet(std::span<std::uint8_t const> input)
        -> std::expected<PacketView, WireError>;

    [[nodiscard]] auto fragment_udp_packet(
        std::uint16_t assoc_id,
        std::uint16_t packet_id,
        TargetAddress const& destination,
        std::span<std::uint8_t const> payload,
        std::size_t max_packet_size) -> std::expected<std::vector<std::vector<std::uint8_t>>, WireError>;

    // Bounded UDP fragment reassembler keyed by (assoc_id, packet_id).
    class UdpDefragmenter {
        struct Entry {
            std::uint16_t assoc_id = 0;
            std::uint16_t packet_id = 0;
            std::uint64_t stamp = 0;
            std::uint64_t created_ns = 0;
            std::uint8_t frag_total = 0;
            std::uint8_t received_count = 0;
            std::uint64_t received_mask = 0;
            TargetAddress destination;
            std::vector<std::vector<std::uint8_t>> fragments;
            std::size_t total_bytes = 0;
        };
        std::array<std::optional<Entry>, max_defrag_entries> slots_{};
        std::uint64_t clock_ = 0;
    public:
        struct Completed {
            std::uint16_t assoc_id = 0;
            std::uint16_t packet_id = 0;
            TargetAddress destination;
            std::vector<std::uint8_t> payload;
        };
        [[nodiscard]] auto feed(PacketView const& packet, std::uint64_t now_ns = 0) -> std::expected<std::optional<Completed>, WireError>;
        [[nodiscard]] auto active_entries() const noexcept -> std::size_t;
        auto clear_association(std::uint16_t assoc_id) noexcept -> void;
    };
}
