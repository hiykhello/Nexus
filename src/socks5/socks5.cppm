export module nexus.socks5;
import std;

export namespace nexus::socks5 {
    enum class Status {
        incomplete, accepted, invalid_version, invalid_reserved,
        no_acceptable_method, unsupported_command, unsupported_address, invalid_address, unsupported_fragment, too_large,
        unauthorized_source, association_closed
    };

    struct Greeting {
        Status status = Status::incomplete;
        std::size_t consumed = 0;
    };

    struct Request {
        Status status = Status::incomplete;
        std::size_t consumed = 0;
        std::uint8_t address_type = 0;
        std::array<std::uint8_t, 255> address{};
        std::uint8_t address_length = 0;
        std::uint16_t port = 0;
    };

    // Parse one frame without retaining or modifying the input. Trailing
    // bytes belong to the next frame or the relayed application stream.
    [[nodiscard]] auto parse_greeting(std::span<std::uint8_t const> input, std::uint8_t method = 0) noexcept -> Greeting;
    [[nodiscard]] auto parse_request(std::span<std::uint8_t const> input) noexcept -> Request;

    // DATA borrows the datagram input. FRAG must be zero; reassembly is not supported.
    struct UdpDatagram {
        std::uint8_t address_type = 0;
        std::array<std::uint8_t, 255> address{};
        std::uint8_t address_length = 0;
        std::uint16_t port = 0;
        std::span<std::uint8_t const> data;
    };
    [[nodiscard]] auto parse_udp_datagram(std::span<std::uint8_t const> input) noexcept -> std::expected<UdpDatagram, Status>;
    // Caller owns the encoded datagram and applies transport-specific size limits.
    [[nodiscard]] auto encode_udp_datagram(UdpDatagram const& packet) -> std::expected<std::vector<std::uint8_t>, Status>;

    struct UdpPeer {
        // Address types 1 and 4 only. IPv4 uses the first four bytes and zeros the rest.
        std::uint8_t address_type = 0;
        std::array<std::uint8_t,16> address{};
        std::uint16_t port = 0;
        auto operator==(UdpPeer const&) const -> bool = default;
    };
    // One TCP control connection owns this state. Callers normalize mapped
    // addresses before creation and admission, and serialize all operations.
    class UdpAssociation {
        UdpPeer peer_;
        bool closed_ = false;
        explicit UdpAssociation(UdpPeer peer) : peer_(peer) {}
    public:
        UdpAssociation(UdpAssociation const&) = delete;
        auto operator=(UdpAssociation const&) -> UdpAssociation& = delete;
        UdpAssociation(UdpAssociation&& other) noexcept : peer_(other.peer_), closed_(std::exchange(other.closed_,true)) {}
        auto operator=(UdpAssociation&& other) noexcept -> UdpAssociation& {
            if (this!=&other) { peer_=other.peer_; closed_=std::exchange(other.closed_,true); }
            return *this;
        }
        // Hint address may be unspecified; any specified address must match the TCP peer.
        [[nodiscard]] static auto create(UdpPeer tcp_peer, UdpPeer hint) noexcept -> std::expected<UdpAssociation,Status>;
        // An unknown port is learned only after a complete, unfragmented packet parses.
        [[nodiscard]] auto admit(UdpPeer source, std::span<std::uint8_t const> input) noexcept -> std::expected<UdpDatagram,Status>;
        auto close() noexcept -> void { closed_=true; }
    };
}
