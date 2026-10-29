export module nexus.packet;
import std;

export namespace nexus::packet {
    using Bytes = std::vector<std::uint8_t>;
    using Address4 = std::array<std::uint8_t, 4>;
    using Address6 = std::array<std::uint8_t, 16>;
    enum class PacketError { truncated, invalid_version, unsupported_header, invalid_length,
                             invalid_checksum, unsupported_fragment, unsupported_protocol, too_large };
    struct Udp4View {
        Address4 source{}, destination{};
        std::uint16_t source_port = 0, destination_port = 0;
        // The payload borrows the input passed to parse_udp4.
        std::span<std::uint8_t const> payload;
    };
    [[nodiscard]] auto internet_checksum(std::span<std::uint8_t const> bytes) noexcept -> std::uint16_t;
    [[nodiscard]] auto parse_udp4(std::span<std::uint8_t const> packet) noexcept -> std::expected<Udp4View, PacketError>;
    [[nodiscard]] auto make_udp4(Address4 source, Address4 destination, std::uint16_t source_port,
        std::uint16_t destination_port, std::span<std::uint8_t const> payload, std::size_t mtu = 1500)
        -> std::expected<Bytes, PacketError>;

    struct Tcp4View {
        Address4 source{}, destination{};
        std::uint16_t source_port = 0, destination_port = 0;
        std::uint32_t sequence = 0, acknowledgement = 0;
        std::uint16_t flags = 0, window = 0, urgent = 0;
        // Both spans borrow the input. Option semantics are validated separately.
        std::span<std::uint8_t const> options, payload;
    };
    [[nodiscard]] auto parse_tcp4(std::span<std::uint8_t const> packet) noexcept -> std::expected<Tcp4View, PacketError>;
    [[nodiscard]] auto make_tcp4(Tcp4View segment, std::size_t mtu = 1500) -> std::expected<Bytes, PacketError>;
    // Reuses storage where possible; the resulting bytes do not borrow the input.
    [[nodiscard]] auto make_tcp4(Tcp4View segment, std::size_t mtu, Bytes storage) -> std::expected<Bytes, PacketError>;
    struct TcpOptionView { std::uint8_t kind = 0; std::span<std::uint8_t const> data; };
    struct TcpOptions {
        std::array<TcpOptionView, 40> items{};
        std::size_t count = 0;
    };
    // Views borrow the option bytes; EOL terminates parsing and NOP is included.
    [[nodiscard]] auto parse_tcp_options(std::span<std::uint8_t const> options) noexcept
        -> std::expected<TcpOptions, PacketError>;
    struct TcpSynOptions {
        std::optional<std::uint16_t> mss;
        std::optional<std::uint8_t> window_scale;
        bool sack_permitted = false;
        std::optional<std::pair<std::uint32_t, std::uint32_t>> timestamp;
    };
    // Decode a SYN's known options; duplicates and malformed known lengths are rejected.
    [[nodiscard]] auto parse_tcp_syn_options(std::span<std::uint8_t const> options) noexcept
        -> std::expected<TcpSynOptions, PacketError>;

    struct Udp6View {
        Address6 source{}, destination{};
        std::uint16_t source_port = 0, destination_port = 0;
        // The payload borrows the input passed to parse_udp6.
        std::span<std::uint8_t const> payload;
    };
    // Supports at most one Hop-by-Hop header followed by one Destination
    // Options header. Pad1/PadN and unknown options with the skip action are
    // accepted; other options and extensions are rejected without ICMP.
    [[nodiscard]] auto parse_udp6(std::span<std::uint8_t const> packet) noexcept -> std::expected<Udp6View, PacketError>;
    [[nodiscard]] auto make_udp6(Address6 source, Address6 destination, std::uint16_t source_port,
        std::uint16_t destination_port, std::span<std::uint8_t const> payload, std::size_t mtu = 1500)
        -> std::expected<Bytes, PacketError>;

    enum class Side { first, second };
    enum class DeviceError { closed, peer_closed, empty_packet, packet_too_large, queue_full };
    struct DeviceLimits {
        std::size_t packet_bytes = 1500;
        std::size_t queue_packets = 64;
        std::size_t queue_bytes = 96000;
    };
    // Single-owner deterministic packet link; each direction has its own limits.
    class MemoryLink {
        struct Queue { std::deque<Bytes> packets; std::size_t bytes = 0; bool closed = false; };
        DeviceLimits limits_;
        std::array<Queue, 2> queues_;
    public:
        explicit MemoryLink(DeviceLimits limits = {}) : limits_(limits) {}
        [[nodiscard]] auto send(Side from, std::span<std::uint8_t const> packet) -> std::expected<void, DeviceError>;
        [[nodiscard]] auto receive(Side to) -> std::expected<std::optional<Bytes>, DeviceError>;
        auto close(Side side) noexcept -> void;
    };
}
