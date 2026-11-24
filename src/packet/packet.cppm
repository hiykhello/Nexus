export module packet;
import std;

export namespace packet {
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
        std::uint8_t dscp=0;
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
        std::uint8_t dscp=0;
    };
    [[nodiscard]] auto parse_tcp4(std::span<std::uint8_t const> packet) noexcept -> std::expected<Tcp4View, PacketError>;
    [[nodiscard]] auto make_tcp4(Tcp4View segment, std::size_t mtu = 1500) -> std::expected<Bytes, PacketError>;
    // Reuses storage where possible; the resulting bytes do not borrow the input.
    [[nodiscard]] auto make_tcp4(Tcp4View segment, std::size_t mtu, Bytes storage) -> std::expected<Bytes, PacketError>;
    struct Tcp6View {
        Address6 source{}, destination{};
        std::uint16_t source_port = 0, destination_port = 0;
        std::uint32_t sequence = 0, acknowledgement = 0;
        std::uint16_t flags = 0, window = 0, urgent = 0;
        std::span<std::uint8_t const> options, payload;
        std::uint8_t dscp=0;
    };
    // Basic IPv6 header only; options and payload borrow the input.
    [[nodiscard]] auto parse_tcp6(std::span<std::uint8_t const> packet) noexcept -> std::expected<Tcp6View, PacketError>;
    [[nodiscard]] auto make_tcp6(Tcp6View segment, std::size_t mtu = 1500) -> std::expected<Bytes, PacketError>;
    [[nodiscard]] auto make_tcp6(Tcp6View segment, std::size_t mtu, Bytes storage) -> std::expected<Bytes, PacketError>;
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

    struct Udp6Fragment {
        std::size_t prefix_length,next_header_field,offset;
        std::uint32_t identification;
        bool more;
    };
    // Accepts the UDP fragment subset with an optional Hop-by-Hop header
    // before Fragment and optional Destination Options in the first fragment.
    [[nodiscard]] auto parse_udp6_fragment(std::span<std::uint8_t const> packet) noexcept
        -> std::optional<Udp6Fragment>;

    struct Udp6View {
        Address6 source{}, destination{};
        std::uint16_t source_port = 0, destination_port = 0;
        // The payload borrows the input passed to parse_udp6.
        std::span<std::uint8_t const> payload;
        std::uint8_t dscp=0;
    };
    // Supports at most one Hop-by-Hop header followed by one Destination
    // Options header. Pad1/PadN and unknown options with the skip action are
    // accepted; other options and extensions are rejected without ICMP.
    [[nodiscard]] auto parse_udp6(std::span<std::uint8_t const> packet) noexcept -> std::expected<Udp6View, PacketError>;
    [[nodiscard]] auto make_udp6(Address6 source, Address6 destination, std::uint16_t source_port,
        std::uint16_t destination_port, std::span<std::uint8_t const> payload, std::size_t mtu = 1500)
        -> std::expected<Bytes, PacketError>;

    enum class EchoKind { request, reply };
    struct IcmpEcho4View {
        Address4 source{}, destination{};
        EchoKind kind = EchoKind::request;
        std::uint16_t identifier = 0, sequence = 0;
        // Payload borrows the input passed to parse_icmp_echo4.
        std::span<std::uint8_t const> payload;
    };
    struct IcmpEcho6View {
        Address6 source{}, destination{};
        EchoKind kind = EchoKind::request;
        std::uint16_t identifier = 0, sequence = 0;
        std::span<std::uint8_t const> payload;
    };
    // IPv4 NOP/EOL options and IPv6 hop-by-hop/destination options are supported;
    // fragmentation, other extension headers and jumbograms are not supported.
    [[nodiscard]] auto parse_icmp_echo4(std::span<std::uint8_t const> packet) noexcept -> std::expected<IcmpEcho4View, PacketError>;
    [[nodiscard]] auto parse_icmp_echo6(std::span<std::uint8_t const> packet) noexcept -> std::expected<IcmpEcho6View, PacketError>;
    [[nodiscard]] auto make_icmp_echo4(IcmpEcho4View message, std::size_t mtu = 1500) -> std::expected<Bytes, PacketError>;
    [[nodiscard]] auto make_icmp_echo6(IcmpEcho6View message, std::size_t mtu = 1500) -> std::expected<Bytes, PacketError>;
    struct IcmpPtb4View {
        Address4 source{}, destination{};
        std::uint16_t next_hop_mtu = 0;
        std::span<std::uint8_t const> quote;
    };
    struct IcmpPtb6View {
        Address6 source{}, destination{};
        std::uint32_t next_hop_mtu = 0;
        std::span<std::uint8_t const> quote;
    };
    [[nodiscard]] auto parse_icmp_ptb4(std::span<std::uint8_t const> packet) noexcept -> std::expected<IcmpPtb4View, PacketError>;
    [[nodiscard]] auto parse_icmp_ptb6(std::span<std::uint8_t const> packet) noexcept -> std::expected<IcmpPtb6View, PacketError>;
    [[nodiscard]] auto make_icmp_ptb4(IcmpPtb4View message, std::size_t mtu = 1500) -> std::expected<Bytes, PacketError>;
    [[nodiscard]] auto make_icmp_ptb6(IcmpPtb6View message, std::size_t mtu = 1500) -> std::expected<Bytes, PacketError>;
    // The caller has validated the invoking UDP packet. Return no error
    // packet for non-unicast endpoints or an MTU too small for its quote.
    [[nodiscard]] auto udp_administratively_prohibited(std::span<std::uint8_t const> packet,std::size_t mtu)
        -> std::optional<Bytes>;

    enum class Side { first, second };
    // Single-owner lifetime token; invalidation prevents delivery after tuple reuse.
    struct TcpGeneration { bool valid = true; };
    enum class PacketKind { ordinary, stateless_tcp_reset, stateful_tcp_reset };
    struct QueuedPacket { Bytes bytes; PacketKind kind = PacketKind::ordinary; std::uint64_t flow_id = 0; std::shared_ptr<TcpGeneration> generation; };
    enum class DeviceError { closed, peer_closed, empty_packet, packet_too_large, queue_full };
    struct DeviceLimits {
        std::size_t packet_bytes = 1500;
        std::size_t queue_packets = 64;
        std::size_t queue_bytes = 96000;
    };
    // Single-owner deterministic packet link; each direction has its own limits.
    class MemoryLink {
        struct Queue { std::deque<QueuedPacket> packets; std::size_t bytes = 0; bool closed = false; };
        DeviceLimits limits_;
        std::array<Queue, 2> queues_;
    public:
        explicit MemoryLink(DeviceLimits limits = {}) : limits_(limits) {}
        [[nodiscard]] auto send(Side from, std::span<std::uint8_t const> packet, PacketKind kind = PacketKind::ordinary,
                                std::uint64_t flow_id = 0, std::shared_ptr<TcpGeneration> generation = {}) -> std::expected<void, DeviceError>;
        [[nodiscard]] auto send_owned(Side from, Bytes&& packet, PacketKind kind = PacketKind::ordinary,
                                      std::uint64_t flow_id = 0, std::shared_ptr<TcpGeneration> generation = {}) -> std::expected<void, DeviceError>;
        // The whole datagram is admitted or the queue is left unchanged.
        [[nodiscard]] auto send_packets(Side from,std::vector<Bytes> packets) -> std::expected<void,DeviceError>;
        // receive discards metadata; forwarding consumers must use receive_packet.
        [[nodiscard]] auto receive(Side to) -> std::expected<std::optional<Bytes>, DeviceError>;
        [[nodiscard]] auto receive_packet(Side to) -> std::expected<std::optional<QueuedPacket>, DeviceError>;
        auto close(Side side) noexcept -> void;
    };
}
