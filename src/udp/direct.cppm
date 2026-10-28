export module nexus.udp.direct;
export import nexus.udp.route;
import nexus.rules;
import std;

export namespace nexus::udp {
    using DirectError = std::variant<RoutedError, Error, std::error_code>;
    struct DirectSocket {
        FlowId id;
        int fd;
        DirectSocket(FlowId flow, int value);
        DirectSocket(DirectSocket const&) = delete;
        auto operator=(DirectSocket const&) -> DirectSocket& = delete;
        DirectSocket(DirectSocket&& other) noexcept;
        auto operator=(DirectSocket&& other) noexcept -> DirectSocket&;
        ~DirectSocket();
    };
    // Linux nonblocking IPv4 UDP direct transport. Single owner, no background
    // thread. Caller supplies monotonic milliseconds and polls regularly.
    class Direct4 {
        std::vector<DirectSocket> sockets;
        RoutedBridge4 bridge;
        std::size_t cursor = 0;
        std::optional<std::error_code> deferred_error;
        bool deferred_allocation_failure = false;
    public:
        Direct4(rules::Matcher policy, Mapping mapping, Filtering filtering, Limits limits = {}, std::size_t mtu = 1500);
        ~Direct4();
        Direct4(Direct4 const&) = delete;
        auto operator=(Direct4 const&) -> Direct4& = delete;
        [[nodiscard]] auto submit(std::span<std::uint8_t const> packet, std::uint64_t now) -> std::expected<void, DirectError>;
        // Peeks before consuming; sockets must have no other readers. Reads at most
        // one datagram per flow and at most 64 per call. Invalid,
        // unauthorized or oversized replies are dropped. Returned packets are owned.
        // An error after collected replies is reported by the next poll; stop discards it.
        // A deferred allocation failure throws std::bad_alloc on the next poll.
        [[nodiscard]] auto poll(std::uint64_t now) -> std::expected<std::vector<packet::Bytes>, DirectError>;
        [[nodiscard]] auto expire(std::uint64_t now) -> std::expected<std::size_t, Error>;
        [[nodiscard]] auto stop(std::uint64_t now) -> std::expected<void, Error>;
        [[nodiscard]] auto size() const noexcept -> std::size_t;
    };
    // Same ownership and polling contract as Direct4; no IPv6 zone support.
    class Direct6 {
        std::vector<DirectSocket> sockets;
        RoutedBridge6 bridge;
        std::size_t cursor = 0;
        std::optional<std::error_code> deferred_error;
        bool deferred_allocation_failure = false;
    public:
        Direct6(rules::Matcher policy, Mapping mapping, Filtering filtering, Limits limits = {}, std::size_t mtu = 1500);
        ~Direct6();
        Direct6(Direct6 const&) = delete;
        auto operator=(Direct6 const&) -> Direct6& = delete;
        [[nodiscard]] auto submit(std::span<std::uint8_t const> packet, std::uint64_t now) -> std::expected<void, DirectError>;
        [[nodiscard]] auto poll(std::uint64_t now) -> std::expected<std::vector<packet::Bytes>, DirectError>;
        [[nodiscard]] auto expire(std::uint64_t now) -> std::expected<std::size_t, Error>;
        [[nodiscard]] auto stop(std::uint64_t now) -> std::expected<void, Error>;
        [[nodiscard]] auto size() const noexcept -> std::size_t;
    };

}
