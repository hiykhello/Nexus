export module nexus.tcp.table;
export import nexus.tcp.connection;
import std;

export namespace nexus::tcp {
    using ConnectionId = std::uint64_t;
    struct Target4 { packet::Address4 address; std::uint16_t port; };
    struct Target6 { packet::Address6 address; std::uint16_t port; };
    enum class TableError { invalid_capacity, invalid_challenge_limit, duplicate, full, invalid_syn, id_exhausted, not_found, time_reversed };
    struct ChallengeAckLimits { std::size_t count = 100; std::uint64_t interval_ms = 1000; };
    // Single owner. Pointers returned by get are invalidated by removal or table destruction.
    class ConnectionTable {
        struct Entry {
            ConnectionId id;
            packet::Address4 source, destination;
            std::uint16_t source_port, destination_port;
            PassiveConnection connection;
            bool eof_observed = false;
            bool reset_pending = false;
        };
        std::list<Entry> entries_;
        std::size_t limit_, hard_limit_, buffer_capacity_;
        ChallengeAckLimits challenge_limits_;
        std::optional<std::uint64_t> challenge_start_;
        std::size_t challenge_count_ = 0;
        ConnectionId next_id_ = 1;
        ConnectionTable(std::size_t limit, std::size_t capacity, ChallengeAckLimits challenge)
            : limit_(limit), hard_limit_(limit), buffer_capacity_(capacity), challenge_limits_(challenge) {}
    public:
        ConnectionTable(ConnectionTable const&) = delete;
        auto operator=(ConnectionTable const&) -> ConnectionTable& = delete;
        ConnectionTable(ConnectionTable&&) = default;
        auto operator=(ConnectionTable&&) -> ConnectionTable& = default;
        [[nodiscard]] static auto create(std::size_t limit, std::size_t buffer_capacity, ChallengeAckLimits challenge = {})
            -> std::expected<ConnectionTable, TableError>;
        // Shared across this table. A backwards clock never grants a fresh allowance.
        [[nodiscard]] auto claim_challenge_ack(std::uint64_t now) noexcept -> bool;
        [[nodiscard]] auto open(packet::Tcp4View syn, std::uint32_t iss, std::uint64_t now)
            -> std::expected<ConnectionId, TableError>;
        [[nodiscard]] auto find(packet::Tcp4View segment) const noexcept -> std::optional<ConnectionId>;
        [[nodiscard]] auto get(ConnectionId id) noexcept -> PassiveConnection*;
        [[nodiscard]] auto target(ConnectionId id) const noexcept -> std::optional<Target4>;
        [[nodiscard]] auto next(ConnectionId after) const noexcept -> std::optional<ConnectionId>;
        // Marks EOF delivered to the application; succeeds only after receive data is drained.
        [[nodiscard]] auto observe_eof(ConnectionId id) noexcept -> bool;
        [[nodiscard]] auto hold_reset(ConnectionId id, bool hold) noexcept -> bool;
        // Removes only expired, reset or fully reclaimable flows; false retains the tuple.
        [[nodiscard]] auto reclaim(ConnectionId id, std::uint64_t now) -> std::expected<bool, TableError>;
        // Forced removal is for explicit abort/shutdown and discards buffered data.
        [[nodiscard]] auto abort(ConnectionId id) noexcept -> bool;
        [[nodiscard]] auto size() const noexcept -> std::size_t { return entries_.size(); }
        // Reducing the admission limit retains existing flows.
        auto admission_limit(std::size_t limit) noexcept -> void { limit_ = std::min(limit, hard_limit_); }
    };
    class ConnectionTable6 {
        struct Entry {
            ConnectionId id;
            packet::Address6 source, destination;
            std::uint16_t source_port, destination_port;
            PassiveConnection6 connection;
            bool eof_observed = false, reset_pending = false;
        };
        std::list<Entry> entries_;
        std::size_t limit_, hard_limit_, buffer_capacity_;
        ChallengeAckLimits challenge_limits_;
        std::optional<std::uint64_t> challenge_start_;
        std::size_t challenge_count_ = 0;
        ConnectionId next_id_ = 1;
        ConnectionTable6(std::size_t limit, std::size_t capacity, ChallengeAckLimits challenge)
            : limit_(limit), hard_limit_(limit), buffer_capacity_(capacity), challenge_limits_(challenge) {}
    public:
        ConnectionTable6(ConnectionTable6 const&) = delete;
        auto operator=(ConnectionTable6 const&) -> ConnectionTable6& = delete;
        ConnectionTable6(ConnectionTable6&&) = default;
        auto operator=(ConnectionTable6&&) -> ConnectionTable6& = default;
        [[nodiscard]] static auto create(std::size_t limit, std::size_t buffer_capacity, ChallengeAckLimits challenge = {})
            -> std::expected<ConnectionTable6, TableError>;
        [[nodiscard]] auto claim_challenge_ack(std::uint64_t now) noexcept -> bool;
        [[nodiscard]] auto open(packet::Tcp6View syn, std::uint32_t iss, std::uint64_t now)
            -> std::expected<ConnectionId, TableError>;
        [[nodiscard]] auto find(packet::Tcp6View segment) const noexcept -> std::optional<ConnectionId>;
        [[nodiscard]] auto get(ConnectionId id) noexcept -> PassiveConnection6*;
        [[nodiscard]] auto target(ConnectionId id) const noexcept -> std::optional<Target6>;
        [[nodiscard]] auto next(ConnectionId after) const noexcept -> std::optional<ConnectionId>;
        [[nodiscard]] auto observe_eof(ConnectionId id) noexcept -> bool;
        [[nodiscard]] auto hold_reset(ConnectionId id, bool hold) noexcept -> bool;
        [[nodiscard]] auto reclaim(ConnectionId id, std::uint64_t now) -> std::expected<bool, TableError>;
        [[nodiscard]] auto abort(ConnectionId id) noexcept -> bool;
        [[nodiscard]] auto size() const noexcept -> std::size_t { return entries_.size(); }
        // Reducing the admission limit retains existing flows.
        auto admission_limit(std::size_t limit) noexcept -> void { limit_ = std::min(limit, hard_limit_); }
    };
}
