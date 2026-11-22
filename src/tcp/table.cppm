export module tcp.table;
export import tcp.connection;
import std;

export namespace tcp {
    using ConnectionId = std::uint64_t;
    struct Target4 { packet::Address4 address; std::uint16_t port; };
    struct Target6 { packet::Address6 address; std::uint16_t port; };
    struct Endpoints4 { Target4 source, target; };
    struct Endpoints6 { Target6 source, target; };
    enum class TableError { invalid_capacity, invalid_challenge_limit, duplicate, full, invalid_syn, id_exhausted, not_found, time_reversed };
    struct ChallengeAckLimits { std::size_t count = 100; std::uint64_t interval_ms = 1000; };
    // Single owner. O(1) hash-indexed by 4-tuple and ConnectionId; pointers returned by get stay valid until removal.
    class ConnectionTable {
        struct Watch { packet::Address4 source, destination; std::uint16_t source_port, destination_port; std::weak_ptr<packet::TcpGeneration> token; };
        std::vector<Watch> watches_;
        struct TupleKey {
            packet::Address4 source, destination;
            std::uint16_t source_port, destination_port;
            auto operator==(TupleKey const&) const noexcept -> bool = default;
        };
        struct TupleHash {
            auto operator()(TupleKey const& k) const noexcept -> std::size_t {
                std::size_t h = 14695981039346656037ull;
                auto mix = [&](std::uint64_t v) noexcept { h ^= v; h *= 1099511628211ull; };
                std::uint32_t s = 0, d = 0;
                for (int i = 0; i < 4; ++i) { s = (s << 8) | k.source[i]; d = (d << 8) | k.destination[i]; }
                mix(s); mix(d); mix((std::uint64_t(k.source_port) << 16) | k.destination_port);
                return h;
            }
        };
        struct Entry {
            ConnectionId id;
            packet::Address4 source, destination;
            std::uint16_t source_port, destination_port;
            PassiveConnection connection;
            bool eof_observed = false;
            bool reset_pending = false;
        };
        using List = std::list<Entry>;
        List entries_;
        std::unordered_map<ConnectionId, List::iterator> by_id_;
        std::unordered_map<TupleKey, List::iterator, TupleHash> by_tuple_;
        std::size_t limit_, hard_limit_, buffer_capacity_;
        ChallengeAckLimits challenge_limits_;
        std::optional<std::uint64_t> challenge_start_;
        std::size_t challenge_count_ = 0;
        std::optional<std::uint64_t> reset_start_;
        std::size_t reset_count_ = 0;
        ConnectionId next_id_ = 1;
        ConnectionTable(std::size_t limit, std::size_t capacity, ChallengeAckLimits challenge)
            : limit_(limit), hard_limit_(limit), buffer_capacity_(capacity), challenge_limits_(challenge) {}
        auto erase_entry(List::iterator it) noexcept -> void;
    public:
        ConnectionTable(ConnectionTable const&) = delete;
        auto operator=(ConnectionTable const&) -> ConnectionTable& = delete;
        ConnectionTable(ConnectionTable&&) = default;
        auto operator=(ConnectionTable&&) -> ConnectionTable& = default;
        [[nodiscard]] static auto create(std::size_t limit, std::size_t buffer_capacity, ChallengeAckLimits challenge = {})
            -> std::expected<ConnectionTable, TableError>;
        [[nodiscard]] auto claim_challenge_ack(std::uint64_t now) noexcept -> bool;
        [[nodiscard]] auto stateless_reset_available(std::uint64_t now) const noexcept -> bool;
        [[nodiscard]] auto claim_stateless_reset(std::uint64_t now) noexcept -> bool;
        [[nodiscard]] auto open(packet::Tcp4View syn, std::uint32_t iss, std::uint64_t now)
            -> std::expected<ConnectionId, TableError>;
        [[nodiscard]] auto find(packet::Tcp4View segment) const noexcept -> std::optional<ConnectionId>;
        [[nodiscard]] auto watch(packet::Tcp4View segment) -> std::shared_ptr<packet::TcpGeneration>;
        [[nodiscard]] auto watched_generations() const noexcept -> std::size_t;
        [[nodiscard]] auto get(ConnectionId id) noexcept -> PassiveConnection*;
        [[nodiscard]] auto target(ConnectionId id) const noexcept -> std::optional<Target4>;
        [[nodiscard]] auto endpoints(ConnectionId id) const noexcept -> std::optional<Endpoints4>;
        [[nodiscard]] auto next(ConnectionId after) const noexcept -> std::optional<ConnectionId>;
        [[nodiscard]] auto observe_eof(ConnectionId id) noexcept -> bool;
        [[nodiscard]] auto hold_reset(ConnectionId id, bool hold) noexcept -> bool;
        [[nodiscard]] auto reclaim(ConnectionId id, std::uint64_t now) -> std::expected<bool, TableError>;
        [[nodiscard]] auto abort(ConnectionId id) noexcept -> bool;
        [[nodiscard]] auto size() const noexcept -> std::size_t { return entries_.size(); }
        auto admission_limit(std::size_t limit) noexcept -> void { limit_ = std::min(limit, hard_limit_); }
    };
    class ConnectionTable6 {
        struct Watch { packet::Address6 source, destination; std::uint16_t source_port, destination_port; std::weak_ptr<packet::TcpGeneration> token; };
        std::vector<Watch> watches_;
        struct TupleKey {
            packet::Address6 source, destination;
            std::uint16_t source_port, destination_port;
            auto operator==(TupleKey const&) const noexcept -> bool = default;
        };
        struct TupleHash {
            auto operator()(TupleKey const& k) const noexcept -> std::size_t {
                std::size_t h = 14695981039346656037ull;
                auto mix = [&](std::uint64_t v) noexcept { h ^= v; h *= 1099511628211ull; };
                for (auto b : k.source) mix(b);
                for (auto b : k.destination) mix(b);
                mix((std::uint64_t(k.source_port) << 16) | k.destination_port);
                return h;
            }
        };
        struct Entry {
            ConnectionId id;
            packet::Address6 source, destination;
            std::uint16_t source_port, destination_port;
            PassiveConnection6 connection;
            bool eof_observed = false, reset_pending = false;
        };
        using List = std::list<Entry>;
        List entries_;
        std::unordered_map<ConnectionId, List::iterator> by_id_;
        std::unordered_map<TupleKey, List::iterator, TupleHash> by_tuple_;
        std::size_t limit_, hard_limit_, buffer_capacity_;
        ChallengeAckLimits challenge_limits_;
        std::optional<std::uint64_t> challenge_start_;
        std::size_t challenge_count_ = 0;
        std::optional<std::uint64_t> reset_start_;
        std::size_t reset_count_ = 0;
        ConnectionId next_id_ = 1;
        ConnectionTable6(std::size_t limit, std::size_t capacity, ChallengeAckLimits challenge)
            : limit_(limit), hard_limit_(limit), buffer_capacity_(capacity), challenge_limits_(challenge) {}
        auto erase_entry(List::iterator it) noexcept -> void;
    public:
        ConnectionTable6(ConnectionTable6 const&) = delete;
        auto operator=(ConnectionTable6 const&) -> ConnectionTable6& = delete;
        ConnectionTable6(ConnectionTable6&&) = default;
        auto operator=(ConnectionTable6&&) -> ConnectionTable6& = default;
        [[nodiscard]] static auto create(std::size_t limit, std::size_t buffer_capacity, ChallengeAckLimits challenge = {})
            -> std::expected<ConnectionTable6, TableError>;
        [[nodiscard]] auto claim_challenge_ack(std::uint64_t now) noexcept -> bool;
        [[nodiscard]] auto stateless_reset_available(std::uint64_t now) const noexcept -> bool;
        [[nodiscard]] auto claim_stateless_reset(std::uint64_t now) noexcept -> bool;
        [[nodiscard]] auto open(packet::Tcp6View syn, std::uint32_t iss, std::uint64_t now)
            -> std::expected<ConnectionId, TableError>;
        [[nodiscard]] auto find(packet::Tcp6View segment) const noexcept -> std::optional<ConnectionId>;
        [[nodiscard]] auto watch(packet::Tcp6View segment) -> std::shared_ptr<packet::TcpGeneration>;
        [[nodiscard]] auto watched_generations() const noexcept -> std::size_t;
        [[nodiscard]] auto get(ConnectionId id) noexcept -> PassiveConnection6*;
        [[nodiscard]] auto target(ConnectionId id) const noexcept -> std::optional<Target6>;
        [[nodiscard]] auto endpoints(ConnectionId id) const noexcept -> std::optional<Endpoints6>;
        [[nodiscard]] auto next(ConnectionId after) const noexcept -> std::optional<ConnectionId>;
        [[nodiscard]] auto observe_eof(ConnectionId id) noexcept -> bool;
        [[nodiscard]] auto hold_reset(ConnectionId id, bool hold) noexcept -> bool;
        [[nodiscard]] auto reclaim(ConnectionId id, std::uint64_t now) -> std::expected<bool, TableError>;
        [[nodiscard]] auto abort(ConnectionId id) noexcept -> bool;
        [[nodiscard]] auto size() const noexcept -> std::size_t { return entries_.size(); }
        auto admission_limit(std::size_t limit) noexcept -> void { limit_ = std::min(limit, hard_limit_); }
    };
}
