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

    // Single owner. Pointer-stable pre-allocated slab with generation-tagged ConnectionId
    // (low 20 bits = slot index), intrusive active/free lists, and open-addressed 4-tuple index.
    template<class Connection, class Address, class SegmentView, class Target, class Endpoints>
    class BasicConnectionTable {
        static constexpr std::uint32_t kNull = std::numeric_limits<std::uint32_t>::max();
        static constexpr std::uint32_t kSlotBits = 20;
        static constexpr std::uint32_t kMaxCapacity = 1u << kSlotBits;
        static constexpr std::uint64_t kSlotMask = (std::uint64_t{1} << kSlotBits) - 1;
        static constexpr std::uint64_t kMaxGen = (std::uint64_t{1} << (64 - kSlotBits)) - 1;

        struct Watch {
            Address source, destination;
            std::uint16_t source_port, destination_port;
            std::weak_ptr<packet::TcpGeneration> token;
        };
        struct TupleKey {
            Address source{}, destination{};
            std::uint16_t source_port = 0, destination_port = 0;
            auto operator==(TupleKey const&) const noexcept -> bool = default;
        };
        struct Slot {
            ConnectionId id = 0;
            std::size_t hash = 0;
            TupleKey key{};
            std::optional<Connection> connection;
            std::uint32_t prev_active = kNull;
            std::uint32_t next_active = kNull;
            std::uint32_t next_free = kNull;
            bool used = false;
            bool eof_observed = false;
            bool reset_pending = false;
            bool app_detached = false;
        };

        std::vector<Watch> watches_;
        std::vector<Slot> slots_;
        std::vector<std::uint32_t> buckets_;
        std::size_t bucket_mask_ = 0;
        std::size_t active_count_ = 0;
        std::uint32_t active_head_ = kNull;
        std::uint32_t active_tail_ = kNull;
        std::uint32_t free_head_ = kNull;
        std::uint32_t next_alloc_ = 0;
        std::size_t limit_, hard_limit_, buffer_capacity_;
        ChallengeAckLimits challenge_limits_;
        std::optional<std::uint64_t> challenge_start_;
        std::size_t challenge_count_ = 0;
        std::optional<std::uint64_t> reset_start_;
        std::size_t reset_count_ = 0;
        std::uint64_t next_gen_ = 1;

        BasicConnectionTable(std::size_t limit, std::size_t capacity, ChallengeAckLimits challenge);
        static auto hash_tuple(TupleKey const& k) noexcept -> std::size_t;
        [[nodiscard]] auto lookup_slot(ConnectionId id) noexcept -> Slot*;
        [[nodiscard]] auto lookup_slot(ConnectionId id) const noexcept -> Slot const*;
        [[nodiscard]] auto bucket_find(TupleKey const& key, std::size_t hash) const noexcept -> std::uint32_t;
        auto bucket_insert(std::size_t hash, std::uint32_t idx) noexcept -> void;
        auto bucket_erase(std::uint32_t idx) noexcept -> void;
        auto erase_slot(std::uint32_t idx) noexcept -> void;

    public:
        BasicConnectionTable(BasicConnectionTable const&) = delete;
        auto operator=(BasicConnectionTable const&) -> BasicConnectionTable& = delete;
        BasicConnectionTable(BasicConnectionTable&&) = default;
        auto operator=(BasicConnectionTable&&) -> BasicConnectionTable& = default;

        [[nodiscard]] static constexpr auto slot_index(ConnectionId id) noexcept -> std::uint32_t {
            return static_cast<std::uint32_t>(id & kSlotMask);
        }
        [[nodiscard]] static auto create(std::size_t limit, std::size_t buffer_capacity, ChallengeAckLimits challenge = {})
            -> std::expected<BasicConnectionTable, TableError>;
        [[nodiscard]] auto claim_challenge_ack(std::uint64_t now) noexcept -> bool;
        [[nodiscard]] auto stateless_reset_available(std::uint64_t now) const noexcept -> bool;
        [[nodiscard]] auto claim_stateless_reset(std::uint64_t now) noexcept -> bool;
        [[nodiscard]] auto open(SegmentView syn, std::uint32_t iss, std::uint64_t now)
            -> std::expected<ConnectionId, TableError>;
        [[nodiscard]] auto find(SegmentView segment) const noexcept -> std::optional<ConnectionId>;
        [[nodiscard]] auto watch(SegmentView segment) -> std::shared_ptr<packet::TcpGeneration>;
        [[nodiscard]] auto watched_generations() const noexcept -> std::size_t;
        [[nodiscard]] auto get(ConnectionId id) noexcept -> Connection*;
        [[nodiscard]] auto target(ConnectionId id) const noexcept -> std::optional<Target>;
        [[nodiscard]] auto endpoints(ConnectionId id) const noexcept -> std::optional<Endpoints>;
        [[nodiscard]] auto next(ConnectionId after) const noexcept -> std::optional<ConnectionId>;
        [[nodiscard]] auto observe_eof(ConnectionId id) noexcept -> bool;
        [[nodiscard]] auto hold_reset(ConnectionId id, bool hold) noexcept -> bool;
        [[nodiscard]] auto detach(ConnectionId id) noexcept -> bool;
        [[nodiscard]] auto is_detached(ConnectionId id) const noexcept -> bool;
        [[nodiscard]] auto reclaim(ConnectionId id, std::uint64_t now) -> std::expected<bool, TableError>;
        [[nodiscard]] auto abort(ConnectionId id) noexcept -> bool;
        [[nodiscard]] auto size() const noexcept -> std::size_t { return active_count_; }
        auto admission_limit(std::size_t limit) noexcept -> void { limit_ = std::min(limit, hard_limit_); }
    };

    using ConnectionTable = BasicConnectionTable<PassiveConnection, packet::Address4, packet::Tcp4View, Target4, Endpoints4>;
    using ConnectionTable6 = BasicConnectionTable<PassiveConnection6, packet::Address6, packet::Tcp6View, Target6, Endpoints6>;
}
