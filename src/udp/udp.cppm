export module udp;
export import packet;
import containers.inplace_vector;
import std;
import functional;

export namespace udp {
    struct Endpoint4 {
        packet::Address4 address{};
        std::uint16_t port = 0;
        auto operator==(Endpoint4 const&) const -> bool = default;
    };
    struct Endpoint6 {
        packet::Address6 address{};
        std::uint16_t port = 0;
        auto operator==(Endpoint6 const&) const -> bool = default;
    };
    enum class Mapping { endpoint_independent, address_dependent, address_port_dependent };
    enum class Filtering { endpoint_independent, address_dependent, address_port_dependent };
    enum class Error { invalid_config, time_reversed, capacity, peer_limit, no_flow,
                       remote_mismatch, forbidden, id_exhausted, send_failed, send_in_progress, stale_send };
    struct Limits {
        std::size_t flows = 256;
        std::size_t peers_per_flow = 32;
        std::uint64_t idle_ms = 60000;
    };
    using FlowId = std::uint64_t;
    // Called synchronously on the owner when a live flow is removed. The
    // receiver must outlive the table and must not reenter it. Failed initial
    // reservations can retire an ID before it is returned; destruction itself
    // does not notify, so the owner must close remaining resources on shutdown.
    struct RetirementHandler {
        void* context = nullptr;
        void (*notify)(void*, FlowId) noexcept = nullptr;
    };

    // Single-owner state. Pre-allocated slab with generation-tagged FlowId
    // (low 20 bits = slot index), intrusive LRU list, and flat local-endpoint hash index.
    template <typename Endpoint>
    class BasicFlowTable {
        static constexpr std::uint32_t kNull = std::numeric_limits<std::uint32_t>::max();
        static constexpr std::uint32_t kSlotBits = 20;
        static constexpr std::uint32_t kMaxFlows = 1u << kSlotBits;
        static constexpr std::uint64_t kSlotMask = (std::uint64_t{1} << kSlotBits) - 1;
        static constexpr std::uint64_t kMaxGen = (std::uint64_t{1} << (64 - kSlotBits)) - 1;
        static constexpr std::size_t kInlinePeers = 8;

        struct Flow {
            FlowId id = 0;
            std::size_t local_hash = 0;
            Endpoint local{}, mapped_remote{};
            std::uint64_t touched = 0;
            std::uint64_t idle_override_ms = 0;
            containers::inplace_vector<Endpoint, kInlinePeers> inline_peers;
            std::vector<Endpoint> extra_peers;
            std::optional<std::pair<std::uint64_t, Endpoint>> pending;
            std::uint32_t lru_prev = kNull;
            std::uint32_t lru_next = kNull;
            std::uint32_t local_next = kNull;
            std::uint32_t next_free = kNull;
            bool used = false;
            bool sent = false;

            [[nodiscard]] auto peer_count() const noexcept -> std::size_t {
                return inline_peers.size() + extra_peers.size();
            }
            [[nodiscard]] auto has_peer(Endpoint const& key) const noexcept -> bool {
                return std::ranges::find(inline_peers, key) != inline_peers.end() ||
                       std::ranges::find(extra_peers, key) != extra_peers.end();
            }
            auto reserve_one_peer() -> void {
                if (inline_peers.size() < kInlinePeers) return;
                if (extra_peers.size() == extra_peers.capacity())
                    extra_peers.reserve(std::max<std::size_t>(16, extra_peers.capacity() * 2));
            }
            auto add_peer(Endpoint const& key) -> void {
                if (inline_peers.size() < kInlinePeers) inline_peers.push_back(key);
                else extra_peers.push_back(key);
            }
        };
        struct LocalBucket {
            std::uint32_t head = kNull;
            std::size_t hash = 0;
        };

        Mapping mapping_;
        Filtering filtering_;
        Limits limits_;
        std::vector<Flow> slots_;
        std::vector<LocalBucket> local_buckets_;
        std::size_t local_mask_ = 0;
        std::size_t active_count_ = 0;
        std::uint32_t lru_head_ = kNull;
        std::uint32_t lru_tail_ = kNull;
        std::uint32_t free_head_ = kNull;
        std::uint32_t next_alloc_ = 0;
        std::uint64_t now_ = 0, next_gen_ = 1, next_send_ = 1;
        std::size_t custom_idle_count_ = 0;
        bool initialized_ = false;
        RetirementHandler retirement_{};

        static auto hash_endpoint(Endpoint const& ep) noexcept -> std::size_t;
        [[nodiscard]] auto lookup_slot(FlowId id) noexcept -> Flow*;
        [[nodiscard]] auto local_find_head(Endpoint const& local, std::size_t hash) const noexcept -> std::uint32_t;
        auto local_insert(std::uint32_t idx) noexcept -> void;
        auto local_erase(std::uint32_t idx) noexcept -> void;
        auto lru_unlink(std::uint32_t idx) noexcept -> void;
        auto lru_link_tail(std::uint32_t idx) noexcept -> void;
        auto lru_touch(std::uint32_t idx) noexcept -> void;
        auto erase_slot(std::uint32_t idx) noexcept -> void;
        [[nodiscard]] auto advance(std::uint64_t now) -> std::expected<std::size_t, Error>;
        [[nodiscard]] auto compatible(Flow const& flow, Endpoint remote) const -> bool;
    public:
        BasicFlowTable(Mapping mapping, Filtering filtering, Limits limits = {}, RetirementHandler retirement = {});
        BasicFlowTable(BasicFlowTable const&) = delete;
        auto operator=(BasicFlowTable const&) -> BasicFlowTable& = delete;
        [[nodiscard]] static constexpr auto slot_index(FlowId id) noexcept -> std::uint32_t {
            return static_cast<std::uint32_t>(id & kSlotMask);
        }
        [[nodiscard]] auto open(Endpoint local, Endpoint remote, std::uint64_t now) -> std::expected<FlowId, Error>;
        [[nodiscard]] auto open_send(Endpoint local, Endpoint remote, std::uint64_t now)
            -> std::expected<std::pair<FlowId, std::uint64_t>, Error>;
        // One in-flight send per flow. Completion succeeds only for the original
        // live flow and token; cancellation/failure releases the reserved peer.
        [[nodiscard]] auto begin_send(FlowId id, Endpoint remote, std::uint64_t now) -> std::expected<std::uint64_t, Error>;
        [[nodiscard]] auto finish_send(FlowId id, std::uint64_t token, bool success, std::uint64_t now) -> std::expected<void, Error>;
        // Sender is borrowed for this synchronous call, is not stored, and must not
        // reenter this table. Its target must remain alive until transmit returns.
        // Peer capacity is reserved before it runs; failure grants no new permission.
        [[nodiscard]] auto transmit(FlowId id, Endpoint remote, std::uint64_t now,
            functional::function_ref<bool()> sender) -> std::expected<void, Error>;
        [[nodiscard]] auto accept_reply(FlowId id, Endpoint remote, std::uint64_t now) -> std::expected<Endpoint, Error>;
        [[nodiscard]] auto close(FlowId id, std::uint64_t now) -> std::expected<void, Error>;
        // Retire every flow, including in-flight sends, and notify the owner.
        [[nodiscard]] auto clear(std::uint64_t now) -> std::expected<std::size_t, Error>;
        [[nodiscard]] auto expire(std::uint64_t now) -> std::expected<std::size_t, Error> { return advance(now); }
        auto set_flow_idle_ms(FlowId id, std::uint64_t idle_ms) noexcept -> bool;
        [[nodiscard]] auto size() const noexcept -> std::size_t { return active_count_; }
    };
    using FlowTable = BasicFlowTable<Endpoint4>;
    using FlowTable6 = BasicFlowTable<Endpoint6>;
    using BridgeError = std::variant<packet::PacketError, Error>;
    struct OutboundDatagram {
        FlowId flow;
        std::uint64_t token;
        Endpoint4 remote;
        packet::Bytes payload; // Owned by the caller until transport completion.
    };
    // Transport-independent, single-owner UDP/IP bridge. No routing or sockets.
    class Bridge4 {
        FlowTable flows_;
        std::size_t mtu_;
    public:
        Bridge4(Mapping mapping, Filtering filtering, Limits limits = {}, std::size_t mtu = 1500,
                RetirementHandler retirement = {})
            : flows_(mapping, filtering, limits, retirement), mtu_(mtu) {}
        [[nodiscard]] static constexpr auto slot_index(FlowId id) noexcept -> std::uint32_t { return FlowTable::slot_index(id); }
        [[nodiscard]] auto prepare(std::span<std::uint8_t const> input, std::uint64_t now)
            -> std::expected<OutboundDatagram, BridgeError>;
        [[nodiscard]] auto prepare_parsed(packet::Udp4View const& parsed, std::uint64_t now)
            -> std::expected<OutboundDatagram, BridgeError>;
        [[nodiscard]] auto complete(FlowId id, std::uint64_t token, bool success, std::uint64_t now)
            -> std::expected<void, Error> { return flows_.finish_send(id, token, success, now); }
        [[nodiscard]] auto reply(FlowId id, Endpoint4 remote, std::span<std::uint8_t const> payload, std::uint64_t now)
            -> std::expected<packet::Bytes, BridgeError>;
        [[nodiscard]] auto close(FlowId id, std::uint64_t now) -> std::expected<void, Error> { return flows_.close(id, now); }
        [[nodiscard]] auto clear(std::uint64_t now) -> std::expected<std::size_t, Error> { return flows_.clear(now); }
        [[nodiscard]] auto expire(std::uint64_t now) -> std::expected<std::size_t, Error> { return flows_.expire(now); }
        auto set_flow_idle_ms(FlowId id, std::uint64_t idle_ms) noexcept -> bool { return flows_.set_flow_idle_ms(id, idle_ms); }
        [[nodiscard]] auto size() const noexcept -> std::size_t { return flows_.size(); }
    };

    struct OutboundDatagram6 {
        FlowId flow;
        std::uint64_t token;
        Endpoint6 remote;
        packet::Bytes payload;
    };
    class Bridge6 {
        FlowTable6 flows_;
        std::size_t mtu_;
    public:
        Bridge6(Mapping mapping, Filtering filtering, Limits limits = {}, std::size_t mtu = 1500,
                RetirementHandler retirement = {})
            : flows_(mapping, filtering, limits, retirement), mtu_(mtu) {}
        [[nodiscard]] static constexpr auto slot_index(FlowId id) noexcept -> std::uint32_t { return FlowTable6::slot_index(id); }
        [[nodiscard]] auto prepare(std::span<std::uint8_t const> input, std::uint64_t now)
            -> std::expected<OutboundDatagram6, BridgeError>;
        [[nodiscard]] auto prepare_parsed(packet::Udp6View const& parsed, std::uint64_t now)
            -> std::expected<OutboundDatagram6, BridgeError>;
        [[nodiscard]] auto complete(FlowId id, std::uint64_t token, bool success, std::uint64_t now)
            -> std::expected<void, Error> { return flows_.finish_send(id, token, success, now); }
        [[nodiscard]] auto reply(FlowId id, Endpoint6 remote, std::span<std::uint8_t const> payload, std::uint64_t now)
            -> std::expected<packet::Bytes, BridgeError>;
        [[nodiscard]] auto close(FlowId id, std::uint64_t now) -> std::expected<void, Error> { return flows_.close(id, now); }
        [[nodiscard]] auto clear(std::uint64_t now) -> std::expected<std::size_t, Error> { return flows_.clear(now); }
        [[nodiscard]] auto expire(std::uint64_t now) -> std::expected<std::size_t, Error> { return flows_.expire(now); }
        auto set_flow_idle_ms(FlowId id, std::uint64_t idle_ms) noexcept -> bool { return flows_.set_flow_idle_ms(id, idle_ms); }
        [[nodiscard]] auto size() const noexcept -> std::size_t { return flows_.size(); }
    };
}
