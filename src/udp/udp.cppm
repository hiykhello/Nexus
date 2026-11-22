export module udp;
export import packet;
import std;
import nexus.compat;

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

    // Single-owner state. Times are monotonic milliseconds supplied by the caller.
    // IDs are unique for this table's lifetime, including after expiry.
    template <typename Endpoint>
    class BasicFlowTable {
        struct EndpointHash {
            auto operator()(Endpoint const& ep) const noexcept -> std::size_t {
                std::size_t h = 14695981039346656037ull;
                for (auto b : ep.address) { h ^= b; h *= 1099511628211ull; }
                h ^= ep.port; h *= 1099511628211ull;
                return h;
            }
        };
        struct Flow {
            FlowId id;
            Endpoint local, mapped_remote;
            std::uint64_t touched;
            bool sent = false;
            std::vector<Endpoint> peers;
            std::optional<std::pair<std::uint64_t, Endpoint>> pending;
            std::uint64_t idle_override_ms = 0;
        };
        using List = std::list<Flow>;
        Mapping mapping_;
        Filtering filtering_;
        Limits limits_;
        List flows_;
        std::unordered_map<FlowId, typename List::iterator> by_id_;
        std::unordered_map<Endpoint, std::vector<typename List::iterator>, EndpointHash> by_local_;
        std::uint64_t now_ = 0, next_id_ = 1, next_send_ = 1;
        bool initialized_ = false;
        RetirementHandler retirement_{};
        auto erase_flow(typename List::iterator it) noexcept -> void;
        [[nodiscard]] auto advance(std::uint64_t now) -> std::expected<std::size_t, Error>;
        [[nodiscard]] auto compatible(Flow const& flow, Endpoint remote) const -> bool;
    public:
        BasicFlowTable(Mapping mapping, Filtering filtering, Limits limits = {}, RetirementHandler retirement = {})
            : mapping_(mapping), filtering_(filtering), limits_(limits), retirement_(retirement) {}
        BasicFlowTable(BasicFlowTable const&) = delete;
        auto operator=(BasicFlowTable const&) -> BasicFlowTable& = delete;
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
            nexus::function_ref<bool()> sender) -> std::expected<void, Error>;
        [[nodiscard]] auto accept_reply(FlowId id, Endpoint remote, std::uint64_t now) -> std::expected<Endpoint, Error>;
        [[nodiscard]] auto close(FlowId id, std::uint64_t now) -> std::expected<void, Error>;
        // Retire every flow, including in-flight sends, and notify the owner.
        [[nodiscard]] auto clear(std::uint64_t now) -> std::expected<std::size_t, Error>;
        [[nodiscard]] auto expire(std::uint64_t now) -> std::expected<std::size_t, Error> { return advance(now); }
        auto set_flow_idle_ms(FlowId id, std::uint64_t idle_ms) noexcept -> bool;
        [[nodiscard]] auto size() const noexcept -> std::size_t { return flows_.size(); }
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
        [[nodiscard]] auto prepare(std::span<std::uint8_t const> input, std::uint64_t now)
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
        [[nodiscard]] auto prepare(std::span<std::uint8_t const> input, std::uint64_t now)
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
