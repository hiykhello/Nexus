export module nexus.udp.route;
export import nexus.udp;
import nexus.rules;
import std;

export namespace nexus::udp {
    enum class RouteError { blocked, invalid_packet, policy_error };
    using RoutedError = std::variant<RouteError, BridgeError>;
    // A policy snapshot is owned for the lifetime of the bridge.
    class RoutedBridge4 {
        rules::Matcher policy_;
        Bridge4 bridge_;
    public:
        RoutedBridge4(rules::Matcher policy, Mapping mapping, Filtering filtering, Limits limits = {}, std::size_t mtu = 1500,
                      RetirementHandler retirement = {})
            : policy_(std::move(policy)), bridge_(mapping, filtering, limits, mtu, retirement) {}
        [[nodiscard]] auto prepare(std::span<std::uint8_t const> input, std::uint64_t now)
            -> std::expected<OutboundDatagram, RoutedError>;
        [[nodiscard]] auto complete(FlowId id, std::uint64_t token, bool success, std::uint64_t now)
            -> std::expected<void, Error> { return bridge_.complete(id, token, success, now); }
        [[nodiscard]] auto reply(FlowId id, Endpoint4 remote, std::span<std::uint8_t const> payload, std::uint64_t now)
            -> std::expected<packet::Bytes, BridgeError> { return bridge_.reply(id, remote, payload, now); }
        [[nodiscard]] auto expire(std::uint64_t now) -> std::expected<std::size_t, Error> { return bridge_.expire(now); }
        [[nodiscard]] auto close(FlowId id, std::uint64_t now) -> std::expected<void, Error> { return bridge_.close(id, now); }
        [[nodiscard]] auto clear(std::uint64_t now) -> std::expected<std::size_t, Error> { return bridge_.clear(now); }
        [[nodiscard]] auto size() const noexcept -> std::size_t { return bridge_.size(); }
    };
    class RoutedBridge6 {
        rules::Matcher policy_;
        Bridge6 bridge_;
    public:
        RoutedBridge6(rules::Matcher policy, Mapping mapping, Filtering filtering, Limits limits = {}, std::size_t mtu = 1500,
                      RetirementHandler retirement = {})
            : policy_(std::move(policy)), bridge_(mapping, filtering, limits, mtu, retirement) {}
        [[nodiscard]] auto prepare(std::span<std::uint8_t const> input, std::uint64_t now)
            -> std::expected<OutboundDatagram6, RoutedError>;
        [[nodiscard]] auto complete(FlowId id, std::uint64_t token, bool success, std::uint64_t now)
            -> std::expected<void, Error> { return bridge_.complete(id, token, success, now); }
        [[nodiscard]] auto reply(FlowId id, Endpoint6 remote, std::span<std::uint8_t const> payload, std::uint64_t now)
            -> std::expected<packet::Bytes, BridgeError> { return bridge_.reply(id, remote, payload, now); }
        [[nodiscard]] auto expire(std::uint64_t now) -> std::expected<std::size_t, Error> { return bridge_.expire(now); }
        [[nodiscard]] auto close(FlowId id, std::uint64_t now) -> std::expected<void, Error> { return bridge_.close(id, now); }
        [[nodiscard]] auto clear(std::uint64_t now) -> std::expected<std::size_t, Error> { return bridge_.clear(now); }
        [[nodiscard]] auto size() const noexcept -> std::size_t { return bridge_.size(); }
    };
}
