export module nexus.tcp.dispatch;
export import nexus.tcp.table;
export import nexus.rules;
import std;

export namespace nexus::tcp {
    enum class DispatchError { invalid_packet, invalid_target, unknown_flow, table_error, output_error, blocked, policy_error };
    struct DispatchFailure {
        DispatchError error;
        std::optional<packet::PacketError> packet_error;
        std::optional<TableError> table_error;
    };
    struct DispatchResult {
        ConnectionId id;
        bool opened = false;
        bool challenge_suppressed = false;
        std::optional<ConnectionError> input_error;
        std::optional<packet::Bytes> reply;
    };
    // Caller owns replies and drives retransmission, backpressure and flow lifetime.
    [[nodiscard]] auto dispatch(ConnectionTable& table, std::span<std::uint8_t const> bytes,
                                std::uint32_t iss, std::uint64_t now, std::size_t mtu = 1500)
        -> std::expected<DispatchResult, DispatchFailure>;
    [[nodiscard]] auto dispatch_routed(ConnectionTable& table, rules::Matcher const& policy,
                                       std::span<std::uint8_t const> bytes, std::uint32_t iss,
                                       std::uint64_t now, std::size_t mtu = 1500)
        -> std::expected<DispatchResult, DispatchFailure>;
}
