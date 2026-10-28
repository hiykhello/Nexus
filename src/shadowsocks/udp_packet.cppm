export module nexus.shadowsocks.udp_packet;
import std;

export namespace nexus::shadowsocks {
    enum class UdpDirection { client, server };
    enum class UdpPacketError { invalid_key, invalid_length, authentication, invalid_type, invalid_timestamp, invalid_session, session_collision, invalid_address, crypto };
    struct UdpPacket {
        std::array<std::uint8_t,8> session_id{};
        std::uint64_t packet_id=0;
        std::uint64_t timestamp=0;
        std::optional<std::array<std::uint8_t,8>> client_session;
        std::vector<std::uint8_t> address;
        std::vector<std::uint8_t> payload;
    };
    // Inputs are owned by the caller; the session owner enforces packet ID
    // uniqueness and supplies fresh session IDs and any desired random padding.
    [[nodiscard]] auto encode_udp_packet(std::span<std::uint8_t const> psk, UdpDirection direction,
        UdpPacket const& packet, std::span<std::uint8_t const> padding) -> std::expected<std::vector<std::uint8_t>,UdpPacketError>;
    // Authenticate before parsing. For server messages, expected_client is
    // mandatory and must identify the client session to which it belongs.
    // This function does not update replay windows or any network endpoint.
    [[nodiscard]] auto decode_udp_packet(std::span<std::uint8_t const> psk, UdpDirection direction,
        std::span<std::uint8_t const> packet, std::uint64_t now,
        std::optional<std::array<std::uint8_t,8>> expected_client = {}) -> std::expected<UdpPacket,UdpPacketError>;
}
