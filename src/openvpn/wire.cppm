export module openvpn.wire;
import std;
export import openvpn.types;

export namespace openvpn {
    struct KeyMaterial {
        std::array<std::uint8_t, 32> tx_key{};
        std::array<std::uint8_t, 32> rx_key{};
        std::array<std::uint8_t, 8> tx_iv{};
        std::array<std::uint8_t, 8> rx_iv{};
    };

    class ReplayWindow {
        std::uint32_t highest_{0};
        std::uint64_t bitmap_{0};
        bool initialized_{false};
    public:
        [[nodiscard]] auto check_and_accept(std::uint32_t packet_id) noexcept -> bool;
        auto reset() noexcept -> void { highest_ = 0; bitmap_ = 0; initialized_ = false; }
        [[nodiscard]] auto highest() const noexcept -> std::uint32_t { return highest_; }
    };

    [[nodiscard]] auto encode_control_packet(ControlPacket const& pkt) -> std::expected<std::vector<std::uint8_t>, std::string>;
    [[nodiscard]] auto decode_control_packet(std::span<std::uint8_t const> wire) -> std::expected<ControlPacket, std::string>;
    [[nodiscard]] auto derive_data_keys(std::span<std::uint8_t const> master_secret,
                                        std::span<std::uint8_t const> client_random,
                                        std::span<std::uint8_t const> server_random,
                                        bool server_role = false) -> std::expected<KeyMaterial, std::string>;
}
