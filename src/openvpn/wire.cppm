export module openvpn.wire;
import std;
import crypto;
export import openvpn.types;

export namespace openvpn {
    struct KeyMaterial {
        std::array<std::uint8_t, 32> tx_key{};
        std::array<std::uint8_t, 32> rx_key{};
        std::array<std::uint8_t, 8> tx_iv{};
        std::array<std::uint8_t, 8> rx_iv{};
        ~KeyMaterial() {
            crypto::cleanse(tx_key);
            crypto::cleanse(rx_key);
            crypto::cleanse(tx_iv);
            crypto::cleanse(rx_iv);
        }
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
    [[nodiscard]] auto encode_tcp_frame(std::span<std::uint8_t const> packet) -> std::expected<std::vector<std::uint8_t>, std::string>;
    [[nodiscard]] auto decode_tcp_frame(std::span<std::uint8_t const> stream)
        -> std::expected<std::optional<std::pair<std::vector<std::uint8_t>, std::size_t>>, std::string>;
    [[nodiscard]] auto encode_key_method2_client(KeyMethod2Client const& km) -> std::expected<std::vector<std::uint8_t>, std::string>;
    [[nodiscard]] auto decode_key_method2_client(std::span<std::uint8_t const> wire) -> std::expected<KeyMethod2Client, std::string>;
    [[nodiscard]] auto encode_key_method2_server(KeyMethod2Server const& km) -> std::expected<std::vector<std::uint8_t>, std::string>;
    [[nodiscard]] auto decode_key_method2_server(std::span<std::uint8_t const> wire) -> std::expected<KeyMethod2Server, std::string>;
    [[nodiscard]] auto derive_data_keys(std::span<std::uint8_t const> master_secret,
                                        std::span<std::uint8_t const> client_random,
                                        std::span<std::uint8_t const> server_random,
                                        bool server_role = false) -> std::expected<KeyMaterial, std::string>;
    [[nodiscard]] auto derive_key_method2_keys(
        std::span<std::uint8_t const, 48> pre_master,
        std::span<std::uint8_t const, 32> client_random1, std::span<std::uint8_t const, 32> server_random1,
        std::span<std::uint8_t const, 32> client_random2, std::span<std::uint8_t const, 32> server_random2,
        std::uint64_t client_session_id, std::uint64_t server_session_id,
        bool server_role = false) -> std::expected<KeyMaterial, std::string>;
    [[nodiscard]] auto parse_push_reply(std::string_view text) -> std::expected<PushConfig, std::string>;
}
