export module openvpn.types;
import std;

export namespace openvpn {
    enum class Opcode : std::uint8_t {
        control_v1 = 4,
        ack_v1 = 5,
        control_hard_reset_client_v2 = 7,
        control_hard_reset_server_v2 = 8,
        data_v2 = 9,
    };

    enum class Cipher {
        aes_256_gcm,
        chacha20_poly1305,
    };

    struct Config {
        std::string remote_host;
        std::uint16_t remote_port = 1194;
        Cipher cipher = Cipher::aes_256_gcm;
        std::uint32_t peer_id = 0;
        std::uint32_t replay_window = 64;
        std::uint16_t mtu = 1400;
    };

    struct ControlPacket {
        Opcode opcode = Opcode::control_v1;
        std::uint8_t key_id = 0;
        std::uint64_t session_id = 0;
        std::vector<std::uint32_t> acks;
        std::uint64_t remote_session_id = 0;
        std::optional<std::uint32_t> packet_id;
        std::vector<std::uint8_t> payload;
    };

    struct DataV2Header {
        std::uint8_t key_id = 0;
        std::uint32_t peer_id = 0;
        std::uint32_t packet_id = 0;
    };
}
