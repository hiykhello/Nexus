export module openvpn.types;
import std;
import crypto;

export namespace openvpn {
    enum class Opcode : std::uint8_t {
        control_soft_reset_v1 = 3,
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

    enum class Transport : std::uint8_t { udp, tcp };

    enum class TlsAuthMode : std::uint8_t {
        none = 0,
        tls_auth = 1,
        tls_crypt = 2,
    };

    enum class KeyDirection : std::int8_t {
        bidirectional = -1,
        client_0 = 0,
        client_1 = 1,
    };

    struct RouteV4 {
        std::array<std::uint8_t, 4> network{};
        std::array<std::uint8_t, 4> netmask{255, 255, 255, 255};
        std::optional<std::array<std::uint8_t, 4>> gateway;
        auto operator==(RouteV4 const&) const -> bool = default;
    };

    struct RouteV6 {
        std::array<std::uint8_t, 16> network{};
        std::uint8_t prefix_len = 128;
        std::optional<std::array<std::uint8_t, 16>> gateway;
        auto operator==(RouteV6 const&) const -> bool = default;
    };

    inline constexpr std::array<std::uint8_t, 16> ping_magic{
        0x2a, 0x18, 0x7b, 0xf3, 0x64, 0x1e, 0xb4, 0xcb,
        0x07, 0xed, 0x2d, 0x0a, 0x98, 0x1f, 0xc7, 0x48,
    };

    struct KeyMethod2Client {
        std::array<std::uint8_t, 48> pre_master{};
        std::array<std::uint8_t, 32> random1{}, random2{};
        std::string options, username, password, peer_info;
        ~KeyMethod2Client() {
            crypto::cleanse(pre_master);
            if (!password.empty())
                crypto::cleanse(std::span<std::uint8_t>(reinterpret_cast<std::uint8_t*>(password.data()), password.size()));
        }
    };

    struct KeyMethod2Server {
        std::array<std::uint8_t, 32> random1{}, random2{};
        std::string options;
    };

    struct PushConfig {
        std::optional<std::array<std::uint8_t, 4>> local_v4;
        std::optional<std::array<std::uint8_t, 16>> local_v6;
        std::optional<std::uint32_t> peer_id;
        std::optional<Cipher> cipher;
        std::optional<std::uint16_t> mtu;
        std::uint16_t ping_s = 10;
        std::uint16_t ping_restart_s = 60;
        std::optional<std::array<std::uint8_t, 4>> netmask_v4;
        std::uint8_t prefix_v6 = 64;
        std::optional<std::array<std::uint8_t, 4>> gateway_v4;
        std::optional<std::array<std::uint8_t, 16>> gateway_v6;
        std::vector<RouteV4> routes_v4;
        std::vector<RouteV6> routes_v6;
        std::vector<std::string> dns_servers;
        std::vector<std::string> search_domains;
        bool redirect_gateway = false;
        bool redirect_gateway_v6 = false;
        bool topology_subnet = false;
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
