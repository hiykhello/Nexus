export module openconnect.types;
import std;

export namespace openconnect {
    enum class CstpType : std::uint8_t {
        data = 0x00,
        dpd_req = 0x03,
        dpd_resp = 0x04,
        disconnect = 0x05,
        keepalive = 0x07,
        compressed = 0x08,
    };

    struct AuthRequest {
        std::string username;
        std::string password;
        std::string group;
        std::string user_agent{"AnyConnect Linux_64 5.0"};
    };

    struct AuthResult {
        bool authenticated = false;
        std::string cookie;
        std::string dtls_session_id;
        std::string ipv4_address;
        std::uint16_t mtu = 1400;
        std::string banner;
    };

    struct CstpFrame {
        CstpType type = CstpType::data;
        std::vector<std::uint8_t> payload;
        auto operator==(CstpFrame const&) const -> bool = default;
    };
}
