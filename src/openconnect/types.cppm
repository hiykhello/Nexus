export module openconnect.types;
import std;
import crypto;

export namespace openconnect {
    enum class CstpType : std::uint8_t {
        data = 0x00,
        dpd_req = 0x03,
        dpd_resp = 0x04,
        disconnect = 0x05,
        keepalive = 0x07,
        compressed = 0x08,
    };

    enum class DtlsVersion : std::uint16_t {
        none = 0,
        dtls1_2 = 0xfefd,
        dtls1_3 = 0xfefc,
    };

    enum class DtlsCipher : std::uint8_t {
        aes_128_gcm,
        aes_256_gcm,
        chacha20_poly1305,
    };

    struct AuthRequest {
        std::string username;
        std::string password;
        std::string group;
        std::string opaque;
        std::string user_agent{"AnyConnect Linux_64 5.0"};
        bool client_cert_auth = false;
        std::string client_cert_fingerprint_hex;
        ~AuthRequest() {
            if (!password.empty())
                crypto::cleanse(std::span<std::uint8_t>(reinterpret_cast<std::uint8_t*>(password.data()), password.size()));
        }
    };

    struct AuthResult {
        bool authenticated = false;
        bool needs_auth_reply = false;
        std::string cookie;
        std::string opaque;
        std::string dtls_session_id;
        std::string ipv4_address;
        std::string ipv6_address;
        std::uint16_t mtu = 1400;
        std::uint16_t dpd_s = 30;
        std::uint16_t keepalive_s = 20;
        std::uint16_t dtls_port = 0;
        std::string dtls_cipher;
        std::vector<std::string> dns_servers;
        std::string banner;
        DtlsVersion dtls_version = DtlsVersion::none;
        std::uint16_t dtls_mtu = 0;
        std::uint16_t dtls_dpd_s = 0;
        std::uint16_t dtls_keepalive_s = 0;
        std::string dtls_app_id;
        bool cert_auth_accepted = false;
        ~AuthResult() {
            if (!cookie.empty())
                crypto::cleanse(std::span<std::uint8_t>(reinterpret_cast<std::uint8_t*>(cookie.data()), cookie.size()));
        }
    };

    struct CstpFrame {
        CstpType type = CstpType::data;
        std::vector<std::uint8_t> payload;
        auto operator==(CstpFrame const&) const -> bool = default;
    };
}
