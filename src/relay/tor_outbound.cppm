export module relay.tor_outbound;
import std;

export namespace relay::tor {
    struct Config {
        std::string socks_host{"127.0.0.1"};
        std::uint16_t socks_port = 9050;
        std::string control_host{"127.0.0.1"};
        std::uint16_t control_port = 9051;
        std::string control_password;
        std::string cookie_hex;
        bool isolate_streams = true;
        bool allow_remote_socks = false;
    };

    struct ControlReply {
        int code = 0;
        bool ok = false;
        std::vector<std::string> lines;
        std::optional<int> bootstrap_progress;
    };

    [[nodiscard]] auto validate_config(Config const& cfg) -> std::expected<void, std::string>;
    [[nodiscard]] auto build_socks5_greeting(bool with_isolation_auth) -> std::vector<std::uint8_t>;
    [[nodiscard]] auto build_socks5_isolation_auth(std::string_view username, std::string_view password)
        -> std::expected<std::vector<std::uint8_t>, std::string>;
    [[nodiscard]] auto build_socks5_connect_domain(std::string_view host, std::uint16_t port)
        -> std::expected<std::vector<std::uint8_t>, std::string>;
    [[nodiscard]] auto build_control_authenticate(Config const& cfg) -> std::expected<std::string, std::string>;
    [[nodiscard]] auto build_control_newnym() -> std::string;
    [[nodiscard]] auto build_control_getinfo(std::string_view key) -> std::expected<std::string, std::string>;
    [[nodiscard]] auto parse_control_reply(std::string_view raw) -> std::expected<ControlReply, std::string>;
}
