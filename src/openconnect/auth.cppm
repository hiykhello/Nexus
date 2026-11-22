export module openconnect.auth;
import std;
export import openconnect.types;

export namespace openconnect {
    [[nodiscard]] auto build_config_auth_xml(AuthRequest const& req) -> std::string;
    [[nodiscard]] auto parse_config_auth_response(std::string_view xml) -> std::expected<AuthResult, std::string>;
    [[nodiscard]] auto build_cstp_connect_headers(std::string_view host, std::string_view cookie,
                                                  std::uint16_t mtu = 1400) -> std::string;
    [[nodiscard]] auto parse_cstp_connect_headers(std::string_view raw_headers) -> std::expected<AuthResult, std::string>;
}
