export module masque.connect_udp;
import std;
import http.header;

export namespace masque {
    enum class ConnectUdpError { malformed,not_connect_udp,failed_response };
    struct ConnectUdpRequest {std::string_view authority,path;};
    // Header views are borrowed until nghttp3 releases them. Policy must own
    // copies before asynchronous auth, URI parsing, DNS or UDP socket setup.
    // This parser never authorizes a destination or decodes the URI template.
    [[nodiscard]] auto parse_connect_udp_request(std::span<http::HeaderField const> fields) noexcept -> std::expected<ConnectUdpRequest,ConnectUdpError>;
    [[nodiscard]] auto parse_connect_udp_response(std::span<http::HeaderField const> fields) noexcept -> std::expected<unsigned,ConnectUdpError>;
}
