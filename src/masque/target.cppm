export module masque.target;
import std;

export namespace masque {
    enum class TargetError { invalid_path,invalid_host,invalid_port };
    struct UdpTarget {std::string host;std::uint16_t port=0;};
    // Fixed well-known server template. General RFC 6570 templates are not
    // accepted by this parser and must be implemented explicitly elsewhere.
    [[nodiscard]] auto parse_well_known_udp_target(std::string_view path) -> std::expected<UdpTarget,TargetError>;
}
