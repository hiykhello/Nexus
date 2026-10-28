export module nexus.vless;
import std;

export namespace nexus::vless {
    enum class AddressKind : std::uint8_t { ipv4=1, domain=2, ipv6=3 };
    enum class HeaderStatus { incomplete, accepted, malformed, unsupported };
    enum class EncodeError { invalid_address, invalid_port };
    // Canonical UUID text, with ASCII hexadecimal digits and four hyphens.
    // File handling and any trailing newline are the caller's responsibility.
    [[nodiscard]] auto parse_user_id(std::string_view text) -> std::optional<std::array<std::uint8_t,16>>;
    struct TcpRequest {
        std::array<std::uint8_t,16> user{};
        AddressKind kind=AddressKind::ipv4;
        std::uint16_t port=0;
        std::vector<std::uint8_t> address;
    };
    struct RequestResult { HeaderStatus status=HeaderStatus::incomplete; std::size_t consumed=0; std::optional<TcpRequest> request; };
    struct ResponseResult { HeaderStatus status=HeaderStatus::incomplete; std::size_t consumed=0; };
    // Only version 0, TCP and empty addons. Authentication and transport are separate.
    [[nodiscard]] auto encode_tcp_request(TcpRequest const& request) -> std::expected<std::vector<std::uint8_t>,EncodeError>;
    // Stops at the header boundary, leaving application data in the caller's input.
    [[nodiscard]] auto parse_tcp_request(std::span<std::uint8_t const> input) -> RequestResult;
    [[nodiscard]] auto parse_response(std::span<std::uint8_t const> input) -> ResponseResult;
    [[nodiscard]] auto encode_response() noexcept -> std::array<std::uint8_t,2>;

    using UserId = std::array<std::uint8_t,16>;
    enum class ServerStatus { reading, dialing, established, rejected };
    struct ServerStep { ServerStatus status; std::size_t consumed; };
    // One authenticated TCP request. The caller owns transport, deadline and
    // bytes after consumed; no response is emitted before successful dialing.
    class ServerHandshake {
        std::vector<UserId> users_;
        std::array<std::uint8_t,278> header_{};
        std::size_t length_=0;
        ServerStatus status_=ServerStatus::reading;
        std::optional<TcpRequest> request_;
        explicit ServerHandshake(std::vector<UserId> users);
    public:
        [[nodiscard]] static auto create(std::span<UserId const> users) -> std::expected<ServerHandshake,std::string>;
        [[nodiscard]] auto feed(std::span<std::uint8_t const> bytes) -> ServerStep;
        // Borrowed until failed dialing or destruction; available after authentication.
        [[nodiscard]] auto request() const noexcept -> TcpRequest const*;
        [[nodiscard]] auto complete_dial(bool connected) -> std::optional<std::array<std::uint8_t,2>>;
        [[nodiscard]] auto status() const noexcept -> ServerStatus { return status_; }
    };
}
