export module vless;
import std;

export namespace vless {
    enum class AddressKind : std::uint8_t { ipv4=1, domain=2, ipv6=3 };
    enum class HeaderStatus { incomplete, accepted, malformed, unsupported };
    enum class EncodeError { invalid_address, invalid_port };
    // Canonical UUID text, with ASCII hexadecimal digits and four hyphens.
    // File handling and any trailing newline are the caller's responsibility.
    [[nodiscard]] auto parse_user_id(std::string_view text) -> std::optional<std::array<std::uint8_t,16>>;
    enum class TargetCommand : std::uint8_t { tcp=1, udp=2 };
    inline constexpr std::string_view packetaddr_domain="sp.packet-addr.v2fly.arpa";
    struct TcpRequest {
        std::array<std::uint8_t,16> user{};
        AddressKind kind=AddressKind::ipv4;
        std::uint16_t port=0;
        std::vector<std::uint8_t> address;
        TargetCommand command=TargetCommand::tcp;
    };
    struct RequestResult { HeaderStatus status=HeaderStatus::incomplete; std::size_t consumed=0; std::optional<TcpRequest> request; };
    struct ResponseResult { HeaderStatus status=HeaderStatus::incomplete; std::size_t consumed=0; };
    // Only version 0, TCP and empty addons. Authentication and transport are separate.
    [[nodiscard]] auto encode_tcp_request(TcpRequest const& request) -> std::expected<std::vector<std::uint8_t>,EncodeError>;
    [[nodiscard]] auto encode_udp_request(TcpRequest const& request) -> std::expected<std::vector<std::uint8_t>,EncodeError>;
    // Stops at the header boundary, leaving application data in the caller's input.
    [[nodiscard]] auto parse_tcp_request(std::span<std::uint8_t const> input) -> RequestResult;
    // Explicit Vision entry points; ordinary ServerHandshake continues to reject
    // nonempty addons until the caller can enforce Vision transport semantics.
    [[nodiscard]] auto encode_vision_tcp_request(TcpRequest const& request) -> std::expected<std::vector<std::uint8_t>,EncodeError>;
    [[nodiscard]] auto parse_vision_tcp_request(std::span<std::uint8_t const> input) -> RequestResult;
    // Mux command has no address or port on the wire. Callers must authenticate
    // the UUID and implement Mux/XUDP before accepting this request.
    struct MuxRequestResult { HeaderStatus status=HeaderStatus::incomplete; std::size_t consumed=0; std::optional<std::array<std::uint8_t,16>> user; };
    [[nodiscard]] auto encode_mux_request(std::array<std::uint8_t,16> const& user,bool vision=false) -> std::vector<std::uint8_t>;
    [[nodiscard]] auto parse_mux_request(std::span<std::uint8_t const> input,bool vision=false) -> MuxRequestResult;
    [[nodiscard]] auto parse_response(std::span<std::uint8_t const> input) -> ResponseResult;
    [[nodiscard]] auto encode_response() noexcept -> std::array<std::uint8_t,2>;

    using UserId = std::array<std::uint8_t,16>;
    enum class ServerStatus { reading, dialing, established, rejected };
    struct ServerStep { ServerStatus status; std::size_t consumed; };
    // One authenticated request. The caller owns transport, deadline and
    // bytes after consumed. UDP and Mux require explicit opt-in.
    class ServerHandshake {
        std::vector<UserId> users_;
        // 278-byte maximal TCP header plus the 255-byte addon limit.
        std::array<std::uint8_t,533> header_{};
        std::size_t length_=0;
        bool vision_=false, mux_allowed_=false, udp_allowed_=false;
        ServerStatus status_=ServerStatus::reading;
        std::optional<TcpRequest> request_;
        std::optional<UserId> mux_user_;
        explicit ServerHandshake(std::vector<UserId> users, bool vision);
    public:
        [[nodiscard]] static auto create(std::span<UserId const> users) -> std::expected<ServerHandshake,std::string>;
        // Opt in only when the caller implements Vision over an authenticated
        // transport. A successful handshake requires the Vision addon.
        [[nodiscard]] static auto create_vision(std::span<UserId const> users) -> std::expected<ServerHandshake,std::string>;
        // Call before feeding bytes only when the owner implements the Mux stream.
        [[nodiscard]] auto allow_mux() noexcept -> bool;
        [[nodiscard]] auto allow_udp() noexcept -> bool;
        [[nodiscard]] auto feed(std::span<std::uint8_t const> bytes) -> ServerStep;
        // Borrowed until failed dialing or destruction; available after authentication.
        [[nodiscard]] auto request() const noexcept -> TcpRequest const*;
        [[nodiscard]] auto mux_user() const noexcept -> UserId const*;
        [[nodiscard]] auto complete_dial(bool connected) -> std::optional<std::array<std::uint8_t,2>>;
        [[nodiscard]] auto status() const noexcept -> ServerStatus { return status_; }
        [[nodiscard]] auto is_vision() const noexcept -> bool { return vision_; }
    };
}
