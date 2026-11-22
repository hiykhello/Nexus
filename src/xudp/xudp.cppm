export module xudp;
import std;

export namespace xudp {
    // Xray-compatible UDP frames inside the VLESS Mux stream. Routing,
    // session allocation and reconnect semantics are owned by the caller.
    enum class Family { ipv4, domain, ipv6 };
    struct Address {
        Family family=Family::ipv4;
        std::array<std::uint8_t,255> bytes{};
        std::uint8_t length=0;
        std::uint16_t port=0;
        auto operator==(Address const&) const -> bool = default;
    };
    enum class Kind : std::uint8_t { open=1, data=2, end=3, keepalive=4 };
    enum class Status { incomplete, ready, invalid, too_large, closed };
    struct Frame {
        std::uint16_t session=0;
        Kind kind=Kind::data;
        bool has_data=false, error=false;
        std::optional<Address> address;
        std::optional<std::array<std::uint8_t,8>> global_id;
        std::span<std::uint8_t const> payload{};
    };
    struct Result { Status status=Status::incomplete; std::size_t consumed=0; Frame frame{}; };
    // Parsing borrows the input. Unknown metadata trailers are ignored as in
    // Xray's mux parser; limits keep malformed peers from forcing unbounded memory.
    [[nodiscard]] auto parse(std::span<std::uint8_t const>,std::size_t max_payload=65535) noexcept -> Result;
    [[nodiscard]] auto encode(Frame const&) -> std::expected<std::vector<std::uint8_t>,Status>;
    class Decoder {
        std::vector<std::uint8_t> bytes_;
        std::size_t max_payload_, frame_size_=0;
        Status status_=Status::incomplete;
    public:
        explicit Decoder(std::size_t max_payload=65535) noexcept : max_payload_(std::min(max_payload,std::size_t{65535})) {}
        Decoder(Decoder const&)=delete;
        auto operator=(Decoder const&) -> Decoder& = delete;
        [[nodiscard]] auto feed(std::span<std::uint8_t const>) -> Result;
        [[nodiscard]] auto frame() const noexcept -> std::optional<Frame>;
        [[nodiscard]] auto consume() noexcept -> bool;
        [[nodiscard]] auto at_boundary() const noexcept -> bool { return status_==Status::incomplete && bytes_.empty(); }
        auto close() noexcept -> void { status_=Status::closed; bytes_.clear(); }
    };
}
