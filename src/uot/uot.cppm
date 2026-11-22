export module uot;
export import net.datagram_frame;
import std;

export namespace uot {
    inline constexpr std::string_view v1_destination="sp.udp-over-tcp.arpa";
    inline constexpr std::string_view v2_destination="sp.v2.udp-over-tcp.arpa";
    using Family=net::ProxyAddressFamily;
    using Address=net::ProxyAddress;
    using Status=net::DatagramStatus;
    using PacketResult=net::DatagramResult;
    using FeedResult=net::DatagramFeed;
    struct Request { bool connected=false; Address destination{}; };
    struct RequestResult { Status status=Status::incomplete; std::size_t consumed=0; Request request{}; };
    auto encode_request(Request const&) -> std::expected<std::vector<std::uint8_t>,Status>;
    auto parse_request(std::span<std::uint8_t const>) noexcept -> RequestResult;
    inline auto encode_packet(bool connected,Address const& address,std::span<std::uint8_t const> payload)
        -> std::expected<std::vector<std::uint8_t>,Status> {
        return net::encode_datagram({net::AddressWire::uot,connected,false},address,payload);
    }
    inline auto parse_packet(bool connected,Address const& address,std::span<std::uint8_t const> input) noexcept -> PacketResult {
        return net::parse_datagram({net::AddressWire::uot,connected,false},address,input);
    }
    // Request framing is specific to UoT v2. The packet decoder shares the
    // bounded frame core while retaining UoT's distinct address family bytes.
    class RequestDecoder {
        std::array<std::uint8_t,260> input_{};
        std::size_t size_=0;
        Status status_=Status::incomplete;
        Request request_{};
    public:
        auto feed(std::span<std::uint8_t const>) noexcept -> FeedResult;
        auto request() const noexcept -> std::optional<Request>;
        auto close() noexcept -> void;
    };
    class PacketDecoder : public net::DatagramDecoder {
    public:
        explicit PacketDecoder(bool connected,Address destination={},std::size_t max_payload=65535) noexcept
            : net::DatagramDecoder({net::AddressWire::uot,connected,false},destination,max_payload) {}
    };
}
