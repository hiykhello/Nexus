export module hysteria2.wire;
import std;
import quic.varint;

export namespace hysteria2 {
    inline constexpr std::uint64_t tcp_request_type=0x401;
    inline constexpr std::size_t max_address_bytes=2048,max_message_bytes=2048,max_padding_bytes=4096;
    enum class WireStatus { incomplete,accepted,invalid_type,invalid_status,invalid_length,too_large,truncated,closed };
    enum class TcpStatus : std::uint8_t { success=0,error=1 };
    struct WireFeed { WireStatus status=WireStatus::incomplete; std::size_t consumed=0; };
    struct TcpRequest { std::string_view address; };
    struct TcpResponse { TcpStatus status; std::string_view message; };

    [[nodiscard]] auto encode_tcp_request(std::string_view address,std::span<std::uint8_t const> padding={})
        -> std::expected<std::vector<std::uint8_t>,WireStatus>;
    [[nodiscard]] auto encode_tcp_response(TcpStatus status,std::string_view message={},std::span<std::uint8_t const> padding={})
        -> std::expected<std::vector<std::uint8_t>,WireStatus>;
    enum class TcpHeaderKind { request,response };
    // Only the protocol header is retained. Padding is skipped directly and
    // the application suffix stays in the caller's input. Address text is
    // preserved for the shared endpoint/routing parser; this codec does not
    // reinterpret hostnames, numeric addresses or routing metadata.
    template<TcpHeaderKind Kind>
    class TcpHeaderDecoder {
        enum class Field { tag,length,text,padding_length,padding,done,failed,closed };
        Field field_=Field::tag;
        quic::VarintDecoder integer_;
        std::array<char,max_address_bytes> text_{};
        std::size_t size_=0,remaining_=0;
        TcpStatus response_=TcpStatus::success;
        WireStatus status_=WireStatus::incomplete;
        auto fail(WireStatus status,std::size_t consumed) noexcept -> WireFeed {
            field_=Field::failed; status_=status; return {status,consumed};
        }
    public:
        TcpHeaderDecoder()=default;
        TcpHeaderDecoder(TcpHeaderDecoder const&)=delete;
        auto operator=(TcpHeaderDecoder const&) -> TcpHeaderDecoder& = delete;
        auto feed(std::span<std::uint8_t const> input) noexcept -> WireFeed;
        auto request() const noexcept -> std::optional<TcpRequest> requires (Kind==TcpHeaderKind::request) {
            if (status_!=WireStatus::accepted) return {};
            return TcpRequest{std::string_view(text_.data(),size_)};
        }
        auto response() const noexcept -> std::optional<TcpResponse> requires (Kind==TcpHeaderKind::response) {
            if (status_!=WireStatus::accepted) return {};
            return TcpResponse{response_,std::string_view(text_.data(),size_)};
        }
        auto finish() noexcept -> WireStatus {
            if (status_==WireStatus::incomplete) { field_=Field::failed; status_=WireStatus::truncated; }
            return status_;
        }
        auto close() noexcept -> void { field_=Field::closed; status_=WireStatus::closed; }
    };
    using TcpRequestDecoder=TcpHeaderDecoder<TcpHeaderKind::request>;
    using TcpResponseDecoder=TcpHeaderDecoder<TcpHeaderKind::response>;
}

