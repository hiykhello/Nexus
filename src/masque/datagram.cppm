export module masque.datagram;
import std;
import quic.varint;

export namespace masque {
    // RFC 9297: only client-initiated bidirectional request streams can own
    // HTTP/3 Datagrams. The caller enforces SETTINGS and stream lifetime.
    inline constexpr std::uint64_t max_quarter_stream_id=(std::uint64_t{1}<<60)-1;
    inline constexpr std::size_t max_udp_payload=65527;
    enum class DatagramError { malformed,invalid_stream,buffer_too_small,payload_too_large };
    // Both views borrow their original input; the caller keeps it alive until
    // the last payload consumer finishes.
    struct Http3DatagramView {
        std::uint64_t stream_id=0;
        std::span<std::uint8_t const> payload;
    };
    struct ProxyDatagramView {
        std::uint64_t context_id=0;
        std::span<std::uint8_t const> payload;
    };
    // Malformed HTTP/3 prefix maps to H3_DATAGRAM_ERROR at the connection;
    // a nonzero context is returned intact for its extension or silent drop.
    // A context-zero UDP payload exceeding the RFC limit aborts its request
    // stream; it is not an HTTP/3 connection error.
    inline auto parse_http3_datagram(std::span<std::uint8_t const> input) noexcept -> std::expected<Http3DatagramView,DatagramError> {
        auto quarter=quic::read_varint(input);
        if(quarter.status!=quic::VarintStatus::accepted || quarter.value>max_quarter_stream_id)
            return std::unexpected(DatagramError::malformed);
        return Http3DatagramView{quarter.value*4,input.subspan(quarter.consumed)};
    }
    inline auto parse_proxy_datagram(std::span<std::uint8_t const> input,bool udp) noexcept -> std::expected<ProxyDatagramView,DatagramError> {
        auto context=quic::read_varint(input);
        if(context.status!=quic::VarintStatus::accepted)return std::unexpected(DatagramError::malformed);
        auto payload=input.subspan(context.consumed);
        if(udp && !context.value && payload.size()>max_udp_payload)return std::unexpected(DatagramError::payload_too_large);
        return ProxyDatagramView{context.value,payload};
    }
    // Writes only the prefix: callers own/retain the payload and must check
    // the native QUIC DATAGRAM capacity before committing the complete packet.
    inline auto write_http3_datagram_prefix(std::span<std::uint8_t> output,std::uint64_t stream_id) noexcept -> std::expected<std::size_t,DatagramError> {
        if(stream_id>quic::max_varint || (stream_id&3))return std::unexpected(DatagramError::invalid_stream);
        auto size=quic::write_varint(output,stream_id/4);
        if(!size)return std::unexpected(DatagramError::buffer_too_small);
        return *size;
    }
    inline auto write_proxy_datagram_prefix(std::span<std::uint8_t> output,std::uint64_t context_id,std::size_t payload_size,bool udp) noexcept -> std::expected<std::size_t,DatagramError> {
        if(context_id>quic::max_varint)return std::unexpected(DatagramError::malformed);
        if(udp && !context_id && payload_size>max_udp_payload)return std::unexpected(DatagramError::payload_too_large);
        auto size=quic::write_varint(output,context_id);
        if(!size)return std::unexpected(DatagramError::buffer_too_small);
        return *size;
    }
}
