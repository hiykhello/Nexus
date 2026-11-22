module hysteria2.wire;
import std;
import quic.varint;

namespace hysteria2 {
    auto encode_tcp_request(std::string_view address,std::span<std::uint8_t const> padding)
        -> std::expected<std::vector<std::uint8_t>,WireStatus> {
        if (address.empty()) return std::unexpected(WireStatus::invalid_length);
        if (address.size()>max_address_bytes || padding.size()>max_padding_bytes) return std::unexpected(WireStatus::too_large);
        std::vector<std::uint8_t> output;
        output.reserve(2+quic::varint_size(address.size())+address.size()+quic::varint_size(padding.size())+padding.size());
        (void)quic::append_varint(output,tcp_request_type);
        (void)quic::append_varint(output,address.size());
        output.insert(output.end(),address.begin(),address.end());
        (void)quic::append_varint(output,padding.size());
        output.insert(output.end(),padding.begin(),padding.end());
        return output;
    }
    auto encode_tcp_response(TcpStatus status,std::string_view message,std::span<std::uint8_t const> padding)
        -> std::expected<std::vector<std::uint8_t>,WireStatus> {
        if (status!=TcpStatus::success && status!=TcpStatus::error) return std::unexpected(WireStatus::invalid_status);
        if (message.size()>max_message_bytes || padding.size()>max_padding_bytes) return std::unexpected(WireStatus::too_large);
        std::vector<std::uint8_t> output;
        output.reserve(1+quic::varint_size(message.size())+message.size()+quic::varint_size(padding.size())+padding.size());
        output.push_back(static_cast<std::uint8_t>(status));
        (void)quic::append_varint(output,message.size());
        output.insert(output.end(),message.begin(),message.end());
        (void)quic::append_varint(output,padding.size());
        output.insert(output.end(),padding.begin(),padding.end());
        return output;
    }

    template<TcpHeaderKind Kind>
    auto TcpHeaderDecoder<Kind>::feed(std::span<std::uint8_t const> input) noexcept -> WireFeed {
        if (status_!=WireStatus::incomplete) return {status_,0};
        std::size_t consumed=0;
        while (field_!=Field::done) {
            if (field_==Field::padding && !remaining_) { field_=Field::done; break; }
            if (consumed==input.size()) return {WireStatus::incomplete,consumed};
            if (field_==Field::tag && Kind==TcpHeaderKind::response) {
                auto byte=input[consumed++];
                if (byte>1) return fail(WireStatus::invalid_status,consumed);
                response_=static_cast<TcpStatus>(byte); field_=Field::length;
                continue;
            }
            if (field_==Field::tag || field_==Field::length || field_==Field::padding_length) {
                auto decoded=integer_.feed(input.subspan(consumed)); consumed+=decoded.consumed;
                if (decoded.status!=quic::VarintStatus::accepted) return {WireStatus::incomplete,consumed};
                integer_.reset();
                if (field_==Field::tag) {
                    if (decoded.value!=tcp_request_type) return fail(WireStatus::invalid_type,consumed);
                    field_=Field::length;
                } else if (field_==Field::length) {
                    if constexpr (Kind==TcpHeaderKind::request)
                        if (!decoded.value) return fail(WireStatus::invalid_length,consumed);
                    if (decoded.value>text_.size()) return fail(WireStatus::too_large,consumed);
                    remaining_=static_cast<std::size_t>(decoded.value);
                    field_=remaining_ ? Field::text : Field::padding_length;
                } else {
                    if (decoded.value>max_padding_bytes) return fail(WireStatus::too_large,consumed);
                    remaining_=static_cast<std::size_t>(decoded.value); field_=Field::padding;
                }
            } else {
                auto copied=std::min(remaining_,input.size()-consumed);
                if (field_==Field::text) {
                    std::copy_n(input.begin()+consumed,copied,text_.begin()+size_); size_+=copied;
                }
                consumed+=copied; remaining_-=copied;
                if (!remaining_) field_=field_==Field::text ? Field::padding_length : Field::done;
            }
        }
        status_=WireStatus::accepted; return {status_,consumed};
    }

    template auto TcpHeaderDecoder<TcpHeaderKind::request>::feed(std::span<std::uint8_t const>) noexcept -> WireFeed;
    template auto TcpHeaderDecoder<TcpHeaderKind::response>::feed(std::span<std::uint8_t const>) noexcept -> WireFeed;
}
