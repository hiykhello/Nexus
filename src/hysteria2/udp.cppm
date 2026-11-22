export module hysteria2.udp;
import std;
import quic.varint;
import hysteria2.wire;

export namespace hysteria2 {
    inline constexpr std::size_t max_udp_payload=65535;
    enum class UdpError { truncated,invalid_address,invalid_fragment,too_large,too_many_fragments };
    struct UdpPacket {
        std::uint32_t session=0;
        std::uint16_t packet=0;
        std::uint8_t fragment=0,count=1;
        std::string_view address;
        std::span<std::uint8_t const> payload;
    };
    inline auto valid_fragment(std::uint8_t index,std::uint8_t count) noexcept -> bool {
        // Per the protocol, both IDs are irrelevant for an unfragmented
        // message. Do not require fragment=0 when count=1.
        return count==1 || (count>1 && index<count);
    }
    inline auto parse_udp_packet(std::span<std::uint8_t const> input) noexcept -> std::expected<UdpPacket,UdpError> {
        if (input.size()<9) return std::unexpected(UdpError::truncated);
        auto length=quic::read_varint(input.subspan(8));
        if (length.status!=quic::VarintStatus::accepted) return std::unexpected(UdpError::truncated);
        if (!length.value || length.value>max_address_bytes) return std::unexpected(UdpError::invalid_address);
        auto offset=8+length.consumed;
        if (length.value>input.size()-offset) return std::unexpected(UdpError::truncated);
        auto size=static_cast<std::size_t>(length.value);
        if (input.size()-offset-size>max_udp_payload) return std::unexpected(UdpError::too_large);
        if (!valid_fragment(input[6],input[7])) return std::unexpected(UdpError::invalid_fragment);
        std::uint32_t session=0;
        for (std::size_t i=0;i<4;++i) session=(session<<8)|input[i];
        return UdpPacket{session,static_cast<std::uint16_t>((std::uint16_t(input[4])<<8)|input[5]),input[6],input[7],
            {reinterpret_cast<char const*>(input.data()+offset),size},input.subspan(offset+size)};
    }
    inline auto write_udp_header(std::span<std::uint8_t> output,UdpPacket const& packet) noexcept -> std::expected<std::size_t,UdpError> {
        if (packet.address.empty() || packet.address.size()>max_address_bytes) return std::unexpected(UdpError::invalid_address);
        if (packet.payload.size()>max_udp_payload) return std::unexpected(UdpError::too_large);
        if (!valid_fragment(packet.fragment,packet.count)) return std::unexpected(UdpError::invalid_fragment);
        auto size=8+quic::varint_size(packet.address.size())+packet.address.size();
        if (output.size()<size) return std::unexpected(UdpError::too_large);
        for (unsigned i=0;i<4;++i) output[i]=static_cast<std::uint8_t>(packet.session>>(24-i*8));
        output[4]=static_cast<std::uint8_t>(packet.packet>>8);output[5]=static_cast<std::uint8_t>(packet.packet);
        output[6]=packet.fragment;output[7]=packet.count;
        auto length=*quic::write_varint(output.subspan(8),packet.address.size());
        std::ranges::copy(packet.address,output.begin()+8+length);return size;
    }
    inline auto encode_udp_packet(UdpPacket const& packet) -> std::expected<std::vector<std::uint8_t>,UdpError> {
        std::array<std::uint8_t,8+8+max_address_bytes> header{};
        auto size=write_udp_header(header,packet);if(!size)return std::unexpected(size.error());
        std::vector<std::uint8_t> output;output.reserve(*size+packet.payload.size());
        output.insert(output.end(),header.begin(),header.begin()+*size);output.insert(output.end(),packet.payload.begin(),packet.payload.end());
        return output;
    }
    // The owner keeps address and payload alive through every QUIC write.
    // Only the plan and per-fragment views are produced, with no payload copy.
    class FragmentPlan {
        UdpPacket packet_;
        std::size_t payload_bytes_=0;
    public:
        static auto create(std::uint32_t session,std::uint16_t id,std::string_view address,std::span<std::uint8_t const> payload,
            std::size_t datagram_bytes) noexcept -> std::expected<FragmentPlan,UdpError> {
            if (address.empty() || address.size()>max_address_bytes) return std::unexpected(UdpError::invalid_address);
            if (payload.size()>max_udp_payload) return std::unexpected(UdpError::too_large);
            auto header=8+quic::varint_size(address.size())+address.size();
            if (datagram_bytes<header || (datagram_bytes==header && !payload.empty())) return std::unexpected(UdpError::too_large);
            auto available=datagram_bytes-header;
            auto count=payload.empty() ? 1 : (payload.size()-1)/available+1;
            if (count>255) return std::unexpected(UdpError::too_many_fragments);
            FragmentPlan result;
            result.packet_={session,id,0,static_cast<std::uint8_t>(count),address,payload}; result.payload_bytes_=available;
            return result;
        }
        auto count() const noexcept -> std::size_t { return packet_.count; }
        auto fragment(std::size_t index) const noexcept -> std::optional<UdpPacket> {
            if (index>=packet_.count) return {};
            auto result=packet_;
            result.fragment=static_cast<std::uint8_t>(index);
            auto offset=index*payload_bytes_;
            result.payload=packet_.payload.subspan(offset,std::min(payload_bytes_,packet_.payload.size()-offset));
            return result;
        }
    };
}

