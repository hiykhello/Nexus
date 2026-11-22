export module tailscale.stun;
import std;
import net.udp_socket;

export namespace tailscale::stun {
    using Transaction=std::array<std::uint8_t,12>;
    using Endpoint=net::UdpEndpoint;
    inline constexpr std::size_t header_size=20;
    inline constexpr std::array<std::uint8_t,4> cookie{0x21,0x12,0xa4,0x42};
    inline constexpr std::string_view software="tailnode";
    enum class Error { incomplete,not_stun,wrong_type,invalid_length,invalid_attribute,invalid_address,
        wrong_transaction,missing_software,missing_fingerprint,invalid_fingerprint,conflicting_address };
    struct Message { std::uint16_t type; Transaction transaction; std::span<std::uint8_t const> attributes; std::size_t consumed; };
    struct Response { Transaction transaction; Endpoint mapped; std::size_t consumed; };
    struct EncodedResponse { std::array<std::uint8_t,44> bytes{}; std::size_t size=0; auto view() const noexcept { return std::span(bytes).first(size); } };
    namespace detail {
        inline auto u16(std::span<std::uint8_t const> bytes) noexcept -> std::uint16_t {
            return static_cast<std::uint16_t>((std::uint16_t(bytes[0])<<8)|bytes[1]);
        }
        inline auto u32(std::span<std::uint8_t const> bytes) noexcept -> std::uint32_t {
            return (std::uint32_t(bytes[0])<<24)|(std::uint32_t(bytes[1])<<16)|(std::uint32_t(bytes[2])<<8)|bytes[3];
        }
        inline auto write16(std::span<std::uint8_t> bytes,std::uint16_t value) noexcept -> void {
            bytes[0]=static_cast<std::uint8_t>(value>>8); bytes[1]=static_cast<std::uint8_t>(value);
        }
        inline auto write32(std::span<std::uint8_t> bytes,std::uint32_t value) noexcept -> void {
            for (unsigned i=0;i<4;++i) bytes[i]=static_cast<std::uint8_t>(value>>(24-i*8));
        }
        inline auto fingerprint(std::span<std::uint8_t const> bytes) noexcept -> std::uint32_t {
            std::uint32_t crc=0xffffffff;
            for (auto byte:bytes) {
                crc^=byte;
                for (unsigned bit=0;bit<8;++bit) crc=(crc>>1)^((crc&1) ? 0xedb88320 : 0);
            }
            return (~crc)^0x5354554e;
        }
        inline auto normalize(Endpoint peer) noexcept -> Endpoint {
            if (peer.family==6 && std::ranges::all_of(std::span(peer.address).first(10),[](auto byte) { return byte==0; }) &&
                peer.address[10]==0xff && peer.address[11]==0xff) {
                auto bytes=peer.address;
                peer.family=4; peer.address={}; std::copy_n(bytes.begin()+12,4,peer.address.begin());
            }
            return peer;
        }
        inline auto mapped(std::span<std::uint8_t const> attr,Transaction const& transaction,bool xored) noexcept -> std::expected<Endpoint,Error> {
            if (attr.size()<4) return std::unexpected(Error::invalid_attribute);
            auto size=attr[1]==1 ? 4u : attr[1]==2 ? 16u : 0u;
            if (!size || attr.size()<4+size) return std::unexpected(Error::invalid_address);
            Endpoint result{size==4 ? std::uint8_t{4} : std::uint8_t{6},{},u16(attr.subspan(2))};
            if (xored) result.port^=0x2112;
            for (unsigned i=0;i<size;++i) result.address[i]=attr[4+i]^(xored ? (i<4 ? cookie[i] : transaction[i-4]) : 0);
            return normalize(result);
        }
    }
    inline auto parse_message(std::span<std::uint8_t const> packet) noexcept -> std::expected<Message,Error> {
        if (packet.size()<header_size) return std::unexpected(Error::incomplete);
        if ((packet[0]&0xc0) || !std::ranges::equal(packet.subspan(4,4),cookie)) return std::unexpected(Error::not_stun);
        auto size=detail::u16(packet.subspan(2));
        if (size%4) return std::unexpected(Error::invalid_length);
        if (packet.size()-header_size<size) return std::unexpected(Error::incomplete);
        Message result{detail::u16(packet),{},packet.subspan(header_size,size),header_size+size};
        std::copy_n(packet.begin()+8,result.transaction.size(),result.transaction.begin()); return result;
    }
    // The fingerprint is checked when present. Response packets need not
    // contain one. Unknown attributes are skipped with their 32-bit padding.
    inline auto parse_response(std::span<std::uint8_t const> packet,std::optional<Transaction> expected={}) noexcept
        -> std::expected<Response,Error> {
        auto message=parse_message(packet);
        if (!message) return std::unexpected(message.error());
        if (message->type!=0x0101) return std::unexpected(Error::wrong_type);
        if (expected && message->transaction!=*expected) return std::unexpected(Error::wrong_transaction);
        std::optional<Endpoint> canonical,fallback;
        auto attributes=message->attributes;
        std::size_t offset=header_size;
        while (!attributes.empty()) {
            if (attributes.size()<4) return std::unexpected(Error::invalid_attribute);
            auto type=detail::u16(attributes),size=detail::u16(attributes.subspan(2));
            auto padded=(std::size_t(size)+3)&~std::size_t{3};
            if (padded>attributes.size()-4) return std::unexpected(Error::invalid_attribute);
            auto value=attributes.subspan(4,size);
            if (type==0x8028) {
                if (size!=4 || attributes.size()!=8 || detail::u32(value)!=detail::fingerprint(packet.first(offset)))
                    return std::unexpected(Error::invalid_fingerprint);
            } else if (type==0x0020 || type==0x8020 || type==0x0001) {
                auto address=detail::mapped(value,message->transaction,type!=0x0001);
                if (!address) return std::unexpected(address.error());
                auto& destination=type==0x0001 ? fallback : canonical;
                if (destination && *destination!=*address) return std::unexpected(Error::conflicting_address);
                destination=*address;
            }
            auto consumed=4+padded;
            offset+=consumed; attributes=attributes.subspan(consumed);
        }
        if (!canonical && !fallback) return std::unexpected(Error::invalid_address);
        return Response{message->transaction,canonical ? *canonical : *fallback,message->consumed};
    }
    inline auto parse_binding_request(std::span<std::uint8_t const> packet) noexcept -> std::expected<Transaction,Error> {
        auto message=parse_message(packet);
        if (!message) return std::unexpected(message.error());
        if (message->type!=0x0001) return std::unexpected(Error::wrong_type);
        if (message->consumed!=packet.size()) return std::unexpected(Error::invalid_length);
        auto attributes=message->attributes;
        bool software_seen=false,fingerprint_seen=false;
        std::size_t offset=header_size;
        while (!attributes.empty()) {
            if (attributes.size()<4) return std::unexpected(Error::invalid_attribute);
            auto type=detail::u16(attributes),size=detail::u16(attributes.subspan(2));
            auto padded=(std::size_t(size)+3)&~std::size_t{3};
            if (padded>attributes.size()-4) return std::unexpected(Error::invalid_attribute);
            auto value=attributes.subspan(4,size);
            if (type==0x8022 && size==software.size() &&
                std::ranges::equal(value,std::span(reinterpret_cast<std::uint8_t const*>(software.data()),software.size()))) software_seen=true;
            if (type==0x8028) {
                if (size!=4 || attributes.size()!=8 || detail::u32(value)!=detail::fingerprint(packet.first(offset)))
                    return std::unexpected(Error::invalid_fingerprint);
                fingerprint_seen=true;
            }
            auto consumed=4+padded; offset+=consumed; attributes=attributes.subspan(consumed);
        }
        if (!software_seen) return std::unexpected(Error::missing_software);
        if (!fingerprint_seen) return std::unexpected(Error::missing_fingerprint);
        return message->transaction;
    }
    inline auto encode_request(Transaction const& transaction) noexcept -> std::array<std::uint8_t,40> {
        std::array<std::uint8_t,40> result{};
        result[1]=1; result[3]=20; std::ranges::copy(cookie,result.begin()+4); std::ranges::copy(transaction,result.begin()+8);
        detail::write16(std::span(result).subspan(20),0x8022); detail::write16(std::span(result).subspan(22),8);
        std::copy_n(software.begin(),software.size(),result.begin()+24);
        detail::write16(std::span(result).subspan(32),0x8028); detail::write16(std::span(result).subspan(34),4);
        detail::write32(std::span(result).subspan(36),detail::fingerprint(std::span(result).first(32)));
        return result;
    }
    inline auto encode_response(Transaction const& transaction,Endpoint peer) noexcept -> std::expected<EncodedResponse,Error> {
        peer=detail::normalize(peer);
        auto size=peer.family==4 ? 4u : peer.family==6 ? 16u : 0u;
        if (!size) return std::unexpected(Error::invalid_address);
        EncodedResponse result; result.size=28+size;
        result.bytes[0]=1; result.bytes[1]=1; detail::write16(std::span(result.bytes).subspan(2),static_cast<std::uint16_t>(8+size));
        std::ranges::copy(cookie,result.bytes.begin()+4); std::ranges::copy(transaction,result.bytes.begin()+8);
        detail::write16(std::span(result.bytes).subspan(20),0x0020);
        detail::write16(std::span(result.bytes).subspan(22),static_cast<std::uint16_t>(4+size));
        result.bytes[25]=size==4 ? 1 : 2; detail::write16(std::span(result.bytes).subspan(26),peer.port^0x2112);
        for (unsigned i=0;i<size;++i) result.bytes[28+i]=peer.address[i]^(i<4 ? cookie[i] : transaction[i-4]);
        return result;
    }
}

