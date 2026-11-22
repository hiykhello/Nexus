export module net.datagram_frame;
import std;

export namespace net {
    enum class ProxyAddressFamily { ipv4, ipv6, domain };
    struct ProxyAddress {
        ProxyAddressFamily family=ProxyAddressFamily::ipv4;
        std::array<std::uint8_t,255> bytes{};
        std::uint8_t length=0;
        std::uint16_t port=0;
        auto operator==(ProxyAddress const&) const -> bool = default;
    };
    enum class DatagramStatus { incomplete, accepted, invalid_address, too_large, closed, invalid_frame };
    enum class AddressWire { socks, uot, packetaddr };
    struct AddressResult { DatagramStatus status=DatagramStatus::incomplete; std::size_t consumed=0; ProxyAddress address{}; };
    inline auto valid_proxy_address(ProxyAddress const& address) noexcept -> bool {
        switch (address.family) {
        case ProxyAddressFamily::ipv4: return address.length==4;
        case ProxyAddressFamily::ipv6: return address.length==16;
        case ProxyAddressFamily::domain: return address.length!=0;
        }
        return false;
    }
    inline auto address_tags(AddressWire wire) noexcept -> std::array<std::uint8_t,3> {
        if (wire==AddressWire::socks) return {1,4,3};
        if (wire==AddressWire::packetaddr) return {1,2,0xff};
        return {0,1,2};
    }
    inline auto append_proxy_address(std::vector<std::uint8_t>& output,ProxyAddress const& address,AddressWire wire) -> bool {
        if (!valid_proxy_address(address) || (wire==AddressWire::packetaddr && address.family==ProxyAddressFamily::domain))
            return false;
        auto tags=address_tags(wire);
        output.push_back(address.family==ProxyAddressFamily::ipv4 ? tags[0] : address.family==ProxyAddressFamily::ipv6 ? tags[1] : tags[2]);
        if (address.family==ProxyAddressFamily::domain) output.push_back(address.length);
        output.insert(output.end(),address.bytes.begin(),address.bytes.begin()+address.length);
        output.push_back(static_cast<std::uint8_t>(address.port>>8)); output.push_back(static_cast<std::uint8_t>(address.port));
        return true;
    }
    inline auto parse_proxy_address(std::span<std::uint8_t const> input,AddressWire wire) noexcept -> AddressResult {
        if (input.empty()) return {};
        auto tags=address_tags(wire);
        ProxyAddress address;
        std::size_t offset=1;
        if (input[0]==tags[0]) { address.family=ProxyAddressFamily::ipv4; address.length=4; }
        else if (input[0]==tags[1]) { address.family=ProxyAddressFamily::ipv6; address.length=16; }
        else if (wire!=AddressWire::packetaddr && input[0]==tags[2]) {
            address.family=ProxyAddressFamily::domain;
            if (input.size()<2) return {};
            address.length=input[1]; offset=2;
            if (!address.length) return {DatagramStatus::invalid_address};
        } else return {DatagramStatus::invalid_address};
        auto size=offset+address.length+2;
        if (input.size()<size) return {};
        std::copy_n(input.begin()+offset,address.length,address.bytes.begin());
        address.port=static_cast<std::uint16_t>((std::uint16_t(input[size-2])<<8)|input[size-1]);
        return {DatagramStatus::accepted,size,address};
    }
    struct DatagramFraming {
        AddressWire address=AddressWire::uot;
        bool connected=false,crlf=false;
        auto operator==(DatagramFraming const&) const -> bool = default;
    };
    enum class PacketTransportKind { none,framed,xudp };
    struct PacketTransport {
        PacketTransportKind kind=PacketTransportKind::none;
        DatagramFraming framing{};
        bool needs_uot_request=false;
    };
    struct DatagramResult {
        DatagramStatus status=DatagramStatus::incomplete;
        std::size_t consumed=0;
        ProxyAddress destination{};
        std::span<std::uint8_t const> payload{};
    };
    struct DatagramFeed { DatagramStatus status=DatagramStatus::incomplete; std::size_t consumed=0; };
    inline auto encode_datagram(DatagramFraming framing,ProxyAddress const& address,std::span<std::uint8_t const> payload)
        -> std::expected<std::vector<std::uint8_t>,DatagramStatus> {
        if (framing.address==AddressWire::packetaddr) {
            if (!valid_proxy_address(address) || address.family==ProxyAddressFamily::domain || !address.port)
                return std::unexpected(DatagramStatus::invalid_address);
            auto header_size=std::size_t{3}+address.length;
            if (payload.size()>65535-header_size) return std::unexpected(DatagramStatus::too_large);
            auto size=header_size+payload.size();
            std::vector<std::uint8_t> output;
            output.reserve(2+size);
            output.push_back(static_cast<std::uint8_t>(size>>8)); output.push_back(static_cast<std::uint8_t>(size));
            (void)append_proxy_address(output,address,framing.address);
            output.insert(output.end(),payload.begin(),payload.end());
            return output;
        }
        if ((!framing.connected && !valid_proxy_address(address))) return std::unexpected(DatagramStatus::invalid_address);
        if (payload.size()>65535) return std::unexpected(DatagramStatus::too_large);
        std::vector<std::uint8_t> output;
        output.reserve((framing.connected ? 0 : 4+address.length)+2+(framing.crlf ? 2 : 0)+payload.size());
        if (!framing.connected) (void)append_proxy_address(output,address,framing.address);
        output.push_back(static_cast<std::uint8_t>(payload.size()>>8)); output.push_back(static_cast<std::uint8_t>(payload.size()));
        if (framing.crlf) { output.push_back('\r'); output.push_back('\n'); }
        output.insert(output.end(),payload.begin(),payload.end());
        return output;
    }
    inline auto parse_datagram(DatagramFraming framing,ProxyAddress const& destination,std::span<std::uint8_t const> input) noexcept -> DatagramResult {
        std::size_t offset=0;
        auto target=destination;
        if (framing.address==AddressWire::packetaddr) {
            if (input.size()<2) return {};
            auto size=(std::size_t(input[0])<<8)|input[1];
            if (input.size()-2<size) return {};
            auto datagram=input.subspan(2,size);
            auto address=parse_proxy_address(datagram,framing.address);
            if (address.status!=DatagramStatus::accepted || !address.address.port)
                return {DatagramStatus::invalid_address};
            return {DatagramStatus::accepted,size+2,address.address,datagram.subspan(address.consumed)};
        }
        if (!framing.connected) {
            auto address=parse_proxy_address(input,framing.address);
            if (address.status!=DatagramStatus::accepted) return {address.status};
            target=address.address; offset=address.consumed;
        }
        if (input.size()-offset<(framing.crlf ? 4u : 2u)) return {};
        auto size=(std::size_t(input[offset])<<8)|input[offset+1]; offset+=2;
        if (framing.crlf) {
            if (input[offset]!='\r' || input[offset+1]!='\n') return {DatagramStatus::invalid_frame};
            offset+=2;
        }
        if (input.size()-offset<size) return {};
        return {DatagramStatus::accepted,offset+size,target,input.subspan(offset,size)};
    }
    // One retained datagram. Stop exactly at its boundary so the owner can
    // hold the borrowed packet under downstream backpressure.
    class DatagramDecoder {
        DatagramFraming framing_;
        ProxyAddress destination_;
        std::size_t max_payload_,header_size_=0,frame_size_=0;
        std::vector<std::uint8_t> input_;
        DatagramStatus failure_=DatagramStatus::incomplete;
        bool ready_=false,closed_=false;
    public:
        explicit DatagramDecoder(DatagramFraming framing,ProxyAddress destination={},std::size_t max_payload=65535) noexcept
            : framing_(framing),destination_(destination),max_payload_(std::min(max_payload,std::size_t{65535})) {}
        DatagramDecoder(DatagramDecoder const&)=delete;
        auto operator=(DatagramDecoder const&) -> DatagramDecoder& = delete;
        auto feed(std::span<std::uint8_t const> bytes) -> DatagramFeed {
            if (closed_) return {DatagramStatus::closed,0};
            if (failure_!=DatagramStatus::incomplete) return {failure_,0};
            if (ready_) return {DatagramStatus::accepted,0};
            std::size_t consumed=0;
            auto packetaddr=framing_.address==AddressWire::packetaddr;
            auto trailer=framing_.crlf && !packetaddr ? 4u : 2u;
            while (!header_size_) {
                if (framing_.connected || packetaddr) header_size_=trailer;
                else if (!input_.empty()) {
                    auto tags=address_tags(framing_.address);
                    if (input_[0]==tags[0]) header_size_=7+trailer;
                    else if (input_[0]==tags[1]) header_size_=19+trailer;
                    else if (input_[0]==tags[2] && input_.size()>=2) {
                        if (!input_[1]) { failure_=DatagramStatus::invalid_address; return {failure_,consumed}; }
                        header_size_=2+input_[1]+2+trailer;
                    } else if (input_[0]!=tags[2]) { failure_=DatagramStatus::invalid_address; return {failure_,consumed}; }
                }
                if (header_size_) break;
                if (consumed==bytes.size()) return {DatagramStatus::incomplete,consumed};
                input_.push_back(bytes[consumed++]);
            }
            auto copy=[&](std::size_t amount) {
                auto size=std::min(amount,bytes.size()-consumed);
                input_.insert(input_.end(),bytes.begin()+consumed,bytes.begin()+consumed+size); consumed+=size;
            };
            if (input_.size()<header_size_) copy(header_size_-input_.size());
            if (input_.size()<header_size_) return {DatagramStatus::incomplete,consumed};
            if (!frame_size_) {
                if (trailer==4 && (input_[header_size_-2]!='\r' || input_[header_size_-1]!='\n')) {
                    failure_=DatagramStatus::invalid_frame; return {failure_,consumed};
                }
                auto offset=header_size_-trailer;
                auto size=(std::size_t(input_[offset])<<8)|input_[offset+1];
                if (!packetaddr && size>max_payload_) { failure_=DatagramStatus::too_large; return {failure_,consumed}; }
                frame_size_=header_size_+size;
            }
            if (input_.size()<frame_size_) copy(frame_size_-input_.size());
            if (input_.size()<frame_size_) return {DatagramStatus::incomplete,consumed};
            auto parsed=parse_datagram(framing_,destination_,input_);
            if (parsed.status!=DatagramStatus::accepted || parsed.consumed!=input_.size()) {
                failure_=parsed.status==DatagramStatus::incomplete ? DatagramStatus::invalid_frame : parsed.status;
                return {failure_,consumed};
            }
            if (packetaddr && parsed.payload.size()>max_payload_) {
                failure_=DatagramStatus::too_large; return {failure_,consumed};
            }
            ready_=true; return {DatagramStatus::accepted,consumed};
        }
        auto packet() const noexcept -> std::optional<DatagramResult> {
            if (!ready_ || closed_) return {};
            return parse_datagram(framing_,destination_,input_);
        }
        auto consume() noexcept -> bool {
            if (!ready_ || closed_) return false;
            input_.clear(); header_size_=frame_size_=0; ready_=false; return true;
        }
        auto at_boundary() const noexcept -> bool { return !closed_ && failure_==DatagramStatus::incomplete && !ready_ && input_.empty(); }
        auto close() noexcept -> void { closed_=true; ready_=false; input_.clear(); }
    };
}
