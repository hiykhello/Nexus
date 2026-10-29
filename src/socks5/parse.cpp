module nexus.socks5;
import std;

namespace nexus::socks5 {
    auto parse_greeting(std::span<std::uint8_t const> input, std::uint8_t method) noexcept -> Greeting {
        if (input.empty()) return {};
        if (input[0] != 5) return {Status::invalid_version, 1};
        if (input.size() < 2) return {};
        auto const length = std::size_t{2} + input[1];
        if (input.size() < length) return {};
        auto const methods = input.subspan(2, input[1]);
        auto const found = std::find(methods.begin(), methods.end(), method) != methods.end();
        return {found ? Status::accepted : Status::no_acceptable_method, length};
    }

    auto parse_request(std::span<std::uint8_t const> input, bool allow_udp) noexcept -> Request {
        Request result;
        if (input.empty()) return result;
        if (input[0] != 5) {
            result.status = Status::invalid_version;
            result.consumed = 1;
            return result;
        }
        if (input.size() < 4) return result;
        result.consumed = 4;
        if (input[2] != 0) {
            result.status = Status::invalid_reserved;
            return result;
        }
        if (input[1] != 1 && !(allow_udp && input[1] == 3)) {
            result.status = Status::unsupported_command;
            return result;
        }
        result.command = input[1];
        result.address_type = input[3];
        std::size_t offset = 4;
        std::size_t address_length = 0;
        switch (result.address_type) {
        case 1: address_length = 4; break;
        case 4: address_length = 16; break;
        case 3:
            if (input.size() < 5) return {};
            address_length = input[4];
            offset = 5;
            if (address_length == 0) {
                result.status = Status::invalid_address;
                result.consumed = 5;
                return result;
            }
            break;
        default:
            result.status = Status::unsupported_address;
            return result;
        }
        auto const length = offset + address_length + 2;
        if (input.size() < length) return {};
        std::copy_n(input.begin() + offset, address_length, result.address.begin());
        result.address_length = static_cast<std::uint8_t>(address_length);
        result.port = static_cast<std::uint16_t>((std::uint16_t{input[length - 2]} << 8) | input[length - 1]);
        result.status = Status::accepted;
        result.consumed = length;
        return result;
    }

    auto parse_udp_datagram(std::span<std::uint8_t const> input) noexcept -> std::expected<UdpDatagram, Status> {
        if (input.size() < 4) return std::unexpected(Status::incomplete);
        if (input[0] || input[1]) return std::unexpected(Status::invalid_reserved);
        if (input[2]) return std::unexpected(Status::unsupported_fragment);
        UdpDatagram result;
        result.address_type=input[3];
        std::size_t offset=4, length=0;
        switch (result.address_type) {
        case 1: length=4; break;
        case 4: length=16; break;
        case 3:
            if (input.size()<5) return std::unexpected(Status::incomplete);
            length=input[offset++];
            if (!length) return std::unexpected(Status::invalid_address);
            break;
        default: return std::unexpected(Status::unsupported_address);
        }
        if (input.size()-offset < length+2) return std::unexpected(Status::incomplete);
        std::copy_n(input.begin()+offset,length,result.address.begin());
        result.address_length=static_cast<std::uint8_t>(length);
        offset+=length;
        result.port=static_cast<std::uint16_t>((std::uint16_t{input[offset]}<<8)|input[offset+1]);
        result.data=input.subspan(offset+2);
        return result;
    }

    auto encode_udp_datagram(UdpDatagram const& packet) -> std::expected<std::vector<std::uint8_t>, Status> {
        switch (packet.address_type) {
        case 1: if (packet.address_length!=4) return std::unexpected(Status::invalid_address); break;
        case 4: if (packet.address_length!=16) return std::unexpected(Status::invalid_address); break;
        case 3: if (!packet.address_length) return std::unexpected(Status::invalid_address); break;
        default: return std::unexpected(Status::unsupported_address);
        }
        std::vector<std::uint8_t> result;
        auto header=std::size_t{6}+packet.address_length+(packet.address_type==3 ? 1 : 0);
        if (packet.data.size()>result.max_size()-header) return std::unexpected(Status::too_large);
        result.reserve(header+packet.data.size());
        result.insert(result.end(),{0,0,0,packet.address_type});
        if (packet.address_type==3) result.push_back(packet.address_length);
        result.insert(result.end(),packet.address.begin(),packet.address.begin()+packet.address_length);
        result.push_back(static_cast<std::uint8_t>(packet.port>>8));
        result.push_back(static_cast<std::uint8_t>(packet.port));
        result.insert(result.end(),packet.data.begin(),packet.data.end());
        return result;
    }

    namespace {
        auto valid_peer(UdpPeer const& peer) noexcept -> bool {
            if (peer.address_type==4) return true;
            return peer.address_type==1 && std::ranges::all_of(std::span(peer.address).subspan(4), [](auto byte) { return byte==0; });
        }
        auto unspecified(UdpPeer const& peer) noexcept -> bool {
            return std::ranges::all_of(peer.address, [](auto byte) { return byte==0; });
        }
    }
    auto UdpAssociation::create(UdpPeer tcp_peer, UdpPeer hint) noexcept -> std::expected<UdpAssociation,Status> {
        if (!valid_peer(tcp_peer) || !valid_peer(hint) || unspecified(tcp_peer)) return std::unexpected(Status::invalid_address);
        if (!unspecified(hint) && (hint.address_type!=tcp_peer.address_type || hint.address!=tcp_peer.address))
            return std::unexpected(Status::unauthorized_source);
        tcp_peer.port=hint.port;
        return UdpAssociation(tcp_peer);
    }
    auto UdpAssociation::admit(UdpPeer source, std::span<std::uint8_t const> input) noexcept -> std::expected<UdpDatagram,Status> {
        if (closed_) return std::unexpected(Status::association_closed);
        if (!valid_peer(source) || !source.port || source.address_type!=peer_.address_type || source.address!=peer_.address ||
            (peer_.port && source.port!=peer_.port)) return std::unexpected(Status::unauthorized_source);
        auto packet=parse_udp_datagram(input);
        if (!packet) return std::unexpected(packet.error());
        if (!peer_.port) peer_.port=source.port;
        return packet;
    }
    auto UdpAssociation::begin_send(UdpPeer target) noexcept -> std::expected<std::uint64_t,Status> {
        if (closed_) return std::unexpected(Status::association_closed);
        if (!valid_peer(target) || unspecified(target) || !target.port) return std::unexpected(Status::invalid_address);
        auto end=targets_.begin()+target_count_;
        auto it=std::find_if(targets_.begin(),end,[&](auto const& item) { return item.peer==target; });
        if (it!=end && it->pending) return std::unexpected(Status::send_in_progress);
        if (it==end && target_count_==targets_.size()) return std::unexpected(Status::target_capacity);
        if (!next_token_) return std::unexpected(Status::token_exhausted);
        if (it==end) { it=targets_.begin()+target_count_++; *it=Target{target}; }
        it->pending=next_token_++;
        return it->pending;
    }
    auto UdpAssociation::finish_send(std::uint64_t token, bool success) noexcept -> std::expected<void,Status> {
        if (closed_) return std::unexpected(Status::association_closed);
        auto end=targets_.begin()+target_count_;
        auto it=std::find_if(targets_.begin(),end,[&](auto const& item) { return token && item.pending==token; });
        if (it==end) return std::unexpected(Status::stale_send);
        it->pending=0;
        if (success) it->confirmed=true;
        else if (!it->confirmed) { *it=targets_[--target_count_]; targets_[target_count_]=Target{}; }
        return {};
    }
    auto UdpAssociation::accepts_reply(UdpPeer source) const noexcept -> bool {
        if (closed_) return false;
        auto end=targets_.begin()+target_count_;
        return std::find_if(targets_.begin(),end,[&](auto const& item) { return item.confirmed && item.peer==source; })!=end;
    }
}
