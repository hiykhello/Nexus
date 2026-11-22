module shadowsocks.udp_packet;
import std;
import shadowsocks.key;
import shadowsocks.udp_cipher;

namespace shadowsocks {
    namespace {
        auto length(std::span<std::uint8_t const> address) -> std::optional<std::size_t> {
            if (address.empty()) return {};
            std::size_t size=0;
            switch (address[0]) {
                case 1: size=7; break;
                case 4: size=19; break;
                case 3:
                    if (address.size()<2 || !address[1]) return {};
                    size=static_cast<std::size_t>(address[1])+4; break;
                default: return {};
            }
            return address.size()>=size ? std::optional{size} : std::nullopt;
        }
        auto store_u64(std::vector<std::uint8_t>& out,std::uint64_t value) -> void {
            for (int shift=56;shift>=0;shift-=8) out.push_back(static_cast<std::uint8_t>(value>>shift));
        }
        auto read_u64(std::span<std::uint8_t const,8> bytes) -> std::uint64_t {
            std::uint64_t value=0;
            for (auto byte:bytes) value=(value<<8)|byte;
            return value;
        }
        auto map(UdpCipherError error) -> UdpPacketError {
            switch (error) {
                case UdpCipherError::invalid_key: return UdpPacketError::invalid_key;
                case UdpCipherError::invalid_length: return UdpPacketError::invalid_length;
                case UdpCipherError::authentication: return UdpPacketError::authentication;
                case UdpCipherError::crypto: return UdpPacketError::crypto;
            }
            return UdpPacketError::crypto;
        }
    }
    auto encode_udp_packet(std::span<std::uint8_t const> psk,UdpDirection direction,UdpPacket const& packet,
                           std::span<std::uint8_t const> padding,CipherMethod method,
                           std::span<std::array<std::uint8_t,32> const> identities) -> std::expected<std::vector<std::uint8_t>,UdpPacketError> {
        auto address=length(packet.address);
        if (!address || *address!=packet.address.size()) return std::unexpected(UdpPacketError::invalid_address);
        auto server=direction==UdpDirection::server;
        if ((!server && packet.client_session) || (server && (!packet.client_session || *packet.client_session==packet.session_id)))
            return std::unexpected(UdpPacketError::invalid_session);
        if (identities.size()>8 || (!identities.empty() && (server || method!=CipherMethod::aes)))
            return std::unexpected(UdpPacketError::invalid_key);
        auto fixed=std::size_t{11}+(server ? 8 : 0);
        auto maximum=65535-udp_cipher_overhead(method)-16*identities.size();
        if (padding.size()>65535 || fixed+padding.size()+packet.address.size()>maximum ||
            packet.payload.size()>maximum-fixed-padding.size()-packet.address.size())
            return std::unexpected(UdpPacketError::invalid_length);
        std::vector<std::uint8_t> body; body.reserve(fixed+padding.size()+packet.address.size()+packet.payload.size());
        body.push_back(server ? 1 : 0); store_u64(body,packet.timestamp);
        if (server) body.insert(body.end(),packet.client_session->begin(),packet.client_session->end());
        body.push_back(static_cast<std::uint8_t>(padding.size()>>8)); body.push_back(static_cast<std::uint8_t>(padding.size()));
        body.insert(body.end(),padding.begin(),padding.end());
        body.insert(body.end(),packet.address.begin(),packet.address.end());
        body.insert(body.end(),packet.payload.begin(),packet.payload.end());
        std::array<std::uint8_t,16> header{};
        std::ranges::copy(packet.session_id,header.begin());
        for (std::size_t i=0;i<8;++i) header[8+i]=static_cast<std::uint8_t>(packet.packet_id>>(56-8*i));
        auto sealed=seal_udp(psk,header,body,method,identities);
        if (!sealed) return std::unexpected(map(sealed.error()));
        return *std::move(sealed);
    }
    namespace {
    auto decode_plaintext(UdpPlaintext const& plaintext,UdpDirection direction,
                          std::uint64_t now,std::optional<std::array<std::uint8_t,8>> expected_client)
        -> std::expected<UdpPacket,UdpPacketError> {
        auto server=direction==UdpDirection::server;
        if (server!=expected_client.has_value()) return std::unexpected(UdpPacketError::invalid_session);
        auto body=std::span<std::uint8_t const>{plaintext.body};
        auto fixed=std::size_t{11}+(server ? 8 : 0);
        if (body.size()<fixed) return std::unexpected(UdpPacketError::invalid_length);
        if (body[0]!=(server ? 1 : 0)) return std::unexpected(UdpPacketError::invalid_type);
        auto timestamp=read_u64(std::span<std::uint8_t const,8>{body.data()+1,8});
        if ((timestamp>now ? timestamp-now : now-timestamp)>30) return std::unexpected(UdpPacketError::invalid_timestamp);
        UdpPacket result;
        std::ranges::copy(std::span{plaintext.separate_header}.first<8>(),result.session_id.begin());
        result.packet_id=read_u64(std::span<std::uint8_t const,8>{plaintext.separate_header.data()+8,8});
        result.timestamp=timestamp;
        if (server) {
            std::array<std::uint8_t,8> client{}; std::ranges::copy(body.subspan(9,8),client.begin());
            if (client!=*expected_client) return std::unexpected(UdpPacketError::invalid_session);
            if (client==result.session_id) return std::unexpected(UdpPacketError::session_collision);
            result.client_session=client;
        }
        auto padding_offset=std::size_t{9}+(server ? 8 : 0);
        auto padding=(static_cast<std::size_t>(body[padding_offset])<<8)|body[padding_offset+1];
        if (padding>body.size()-fixed) return std::unexpected(UdpPacketError::invalid_length);
        auto remaining=body.subspan(fixed+padding);
        auto address=length(remaining);
        if (!address) return std::unexpected(UdpPacketError::invalid_address);
        result.address.assign(remaining.begin(),remaining.begin()+*address);
        result.payload.assign(remaining.begin()+*address,remaining.end());
        return result;
    }
    }
    auto decode_udp_packet(std::span<std::uint8_t const> psk,UdpDirection direction,std::span<std::uint8_t const> packet,
                           std::uint64_t now,std::optional<std::array<std::uint8_t,8>> expected_client,CipherMethod method)
        -> std::expected<UdpPacket,UdpPacketError> {
        if ((direction==UdpDirection::server)!=expected_client.has_value())
            return std::unexpected(UdpPacketError::invalid_session);
        auto plaintext=open_udp(psk,packet,method);
        if (!plaintext) return std::unexpected(map(plaintext.error()));
        return decode_plaintext(*plaintext,direction,now,expected_client);
    }
    auto decode_udp_identity_packet(std::span<std::uint8_t const> psk,std::array<std::uint8_t,16> header,
        std::span<std::uint8_t const> ciphertext,std::uint64_t now) -> std::expected<UdpPacket,UdpPacketError> {
        auto plaintext=open_udp_aes_body(psk,header,ciphertext);
        if (!plaintext) return std::unexpected(map(plaintext.error()));
        return decode_plaintext(*plaintext,UdpDirection::client,now,{});
    }
}
