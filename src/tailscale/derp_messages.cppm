export module tailscale.derp_messages;
export import tailscale.derp;
import std;

export namespace tailscale::derp {
    using Nonce=std::array<std::uint8_t,nonce_size>;
    struct SealedInfo { Nonce nonce; std::span<std::uint8_t const> ciphertext; };
    struct ClientInfoEnvelope { Key node; SealedInfo sealed; };
    struct Packet { Key peer; std::span<std::uint8_t const> bytes; };
    struct ForwardedPacket { Key source,destination; std::span<std::uint8_t const> bytes; };
    struct PeerGone { Key peer; std::uint8_t reason=0; };
    struct PeerPresent {
        Key peer;
        std::optional<std::array<std::uint8_t,16>> address;
        std::uint16_t port=0;
        std::optional<std::uint8_t> flags;
        std::string_view app_name;
    };
    struct Restarting { std::chrono::milliseconds reconnect_in,try_for; };
    namespace detail {
        inline auto key_at(std::span<std::uint8_t const> input,std::size_t begin=0) noexcept -> Key {
            Key result; std::copy_n(input.begin()+begin,key_size,result.begin()); return result;
        }
        inline auto u32(std::span<std::uint8_t const> bytes) noexcept -> std::uint32_t {
            return (std::uint32_t(bytes[0])<<24)|(std::uint32_t(bytes[1])<<16)|(std::uint32_t(bytes[2])<<8)|bytes[3];
        }
        inline auto joined(Type type,std::initializer_list<std::span<std::uint8_t const>> parts)
            -> std::expected<std::vector<std::uint8_t>,Error> {
            std::size_t size=0;
            for (auto part:parts) {
                if (part.size()>payload_limit(type)-std::min(size,payload_limit(type))) return std::unexpected(Error::too_large);
                size+=part.size();
            }
            auto header=encode_header(type,size);
            if (!header) return std::unexpected(header.error());
            std::vector<std::uint8_t> result;
            result.reserve(header_size+size); result.insert(result.end(),header->begin(),header->end());
            for (auto part:parts) result.insert(result.end(),part.begin(),part.end());
            return result;
        }
    }
    inline auto parse_server_key(Frame frame) noexcept -> std::expected<Key,Error> {
        if (frame.type!=Type::server_key) return std::unexpected(Error::wrong_type);
        if (frame.payload.size()<magic.size()+key_size || !std::ranges::equal(frame.payload.first(magic.size()),magic))
            return std::unexpected(Error::invalid);
        return detail::key_at(frame.payload,magic.size());
    }
    // These are encrypted envelopes, not authenticated or parsed JSON. NaCl
    // verification must complete before any caller accepts an identity.
    inline auto parse_sealed_info(std::span<std::uint8_t const> payload) noexcept -> std::expected<SealedInfo,Error> {
        if (payload.size()<nonce_size+box_overhead) return std::unexpected(Error::invalid);
        if (payload.size()>max_frame_size) return std::unexpected(Error::too_large);
        SealedInfo result;
        std::copy_n(payload.begin(),nonce_size,result.nonce.begin());
        result.ciphertext=payload.subspan(nonce_size); return result;
    }
    inline auto parse_client_info(Frame frame) noexcept -> std::expected<ClientInfoEnvelope,Error> {
        if (frame.type!=Type::client_info) return std::unexpected(Error::wrong_type);
        if (frame.payload.size()<key_size || frame.payload.size()>max_client_info_size) return std::unexpected(Error::invalid);
        auto sealed=parse_sealed_info(frame.payload.subspan(key_size));
        if (!sealed) return std::unexpected(sealed.error());
        return ClientInfoEnvelope{detail::key_at(frame.payload),*sealed};
    }
    inline auto parse_server_info(Frame frame) noexcept -> std::expected<SealedInfo,Error> {
        if (frame.type!=Type::server_info) return std::unexpected(Error::wrong_type);
        return parse_sealed_info(frame.payload);
    }
    inline auto parse_packet(Frame frame,Type expected=Type::recv_packet) noexcept -> std::expected<Packet,Error> {
        if (expected!=Type::send_packet && expected!=Type::recv_packet) return std::unexpected(Error::wrong_type);
        if (frame.type!=expected) return std::unexpected(Error::wrong_type);
        if (frame.payload.size()<key_size) return std::unexpected(Error::invalid);
        if (frame.payload.size()-key_size>max_packet_size) return std::unexpected(Error::too_large);
        return Packet{detail::key_at(frame.payload),frame.payload.subspan(key_size)};
    }
    inline auto parse_forwarded_packet(Frame frame) noexcept -> std::expected<ForwardedPacket,Error> {
        if (frame.type!=Type::forward_packet) return std::unexpected(Error::wrong_type);
        if (frame.payload.size()<key_size*2) return std::unexpected(Error::invalid);
        if (frame.payload.size()-key_size*2>max_packet_size) return std::unexpected(Error::too_large);
        return ForwardedPacket{detail::key_at(frame.payload),detail::key_at(frame.payload,key_size),frame.payload.subspan(key_size*2)};
    }
    inline auto parse_peer_gone(Frame frame) noexcept -> std::expected<PeerGone,Error> {
        if (frame.type!=Type::peer_gone) return std::unexpected(Error::wrong_type);
        if (frame.payload.size()<key_size) return std::unexpected(Error::invalid);
        return PeerGone{detail::key_at(frame.payload),frame.payload.size()>key_size ? frame.payload[key_size] : std::uint8_t{0}};
    }
    inline auto valid_app_name(std::string_view text) noexcept -> bool {
        return text.size()<=32 && std::ranges::all_of(text,[](unsigned char c) { return c>=32 && c<=126; });
    }
    inline auto parse_peer_present(Frame frame) noexcept -> std::expected<PeerPresent,Error> {
        if (frame.type!=Type::peer_present) return std::unexpected(Error::wrong_type);
        if (frame.payload.size()<key_size) return std::unexpected(Error::invalid);
        PeerPresent result{detail::key_at(frame.payload)};
        auto rest=frame.payload.subspan(key_size);
        if (rest.size()<18) return result;
        result.address.emplace(); std::copy_n(rest.begin(),16,result.address->begin());
        result.port=static_cast<std::uint16_t>((std::uint16_t(rest[16])<<8)|rest[17]); rest=rest.subspan(18);
        if (rest.empty()) return result;
        result.flags=rest[0]; rest=rest.subspan(1);
        if (!rest.empty() && rest.size()-1>=rest[0]) {
            auto text=std::string_view(reinterpret_cast<char const*>(rest.data()+1),rest[0]);
            if (valid_app_name(text)) result.app_name=text;
        }
        return result;
    }
    inline auto parse_ping(Frame frame,Type expected=Type::ping) noexcept -> std::expected<std::array<std::uint8_t,8>,Error> {
        if ((expected!=Type::ping && expected!=Type::pong) || frame.type!=expected) return std::unexpected(Error::wrong_type);
        if (frame.payload.size()<8) return std::unexpected(Error::invalid);
        std::array<std::uint8_t,8> result; std::copy_n(frame.payload.begin(),8,result.begin()); return result;
    }
    inline auto parse_note_preferred(Frame frame) noexcept -> std::expected<bool,Error> {
        if (frame.type!=Type::note_preferred) return std::unexpected(Error::wrong_type);
        if (frame.payload.size()!=1) return std::unexpected(Error::invalid);
        return frame.payload[0]!=0;
    }
    inline auto parse_close_peer(Frame frame) noexcept -> std::expected<Key,Error> {
        if (frame.type!=Type::close_peer) return std::unexpected(Error::wrong_type);
        if (frame.payload.size()!=key_size) return std::unexpected(Error::invalid);
        return detail::key_at(frame.payload);
    }
    inline auto parse_restarting(Frame frame) noexcept -> std::expected<Restarting,Error> {
        if (frame.type!=Type::restarting) return std::unexpected(Error::wrong_type);
        if (frame.payload.size()<8) return std::unexpected(Error::invalid);
        return Restarting{std::chrono::milliseconds(detail::u32(frame.payload)),std::chrono::milliseconds(detail::u32(frame.payload.subspan(4)))};
    }
    inline auto encode_server_key(Key const& key,std::span<std::uint8_t const> extension={}) -> std::expected<std::vector<std::uint8_t>,Error> {
        return detail::joined(Type::server_key,{magic,key,extension});
    }
    inline auto encode_client_info(Key const& node,Nonce const& nonce,std::span<std::uint8_t const> ciphertext)
        -> std::expected<std::vector<std::uint8_t>,Error> {
        if (ciphertext.size()<box_overhead) return std::unexpected(Error::invalid);
        return detail::joined(Type::client_info,{node,nonce,ciphertext});
    }
    inline auto encode_server_info(Nonce const& nonce,std::span<std::uint8_t const> ciphertext)
        -> std::expected<std::vector<std::uint8_t>,Error> {
        if (ciphertext.size()<box_overhead) return std::unexpected(Error::invalid);
        return detail::joined(Type::server_info,{nonce,ciphertext});
    }
    inline auto encode_packet(Type type,Key const& peer,std::span<std::uint8_t const> bytes)
        -> std::expected<std::vector<std::uint8_t>,Error> {
        if (type!=Type::send_packet && type!=Type::recv_packet) return std::unexpected(Error::wrong_type);
        return detail::joined(type,{peer,bytes});
    }
    inline auto encode_forwarded_packet(Key const& source,Key const& destination,std::span<std::uint8_t const> bytes)
        -> std::expected<std::vector<std::uint8_t>,Error> { return detail::joined(Type::forward_packet,{source,destination,bytes}); }
    inline auto encode_peer_gone(Key const& peer,std::uint8_t reason) -> std::expected<std::vector<std::uint8_t>,Error> {
        return detail::joined(Type::peer_gone,{peer,std::span(&reason,1)});
    }
    inline auto encode_ping(Type type,std::array<std::uint8_t,8> const& token) -> std::expected<std::vector<std::uint8_t>,Error> {
        if (type!=Type::ping && type!=Type::pong) return std::unexpected(Error::wrong_type);
        return detail::joined(type,{token});
    }
    inline auto encode_note_preferred(bool value) -> std::expected<std::vector<std::uint8_t>,Error> {
        std::uint8_t flag=value ? 1 : 0; return detail::joined(Type::note_preferred,{std::span(&flag,1)});
    }
    inline auto encode_restarting(std::uint32_t reconnect_ms,std::uint32_t try_ms) -> std::expected<std::vector<std::uint8_t>,Error> {
        std::array<std::uint8_t,8> body{};
        for (unsigned i=0;i<4;++i) {
            body[i]=static_cast<std::uint8_t>(reconnect_ms>>(24-i*8)); body[i+4]=static_cast<std::uint8_t>(try_ms>>(24-i*8));
        }
        return detail::joined(Type::restarting,{body});
    }
}

