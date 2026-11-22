module tls.handshake_policy;
import std;

namespace tls {
    auto offers_alpn(ClientHello const& hello,std::span<std::uint8_t const> required) noexcept -> bool {
        if (required.empty() || required.size()>255) return false;
        auto* extension=hello.extension(16);
        if (!extension || extension->data.size()<3) return false;
        auto const& bytes=extension->data;
        if (((std::size_t{bytes[0]}<<8)|bytes[1])!=bytes.size()-2) return false;
        bool match=false;
        for (std::size_t offset=2;offset<bytes.size();) {
            auto size=std::size_t(bytes[offset++]);
            if (!size || size>bytes.size()-offset) return false;
            match|=std::ranges::equal(std::span(bytes).subspan(offset,size),required); offset+=size;
        }
        return match;
    }
    auto validate_handshake_transport(ClientHello const& hello,HandshakeTransport transport) noexcept -> std::expected<void,HandshakePolicyError> {
        using E=HandshakePolicyError;
        if (transport==HandshakeTransport::tcp) {
            if (hello.extension(0x39)) return std::unexpected(E::unsupported_transport_parameters);
            return {};
        }
        if (!hello.session_id.empty()) return std::unexpected(E::invalid_session_id);
        if (!hello.extension(0x39)) return std::unexpected(E::missing_transport_parameters);
        return {};
    }

    auto encode_encrypted_extensions(std::span<std::uint8_t const> alpn,std::optional<std::span<std::uint8_t const>> quic_parameters)
        -> std::expected<std::vector<std::uint8_t>,HandshakePolicyError> {
        using E=HandshakePolicyError;
        if (alpn.size()>255 || (quic_parameters && alpn.empty())) return std::unexpected(E::invalid_alpn);
        auto extension_size=alpn.empty() ? std::size_t{0} : alpn.size()+7;
        if (quic_parameters) {
            if (quic_parameters->size()>65535-4-extension_size) return std::unexpected(E::too_large);
            extension_size+=4+quic_parameters->size();
        }
        std::vector<std::uint8_t> message(6+extension_size);
        auto put16=[&](std::size_t pos,std::size_t value) { message[pos]=static_cast<std::uint8_t>(value>>8); message[pos+1]=static_cast<std::uint8_t>(value); };
        auto body=extension_size+2;
        message[0]=8; message[1]=static_cast<std::uint8_t>(body>>16); message[2]=static_cast<std::uint8_t>(body>>8); message[3]=static_cast<std::uint8_t>(body);
        put16(4,extension_size); std::size_t offset=6;
        if (!alpn.empty()) {
            put16(offset,16); put16(offset+2,alpn.size()+3); put16(offset+4,alpn.size()+1); message[offset+6]=static_cast<std::uint8_t>(alpn.size());
            std::ranges::copy(alpn,message.begin()+offset+7); offset+=alpn.size()+7;
        }
        if (quic_parameters) {
            put16(offset,0x39); put16(offset+2,quic_parameters->size());
            std::ranges::copy(*quic_parameters,message.begin()+offset+4);
        }
        return message;
    }
}
