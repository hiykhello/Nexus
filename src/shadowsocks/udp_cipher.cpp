module shadowsocks.udp_cipher;
import std;
import crypto;
import shadowsocks.key;
import shadowsocks.identity;

namespace shadowsocks {
    namespace {
        constexpr std::size_t max_packet=65535;
        auto algorithm(std::size_t size) -> crypto::Aead {
            return size==16 ? crypto::Aead::aes_128_gcm : crypto::Aead::aes_256_gcm;
        }
        auto decrypt_error(crypto::Error error) noexcept -> UdpCipherError {
            return error==crypto::Error::authentication_failed ? UdpCipherError::authentication : UdpCipherError::crypto;
        }
    }
    auto seal_udp(std::span<std::uint8_t const> psk,std::span<std::uint8_t const,16> header,
                  std::span<std::uint8_t const> body,CipherMethod method,
                  std::span<std::array<std::uint8_t,32> const> identities) -> std::expected<std::vector<std::uint8_t>,UdpCipherError> {
        if (psk.size()!=32 && (psk.size()!=16 || method!=CipherMethod::aes)) return std::unexpected(UdpCipherError::invalid_key);
        if (identities.size()>8 || (!identities.empty() && method!=CipherMethod::aes))
            return std::unexpected(UdpCipherError::invalid_key);
        auto overhead=udp_cipher_overhead(method)+16*identities.size();
        if (body.size()>max_packet-overhead) return std::unexpected(UdpCipherError::invalid_length);
        if (method==CipherMethod::chacha20) {
            std::array<std::uint8_t,24> nonce;
            if (!crypto::random_bytes(nonce)) return std::unexpected(UdpCipherError::crypto);
            std::vector<std::uint8_t> plain;
            plain.reserve(header.size()+body.size());
            plain.insert(plain.end(),header.begin(),header.end());
            plain.insert(plain.end(),body.begin(),body.end());
            auto sealed=crypto::seal(crypto::Aead::xchacha20_poly1305,psk,nonce,plain);
            if (!sealed) return std::unexpected(UdpCipherError::crypto);
            std::vector<std::uint8_t> packet;
            packet.reserve(nonce.size()+sealed->size());
            packet.insert(packet.end(),nonce.begin(),nonce.end());
            packet.insert(packet.end(),sealed->begin(),sealed->end());
            return packet;
        }
        auto header_key=identities.empty() ? psk : std::span(identities.front()).first(psk.size());
        auto encrypted=transform_aes_block(header_key,header,true);
        auto key=SessionKey::derive_udp(psk,header.first<8>());
        if (!encrypted || !key) return std::unexpected(UdpCipherError::crypto);
        auto ciphertext=crypto::seal(algorithm(psk.size()),key->view(),header.subspan<4,12>(),body);
        if (!ciphertext) return std::unexpected(UdpCipherError::crypto);
        std::vector<std::uint8_t> packet;
        packet.reserve(overhead+body.size());
        packet.insert(packet.end(),encrypted->begin(),encrypted->end());
        for (std::size_t i=0;i<identities.size();++i) {
            auto next=i+1==identities.size() ? psk : std::span(identities[i+1]).first(psk.size());
            auto hash=identity_hash(next);
            for (std::size_t j=0;j<hash.size();++j) hash[j]^=header[j];
            auto block=transform_aes_block(std::span(identities[i]).first(psk.size()),hash,true);
            if (!block) return std::unexpected(UdpCipherError::crypto);
            packet.insert(packet.end(),block->begin(),block->end());
        }
        packet.insert(packet.end(),ciphertext->begin(),ciphertext->end());
        return packet;
    }
    auto open_udp(std::span<std::uint8_t const> psk,std::span<std::uint8_t const> packet,CipherMethod method)
        -> std::expected<UdpPlaintext,UdpCipherError> {
        if (psk.size()!=32 && (psk.size()!=16 || method!=CipherMethod::aes)) return std::unexpected(UdpCipherError::invalid_key);
        if (packet.size()<udp_cipher_overhead(method) || packet.size()>max_packet)
            return std::unexpected(UdpCipherError::invalid_length);
        if (method==CipherMethod::chacha20) {
            auto plain=crypto::open(crypto::Aead::xchacha20_poly1305,psk,packet.first<24>(),packet.subspan<24>());
            if (!plain) return std::unexpected(decrypt_error(plain.error()));
            UdpPlaintext result;
            std::copy_n(plain->begin(),result.separate_header.size(),result.separate_header.begin());
            result.body.assign(plain->begin()+result.separate_header.size(),plain->end());
            return result;
        }
        auto header=transform_aes_block(psk,packet.first<16>(),false);
        if (!header) return std::unexpected(UdpCipherError::crypto);
        return open_udp_aes_body(psk,*header,packet.subspan(16));
    }
    auto open_udp_aes_body(std::span<std::uint8_t const> psk,
        std::array<std::uint8_t,16> header,std::span<std::uint8_t const> ciphertext)
        -> std::expected<UdpPlaintext,UdpCipherError> {
        if (psk.size()!=16 && psk.size()!=32) return std::unexpected(UdpCipherError::invalid_key);
        if (ciphertext.size()<16 || ciphertext.size()>max_packet-header.size())
            return std::unexpected(UdpCipherError::invalid_length);
        auto view=std::span<std::uint8_t const,16>{header};
        auto key=SessionKey::derive_udp(psk,view.first<8>());
        if (!key) return std::unexpected(UdpCipherError::crypto);
        auto body=crypto::open(algorithm(psk.size()),key->view(),view.subspan<4,12>(),ciphertext);
        if (!body) return std::unexpected(decrypt_error(body.error()));
        return UdpPlaintext{header,std::move(*body)};
    }
}
