module;
#include <openssl/aes.h>
module nexus.shadowsocks.udp_cipher;
import std;
import nexus.crypto;
import nexus.shadowsocks.key;

namespace nexus::shadowsocks {
    namespace {
        constexpr std::size_t max_packet=65535;
        auto block(std::span<std::uint8_t const> key, std::span<std::uint8_t const,16> input, bool encrypt)
            -> std::expected<std::array<std::uint8_t,16>,UdpCipherError> {
            if (key.size()!=16 && key.size()!=32) return std::unexpected(UdpCipherError::invalid_key);
            struct KeySchedule { AES_KEY key{}; ~KeySchedule() { crypto::cleanse(std::span{reinterpret_cast<std::uint8_t*>(&key),sizeof(key)}); } } schedule;
            auto bits=static_cast<unsigned>(key.size()*8);
            auto result=encrypt ? AES_set_encrypt_key(key.data(),bits,&schedule.key) : AES_set_decrypt_key(key.data(),bits,&schedule.key);
            if (result!=0) return std::unexpected(UdpCipherError::crypto);
            std::array<std::uint8_t,16> output{};
            if (encrypt) AES_encrypt(input.data(),output.data(),&schedule.key);
            else AES_decrypt(input.data(),output.data(),&schedule.key);
            return output;
        }
        auto algorithm(std::size_t size) -> crypto::Aead {
            return size==16 ? crypto::Aead::aes_128_gcm : crypto::Aead::aes_256_gcm;
        }
    }
    auto seal_udp(std::span<std::uint8_t const> psk,std::span<std::uint8_t const,16> header,
                  std::span<std::uint8_t const> body) -> std::expected<std::vector<std::uint8_t>,UdpCipherError> {
        if (psk.size()!=16 && psk.size()!=32) return std::unexpected(UdpCipherError::invalid_key);
        if (body.size()>max_packet-32) return std::unexpected(UdpCipherError::invalid_length);
        auto encrypted=block(psk,header,true);
        auto key=SessionKey::derive_udp(psk,header.first<8>());
        if (!encrypted || !key) return std::unexpected(UdpCipherError::crypto);
        auto ciphertext=crypto::seal(algorithm(psk.size()),key->view(),header.subspan<4,12>(),body);
        if (!ciphertext) return std::unexpected(UdpCipherError::crypto);
        std::vector<std::uint8_t> packet; packet.reserve(16+ciphertext->size());
        packet.insert(packet.end(),encrypted->begin(),encrypted->end());
        packet.insert(packet.end(),ciphertext->begin(),ciphertext->end());
        return packet;
    }
    auto open_udp(std::span<std::uint8_t const> psk,std::span<std::uint8_t const> packet)
        -> std::expected<UdpPlaintext,UdpCipherError> {
        if (psk.size()!=16 && psk.size()!=32) return std::unexpected(UdpCipherError::invalid_key);
        if (packet.size()<32 || packet.size()>max_packet) return std::unexpected(UdpCipherError::invalid_length);
        auto header=block(psk,packet.first<16>(),false);
        if (!header) return std::unexpected(header.error());
        auto view=std::span<std::uint8_t const,16>{*header};
        auto key=SessionKey::derive_udp(psk,view.first<8>());
        if (!key) return std::unexpected(UdpCipherError::crypto);
        auto body=crypto::open(algorithm(psk.size()),key->view(),view.subspan<4,12>(),packet.subspan(16));
        if (!body) return std::unexpected(body.error()==crypto::Error::authentication_failed ? UdpCipherError::authentication : UdpCipherError::crypto);
        return UdpPlaintext{*header,std::move(*body)};
    }
}
