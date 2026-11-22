module tls.handshake_secrets;
import std;

namespace tls {
    auto cipher_spec(std::uint16_t suite) noexcept -> std::expected<CipherSpec,crypto::Error> {
        switch (suite) {
        case 0x1301: return CipherSpec{crypto::Hash::sha256,crypto::Aead::aes_128_gcm,16};
        case 0x1302: return CipherSpec{crypto::Hash::sha384,crypto::Aead::aes_256_gcm,32};
        case 0x1303: return CipherSpec{crypto::Hash::sha256,crypto::Aead::chacha20_poly1305,32};
        default: return std::unexpected(crypto::Error::unsupported_algorithm);
        }
    }

}
