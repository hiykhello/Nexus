#include <openssl/aead.h>
#include <openssl/sha.h>
#include <array>
#include <algorithm>
#include <cstdint>
#include <iostream>
int main() {
    constexpr std::array<std::uint8_t,32> expected_sha{
        0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,
        0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad};
    constexpr std::array<std::uint8_t,16> expected_tag{
        0x58,0xe2,0xfc,0xce,0xfa,0x7e,0x30,0x61,0x36,0x7f,0x1d,0x57,0xa4,0xe7,0x45,0x5a};
    std::array<std::uint8_t,32> digest{};
    std::array<std::uint8_t,16> key{}, ciphertext{};
    std::array<std::uint8_t,12> nonce{};
    const std::uint8_t message[]{'a','b','c'};
    if (!SHA256(message,sizeof(message),digest.data()) || digest!=expected_sha) return 1;
    EVP_AEAD_CTX context;
    if (!EVP_AEAD_CTX_init(&context,EVP_aead_aes_128_gcm(),key.data(),key.size(),16,nullptr)) return 1;
    std::size_t length=0;
    auto sealed=EVP_AEAD_CTX_seal(&context,ciphertext.data(),&length,ciphertext.size(),nonce.data(),nonce.size(),nullptr,0,nullptr,0);
    if (!sealed || length!=ciphertext.size() || ciphertext!=expected_tag) { EVP_AEAD_CTX_cleanup(&context); return 1; }
    std::array<std::uint8_t,1> plaintext{};
    auto opened=EVP_AEAD_CTX_open(&context,plaintext.data(),&length,plaintext.size(),nonce.data(),nonce.size(),ciphertext.data(),ciphertext.size(),nullptr,0);
    if (!opened || length) { EVP_AEAD_CTX_cleanup(&context); return 1; }
    ciphertext[0]^=1;
    auto tampered=EVP_AEAD_CTX_open(&context,plaintext.data(),&length,plaintext.size(),nonce.data(),nonce.size(),ciphertext.data(),ciphertext.size(),nullptr,0);
    EVP_AEAD_CTX_cleanup(&context);
    if (tampered) return 1;
    std::cout << "BoringSSL static libcrypto SHA-256 and AES-GCM known answers passed\n";
}
