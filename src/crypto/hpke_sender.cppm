module;
#include <openssl/hpke.h>

export module crypto.hpke_sender;
import std;

export namespace crypto {
    enum class HpkeAead : std::uint16_t { aes128 = 1, aes256 = 2, chacha20 = 3 };

    class HpkeSender {
        std::unique_ptr<EVP_HPKE_CTX, decltype(&EVP_HPKE_CTX_free)> context_{nullptr, EVP_HPKE_CTX_free};
        std::array<std::uint8_t,32> encapsulation_{};
    public:
        static constexpr std::size_t overhead = 16;

        [[nodiscard]] static auto create(HpkeAead suite, std::span<const std::uint8_t,32> recipient,
                                         std::span<const std::uint8_t> info) -> std::optional<HpkeSender> {
            auto aead = [suite] -> EVP_HPKE_AEAD const* {
                switch (suite) {
                    case HpkeAead::aes128: return EVP_hpke_aes_128_gcm();
                    case HpkeAead::aes256: return EVP_hpke_aes_256_gcm();
                    case HpkeAead::chacha20: return EVP_hpke_chacha20_poly1305();
                }
                return nullptr;
            }();
            if (!aead) return {};
            HpkeSender sender;
            sender.context_.reset(EVP_HPKE_CTX_new());
            std::size_t length = 0;
            if (!sender.context_ || !EVP_HPKE_CTX_setup_sender(sender.context_.get(), sender.encapsulation_.data(),
                    &length, sender.encapsulation_.size(), EVP_hpke_x25519_hkdf_sha256(), EVP_hpke_hkdf_sha256(),
                    aead, recipient.data(), recipient.size(), info.data(), info.size()) ||
                length != sender.encapsulation_.size()) return {};
            return sender;
        }

        [[nodiscard]] auto encapsulation() const noexcept -> std::span<const std::uint8_t,32> {
            return encapsulation_;
        }

        [[nodiscard]] auto seal(std::span<std::uint8_t> output, std::span<const std::uint8_t> plaintext,
                                std::span<const std::uint8_t> aad) -> bool {
            if (!context_ || output.size() < plaintext.size() || output.size() - plaintext.size() != overhead)
                return false;
            std::size_t length = 0;
            return EVP_HPKE_CTX_seal(context_.get(), output.data(), &length, output.size(), plaintext.data(),
                                     plaintext.size(), aad.data(), aad.size()) && length == output.size();
        }
    };
}
