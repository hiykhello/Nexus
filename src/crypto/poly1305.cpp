module crypto;
import std;
import boringssl;

namespace crypto {
    auto poly1305_to(std::span<std::uint8_t,16> tag,std::span<std::uint8_t const,32> key,
        std::span<std::uint8_t const> message) noexcept -> void {
        boringssl::poly1305_state state{};
        boringssl::CRYPTO_poly1305_init(&state,key.data());
        if (!message.empty()) boringssl::CRYPTO_poly1305_update(&state,message.data(),message.size());
        boringssl::CRYPTO_poly1305_finish(&state,tag.data());
        boringssl::OPENSSL_cleanse(state,sizeof(state));
    }
}
