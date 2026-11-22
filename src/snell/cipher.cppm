export module snell.cipher;
import std;
import snell.kdf;
import snell.record;
import crypto;
export namespace snell {
    // A direction owns exactly one derived key and its Record owns the nonce.
    class Cipher {
        Key key_;
        auto transform(bool encrypt,std::span<std::uint8_t const> nonce,View input) -> std::expected<Bytes,Error> {
            auto result=encrypt ? crypto::seal(crypto::Aead::aes_128_gcm,key_.view(),nonce,input)
                                : crypto::open(crypto::Aead::aes_128_gcm,key_.view(),nonce,input);
            if(!result) return std::unexpected(result.error()==crypto::Error::authentication_failed ? Error::authentication : Error::crypto_failure);
            return std::move(*result);
        }
    public:
        explicit Cipher(Key key):key_(std::move(key)){}
        Cipher(Cipher const&)=delete;auto operator=(Cipher const&) -> Cipher& =delete;
        Cipher(Cipher&&)=default;auto operator=(Cipher&&) -> Cipher& =default;
        auto seal(std::span<std::uint8_t const> nonce,View input) -> std::expected<Bytes,Error>{return transform(true,nonce,input);}
        auto open(std::span<std::uint8_t const> nonce,View input) -> std::expected<Bytes,Error>{return transform(false,nonce,input);}
    };
}
