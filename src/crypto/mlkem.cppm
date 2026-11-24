export module crypto.mlkem;
export import boringssl;
import std;
using namespace boringssl;

export namespace crypto {
    enum class MlkemError { invalid_key, invalid_ciphertext, invalid_state, backend_failure };
    class MlkemSecret {
        std::array<std::uint8_t,32> bytes_{};
        friend class Mlkem768Private;
        friend struct MlkemEncapsulation;
        friend auto mlkem768_encapsulate(std::span<std::uint8_t const>) -> std::expected<struct MlkemEncapsulation,MlkemError>;
    public:
        MlkemSecret() = default;
        ~MlkemSecret();
        MlkemSecret(MlkemSecret const&) = delete;
        auto operator=(MlkemSecret const&) -> MlkemSecret& = delete;
        MlkemSecret(MlkemSecret&&) noexcept;
        auto operator=(MlkemSecret&&) noexcept -> MlkemSecret&;
        [[nodiscard]] auto view() const noexcept -> std::span<std::uint8_t const,32> { return bytes_; }
    };
    struct MlkemEncapsulation { std::array<std::uint8_t,1088> ciphertext{}; MlkemSecret secret; };
    class Mlkem768Private {
        MLKEM768_private_key key_{};
        bool valid_ = true;
        Mlkem768Private() = default;
    public:
        ~Mlkem768Private();
        Mlkem768Private(Mlkem768Private const&) = delete;
        auto operator=(Mlkem768Private const&) -> Mlkem768Private& = delete;
        Mlkem768Private(Mlkem768Private&&) noexcept;
        auto operator=(Mlkem768Private&&) noexcept -> Mlkem768Private&;
        // Uses BoringSSL randomness; entropy failures may abort the process.
        [[nodiscard]] static auto generate() -> std::expected<Mlkem768Private,MlkemError>;
        // Seed is a 64-byte secret, encoded as FIPS 203 d || z. Caller owns and clears its copy.
        [[nodiscard]] static auto from_seed(std::span<std::uint8_t const> seed) -> std::expected<Mlkem768Private,MlkemError>;
        [[nodiscard]] auto public_key() const -> std::expected<std::array<std::uint8_t,1184>,MlkemError>;
        // Correct-length invalid ciphertexts produce an implicit-rejection secret, not an error.
        [[nodiscard]] auto decapsulate(std::span<std::uint8_t const> ciphertext) const -> std::expected<MlkemSecret,MlkemError>;
    };
    [[nodiscard]] auto mlkem768_encapsulate(std::span<std::uint8_t const> public_key) -> std::expected<MlkemEncapsulation,MlkemError>;
}
