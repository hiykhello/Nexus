export module ssh.crypto;
import std;
import crypto;
import ssh.wire;

export namespace ssh {
    enum class CipherKind { none, chacha20_poly1305, aes256_gcm, aes128_gcm };
    enum class KeyKind { ed25519, ecdsa_p256 };

    [[nodiscard]] inline auto parse_cipher_kind(std::string_view name) noexcept -> std::optional<CipherKind> {
        if (name == "chacha20-poly1305@openssh.com") return CipherKind::chacha20_poly1305;
        if (name == "aes256-gcm@openssh.com") return CipherKind::aes256_gcm;
        if (name == "aes128-gcm@openssh.com") return CipherKind::aes128_gcm;
        return {};
    }

    [[nodiscard]] inline auto cipher_key_bytes(CipherKind k) noexcept -> std::size_t {
        switch (k) {
        case CipherKind::none: return 0;
        case CipherKind::aes128_gcm: return 16;
        case CipherKind::aes256_gcm: return 32;
        case CipherKind::chacha20_poly1305: return 64;
        }
        return 0;
    }

    [[nodiscard]] inline auto cipher_iv_bytes(CipherKind k) noexcept -> std::size_t {
        return (k == CipherKind::aes128_gcm || k == CipherKind::aes256_gcm) ? 12 : 0;
    }

    struct PrivateKey {
        KeyKind kind = KeyKind::ed25519;
        std::vector<std::uint8_t> pub_blob;
        std::vector<std::uint8_t> secret_raw; // 64B Ed25519 key or <=32B P-256 scalar
        PrivateKey() = default;
        ~PrivateKey();
        PrivateKey(PrivateKey const&) = delete;
        auto operator=(PrivateKey const&) -> PrivateKey& = delete;
        PrivateKey(PrivateKey&&) noexcept = default;
        auto operator=(PrivateKey&& other) noexcept -> PrivateKey&;

        [[nodiscard]] static auto parse(std::string_view pem) -> std::expected<PrivateKey, std::string>;
        [[nodiscard]] auto algorithm() const noexcept -> std::string_view {
            return kind == KeyKind::ed25519 ? "ssh-ed25519" : "ecdsa-sha2-nistp256";
        }
        [[nodiscard]] auto public_key_blob() const noexcept -> std::span<std::uint8_t const> { return pub_blob; }
        [[nodiscard]] auto sign(std::span<std::uint8_t const> msg) const -> std::expected<std::vector<std::uint8_t>, std::string>;
    };

    [[nodiscard]] auto verify_host_key(
        std::span<std::uint8_t const> host_key_blob,
        std::span<std::array<std::uint8_t, 32> const> allowed_pins,
        std::span<std::uint8_t const> exchange_hash,
        std::span<std::uint8_t const> sig_blob) -> std::expected<void, std::string>;

    [[nodiscard]] auto compute_exchange_hash(
        std::string_view v_c, std::string_view v_s,
        std::span<std::uint8_t const> i_c, std::span<std::uint8_t const> i_s,
        std::span<std::uint8_t const> host_key_blob,
        std::span<std::uint8_t const> q_c, std::span<std::uint8_t const> q_s,
        std::span<std::uint8_t const> shared_k) -> std::expected<std::array<std::uint8_t, 32>, std::string>;

    [[nodiscard]] auto derive_key(
        std::span<std::uint8_t const> shared_k,
        std::span<std::uint8_t const> exchange_hash,
        char letter,
        std::span<std::uint8_t const> session_id,
        std::size_t out_len) -> std::expected<std::vector<std::uint8_t>, std::string>;

    class PacketCipher {
        CipherKind kind_ = CipherKind::none;
        std::array<std::uint8_t, 64> key_{};
        std::array<std::uint8_t, 12> iv_{};
        auto increment_iv() noexcept -> void;
    public:
        PacketCipher() = default;
        ~PacketCipher();
        PacketCipher(PacketCipher const&) = delete;
        auto operator=(PacketCipher const&) -> PacketCipher& = delete;
        PacketCipher(PacketCipher&&) noexcept = default;
        auto operator=(PacketCipher&&) noexcept -> PacketCipher& = default;

        auto activate(CipherKind kind, std::span<std::uint8_t const> key, std::span<std::uint8_t const> iv) -> bool;
        [[nodiscard]] auto kind() const noexcept -> CipherKind { return kind_; }
        [[nodiscard]] auto tag_bytes() const noexcept -> std::size_t { return kind_ == CipherKind::none ? 0 : 16; }
        [[nodiscard]] auto encrypt(std::uint32_t seqno, std::span<std::uint8_t const> payload)
            -> std::expected<std::vector<std::uint8_t>, std::string>;
        [[nodiscard]] auto decrypt_length(std::uint32_t seqno, std::span<std::uint8_t const, 4> raw_hdr) const
            -> std::expected<std::uint32_t, std::string>;
        [[nodiscard]] auto decrypt_body(std::uint32_t seqno, std::span<std::uint8_t const, 4> raw_hdr,
                                        std::span<std::uint8_t const> rest)
            -> std::expected<std::vector<std::uint8_t>, std::string>;
    };
}
