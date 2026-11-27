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

    struct ClientAuth {
        std::string user;
        std::optional<std::string> password;
        std::optional<PrivateKey> private_key;
        std::vector<std::array<std::uint8_t, 32>> host_key_sha256;
        std::string preferred_cipher;
        std::uint32_t keepalive_interval_ms = 30000;
        ClientAuth() = default;
        ClientAuth(ClientAuth&&) noexcept = default;
        auto operator=(ClientAuth&&) noexcept -> ClientAuth& = default;
        ~ClientAuth() {
            if (password && !password->empty())
                crypto::cleanse(std::span<std::uint8_t>(reinterpret_cast<std::uint8_t*>(password->data()), password->size()));
        }
    };

    [[nodiscard]] inline auto build_publickey_auth_request(
        std::span<std::uint8_t const> session_id, std::string_view user, PrivateKey const& pk)
        -> std::optional<std::vector<std::uint8_t>> {
        Writer sign_in, req;
        sign_in.string(session_id).byte(kMsgUserauthRequest).string(user).string("ssh-connection")
            .string("publickey").boolean(true).string(pk.algorithm()).string(pk.public_key_blob());
        auto sig = pk.sign(sign_in.buf);
        if (!sig) return std::nullopt;
        req.byte(kMsgUserauthRequest).string(user).string("ssh-connection")
            .string("publickey").boolean(true).string(pk.algorithm()).string(pk.public_key_blob()).string(*sig);
        return std::move(req.buf);
    }

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

    struct SessionKeys {
        CipherKind c_cs = CipherKind::none;
        CipherKind c_sc = CipherKind::none;
        std::array<std::uint8_t, 32> exchange_hash{};
        std::vector<std::uint8_t> iv_cs, iv_sc, k_cs, k_sc;
        SessionKeys() = default;
        ~SessionKeys();
        SessionKeys(SessionKeys const&) = delete;
        auto operator=(SessionKeys const&) -> SessionKeys& = delete;
        SessionKeys(SessionKeys&&) noexcept = default;
        auto operator=(SessionKeys&&) noexcept -> SessionKeys& = default;
    };

    struct KexNegotiation {
        CipherKind c_cs = CipherKind::none;
        CipherKind c_sc = CipherKind::none;
        bool strict_kex = false;
        bool skip_guessed_kex = false;
    };

    struct RekeyTracker {
        using Clock = std::chrono::steady_clock;
        std::uint32_t tx_pkts = 0, rx_pkts = 0;
        std::uint64_t tx_bytes = 0, rx_bytes = 0, count = 0;
        std::uint32_t limit_pkts = kMaxEncryptedPackets - 65536u;
        std::uint64_t limit_bytes = kMaxEncryptedBytes;
        std::chrono::milliseconds interval{std::chrono::hours(1)};
        std::chrono::milliseconds timeout{std::chrono::seconds(30)};
        Clock::time_point last_rekey{};

        [[nodiscard]] auto hard_bytes_limit() const noexcept -> std::uint64_t {
            constexpr std::uint64_t kHeadroom = 64ull << 20;
            auto base = std::max(kMaxEncryptedBytes, limit_bytes);
            return base > std::numeric_limits<std::uint64_t>::max() - kHeadroom
                ? std::numeric_limits<std::uint64_t>::max() : base + kHeadroom;
        }
        [[nodiscard]] auto time_due(Clock::time_point now) const noexcept -> bool {
            return interval.count() > 0 && (tx_pkts > 0 || rx_pkts > 0) &&
                last_rekey != Clock::time_point{} && (now - last_rekey >= interval);
        }
        [[nodiscard]] auto next_time_due() const noexcept -> std::optional<Clock::time_point> {
            if (interval.count() <= 0 || (tx_pkts == 0 && rx_pkts == 0) || last_rekey == Clock::time_point{})
                return std::nullopt;
            return last_rekey + interval;
        }
        [[nodiscard]] auto should_trigger_tx(bool active, std::size_t next_bytes, Clock::time_point now) const noexcept -> bool {
            if (!active) return false;
            if (tx_pkts >= limit_pkts || tx_bytes >= limit_bytes || time_due(now)) return true;
            return tx_bytes > 0 && limit_bytes > tx_bytes && next_bytes > limit_bytes - tx_bytes;
        }
        [[nodiscard]] auto should_trigger_rx(bool active, Clock::time_point now) const noexcept -> bool {
            if (!active) return false;
            return rx_pkts >= limit_pkts || rx_bytes >= limit_bytes || time_due(now);
        }
        [[nodiscard]] auto tx_hard_exceeded(std::size_t payload_bytes) const noexcept -> bool {
            auto hard = hard_bytes_limit();
            return tx_pkts >= kMaxEncryptedPackets || payload_bytes > hard - std::min(tx_bytes, hard);
        }
        [[nodiscard]] auto rx_hard_exceeded() const noexcept -> bool {
            return rx_pkts >= kMaxEncryptedPackets || rx_bytes >= hard_bytes_limit();
        }
        auto set_limits(std::uint64_t bytes, std::uint32_t pkts, std::chrono::milliseconds iv) noexcept -> void {
            limit_bytes = bytes ? bytes : kMaxEncryptedBytes;
            limit_pkts = pkts ? std::min(pkts, kMaxEncryptedPackets - 1u) : (kMaxEncryptedPackets - 65536u);
            interval = iv;
        }
        auto reset_tx() noexcept -> void { tx_pkts = 0; tx_bytes = 0; }
        auto reset_rx() noexcept -> void { rx_pkts = 0; rx_bytes = 0; }
    };

    [[nodiscard]] auto build_client_kexinit(std::string_view ciphers, bool include_strict_kex)
        -> std::optional<std::vector<std::uint8_t>>;

    [[nodiscard]] auto negotiate_client_kex(std::string_view ciphers, std::span<std::uint8_t const> server_kexinit)
        -> std::optional<KexNegotiation>;

    [[nodiscard]] auto finish_ecdh_kex(
        std::string_view v_c, std::string_view v_s,
        std::span<std::uint8_t const> i_c, std::span<std::uint8_t const> i_s,
        std::span<std::uint8_t const> q_c, crypto::X25519Private const& eph,
        std::span<std::uint8_t const> reply_payload,
        std::span<std::array<std::uint8_t, 32> const> allowed_pins,
        std::span<std::uint8_t const> existing_session_id,
        CipherKind c_cs, CipherKind c_sc) -> std::optional<SessionKeys>;

    class PacketCipher {
        CipherKind kind_ = CipherKind::none;
        std::array<std::uint8_t, 64> key_{};
        std::array<std::uint8_t, 12> iv_{};
        std::uint32_t packets_ = 0;
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
