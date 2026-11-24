export module tls.ktls;
export import tls.client_flight;
export import tls.application_io;
export import tls.record;
export import crypto;
import std;

export namespace tls {
    enum class KtlsStatus {
        ok,
        unavailable,    // Kernel ULP/cipher unsupported before key handoff; safe user-space fallback.
        invalid_state,  // Preconditions failed (unread bytes, TLS 1.2, already installed, etc.).
        would_block,    // Non-blocking control record send hit EAGAIN/EWOULDBLOCK; retry when writable.
        fatal_error     // Failure after handoff or during active kTLS I/O; caller must close socket.
    };

    enum class KtlsDirection { tx, rx };

    enum class KtlsRecvKind {
        data,
        would_block,
        eof,
        close_notify,
        user_canceled,
        fatal_alert,
        key_update,
        key_update_requested,
        ticket_discarded,
        protocol_error,
        io_error
    };

    struct KtlsRecvResult {
        KtlsRecvKind kind = KtlsRecvKind::io_error;
        std::size_t bytes = 0;
        std::uint8_t alert_description = 0;
        int sys_errno = 0;
    };

    // Encoded kernel tls12_crypto_info_* blob (cleansed on destruction).
    struct KtlsCryptoBlob {
        std::array<std::uint8_t, 64> bytes{};
        std::size_t size = 0;
        KtlsCryptoBlob() = default;
        KtlsCryptoBlob(KtlsCryptoBlob const&) = delete;
        auto operator=(KtlsCryptoBlob const&) -> KtlsCryptoBlob& = delete;
        KtlsCryptoBlob(KtlsCryptoBlob&& other) noexcept : bytes(other.bytes), size(other.size) {
            crypto::cleanse(other.bytes); other.size = 0;
        }
        auto operator=(KtlsCryptoBlob&& other) noexcept -> KtlsCryptoBlob& {
            if (this != &other) {
                crypto::cleanse(bytes);
                bytes = other.bytes; size = other.size;
                crypto::cleanse(other.bytes); other.size = 0;
            }
            return *this;
        }
        ~KtlsCryptoBlob() { crypto::cleanse(bytes); size = 0; }
    };

    // Linux kernel kTLS version capability matrix (probed once via uname and cached).
    struct KtlsKernelSupport {
        int major = 0;
        int minor = 0;
        bool tx_aes_gcm = false;        // Linux >= 5.1 (TLS 1.3 AES-128/256-GCM TX)
        bool rx_tls13 = false;          // Linux >= 5.1 (TLS 1.3 RX)
        bool chacha20_poly1305 = false; // Linux >= 5.11 (TLS 1.3 ChaCha20-Poly1305)
        bool tx_zerocopy_ro = false;    // Linux >= 5.19 (TLS_TX_ZEROCOPY_RO)
        bool rx_expect_no_pad = false;  // Linux >= 6.0  (TLS_RX_EXPECT_NO_PAD)
        bool key_update = false;        // Linux >= 6.14 (TLS 1.3 in-kernel KeyUpdate)

        [[nodiscard]] constexpr auto supports_cipher(crypto::Aead aead) const noexcept -> bool {
            if (aead == crypto::Aead::aes_128_gcm || aead == crypto::Aead::aes_256_gcm) return tx_aes_gcm;
            if (aead == crypto::Aead::chacha20_poly1305) return chacha20_poly1305;
            return false;
        }
    };

    [[nodiscard]] auto parse_linux_kernel_release(std::string_view release) noexcept -> KtlsKernelSupport;
    [[nodiscard]] auto probe_ktls_kernel_support() noexcept -> KtlsKernelSupport;

    // Injectable POSIX kTLS ops (zero virtual functions) for deterministic kernel & unit tests.
    struct KtlsOps {
        int (*setsockopt_fn)(int fd, int level, int optname, void const* optval, std::size_t optlen) noexcept = nullptr;
        std::ptrdiff_t (*send_record_fn)(int fd, std::uint8_t record_type, std::uint8_t const* data, std::size_t len, int* err_out) noexcept = nullptr;
        std::ptrdiff_t (*recv_record_fn)(int fd, std::uint8_t* data, std::size_t cap, std::uint8_t* record_type_out, int* err_out) noexcept = nullptr;
        std::optional<KtlsKernelSupport> kernel_override{};
    };

    [[nodiscard]] auto default_ktls_ops() noexcept -> KtlsOps;

    // Builds exact Linux <linux/tls.h> TLS 1.3 crypto_info layout (AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305).
    [[nodiscard]] auto encode_ktls_crypto_info(KtlsKeyMaterial const& material) noexcept -> std::optional<KtlsCryptoBlob>;

    // Safe pre-probe: attaches TCP_ULP="tls" before any user-space keys are extracted.
    // Returns KtlsStatus::unavailable on ENOENT/ENOPROTOOPT/EOPNOTSUPP so user-space TLS stays intact.
    [[nodiscard]] auto probe_ktls_ulp(int fd, KtlsOps ops = default_ktls_ops()) noexcept -> KtlsStatus;

    // Owns per-direction kernel TLS 1.3 offload state, traffic secrets for KeyUpdate rekeying,
    // and strict control-message (TLS_GET_RECORD_TYPE / TLS_SET_RECORD_TYPE) enforcement.
    class KtlsSession {
        KtlsOps ops_;
        crypto::Aead algorithm_ = crypto::Aead::aes_128_gcm;
        crypto::Hash hash_ = crypto::Hash::sha256;
        std::optional<Secret> tx_secret_;
        std::optional<Secret> rx_secret_;
        bool ulp_attached_ = false;
        bool tx_active_ = false;
        bool rx_active_ = false;
        bool tx_closed_ = false;
        bool rx_closed_ = false;
        bool failed_ = false;
        bool key_update_supported_ = false;
        std::uint64_t tx_records_ = 0;
        ApplicationRole role_ = ApplicationRole::client;
        crypto::Bytes handshake_pending_;
        std::array<std::uint8_t, 64> rx_buffered_{};
        std::size_t rx_buf_off_ = 0;
        std::size_t rx_buf_len_ = 0;

        [[nodiscard]] auto install_raw(int fd, KtlsDirection dir, KtlsKeyMaterial const& material) noexcept -> KtlsStatus;
        [[nodiscard]] auto rotate_direction(int fd, KtlsDirection dir) -> KtlsStatus;
        [[nodiscard]] auto handle_handshake(int fd, std::span<std::uint8_t const> payload) -> KtlsRecvResult;
    public:
        static constexpr std::uint64_t kMaxTxRecords = 1ull << 24;

        explicit KtlsSession(ApplicationRole role = ApplicationRole::client, KtlsOps ops = default_ktls_ops()) noexcept
            : ops_(ops), key_update_supported_(ops_.kernel_override.value_or(probe_ktls_kernel_support()).key_update), role_(role) {}
        KtlsSession(KtlsSession const&) = delete;
        auto operator=(KtlsSession const&) -> KtlsSession& = delete;
        KtlsSession(KtlsSession&&) noexcept = default;
        auto operator=(KtlsSession&&) noexcept -> KtlsSession& = default;
        ~KtlsSession() { crypto::cleanse(handshake_pending_); crypto::cleanse(rx_buffered_); }

        [[nodiscard]] auto ulp_attached() const noexcept -> bool { return ulp_attached_; }
        [[nodiscard]] auto tx_active() const noexcept -> bool { return tx_active_ && !failed_; }
        [[nodiscard]] auto rx_active() const noexcept -> bool { return rx_active_ && !failed_; }
        [[nodiscard]] auto tx_closed() const noexcept -> bool { return tx_closed_; }
        [[nodiscard]] auto key_update_supported() const noexcept -> bool { return key_update_supported_; }
        [[nodiscard]] auto tx_rekey_required() const noexcept -> bool { return tx_records_ >= kMaxTxRecords; }
        [[nodiscard]] auto failed() const noexcept -> bool { return failed_; }

        // Attaches TCP_ULP="tls" without mutating user-space TLS state.
        [[nodiscard]] auto attach_ulp(int fd) noexcept -> KtlsStatus;
        // Installs TX or RX independently after caller extracts one-shot material from ApplicationIo.
        [[nodiscard]] auto install_tx(int fd, ApplicationRecords::KtlsDirectionHandoff&& handoff) noexcept -> KtlsStatus;
        [[nodiscard]] auto install_rx(int fd, ApplicationRecords::KtlsDirectionHandoff&& handoff) noexcept -> KtlsStatus;
        // Convenience: probes ULP first; only extracts keys from ApplicationIo after ULP succeeds.
        // Tracks half-installed state safely (never reuses extracted keys in user space).
        [[nodiscard]] auto offload(int fd, ApplicationIo& io, bool want_tx = true, bool want_rx = true) noexcept -> KtlsStatus;

        [[nodiscard]] auto send_application(int fd, std::span<std::uint8_t const> data, int* err_out = nullptr) noexcept -> std::ptrdiff_t;
        [[nodiscard]] auto send_close_notify(int fd) noexcept -> KtlsStatus;
        [[nodiscard]] auto rekey_tx(int fd, bool request_peer_update) -> KtlsStatus;
        [[nodiscard]] auto recv_record(int fd, std::span<std::uint8_t> out) -> KtlsRecvResult;
    };
}
