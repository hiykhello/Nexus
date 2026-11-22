export module quic.packet_keys;
import std;
import crypto;
import crypto.aead_context;
import nexus.thirdparty.boringssl;
import quic.varint;

export namespace quic {
    enum class PacketSuite { aes128_gcm_sha256,aes256_gcm_sha384,chacha20_poly1305_sha256 };
    namespace packet_key_detail {
        struct EraseBytes {
            crypto::Bytes& bytes;
            ~EraseBytes();
        };
        auto expand(crypto::Hash hash,std::span<std::uint8_t const> secret,std::string_view label,std::size_t length)
            -> std::expected<crypto::Bytes,crypto::Error>;
    }
    // QUIC Initial secrets depend on the destination CID. These are raw
    // handshake secrets, not TLS record keys or authenticated peers.
    class InitialSecrets {
        std::array<std::uint8_t,32> client_{},server_{};
        bool ready_=false;
        auto reset_with_salt(std::span<std::uint8_t const>,std::span<std::uint8_t const>) -> std::expected<void,crypto::Error>;
    public:
        InitialSecrets();
        ~InitialSecrets();
        InitialSecrets(InitialSecrets const&)=delete;
        auto operator=(InitialSecrets const&) -> InitialSecrets& = delete;
        auto reset(std::uint32_t version,std::span<std::uint8_t const> destination_id) -> std::expected<void,crypto::Error>;
        // Explicit v2 entry point; reset() remains restricted to v1 for the
        // existing QUIC transport until all of its epochs support v2.
        auto reset_v2(std::span<std::uint8_t const> destination_id) -> std::expected<void,crypto::Error>;
        auto client() const noexcept -> std::span<std::uint8_t const>;
        auto server() const noexcept -> std::span<std::uint8_t const>;
    };
    auto packet_nonce(std::span<std::uint8_t const,12> iv,std::uint64_t packet)
        -> std::expected<std::array<std::uint8_t,12>,crypto::Error>;
    // A library epoch borrows this stable address through its delete callback.
    // Installation allocates only in HKDF/backend setup. Per-packet calls use
    // caller buffers and the original direct AEAD state without allocation.
    // ngtcp2 already supplies its complete nonce; callbacks must not XOR PN a
    // second time. The connection owner enforces nonce and key usage limits.
    class PacketKeys {
        crypto::AeadContext aead_;
        // Mutually exclusive, directly typed algorithm states. Both members
        // are trivial; reset starts the selected lifetime with construct_at.
        union HeaderProtection {
            nex::boringssl::AES_KEY aes{};
            std::array<std::uint8_t,32> chacha;
        } header_;

        std::array<std::uint8_t,12> iv_{};
        bool ready_=false,chacha_=false;
        auto reset_with_labels(PacketSuite,std::span<std::uint8_t const>,bool) -> std::expected<void,crypto::Error>;
    public:
        PacketKeys();
        ~PacketKeys();
        PacketKeys(PacketKeys const&)=delete;
        auto operator=(PacketKeys const&) -> PacketKeys& = delete;
        PacketKeys(PacketKeys&&)=delete;
        auto operator=(PacketKeys&&) -> PacketKeys& = delete;
        auto clear() noexcept -> void;
        auto ready() const noexcept -> bool;
        // The QUIC C boundary borrows this original member at a stable address;
        // it never creates a second cipher object or a per-packet trampoline.
        auto aead_context() noexcept -> crypto::AeadContext&;
        auto reset(PacketSuite suite,std::span<std::uint8_t const> secret) -> std::expected<void,crypto::Error>;
        auto reset_v2(PacketSuite suite,std::span<std::uint8_t const> secret) -> std::expected<void,crypto::Error>;
        auto iv() const noexcept -> std::span<std::uint8_t const,12>;
        auto mask_to(std::span<std::uint8_t,16> output,std::span<std::uint8_t const,16> sample) const noexcept -> std::expected<void,crypto::Error>;
        auto seal_to(std::span<std::uint8_t> output,std::span<std::uint8_t const> nonce,
            std::span<std::uint8_t const> plaintext,std::span<std::uint8_t const> aad={}) -> std::expected<std::size_t,crypto::Error>;
        auto open_to(std::span<std::uint8_t> output,std::span<std::uint8_t const> nonce,
            std::span<std::uint8_t const> ciphertext,std::span<std::uint8_t const> aad={}) -> std::expected<std::size_t,crypto::Error>;
    };
}
