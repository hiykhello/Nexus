export module nexus.shadowsocks.key;
import std;
export namespace nexus::shadowsocks {
    enum class KeyError { invalid_key_length, invalid_salt_length };
    // Owns a 16- or 32-byte session key and clears it on destruction or move.
    class SessionKey {
        std::array<std::uint8_t,32> bytes_{};
        std::size_t size_=0;
        [[nodiscard]] static auto derive_material(std::span<std::uint8_t const> key, std::span<std::uint8_t const> salt)
            -> std::expected<SessionKey,KeyError>;
    public:
        SessionKey() = default;
        ~SessionKey();
        SessionKey(SessionKey const&) = delete;
        auto operator=(SessionKey const&) -> SessionKey& = delete;
        SessionKey(SessionKey&&) noexcept;
        auto operator=(SessionKey&&) noexcept -> SessionKey&;
        [[nodiscard]] auto view() const noexcept -> std::span<std::uint8_t const> { return std::span{bytes_}.first(size_); }
        [[nodiscard]] static auto derive(std::span<std::uint8_t const> key, std::span<std::uint8_t const> salt)
            -> std::expected<SessionKey,KeyError>;
        // UDP derives from the eight-byte session ID, independent of key length.
        [[nodiscard]] static auto derive_udp(std::span<std::uint8_t const> key, std::span<std::uint8_t const,8> session_id)
            -> std::expected<SessionKey,KeyError>;
    };
}
