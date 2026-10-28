export module nexus.tls.key_share;
import std;

export namespace nexus::tls {
    enum class KeyShareError { truncated, invalid_length, empty, duplicate_group, too_many, message_too_large };
    struct KeyShareEntry {
        std::uint16_t group = 0;
        std::vector<std::uint8_t> key_exchange;
        auto operator==(KeyShareEntry const&) const -> bool = default;
    };
    struct KeyShareView {
        std::uint16_t group;
        std::span<std::uint8_t const> key_exchange;
    };
    // Borrows the encoded extension. The input must outlive this view and must
    // not be modified while it is in use.
    class ClientKeyShares {
        std::span<std::uint8_t const> data_;
        explicit ClientKeyShares(std::span<std::uint8_t const> data) noexcept : data_(data) {}
        friend class KeyShare;
    public:
        // Start with cursor=0; returns each entry once and advances the cursor.
        [[nodiscard]] auto next(std::size_t& cursor) const noexcept -> std::optional<KeyShareView>;
    };
    class KeyShare {
    public:
        [[nodiscard]] static auto view_client(std::span<std::uint8_t const> data, std::size_t max_size = 0xffff)
            -> std::expected<ClientKeyShares, KeyShareError>;
        [[nodiscard]] static auto parse_client(std::span<std::uint8_t const> data, std::size_t max_size = 0xffff)
            -> std::expected<std::vector<KeyShareEntry>, KeyShareError>;
        // Borrows the input under the same lifetime and immutability rules as view_client.
        [[nodiscard]] static auto view_server(std::span<std::uint8_t const> data)
            -> std::expected<KeyShareView, KeyShareError>;
        [[nodiscard]] static auto parse_server(std::span<std::uint8_t const> data)
            -> std::expected<KeyShareEntry, KeyShareError>;
        [[nodiscard]] static auto parse_retry(std::span<std::uint8_t const> data)
            -> std::expected<std::uint16_t, KeyShareError>;
        [[nodiscard]] static auto encode_client(std::span<KeyShareEntry const> entries, std::size_t max_size = 0xffff)
            -> std::expected<std::vector<std::uint8_t>, KeyShareError>;
        [[nodiscard]] static auto encode_server(KeyShareEntry const& entry)
            -> std::expected<std::vector<std::uint8_t>, KeyShareError>;
        [[nodiscard]] static auto encode_retry(std::uint16_t group) -> std::vector<std::uint8_t>;
    };
}
