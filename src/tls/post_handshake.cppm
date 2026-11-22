export module tls.post_handshake;
import std;
export namespace tls {
    inline constexpr std::size_t max_new_session_ticket=8+1+255+2+65535+2+65534;
    struct NewSessionTicketView {
        std::uint32_t lifetime=0,age_add=0,max_early_data=0;
        bool early_data=false;
        std::span<std::uint8_t const> nonce,ticket;
    };
    // Borrowed fields expire when the complete message body is changed.
    [[nodiscard]] auto parse_new_session_ticket(std::span<std::uint8_t const> body) noexcept
        -> std::optional<NewSessionTicketView>;
    [[nodiscard]] auto valid_quic_new_session_ticket(std::span<std::uint8_t const> body) noexcept -> bool;
    [[nodiscard]] auto valid_new_session_ticket(std::span<std::uint8_t const> body) noexcept -> bool;
}
