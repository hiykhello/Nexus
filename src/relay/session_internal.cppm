// Internal session handshake, relay, and SOCKS5 UDP declarations.
module relay:session_internal;
import std;
import capy;
import corosio;
import rules;
import socks5;
import :types;
import :session_interface;

namespace relay::session_detail {
    enum class ConnectReply { none, socks5, socks4, http };

    struct HandshakeReader {
        Session& session;
        std::array<std::uint8_t, 1024> buf{};
        std::size_t pos = 0;
        std::size_t end = 0;

        [[nodiscard]] auto avail() const noexcept -> std::size_t { return end - pos; }
        [[nodiscard]] auto tail() const noexcept -> std::span<std::uint8_t const> {
            return std::span(buf).subspan(pos, end - pos);
        }
        auto fill_some() -> capy::task<bool>;
        auto ensure(std::size_t n) -> capy::task<bool>;
        auto read_exact(std::span<std::uint8_t> dst) -> capy::task<bool>;
        auto read_byte(std::uint8_t& out) -> capy::task<bool>;
    };

    auto read_exact(io::tcp_socket& socket, std::span<std::uint8_t> buffer, Session& session) -> capy::task<bool>;
    auto write_all(io::tcp_socket& socket, std::span<std::uint8_t const> buffer,
        Session& session, std::optional<bool> payload_direction = {}) -> capy::task<bool>;
    auto reply(io::tcp_socket& client, std::uint8_t code, io::endpoint endpoint, Session& session) -> capy::task<bool>;
    auto reply_socks4(io::tcp_socket& client, bool granted, io::endpoint endpoint, Session& session) -> capy::task<bool>;

    auto relay_direct(Session& session, bool upstream) -> capy::task<bool>;

    struct PrincipalClientStream {
        Session& session;
        auto read(std::span<std::uint8_t> bytes) -> capy::task<std::expected<std::size_t, std::string>> {
            auto [error, n] = co_await session.client.read_some(capy::mutable_buffer(bytes.data(), bytes.size()));
            if (error == capy::cond::eof) co_return 0;
            if (error) co_return std::unexpected(error.message());
            co_return n;
        }
        auto send(std::span<std::uint8_t const> bytes) { return write_all(session.client, bytes, session); }
        auto close_output() -> capy::task<bool> {
            co_return !session.client.shutdown(io::shutdown_send);
        }
    };

    auto relay_pair(Session& session) -> capy::task<>;
    auto ordered_connect(Session& session, io::io_context& context, socks5::Request const& request,
        std::span<std::uint8_t const> prefix, ConnectReply response, bool redirect_dns = false) -> capy::task<>;
#ifdef NEXUS_ENABLE_SOCKS_UDP
    auto udp_associate(Session& session, io::io_context& context, rules::RouteMatcher const& policy,
        socks5::Request const& request) -> capy::task<>;
#endif
    auto socks4_handshake(Session& session, io::io_context& context, rules::RouteMatcher const& policy,
        std::optional<Credentials> const& credentials, HandshakeReader& reader) -> capy::task<>;
    auto http_handshake(Session& session, io::io_context& context, rules::RouteMatcher const& policy,
        std::uint8_t first, std::optional<Credentials> const& credentials,
        std::span<std::uint8_t const> initial_tail = {}) -> capy::task<>;
}
