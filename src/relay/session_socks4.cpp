// Private SOCKS4 / SOCKS4a inbound handshake for session executor.
module relay;
import :session_internal;
import std;
import capy;
import corosio;
import rules;
import socks5;

namespace relay::session_detail {
    auto reply_socks4(io::tcp_socket& client, bool granted, io::endpoint endpoint, Session& session) -> capy::task<bool> {
        std::array<std::uint8_t, 8> bytes{0, static_cast<std::uint8_t>(granted ? 0x5A : 0x5B), 0, 0, 0, 0, 0, 0};
        if (granted && endpoint.address().is_v4()) {
            bytes[2] = static_cast<std::uint8_t>(endpoint.port() >> 8);
            bytes[3] = static_cast<std::uint8_t>(endpoint.port());
            auto raw = endpoint.address().to_v4().to_bytes();
            std::copy(raw.begin(), raw.end(), bytes.begin() + 4);
        }
        co_return co_await write_all(client, bytes, session);
    }

    auto socks4_handshake(Session& session, io::io_context& context,
        rules::RouteMatcher const& policy, std::optional<Credentials> const& credentials,
        HandshakeReader& reader) -> capy::task<> {
        auto fail = [&] { session.close(); session.done = true; };
        if (credentials) {
            (void)co_await reply_socks4(session.client, false, {}, session);
            fail(); co_return;
        }
        std::array<std::uint8_t, 524> buffer{};
        buffer[0] = 4;
        if (!co_await reader.read_exact(std::span(buffer).subspan(1, 7))) { fail(); co_return; }
        std::size_t filled = 8;
        socks5::Request request{};
        while (filled < buffer.size()) {
            if (!co_await reader.read_byte(buffer[filled])) { fail(); co_return; }
            ++filled;
            request = socks5::parse_socks4_request(std::span(buffer).first(filled));
            if (request.status != socks5::Status::incomplete) break;
        }
        if (request.status != socks5::Status::accepted) {
            (void)co_await reply_socks4(session.client, false, {}, session);
            fail(); co_return;
        }
        session.begin_traffic(TrafficProtocol::socks5, request.port);
        auto tail = reader.tail();
        if (session.ordered_tcp) {
            co_await ordered_connect(session, context, request, tail, ConnectReply::socks4);
            co_return;
        }
        bool first_sent = false;
        auto code = co_await dial(session, context, policy, request, Clock::time_point::max(), tail, &first_sent);
        if (code != 0) {
            (void)co_await reply_socks4(session.client, false, {}, session);
            fail(); co_return;
        }
        if (!co_await reply_socks4(session.client, true, session.tunnel ? io::endpoint{} : session.target.local_endpoint(), session)) {
            fail(); co_return;
        }
        if (!first_sent && !tail.empty()) {
            if (session.meters_principal_bytes()) {
                if (!co_await write_principal_payload(session, true, tail)) { fail(); co_return; }
            } else {
                auto sent = session.tunnel ? co_await session.tunnel->send(tail) : co_await write_all(session.target, tail, session, true);
                if (!sent) { fail(); co_return; }
                if (session.tunnel) session.count_traffic(true, tail.size());
            }
        }
        session.relaying = true;
        co_await relay_pair(session);
    }
}
