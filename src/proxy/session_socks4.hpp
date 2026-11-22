// Private SOCKS4 / SOCKS4a inbound handshake included inside session.cpp.
#pragma once

        auto reply_socks4(io::tcp_socket& client, bool granted, io::endpoint endpoint,
                          Session& session) -> capy::task<bool> {
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
                              rules::RouteMatcher const& policy,
                              std::optional<Credentials> const& credentials) -> capy::task<> {
            auto fail = [&] { session.close(); session.done = true; };
            if (credentials) {
                (void)co_await reply_socks4(session.client, false, {}, session);
                fail(); co_return;
            }
            std::array<std::uint8_t, 524> buffer{};
            buffer[0] = 4;
            std::size_t filled = 1;
            if (!co_await read_exact(session.client, std::span(buffer).subspan(1, 7), session)) { fail(); co_return; }
            filled = 8;
            socks5::Request request{};
            while (filled < buffer.size()) {
                auto [error, n] = co_await session.client.read_some(capy::mutable_buffer(buffer.data() + filled, 1));
                if (error || n == 0) { fail(); co_return; }
                session.touched = Clock::now();
                filled += n;
                request = socks5::parse_socks4_request(std::span(buffer).first(filled));
                if (request.status != socks5::Status::incomplete) break;
            }
            if (request.status != socks5::Status::accepted) {
                (void)co_await reply_socks4(session.client, false, {}, session);
                fail(); co_return;
            }
            session.begin_traffic(TrafficProtocol::socks5, request.port);
            if (session.ordered_tcp) {
                co_await ordered_connect(session, context, request, {}, ConnectReply::socks4);
                co_return;
            }
            auto code = co_await dial(session, context, policy, request);
            if (code != 0) {
                (void)co_await reply_socks4(session.client, false, {}, session);
                fail(); co_return;
            }
            if (!co_await reply_socks4(session.client, true, session.tunnel ? io::endpoint{} : session.target.local_endpoint(), session)) {
                fail(); co_return;
            }
            session.relaying = true;
            co_await relay_pair(session);
        }
