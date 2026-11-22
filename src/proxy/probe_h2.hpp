// Private HTTP/2 PING outbound probe helper included inside tcp_proxy_impl.hpp.
#pragma once

namespace probe_h2_detail {
    inline constexpr std::array<std::uint8_t, 8> kPingOpaque{
        'N', 'X', '9', '5', 'P', 'I', 'N', 'G'
    };

    inline constexpr std::array<std::uint8_t, 50> kPrefaceSettingsPing{
        'P','R','I',' ','*',' ','H','T','T','P','/','2','.','0','\r','\n','\r','\n','S','M','\r','\n','\r','\n',
        0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x08, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00,
        'N', 'X', '9', '5', 'P', 'I', 'N', 'G'
    };

    inline constexpr std::array<std::uint8_t, 9> kSettingsAck{
        0x00, 0x00, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00
    };

    template<class WriteFn, class ReadFn>
    auto exchange_h2_ping(
        Session const& session,
        Clock::time_point deadline,
        WriteFn&& write_all,
        ReadFn&& read_some) -> nex::capy::task<std::optional<std::uint32_t>> {
        auto ping_sent = Clock::now();
        if (!co_await write_all(std::span<std::uint8_t const>(kPrefaceSettingsPing))) {
            co_return std::nullopt;
        }
        std::vector<std::uint8_t> buf;
        buf.reserve(512);
        std::array<std::uint8_t, 512> chunk{};
        unsigned frames = 0;

        while (!session.closed && Clock::now() < deadline && frames < 32) {
            while (buf.size() < 9) {
                auto n = co_await read_some(chunk);
                if (!n || *n == 0 || Clock::now() >= deadline) co_return std::nullopt;
                if (buf.size() + *n > 16384) co_return std::nullopt;
                buf.insert(buf.end(), chunk.begin(), chunk.begin() + static_cast<std::ptrdiff_t>(*n));
            }
            std::uint32_t len = (static_cast<std::uint32_t>(buf[0]) << 16) |
                (static_cast<std::uint32_t>(buf[1]) << 8) |
                static_cast<std::uint32_t>(buf[2]);
            std::uint8_t type = buf[3];
            std::uint8_t flags = buf[4];
            std::uint32_t stream_id = ((static_cast<std::uint32_t>(buf[5]) & 0x7fu) << 24) |
                (static_cast<std::uint32_t>(buf[6]) << 16) |
                (static_cast<std::uint32_t>(buf[7]) << 8) |
                static_cast<std::uint32_t>(buf[8]);
            if (len > 16384) co_return std::nullopt;

            while (buf.size() < 9u + len) {
                auto n = co_await read_some(chunk);
                if (!n || *n == 0 || Clock::now() >= deadline) co_return std::nullopt;
                if (buf.size() + *n > 32768) co_return std::nullopt;
                buf.insert(buf.end(), chunk.begin(), chunk.begin() + static_cast<std::ptrdiff_t>(*n));
            }

            ++frames;
            if (type == 0x06) { // PING
                if (len != 8 || stream_id != 0) co_return std::nullopt;
                if ((flags & 0x01u) != 0) {
                    if (!std::ranges::equal(std::span(buf).subspan(9, 8), kPingOpaque)) co_return std::nullopt;
                    auto rtt = std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - ping_sent);
                    co_return static_cast<std::uint32_t>(std::max<std::int64_t>(0, rtt.count()));
                }
                std::array<std::uint8_t, 17> pong{
                    0x00, 0x00, 0x08, 0x06, 0x01, 0x00, 0x00, 0x00, 0x00,
                    buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15], buf[16]
                };
                if (!co_await write_all(std::span<std::uint8_t const>(pong))) co_return std::nullopt;
            } else if (type == 0x04) { // SETTINGS
                if (stream_id != 0) co_return std::nullopt;
                if ((flags & 0x01u) == 0) {
                    if (!co_await write_all(std::span<std::uint8_t const>(kSettingsAck))) co_return std::nullopt;
                }
            } else if (type == 0x07) { // GOAWAY
                co_return std::nullopt;
            }
            buf.erase(buf.begin(), buf.begin() + static_cast<std::ptrdiff_t>(9u + len));
        }
        co_return std::nullopt;
    }

#ifdef NEXUS_HTTP_CONNECT_TLS
    template<class TlsSocket>
    auto exchange_tls_h2_ping(
        Session const& session,
        TlsSocket& socket,
        OutboundProbe const& probe) -> nex::capy::task<std::optional<std::uint32_t>> {
        using std::chrono::duration_cast;
        using std::chrono::milliseconds;
        using std::chrono::seconds;
        constexpr std::array<std::string_view, 1> kAlpn{"h2"};
        auto profile = tls::ClientProfile::load(
            probe.tls_server_name, probe.tls_ca_file, 0x001d, false, kAlpn);
        if (!profile) co_return std::nullopt;
        auto start = duration_cast<milliseconds>(Clock::now().time_since_epoch()).count();
        auto end = duration_cast<milliseconds>(probe.deadline.time_since_epoch()).count();
        auto verified = duration_cast<seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
        if (start < 0 || end <= start) co_return std::nullopt;
        auto handshake = profile->handshake(
            static_cast<std::uint64_t>(start), static_cast<std::uint64_t>(end), verified);
        if (!handshake) co_return std::nullopt;
        tls::detail::ClientConnection<TlsSocket> client(socket, std::move(*handshake));
        auto authenticated = co_await client.start();
        if (!authenticated || session.closed) co_return std::nullopt;
        auto* application = client.application();
        if (!application) co_return std::nullopt;
        tls::detail::ByteStream<TlsSocket> stream(*application);
        auto write_all = [&](std::span<std::uint8_t const> bytes) -> nex::capy::task<bool> {
            co_return co_await stream.send(bytes);
        };
        auto read_some = [&](std::span<std::uint8_t> out) -> nex::capy::task<std::optional<std::size_t>> {
            auto r = co_await stream.read(out);
            co_return r ? std::optional<std::size_t>{*r} : std::nullopt;
        };
        co_return co_await exchange_h2_ping(session, probe.deadline, write_all, read_some);
    }
#endif
}

    auto Server::probe_h2_ping(Session& session, OutboundProbe& probe)
        -> nex::capy::task<std::optional<std::uint32_t>> {
        if (co_await dial_destination(session, context, probe.route, probe.target, probe.deadline)) {
            co_return std::nullopt;
        }
        session.handshake_deadline = probe.deadline;
        if (probe.use_tls) {
#ifdef NEXUS_HTTP_CONNECT_TLS
            if (session.tunnel) {
                ProxyLowerStream lower{session.tunnel};
                net::ByteStreamAdapter<ProxyLowerStream> adapter(lower);
                co_return co_await probe_h2_detail::exchange_tls_h2_ping(session, adapter, probe);
            }
            co_return co_await probe_h2_detail::exchange_tls_h2_ping(session, session.target, probe);
#else
            co_return std::nullopt;
#endif
        }
        auto write_all = [&](std::span<std::uint8_t const> bytes) -> nex::capy::task<bool> {
            if (session.tunnel) co_return co_await session.tunnel->send(bytes);
            while (!bytes.empty()) {
                auto [error, n] = co_await session.target.write_some(
                    nex::capy::const_buffer(bytes.data(), bytes.size()));
                if (error || n == 0) co_return false;
                bytes = bytes.subspan(n);
            }
            co_return true;
        };
        auto read_some = [&](std::span<std::uint8_t> out) -> nex::capy::task<std::optional<std::size_t>> {
            if (session.tunnel) {
                auto r = co_await session.tunnel->read(out);
                co_return r ? std::optional<std::size_t>{*r} : std::nullopt;
            }
            auto [error, n] = co_await session.target.read_some(
                nex::capy::mutable_buffer(out.data(), out.size()));
            if (error || n == 0) co_return std::nullopt;
            co_return n;
        };
        co_return co_await probe_h2_detail::exchange_h2_ping(session, probe.deadline, write_all, read_some);
    }
