// DNS-over-TCP hijack helper for routed TUN TCP flows.
export module cli.tun_tcp_dns;
import std;
import capy;
import dns.input_budget;
import dns.message;
import relay;
import rules;

export namespace cli::tun_enabled {
    struct TunTcpDnsOps {
        using Clock = std::chrono::steady_clock;

        template<class TcpChannel>
        static auto serve_tcp_dns(void* client, std::span<std::uint8_t const> prefetched, Clock::time_point first_deadline)
            -> capy::task<bool> {
            auto& channel = *static_cast<TcpChannel*>(client);
            auto& session = channel.session;
            session.relaying = true;
            session.select_traffic_path(relay::ConnectPath::datagrams);
            auto const& source = *session.datagram_source;

            auto read_exact = [&](std::span<std::uint8_t> pending, Clock::time_point deadline)
                -> capy::task<std::optional<std::size_t>> {
                auto copied = std::min(pending.size(), prefetched.size());
                std::ranges::copy(prefetched.first(copied), pending.begin());
                prefetched = prefetched.subspan(copied);
                auto remaining = pending.subspan(copied);
                while (!remaining.empty()) {
                    auto size = co_await channel.read(remaining, deadline);
                    if (!size) co_return std::nullopt;
                    if (!*size) co_return pending.size() - remaining.size();
                    remaining = remaining.subspan(*size);
                }
                co_return pending.size();
            };

            constexpr auto timeout = std::chrono::seconds(5);
            for (unsigned count = 0; count < 64 && !session.closed; ++count) {
                auto deadline = count ? Clock::now() + timeout : std::min(first_deadline, Clock::now() + timeout);
                std::array<std::uint8_t, 2> prefix{};
                auto read = co_await read_exact(prefix, deadline);
                if (read == 0) co_return co_await channel.close_output();
                if (read != 2) co_return false;
                auto size = (std::size_t(prefix[0]) << 8) | prefix[1];
                if (size < 12) co_return false;
                auto lease = dns::default_input_budget().acquire(size);
                if (!lease) co_return false;
                dns::Bytes query(size);
                auto body = co_await read_exact(query, deadline);
                if (body != size) co_return false;
                session.count_traffic(true, query.size() + prefix.size());
                session.touched = Clock::now();
                auto response = co_await relay::hijack_dns_query(session, channel.host.routing.executor_context(),
                    query, source, deadline, rules::Network::tcp);
                if (session.closed || Clock::now() >= deadline) co_return false;
                if (!response) continue;
                if (response->size() > 65535) co_return false;
                prefix = {static_cast<std::uint8_t>(response->size() >> 8), static_cast<std::uint8_t>(response->size())};
                if (!co_await channel.send(prefix, deadline)) co_return false;
                if (!co_await channel.send(*response, deadline)) co_return false;
                session.touched = Clock::now();
            }
            if (session.closed || !co_await channel.close_output()) co_return false;
            std::array<std::uint8_t, 1> extra;
            auto ended = co_await channel.read(extra, Clock::now() + timeout);
            co_return ended && *ended == 0;
        }
    };
}
