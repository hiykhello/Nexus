// Connection resolver and SOCKS/direct proxy stream adapters for named HTTP client.
export module http.rule_fetch_connection;
import std;
import capy;
import corosio;
import cli.dns_transports;
import config;
import dns.local_config;
import dns.message;
import dns.message_program;
import dns.response_addresses;
import http.connect;
import relay;
import tls.connector;

export namespace http::detail {
    namespace io = ::corosio;
    namespace capy = ::capy;
    using Clock = std::chrono::steady_clock;

    inline auto endpoint(std::array<std::uint8_t, 16> const& address, bool ipv6, std::uint16_t port) -> io::endpoint {
        if (ipv6) return {io::ipv6_address(address), port};
        io::ipv4_address::bytes_type bytes{};
        std::copy_n(address.begin(), bytes.size(), bytes.begin());
        return {io::ipv4_address(bytes), port};
    }

    struct Resolver {
        io::io_context& context;
        config::DnsRouting const& config;
        std::size_t index;
        http::ConnectRequest target;
        std::span<cli::DnsProtection const> protection;
        dns::MessageProgram* active = nullptr;
        bool canceled = false;

        auto cancel() noexcept -> void {
            canceled = true;
            if (active) active->cancel();
        }

        auto operator()(Clock::time_point deadline) -> capy::task<std::expected<std::vector<io::endpoint>, int>> {
            std::vector<io::endpoint> endpoints;
            using Kind = http::HostKind;
            if (target.kind != Kind::domain) {
                endpoints.push_back(endpoint(target.address, target.kind == Kind::ipv6, target.port));
                co_return endpoints;
            }
            dns::MessageLocalSource local{dns::system_local_snapshots()};
            std::vector<dns::MessageUpstream> upstreams;
            upstreams.reserve(config.servers.size());
            for (auto const& entry : config.servers) {
                dns::MessageUpstream upstream{};
                if (!entry.upstream) upstream.local = &local;
                else {
                    auto const& source = *entry.upstream;
                    upstream.tcp = source.tcp;
                    upstream.host = source.host;
                    upstream.resolver = source.resolver;
                    upstream.port = source.port;
                    if (source.host.empty()) upstream.endpoint = endpoint(source.address, source.ipv6, source.port);
                }
                upstream.protection = protection[upstreams.size()];
                upstreams.push_back(std::move(upstream));
            }
            using Strategy = config::DnsStrategy;
            bool v6_first = config.strategy == Strategy::ipv6_only || config.strategy == Strategy::prefer_ipv6;
            std::array<std::uint16_t, 2> types{1, 28};
            if (v6_first) std::swap(types[0], types[1]);
            for (auto type : types) {
                if (canceled || Clock::now() >= deadline) break;
                if ((type == 1 && config.strategy == Strategy::ipv6_only) ||
                    (type == 28 && config.strategy == Strategy::ipv4_only)) continue;
                dns::MessageProgram program(context, {}, upstreams, index);
                struct Reset { dns::MessageProgram*& slot; ~Reset() { slot = nullptr; } } reset{active};
                active = &program;
                dns::QueryMessage query{0, 0x0100, {target.host, type, 1}, {}};
                auto response = co_await program.run(query, deadline, {});
                if (!response) continue;
                auto parsed = dns::parse_response(*response, query.id, query.question);
                if (!parsed || parsed->rcode) continue;
                auto addresses = dns::response_addresses(*parsed);
                if (!addresses) continue;
                for (auto const& address : *addresses) {
                    if (endpoints.size() == 64) break;
                    endpoints.push_back(endpoint(address.bytes, address.size == 16, target.port));
                }
            }
            if (canceled || endpoints.empty()) co_return std::unexpected(1);
            co_return endpoints;
        }
    };

    struct ProxyStream {
        relay::Server& server;
        relay::Session& session;
        std::size_t outbound;
        Resolver resolver;

        struct Candidates {
            std::vector<io::endpoint> endpoints;
            std::size_t next = 0;
            bool resolved = false;
        };
        auto connect(Clock::time_point deadline, Candidates& candidates) -> capy::task<tls::detail::ConnectResult> {
            using Result = tls::detail::ConnectResult;
            if (!candidates.resolved) {
                candidates.resolved = true;
                auto addresses = co_await resolver(deadline);
                if (!addresses) co_return Clock::now() >= deadline ? Result::timeout : Result::failed;
                candidates.endpoints = std::move(*addresses);
            }
            if (candidates.next == candidates.endpoints.size()) co_return Result::retryable;
            switch (co_await server.open_stream(session, outbound, candidates.endpoints[candidates.next++], deadline)) {
            case relay::PacketConnectResult::connected: co_return Result::connected;
            case relay::PacketConnectResult::retryable: co_return Result::retryable;
            case relay::PacketConnectResult::timeout: co_return Result::timeout;
            case relay::PacketConnectResult::failed: co_return Result::failed;
            }
            co_return Result::failed;
        }
        auto retry() noexcept -> bool {
            if (session.tunnel) session.tunnel->cancel();
            session.tunnel = {};
            return !session.closed;
        }
        auto cancel() noexcept -> void { resolver.cancel(); session.close(); }
        auto read(std::span<std::uint8_t> bytes) { return session.tunnel->read(bytes); }
        auto send(std::span<std::uint8_t const> bytes) { return session.tunnel->send(bytes); }
        auto close_output() { return session.tunnel->close_output(); }
    };
}
