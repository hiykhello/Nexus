// HTTP/3 single-request driver for `nexus tools fetch` (direct or routed UDP outbound).
export module cli.tools_fetch_h3;
import std;
import capy;
import corosio;
import cli.tools_fetch;
import http.header;
import http.rule_fetch_connection;
import hysteria2.transport_options;
import masque.client_session;
import net.packet_stream_socket;
import platform.ip_address;
import platform.socket_options;
import relay;
import tls.profiles;

export namespace cli::fetch {
    inline constexpr bool h3_available = true;

    namespace h3_detail {
        using Clock = std::chrono::steady_clock;

        inline auto format_ep_ip(corosio::endpoint const& ep) -> std::string {
            if (ep.is_v6()) return platform::format_ipv6(ep.address().to_v6().to_bytes());
            return platform::format_ipv4(ep.address().to_v4().to_bytes());
        }

        template<class Client>
        auto run_client_exchange(Client& client, ParsedFetchUrl const& url, FetchOptions const& opts,
            Clock::time_point started, Clock::time_point deadline, FetchResult& out)
            -> capy::task<std::expected<void, std::string>> {
            std::expected<void, std::string> res = std::unexpected("HTTP/3 exchange failed");
            auto drive = [&]() -> capy::task<capy::results<>> { co_return co_await client.run(); };
            auto worker = [&]() -> capy::task<capy::results<>> {
                struct StopGuard {
                    Client& c;
                    ~StopGuard() { c.request_stop(); }
                } guard{client};

                if (!co_await client.wait_http_ready(deadline)) {
                    res = std::unexpected("HTTP/3 handshake failed or timed out");
                    co_return capy::results<>{};
                }
                std::vector<http::HeaderField> extra;
                std::string content_type = "application/octet-stream";
                for (auto const& h : opts.headers) {
                    std::string lo(h.name);
                    for (char& c : lo) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
                    if (lo == "content-type") { content_type = h.value; continue; }
                    if (lo == "host" || lo == "connection" || lo == "content-length" || lo == "accept-encoding") continue;
                    extra.push_back({h.name, h.value});
                }
                constexpr std::size_t kMaxBytes = 16 * 1024 * 1024;
                if (opts.method == "POST") {
                    masque::HttpPost post_body{content_type,
                        {reinterpret_cast<std::uint8_t const*>(opts.body.data()), opts.body.size()}};
                    auto reply = co_await client.post(url.target, post_body, kMaxBytes, deadline);
                    if (!reply) {
                        res = std::unexpected("HTTP/3 POST request failed");
                        co_return capy::results<>{};
                    }
                    out.status = reply->status;
                    out.protocol = "h3";
                    out.ttfb_ms = std::chrono::duration<double, std::milli>(Clock::now() - started).count();
                    for (auto const& [k, v] : reply->fields) {
                        if (!k.starts_with(':')) out.headers.push_back({k, v});
                    }
                    out.body_bytes = reply->body.size();
                    auto take = std::min(opts.max_body_preview, reply->body.size());
                    out.body_preview = reply->body.substr(0, take);
                    out.body_truncated = take < reply->body.size();
                    res = {};
                    co_return capy::results<>{};
                }
                bool first_hdr = true;
                auto observe = [&](std::string_view k, std::string_view v) {
                    if (first_hdr) {
                        first_hdr = false;
                        out.ttfb_ms = std::chrono::duration<double, std::milli>(Clock::now() - started).count();
                    }
                    out.headers.push_back({std::string(k), std::string(v)});
                };
                auto sink = [&](std::string_view chunk, Clock::time_point) -> capy::task<bool> {
                    if (out.body_preview.size() < opts.max_body_preview) {
                        auto take = std::min(opts.max_body_preview - out.body_preview.size(), chunk.size());
                        out.body_preview.append(chunk.data(), take);
                        if (take < chunk.size()) out.body_truncated = true;
                    } else if (opts.max_body_preview > 0) {
                        out.body_truncated = true;
                    }
                    out.body_bytes += chunk.size();
                    co_return true;
                };
                auto reply = co_await client.get_response(url.target, kMaxBytes, deadline, extra,
                    true, true, masque::HttpBodySink{sink}, masque::HttpHeaderSink{observe});
                if (!reply) {
                    res = std::unexpected("HTTP/3 GET request failed or status rejected");
                    co_return capy::results<>{};
                }
                out.status = reply->status;
                out.protocol = "h3";
                if (first_hdr)
                    out.ttfb_ms = std::chrono::duration<double, std::milli>(Clock::now() - started).count();
                res = {};
                co_return capy::results<>{};
            };
            (void)co_await capy::when_all(drive(), worker());
            client.finish();
            co_return res;
        }
    }

    inline auto exchange_h3(corosio::io_context& io, relay::Server* server, std::size_t outbound_idx,
        http::detail::Resolver& resolver, tls::ShapedClientProfile const& tls_profile,
        ParsedFetchUrl const& url, FetchOptions const& opts,
        std::chrono::steady_clock::time_point started, std::chrono::steady_clock::time_point deadline,
        FetchResult& out) -> capy::task<std::expected<void, std::string>> {
        using Clock = std::chrono::steady_clock;
        if (opts.method == "HEAD")
            co_return std::unexpected("HTTP/3 HEAD is not supported; use --method GET or --http 2/1.1");
        auto endpoints = co_await resolver(deadline);
        if (!endpoints || endpoints->empty())
            co_return std::unexpected("HTTP/3 DNS resolution failed");
        auto const& peer = endpoints->front();
        out.resolved_ip = h3_detail::format_ep_ip(peer);

        auto rem_ms = std::max<std::int64_t>(500, std::chrono::duration_cast<std::chrono::milliseconds>(deadline - Clock::now()).count());
        hysteria2::TransportOptions topts{
            .handshake_timeout = std::chrono::milliseconds(rem_ms),
            .idle_timeout = std::chrono::milliseconds(std::max<std::int64_t>(10000, rem_ms)),
        };
        auto profile = masque::ClientProfile::for_http(tls_profile.profile(), url.authority, topts, tls_profile.fingerprint(), nullptr);

        if (server && outbound_idx != 0) {
            auto lease = server->acquire_session();
            if (!lease) co_return std::unexpected("HTTP/3 outbound session quota exhausted");
            relay::Session session(io);
            server->attach_session(session, std::move(*lease));
            session.relaying = true;
            auto tunnel = server->open_packet_tunnel(session, outbound_idx);
            if (!tunnel) co_return std::unexpected("selected outbound does not support UDP/datagrams for HTTP/3");
            auto conn_dl = tunnel->connection_deadline(deadline);
            auto conn_res = co_await tunnel->connect_until(net::packet_peer_address(peer), conn_dl);
            if (conn_res != relay::PacketConnectResult::connected)
                co_return std::unexpected("HTTP/3 outbound datagram tunnel connection failed");
            masque::Client<net::PacketStreamSocket<relay::PacketTunnel>> client(io, profile);
            if (!client.socket().attach(*tunnel, tunnel->transport(), peer))
                co_return std::unexpected("HTTP/3 outbound packet peer is invalid");
            if (!co_await client.socket().prepare(conn_dl))
                co_return std::unexpected("HTTP/3 outbound packet setup failed");
            auto st = client.start(peer, nullptr, nullptr, {}, deadline);
            if (!st) co_return std::unexpected(std::move(st.error()));
            auto result = co_await h3_detail::run_client_exchange(client, url, opts, started, deadline, out);
            session.close();
            co_return result;
        }

        masque::Client<corosio::udp_socket> client(io, profile);
        platform::SocketBinding binding{};
        std::error_code ec;
        auto st = client.start(peer, &binding, nullptr, {}, deadline, &ec);
        if (!st) co_return std::unexpected(std::move(st.error()));
        co_return co_await h3_detail::run_client_exchange(client, url, opts, started, deadline, out);
    }
}
