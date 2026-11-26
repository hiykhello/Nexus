// Live HTTP/1.1, HTTP/2, HTTP/3 diagnostic fetch client (`nexus tools fetch`).
module cli.tools_fetch;
import std;
import capy;
import corosio;
import cli.dns_transports;
import cli.outbounds;
import cli.proxy_providers;
import cli.route_files;
import cli.tools_fetch_h2;
import cli.tools_fetch_h3;
import config;
import dns.https_query;
import dns.quic_query;
import dns.tls_query;
import http.connect;
import http.corosio_https;
import http.header;
import http.rule_fetch_connection;
import platform.ip_address;
import platform.socket_options;
import relay;
import tls.byte_stream;
import tls.connector;
import tls.fingerprint;
import tls.profiles;

namespace cli::fetch {
    namespace {
        using Clock = std::chrono::steady_clock;

        auto format_ep_ip(corosio::endpoint const& ep) -> std::string {
            if (ep.is_v6()) return platform::format_ipv6(ep.address().to_v6().to_bytes());
            return platform::format_ipv4(ep.address().to_v4().to_bytes());
        }

        auto build_http1_request(ParsedFetchUrl const& url, FetchOptions const& opts) -> std::string {
            std::string wire = std::format("{} {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nAccept-Encoding: identity\r\n",
                opts.method, url.target, url.authority);
            bool has_cl = false;
            for (auto const& h : opts.headers) {
                std::string lo(h.name);
                for (char& c : lo) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
                if (lo == "host" || lo == "connection" || lo == "accept-encoding") continue;
                if (lo == "content-length") has_cl = true;
                wire += std::format("{}: {}\r\n", h.name, h.value);
            }
            if ((opts.method == "POST" || !opts.body.empty()) && !has_cl)
                wire += std::format("Content-Length: {}\r\n", opts.body.size());
            wire += "\r\n";
            if (!opts.body.empty()) wire += opts.body;
            return wire;
        }

        struct ResponseCollector {
            FetchResult& out;
            Clock::time_point started;
            std::size_t preview_limit = 2048;
            bool got_headers = false;
            static constexpr std::size_t kMaxBodyBytes = 16 * 1024 * 1024;

            auto operator()(http::ResponseStep const& step) -> bool {
                if (step.informational) return true;
                if (step.event == http::ResponseEvent::header) {
                    got_headers = true;
                    out.status = step.status_code;
                    out.protocol = "http/1.1";
                    out.ttfb_ms = std::chrono::duration<double, std::milli>(Clock::now() - started).count();
                    http::HeaderFieldCursor cur(http::inspect_header(step.wire).field_lines);
                    for (auto f = cur.next(); f.status == http::HeaderFieldStatus::field; f = cur.next())
                        out.headers.push_back({std::string(f.field.name), std::string(f.field.value)});
                    return true;
                }
                if (!step.wire.empty()) {
                    if (out.body_bytes + step.wire.size() > kMaxBodyBytes) return false;
                    if (out.body_preview.size() < preview_limit) {
                        auto take = std::min(preview_limit - out.body_preview.size(), step.wire.size());
                        out.body_preview.append(step.wire.data(), take);
                        if (take < step.wire.size()) out.body_truncated = true;
                    } else if (preview_limit > 0) {
                        out.body_truncated = true;
                    }
                    out.body_bytes += step.wire.size();
                }
                return true;
            }
        };

        auto feed_plain_http1(http::ResponseDecoder& dec, std::string_view data, ResponseCollector& col, bool& complete)
            -> std::expected<void, std::string> {
            while (!data.empty()) {
                auto step = dec.feed(data);
                if (step.event == http::ResponseEvent::malformed || step.event == http::ResponseEvent::truncated || !step.consumed)
                    return std::unexpected("malformed HTTP/1.1 response");
                data.remove_prefix(step.consumed);
                if (!step.wire.empty() && !col(step))
                    return std::unexpected("HTTP/1.1 response body exceeded limit");
                if (step.event == http::ResponseEvent::complete) { complete = true; break; }
            }
            if (!complete && dec.feed({}).event == http::ResponseEvent::complete) complete = true;
            return {};
        }

        auto run_plain_direct(corosio::io_context& io, http::detail::Resolver& resolver, ParsedFetchUrl const& url,
            FetchOptions const& opts, Clock::time_point started, Clock::time_point deadline, FetchResult& out)
            -> capy::task<std::expected<void, std::string>> {
            auto eps = co_await resolver(deadline);
            if (!eps || eps->empty()) co_return std::unexpected("DNS resolution failed");
            corosio::tcp_socket sock(io);
            bool connected = false;
            std::string last_err = "TCP connect failed";
            for (auto const& ep : *eps) {
                if (Clock::now() >= deadline) { last_err = "connect timed out"; break; }
                sock.close();
                if (sock.open()) continue;
                auto [ce] = co_await corosio::timeout(sock.connect(ep), deadline);
                if (!ce) { connected = true; out.resolved_ip = format_ep_ip(ep); break; }
                last_err = ce.message();
            }
            if (!connected) co_return std::unexpected("connect failed: " + last_err);
            auto req = build_http1_request(url, opts);
            std::span<char const> rem(req);
            while (!rem.empty()) {
                auto [we, n] = co_await corosio::timeout(sock.write_some(capy::const_buffer(rem.data(), rem.size())), deadline);
                if (we || !n) co_return std::unexpected("HTTP write failed");
                rem = rem.subspan(n);
            }
            http::ResponseDecoder dec(opts.method == "HEAD", false, http::ChunkOutput::payload);
            ResponseCollector col{out, started, opts.max_body_preview};
            bool complete = false;
            std::array<char, 8192> buf{};
            while (!complete && Clock::now() < deadline) {
                auto [re, n] = co_await corosio::timeout(sock.read_some(capy::mutable_buffer(buf.data(), buf.size())), deadline);
                if (n > 0) {
                    if (auto ok = feed_plain_http1(dec, {buf.data(), n}, col, complete); !ok) co_return ok;
                }
                if (re || n == 0) {
                    if (!complete) {
                        auto end = dec.finish();
                        if (end.event == http::ResponseEvent::complete) complete = true;
                    }
                    break;
                }
            }
            sock.close();
            if (!complete || !col.got_headers) co_return std::unexpected("HTTP/1.1 response truncated or timed out");
            co_return std::expected<void, std::string>{};
        }

        auto run_plain_routed(corosio::io_context& io, relay::Server& server, std::size_t outbound_idx,
            http::detail::Resolver& resolver, ParsedFetchUrl const& url, FetchOptions const& opts,
            Clock::time_point started, Clock::time_point deadline, FetchResult& out)
            -> capy::task<std::expected<void, std::string>> {
            auto eps = co_await resolver(deadline);
            if (!eps || eps->empty()) co_return std::unexpected("DNS resolution failed");
            auto lease = server.acquire_session();
            if (!lease) co_return std::unexpected("outbound session quota exhausted");
            relay::Session session(io);
            server.attach_session(session, std::move(*lease));
            struct CloseGuard { relay::Session& s; ~CloseGuard() { s.close(); } } guard{session};
            bool connected = false;
            for (auto const& ep : *eps) {
                if (Clock::now() >= deadline) break;
                if (co_await server.open_stream(session, outbound_idx, ep, deadline) == relay::PacketConnectResult::connected) {
                    connected = true;
                    out.resolved_ip = format_ep_ip(ep);
                    break;
                }
                if (session.tunnel) { session.tunnel->cancel(); session.tunnel = {}; }
            }
            if (!connected || !session.tunnel) co_return std::unexpected("outbound TCP connect failed");
            session.relaying = true;
            auto req = build_http1_request(url, opts);
            auto req_bytes = std::span<std::uint8_t const>{reinterpret_cast<std::uint8_t const*>(req.data()), req.size()};
            capy::async_event done_ev;
            std::expected<void, std::string> ex_res = std::unexpected("outbound HTTP/1.1 response truncated or timed out");
            auto watchdog = [&]() -> capy::task<capy::results<>> {
                auto [err] = co_await corosio::timeout(done_ev.wait(), deadline);
                if (err && capy::is_timeout(err)) session.close();
                co_return capy::results<>{};
            };
            auto exchange = [&]() -> capy::task<capy::results<>> {
                struct Signal { capy::async_event& ev; ~Signal() { ev.set(); } } sig{done_ev};
                if (!co_await session.tunnel->send(req_bytes)) {
                    ex_res = std::unexpected("outbound HTTP write failed");
                    co_return capy::results<>{};
                }
                http::ResponseDecoder dec(opts.method == "HEAD", false, http::ChunkOutput::payload);
                ResponseCollector col{out, started, opts.max_body_preview};
                bool complete = false;
                std::array<std::uint8_t, 8192> buf{};
                while (!complete && Clock::now() < deadline) {
                    auto r = co_await session.tunnel->read(buf);
                    if (r && *r > 0) {
                        if (auto ok = feed_plain_http1(dec, {reinterpret_cast<char const*>(buf.data()), *r}, col, complete); !ok) {
                            ex_res = std::move(ok);
                            co_return capy::results<>{};
                        }
                        continue;
                    }
                    if (!complete && dec.finish().event == http::ResponseEvent::complete) complete = true;
                    break;
                }
                if (complete && col.got_headers) ex_res = {};
                co_return capy::results<>{};
            };
            (void)co_await capy::when_all(watchdog(), exchange());
            co_return ex_res;
        }

        struct RecordingResolver {
            http::detail::Resolver inner;
            std::string* resolved_ip = nullptr;

            auto cancel() noexcept -> void { inner.cancel(); }
            auto operator()(Clock::time_point dl) -> capy::task<std::expected<std::vector<corosio::endpoint>, int>> {
                auto res = co_await inner(dl);
                if (res && !res->empty() && resolved_ip && resolved_ip->empty())
                    *resolved_ip = format_ep_ip(res->front());
                co_return res;
            }
        };

        struct RecordingProxyStream {
            relay::Server& server;
            relay::Session& session;
            std::size_t outbound;
            RecordingResolver resolver;

            struct Candidates { std::vector<corosio::endpoint> endpoints; std::size_t next = 0; bool resolved = false; };
            auto connect(Clock::time_point dl, Candidates& c) -> capy::task<tls::detail::ConnectResult> {
                using R = tls::detail::ConnectResult;
                if (!c.resolved) {
                    c.resolved = true;
                    auto addrs = co_await resolver(dl);
                    if (!addrs) co_return Clock::now() >= dl ? R::timeout : R::failed;
                    c.endpoints = std::move(*addrs);
                }
                if (c.next == c.endpoints.size()) co_return R::retryable;
                auto const& ep = c.endpoints[c.next++];
                auto rc = co_await server.open_stream(session, outbound, ep, dl);
                if (rc == relay::PacketConnectResult::connected) {
                    if (resolver.resolved_ip) *resolver.resolved_ip = format_ep_ip(ep);
                    co_return R::connected;
                }
                if (rc == relay::PacketConnectResult::retryable) co_return R::retryable;
                if (rc == relay::PacketConnectResult::timeout) co_return R::timeout;
                co_return R::failed;
            }
            auto retry() noexcept -> bool { if (session.tunnel) session.tunnel->cancel(); session.tunnel = {}; return !session.closed; }
            auto cancel() noexcept -> void { resolver.cancel(); session.close(); }
            auto read(std::span<std::uint8_t> b) { return session.tunnel->read(b); }
            auto send(std::span<std::uint8_t const> b) { return session.tunnel->send(b); }
            auto close_output() { return session.tunnel->close_output(); }
        };

        template<class Connector>
        auto exchange_tls_stream(Connector& conn, ParsedFetchUrl const& url, FetchOptions const& opts,
            Clock::time_point started, Clock::time_point deadline, FetchResult& out)
            -> capy::task<std::expected<void, std::string>> {
            auto cr = co_await conn.start(deadline);
            if (cr != tls::detail::ConnectResult::connected)
                co_return std::unexpected(cr == tls::detail::ConnectResult::timeout ? "TLS connect/handshake timed out" : "TLS connection or certificate verification failed");
            auto* neg = conn.negotiated();
            constexpr std::array<std::uint8_t, 2> kH2{'h', '2'};
            bool is_h2 = neg && neg->alpn && std::ranges::equal(*neg->alpn, kH2);
            if (is_h2) {
                if constexpr (h2_available) {
                    tls::detail::ByteStream<typename Connector::Socket> bs(*conn.application());
                    co_return co_await exchange_h2(bs, opts.method, url.authority, url.target,
                        opts.headers, opts.body, started, deadline, opts.max_body_preview, out);
                }
                co_return std::unexpected("HTTP/2 is unavailable in this build");
            }
            if (opts.http_pref == HttpVersionPref::http2)
                co_return std::unexpected("peer did not negotiate HTTP/2 via ALPN");
            auto req = build_http1_request(url, opts);
            ResponseCollector col{out, started, opts.max_body_preview};
            auto ex = co_await http::detail::https_exchange(conn, req, opts.method == "HEAD", col,
                deadline, true, http::ChunkOutput::payload);
            if (!ex || !col.got_headers)
                co_return std::unexpected("HTTPS/1.1 response failed or truncated");
            co_return std::expected<void, std::string>{};
        }

        auto load_fetch_config(FetchOptions const& opts) -> std::expected<config::Config, std::string> {
            config::Config cfg{};
            if (!opts.config_path.empty()) {
                auto raw = cli::read_config_source(opts.config_path, false, {});
                if (!raw) return std::unexpected("config read: " + raw.error());
                cli::ProxyProviderManager providers;
                auto expanded = providers.prepare_initial(*raw, opts.config_path, true);
                if (!expanded) return std::unexpected("provider expand: " + expanded.error());
                auto parsed = config::parse_kdl(*expanded);
                if (!parsed) return std::unexpected("config parse: " + parsed.error());
                cfg = std::move(*parsed);
            } else {
                cfg.direct_outbound_name = "direct";
                cfg.default_outbound_name = "direct";
            }
            if (!cfg.dns || cfg.dns->servers.empty()) {
                cfg.dns.emplace();
                cfg.dns->servers.push_back(config::DnsServer{.name = "system"});
                cfg.dns->final = 0;
            }
            return cfg;
        }
    }

    auto run_fetch(FetchOptions const& opts) -> std::expected<FetchResult, std::string> {
        auto url = parse_fetch_url(opts.url);
        if (!url) return std::unexpected(url.error());
        if (!url->https && (opts.http_pref == HttpVersionPref::http2 || opts.http_pref == HttpVersionPref::http3))
            return std::unexpected("HTTP/2 and HTTP/3 require an https:// URL");
        if (opts.http_pref == HttpVersionPref::http2 && !h2_available)
            return std::unexpected("HTTP/2 is unavailable in this build");
        if (opts.http_pref == HttpVersionPref::http3 && !h3_available)
            return std::unexpected("HTTP/3 is unavailable in this build");

        auto cfg = load_fetch_config(opts);
        if (!cfg) return std::unexpected(cfg.error());

        std::size_t outbound_idx = 0;
        std::string outbound_label = "direct";
        if (!opts.outbound.empty()) {
            auto idx = config::configured_outbound_index(*cfg, opts.outbound);
            if (!idx) return std::unexpected("unknown outbound or group: " + opts.outbound);
            if (*idx == 1) return std::unexpected("cannot fetch through block outbound");
            outbound_idx = *idx;
            auto leaf = config::selected_outbound(*cfg, opts.outbound);
            outbound_label = leaf.empty() || leaf == opts.outbound
                ? opts.outbound : std::format("{} -> {}", opts.outbound, leaf);
        }

        auto transports = cli::prepare_dns_transports(*cfg);
        if (!transports) return std::unexpected("DNS transport init: " + transports.error());

        std::unique_ptr<relay::Server> server;
        std::optional<corosio::io_context> direct_io;
        if (outbound_idx != 0 || cli::uses_proxy_dns(cfg->dns)) {
            auto created = relay::Server::create();
            if (!created) return std::unexpected("relay server init: " + created.error().message());
            if (auto ob = cli::configure_outbounds(**created, *cfg, *transports); !ob)
                return std::unexpected("outbound setup: " + ob.error());
            if (!(*created)->prepare_routing(1) || !(*created)->activate_context())
                return std::unexpected("cannot activate outbound context");
            server = std::move(*created);
        } else {
            direct_io.emplace();
        }
        auto& io = server ? server->executor_context() : *direct_io;

        FetchResult result{};
        result.url = opts.url;
        result.method = opts.method;
        result.outbound = std::move(outbound_label);

        auto started = Clock::now();
        auto deadline = started + std::chrono::milliseconds(opts.timeout_ms);
        std::expected<void, std::string> outcome = std::unexpected("fetch did not complete");

        auto task = [&]() -> capy::task<> {
            http::detail::Resolver base_resolver{io, *cfg->dns, cfg->dns->final, url->destination, *transports};
            if (!url->https) {
                outcome = outbound_idx != 0
                    ? co_await run_plain_routed(io, *server, outbound_idx, base_resolver, *url, opts, started, deadline, result)
                    : co_await run_plain_direct(io, base_resolver, *url, opts, started, deadline, result);
                co_return;
            }
            std::string ca = !opts.ca_file.empty() ? opts.ca_file
                : (cfg->certificate ? cfg->certificate->ca_file : std::string{});
            constexpr std::array<std::string_view, 2> kAlpnAuto{"h2", "http/1.1"};
            std::span<std::string_view const> alpn = kAlpnAuto;
            if (opts.http_pref == HttpVersionPref::http2) alpn = alpn.first(1);
            else if (opts.http_pref == HttpVersionPref::http1_1 || !h2_available) alpn = alpn.last(1);
            auto prof = tls::ClientProfile::load(url->destination.host, ca, 0x11ec, false, alpn);
            if (!prof) { outcome = std::unexpected("TLS profile: " + prof.error()); co_return; }
            auto shaped = tls::ShapedClientProfile::create(std::move(*prof), tls::Fingerprint::native, std::nullopt);
            if (!shaped) { outcome = std::unexpected("TLS shape: " + shaped.error()); co_return; }

            if (opts.http_pref == HttpVersionPref::http3) {
                outcome = co_await exchange_h3(io, server.get(), outbound_idx, base_resolver, *shaped,
                    *url, opts, started, deadline, result);
                co_return;
            }
            RecordingResolver rres{base_resolver, &result.resolved_ip};
            if (outbound_idx != 0) {
                auto lease = server->acquire_session();
                if (!lease) { outcome = std::unexpected("outbound session quota exhausted"); co_return; }
                relay::Session session(io);
                server->attach_session(session, std::move(*lease));
                struct CloseGuard { relay::Session& s; ~CloseGuard() { s.close(); } } guard{session};
                tls::detail::LayerConnector<RecordingProxyStream, tls::ShapedClientProfile> conn(
                    *shaped, *server, session, outbound_idx, std::move(rres));
                outcome = co_await exchange_tls_stream(conn, *url, opts, started, deadline, result);
                co_return;
            }
            tls::detail::PhysicalConnector<RecordingResolver, tls::ShapedClientProfile> conn(
                io, std::move(rres), *shaped, cfg->direct_tcp_options);
            outcome = co_await exchange_tls_stream(conn, *url, opts, started, deadline, result);
        };

        capy::run_async(io.get_executor(), [] {}, [](std::exception_ptr) noexcept {})(task());
        (void)io.run();
        if (server) server->stop();
        else if (direct_io) {
            dns::stop_tls_queries(*direct_io);
            dns::stop_https_queries(*direct_io);
            dns::stop_quic_queries(*direct_io);
            direct_io->restart();
            (void)direct_io->run();
        }
        if (!outcome) return std::unexpected(std::move(outcome.error()));
        result.total_ms = std::chrono::duration<double, std::milli>(Clock::now() - started).count();
        return result;
    }

    auto tools_fetch_main(int argc, char** argv) -> int {
        auto opts = parse_fetch_args(argc, argv);
        if (!opts) {
            std::cerr << "fetch: " << opts.error() << "\n" << kFetchUsage;
            return 2;
        }
        if (opts->help) {
            std::cout << kFetchUsage;
            return 0;
        }
        auto res = run_fetch(*opts);
        if (!res) {
            if (opts->json) {
                std::cout << std::format("{{\"ok\":false,\"error\":{}}}\n", encoding::json_quote(res.error()));
            } else {
                std::cerr << "fetch: " << res.error() << '\n';
            }
            return 1;
        }
        std::cout << (opts->json ? format_fetch_json(*res) : format_fetch_text(*res));
        return 0;
    }
}

extern "C" auto nexus_tools_fetch_entry(int argc, char** argv) -> int {
    return cli::fetch::tools_fetch_main(argc, argv);
}
