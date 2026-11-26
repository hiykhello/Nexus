#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

import std;
import desktop.http_control;
import desktop.workspace_models;
import desktop.workspace_store;

namespace {
    int g_failures = 0;

    auto check(bool cond, std::string_view msg) -> void {
        if (!cond) {
            std::cerr << "FAIL: " << msg << "\n";
            ++g_failures;
        }
    }

    // Minimal loopback HTTP/1.1 mock server for testing Wave 32 Control API & SSE endpoints.
    struct LoopbackHttpMock {
#ifdef _WIN32
        SOCKET listen_fd = INVALID_SOCKET;
#else
        int listen_fd = -1;
#endif
        std::uint16_t port = 0;
        std::thread server_thread;
        std::atomic<bool> stop_flag{false};
        std::mutex mu;
        std::vector<std::string> requests;

        explicit LoopbackHttpMock(std::function<std::string(std::string const& req)> handler) {
#ifdef _WIN32
            WSADATA wsa{};
            (void)::WSAStartup(MAKEWORD(2, 2), &wsa);
            listen_fd = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
#else
            listen_fd = ::socket(AF_INET, SOCK_STREAM, 0);
            int one = 1;
            (void)::setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
#endif
            sockaddr_in addr{};
            addr.sin_family = AF_INET;
            addr.sin_addr.s_addr = ::htonl(INADDR_LOOPBACK);
            addr.sin_port = 0;
            if (::bind(listen_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0 ||
                ::listen(listen_fd, 8) != 0) {
                return;
            }
            socklen_t len = sizeof(addr);
            if (::getsockname(listen_fd, reinterpret_cast<sockaddr*>(&addr), &len) == 0) {
                port = ntohs(addr.sin_port);
            }
            server_thread = std::thread([this, handler = std::move(handler)] {
                while (!stop_flag.load(std::memory_order_acquire)) {
                    auto client = ::accept(listen_fd, nullptr, nullptr);
#ifdef _WIN32
                    if (client == INVALID_SOCKET) break;
#else
                    if (client < 0) break;
#endif
                    if (stop_flag.load(std::memory_order_acquire)) {
#ifdef _WIN32
                        ::closesocket(client);
#else
                        ::close(client);
#endif
                        break;
                    }
                    std::string req;
                    char buf[2048];
                    while (!req.contains("\r\n\r\n")) {
#ifdef _WIN32
                        auto n = ::recv(client, buf, static_cast<int>(sizeof(buf)), 0);
#else
                        auto n = ::recv(client, buf, sizeof(buf), 0);
#endif
                        if (n <= 0) break;
                        req.append(buf, static_cast<std::size_t>(n));
                    }
                    // Read body if Content-Length present
                    if (auto cl_pos = req.find("Content-Length:"); cl_pos != std::string::npos) {
                        auto nl = req.find("\r\n", cl_pos);
                        std::size_t cl = 0;
                        auto sv = std::string_view(req).substr(cl_pos + 15, nl - (cl_pos + 15));
                        while (!sv.empty() && sv.front() == ' ') sv.remove_prefix(1);
                        std::from_chars(sv.data(), sv.data() + sv.size(), cl);
                        auto sep = req.find("\r\n\r\n");
                        while (sep != std::string::npos && req.size() - (sep + 4) < cl) {
#ifdef _WIN32
                            auto n = ::recv(client, buf, static_cast<int>(sizeof(buf)), 0);
#else
                            auto n = ::recv(client, buf, sizeof(buf), 0);
#endif
                            if (n <= 0) break;
                            req.append(buf, static_cast<std::size_t>(n));
                        }
                    }
                    {
                        std::lock_guard lk(mu);
                        requests.push_back(req);
                    }
                    auto resp = handler(req);
                    std::size_t off = 0;
                    while (off < resp.size()) {
#ifdef _WIN32
                        auto n = ::send(client, resp.data() + off, static_cast<int>(resp.size() - off), 0);
#else
                        auto n = ::send(client, resp.data() + off, resp.size() - off, 0);
#endif
                        if (n <= 0) break;
                        off += static_cast<std::size_t>(n);
                    }
#ifdef _WIN32
                    ::closesocket(client);
#else
                    ::close(client);
#endif
                }
            });
        }

        ~LoopbackHttpMock() {
            stop_flag.store(true, std::memory_order_release);
#ifdef _WIN32
            if (listen_fd != INVALID_SOCKET) {
                ::shutdown(listen_fd, SD_BOTH);
                ::closesocket(listen_fd);
            }
#else
            if (listen_fd >= 0) {
                ::shutdown(listen_fd, SHUT_RDWR);
                ::close(listen_fd);
            }
#endif
            if (server_thread.joinable()) server_thread.join();
        }
    };
}

auto main() -> int {
    // 1. Extended outbounds JSON with ewma_ms, last_status, breaker_open
    {
        auto groups = desktop::parse_outbounds_json(
            R"({"groups":[{"name":"proxy","mode":"url-test","selected":"hk-01","override":true,"members":[)"
            R"({"name":"hk-01","state":"healthy","latency_ms":34,"ewma_ms":41,"last_status":204},)"
            R"({"name":"jp-01","state":"timeout","latency_ms":0,"last_status":503,"breaker_open":true}]}]})");
        check(groups.size() == 1, "parse_outbounds_json 1 group");
        check(groups[0].members.size() == 2, "parse_outbounds_json 2 members");
        check(groups[0].members[0].ewma_ms == 41, "ewma_ms parsed");
        check(groups[0].members[0].last_status == 204, "last_status parsed");
        check(!groups[0].members[0].breaker_open, "breaker_open false default");
        check(groups[0].members[1].breaker_open, "breaker_open true parsed");
        check(groups[0].members[1].last_status == 503, "failed member last_status parsed");
    }

    // 2. Live rules JSON parser
    {
        auto rules = desktop::parse_rules_json(
            R"({"rules":[{"index":0,"type":"domain-suffix","action":"route","target":"proxy","summary":"example.com -> proxy"},)"
            R"({"index":1,"type":"ip-is-private","action":"direct","target":"direct","summary":"private -> direct"}]})");
        check(rules.size() == 2, "parse_rules_json count");
        check(rules[0].type == "domain-suffix" && rules[0].target == "proxy", "parse_rules_json row 0");
        check(rules[1].index == 1 && rules[1].action == "direct", "parse_rules_json row 1");
    }

    // 3. Live DNS query JSON parser (NOERROR + error payload)
    {
        auto q = desktop::parse_dns_query_json(
            R"({"name":"example.com","type":"A","rcode":0,"rcode_name":"NOERROR","ttl":300,"elapsed_ms":14,)"
            R"("answers":[{"name":"example.com","type":"A","ttl":300,"data":"93.184.216.34"}]})");
        check(q.ok, "parse_dns_query_json ok");
        check(q.rcode == 0 && q.rcode_name == "NOERROR", "parse_dns_query_json rcode");
        check(q.elapsed_ms == 14 && q.ttl == 300, "parse_dns_query_json timing/ttl");
        check(q.answers.size() == 1 && q.answers[0].data == "93.184.216.34", "parse_dns_query_json answer");

        auto err_q = desktop::parse_dns_query_json(R"({"error":"dns-timeout","message":"upstream timed out"})");
        check(!err_q.ok && err_q.error == "upstream timed out", "parse_dns_query_json flat error");

        auto nested_q = desktop::parse_dns_query_json(R"({"error":{"code":"dns-servfail","message":"upstream SERVFAIL"}})");
        check(!nested_q.ok && nested_q.error == "upstream SERVFAIL", "parse_dns_query_json nested error message");
        auto nested_code = desktop::parse_outbound_probe_json(R"({"error":{"code":"not-found"}})");
        check(!nested_code.ok && nested_code.error == "not-found", "parse_outbound_probe_json nested error code");
        auto nested_probe = desktop::parse_outbound_probe_json(R"({"error":{"code":"probe-fail","message":"outbound hk-99 missing"}})");
        check(!nested_probe.ok && nested_probe.error == "outbound hk-99 missing", "parse_outbound_probe_json nested error message");
    }

    // 4. FakeIP flush JSON parser + parse_logs_json "event" fallback
    {
        auto fl = desktop::parse_fakeip_flush_json(R"({"flushed":42,"fakeip":true})");
        check(fl.ok && fl.fakeip && fl.flushed == 42, "parse_fakeip_flush_json ok");
        auto bad = desktop::parse_fakeip_flush_json(R"({"error":"fakeip-unavailable"})");
        check(!bad.ok && bad.error == "fakeip-unavailable", "parse_fakeip_flush_json flat error");
        auto nested_bad = desktop::parse_fakeip_flush_json(R"({"error":{"code":"fakeip-disabled","message":"fakeip is not enabled"}})");
        check(!nested_bad.ok && nested_bad.error == "fakeip is not enabled", "parse_fakeip_flush_json nested error");

        auto logs = desktop::parse_logs_json(
            R"({"latest_seq":12,"evicted":0,"entries":[)"
            R"({"seq":11,"level":"info","domain":"dns","event":402,"message":"resolved"},)"
            R"({"seq":12,"level":"warn","domain":"proxy","event_code":501,"message":"retry"}]})");
        check(logs.latest_seq == 12 && logs.entries.size() == 2, "parse_logs_json count");
        check(logs.entries[0].event_code == 402, "parse_logs_json Core 'event' fallback");
        check(logs.entries[1].event_code == 501, "parse_logs_json 'event_code' primary");
    }

    // 5. Incremental SSE frame parser (comments, CRLF, split chunks, multi-line data, 256 KiB cap + recovery)
    {
        desktop::SseFrameParser parser;
        std::vector<desktop::SseEvent> evs;
        auto cb = [&](desktop::SseEvent const& e) { evs.push_back(e); return true; };
        check(parser.feed(": keepalive\r\n\r\nevent: lo", cb), "sse chunk 1");
        check(parser.feed("g\r\ndata: {\"seq\":7,\"level\":\"warn\",\"domain\":\"dns\",", cb), "sse chunk 2");
        check(parser.feed("\"message\":\"cache miss\"}\r\n\r\n", cb), "sse chunk 3");
        check(parser.feed("data: line1\ndata: line2\n\n", cb), "sse chunk 4");
        check(evs.size() == 2, "sse parsed 2 events");
        check(evs[0].event == "log", "sse event 0 name");
        auto log_e = desktop::parse_log_entry_json(evs[0].data);
        check(log_e && log_e->seq == 7 && log_e->level == "warn" && log_e->domain == "dns", "sse log entry parsed");
        check(evs[1].event == "message" && evs[1].data == "line1\nline2", "sse multi-line default event");

        // Oversized multi-line frame (> 256 KiB) must be dropped cleanly while preserving subsequent frames
        std::string kb_line = "data: " + std::string(1024, 'x') + "\n";
        for (int i = 0; i < 270; ++i) check(parser.feed(kb_line, cb), "sse oversized multi-line feed");
        check(parser.feed("\nevent: log\ndata: after-multi\n\n", cb), "sse recovery after multi-line oversize");
        // Oversized single line (> 256 KiB) must also be dropped cleanly while preserving subsequent frames
        std::string huge_line = "data: " + std::string(300u * 1024u, 'y') + "\n\n";
        check(parser.feed(huge_line, cb), "sse oversized single-line feed");
        check(parser.feed("event: log\ndata: after-single\n\n", cb), "sse recovery after single-line oversize");
        check(evs.size() == 4 && evs[2].data == "after-multi" && evs[3].data == "after-single",
              "sse oversized frames dropped cleanly and subsequent frames preserved");
    }

    // 6. Live loopback HTTP mock server for /v1/rules, /v1/dns/query, /v1/cache/fakeip/flush, /v1/log-level?domain, and SSE stream
    {
        LoopbackHttpMock mock([](std::string const& req) -> std::string {
            if (req.starts_with("GET /v1/rules ")) {
                std::string b = R"({"rules":[{"index":0,"type":"domain","action":"route","target":"proxy","summary":"a.com"}]})";
                return std::format("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", b.size(), b);
            }
            if (req.starts_with("GET /v1/dns/query?")) {
                std::string b = R"({"name":"nexus.test","type":"AAAA","rcode":0,"rcode_name":"NOERROR","ttl":60,"elapsed_ms":9,"answers":[{"name":"nexus.test","type":"AAAA","ttl":60,"data":"2001:db8::1"}]})";
                return std::format("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", b.size(), b);
            }
            if (req.starts_with("POST /v1/cache/fakeip/flush ")) {
                std::string b = R"({"flushed":19,"fakeip":true})";
                return std::format("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", b.size(), b);
            }
            if (req.starts_with("POST /v1/log-level ")) {
                std::string b = R"({"domain":"dns","level":"debug"})";
                return std::format("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", b.size(), b);
            }
            if (req.starts_with("GET /v1/logs?stream=1&since=500 ")) {
                return "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream; charset=utf-8\r\nConnection: close\r\n\r\n: keepalive\n\n";
            }
            if (req.starts_with("GET /v1/logs?stream=1")) {
                std::string sse =
                    ": keepalive\n\n"
                    "event: log\n"
                    "data: {\"seq\":101,\"level\":\"info\",\"domain\":\"proxy\",\"message\":\"stream hello\"}\n\n"
                    "event: log\n"
                    "data: {\"seq\":102,\"level\":\"error\",\"domain\":\"dns\",\"message\":\"stream boom\"}\n\n";
                return "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream; charset=utf-8\r\nConnection: close\r\n\r\n" + sse;
            }
            if (req.starts_with("GET /v1/sse-chunked-ok ")) {
                std::string ev = "event: log\ndata: chunked-ok\n\n";
                return std::format("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: text/event-stream\r\n\r\n{:x}\r\n{}\r\n0\r\n\r\n", ev.size(), ev);
            }
            if (req.starts_with("GET /v1/sse-chunked-oversize ")) {
                return "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: text/event-stream\r\n\r\n" + std::string(5000, 'A');
            }
            return "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        });
        check(mock.port > 0, "mock server listening");
        desktop::HttpControlClient cli("127.0.0.1", mock.port, "test-bearer-123");

        auto r_rules = cli.rules();
        check(r_rules.ok && desktop::parse_rules_json(r_rules.body).size() == 1, "GET /v1/rules live");

        auto r_dns = cli.dns_query("nexus.test", "AAAA", "remote");
        auto dns_parsed = desktop::parse_dns_query_json(r_dns.body);
        check(r_dns.ok && dns_parsed.ok && dns_parsed.answers.size() == 1 && dns_parsed.answers[0].data == "2001:db8::1", "GET /v1/dns/query live");

        auto r_fip = cli.flush_fakeip();
        auto fip_parsed = desktop::parse_fakeip_flush_json(r_fip.body);
        check(r_fip.ok && fip_parsed.ok && fip_parsed.flushed == 19, "POST /v1/cache/fakeip/flush live");

        auto r_lvl = cli.set_log_level("debug", "dns");
        check(r_lvl.ok, "POST /v1/log-level with domain live");

        std::vector<desktop::LogEntrySnapshot> streamed;
        bool sse_connected = false;
        auto sse_res = cli.stream_logs_sse([&](desktop::SseEvent const& ev) {
            if (ev.event == "log") {
                if (auto e = desktop::parse_log_entry_json(ev.data)) streamed.push_back(std::move(*e));
            }
            return streamed.size() < 2;
        }, {}, {}, {}, {}, 0, [&] { sse_connected = true; });
        check(sse_res.has_value() && sse_connected, "SSE stream_logs_sse succeeded + on_connected fired");
        check(streamed.size() == 2 && streamed[0].seq == 101 && streamed[1].level == "error", "SSE received 2 live logs");

        // Quiet keepalive-only 200 OK stream still fires on_connected immediately
        bool quiet_connected = false;
        int quiet_events = 0;
        auto quiet_res = cli.stream_logs_sse([&](desktop::SseEvent const&) { ++quiet_events; return true; },
                                             {}, {}, {}, {}, 500, [&] { quiet_connected = true; });
        check(quiet_res.has_value() && quiet_connected && quiet_events == 0, "SSE keepalive-only fires on_connected on 200 OK");

        // Valid chunked SSE succeeds & oversized chunk header fails closed
        std::string chunked_payload;
        auto ch_ok = cli.stream_sse("/v1/sse-chunked-ok", [&](desktop::SseEvent const& ev) { chunked_payload = ev.data; return true; });
        check(ch_ok.has_value() && chunked_payload == "chunked-ok", "SSE valid chunked transfer decoded");
        auto ch_bad = cli.stream_sse("/v1/sse-chunked-oversize", [](desktop::SseEvent const&) { return true; });
        check(!ch_bad.has_value(), "SSE oversized chunk header fails closed");

        std::lock_guard lk(mock.mu);
        bool saw_domain_payload = false;
        bool saw_bearer = false;
        for (auto const& req : mock.requests) {
            if (req.contains("Authorization: Bearer test-bearer-123")) saw_bearer = true;
            if (req.contains("\"domain\":\"dns\"")) saw_domain_payload = true;
        }
        check(saw_bearer, "Bearer token forwarded");
        check(saw_domain_payload, "set_log_level forwarded domain field");
    }

    // 7. Wave 30-31 WorkspaceDocument JSON round-trip (h2mux, min_streams, WS early data, TLS fragment/ECH, interrupt_exist_connections, auto_detect_interface, find_process)
    {
        auto doc = desktop::make_default_workspace();
        desktop::WorkspaceProfileItem node{};
        node.id = "w32-node";
        node.remarks = "Wave32 Node";
        node.kind = "node";
        node.node.protocol = "vless";
        node.node.server = "edge.example.net";
        node.node.port = 443;
        node.node.tls.enabled = true;
        node.node.tls.fragment = true;
        node.node.tls.record_fragment = true;
        node.node.tls.ech_mode = "dns";
        node.node.tls.ech_query_server_name = "public.example.net";
        node.node.transport.type = "websocket";
        node.node.transport.path = "/ws";
        node.node.transport.max_early_data = 2048;
        node.node.transport.early_data_header_name = "Sec-WebSocket-Protocol";
        node.node.transport.grpc_idle_timeout_ms = 15000;
        node.node.transport.grpc_ping_timeout_ms = 5000;
        node.node.transport.grpc_permit_without_stream = true;
        node.node.multiplex.enabled = true;
        node.node.multiplex.protocol = "h2mux";
        node.node.multiplex.max_connections = 4;
        node.node.multiplex.min_streams = 2;
        node.node.multiplex.padding = true;
        doc.profiles.push_back(std::move(node));

        desktop::WorkspaceProfileItem grp{};
        grp.id = "w32-grp";
        grp.kind = "policy_group";
        grp.policy_group.strategy = "url-test";
        grp.policy_group.member_ids = {"w32-node"};
        grp.policy_group.interrupt_exist_connections = true;
        doc.profiles.push_back(std::move(grp));

        doc.routing_profiles.front().auto_detect_interface = true;
        doc.routing_profiles.front().find_process = true;
        doc.routing_profiles.front().rules.push_back({
            .id = "r-frag", .domains = {"frag.example.com"}, .tls_fragment = true,
        });

        auto json = desktop::workspace_to_json(doc);
        auto parsed = desktop::workspace_from_json(json);
        check(parsed.has_value(), "workspace_from_json W32 round-trip");
        if (parsed) {
            auto const& pn = parsed->profiles.front().node;
            check(pn.tls.fragment && pn.tls.record_fragment && pn.tls.ech_query_server_name == "public.example.net", "TLS fragment/ECH round-trip");
            check(pn.transport.max_early_data == 2048 && pn.transport.early_data_header_name == "Sec-WebSocket-Protocol", "WS early-data round-trip");
            check(pn.transport.grpc_idle_timeout_ms == 15000 && pn.transport.grpc_ping_timeout_ms == 5000 && pn.transport.grpc_permit_without_stream, "gRPC keepalive round-trip");
            check(pn.multiplex.enabled && pn.multiplex.protocol == "h2mux" && pn.multiplex.max_connections == 4 && pn.multiplex.min_streams == 2 && pn.multiplex.padding, "h2mux round-trip");
            check(parsed->profiles[1].policy_group.interrupt_exist_connections, "interrupt_exist_connections round-trip");
            auto const& rp = parsed->routing_profiles.front();
            check(rp.auto_detect_interface && rp.find_process, "auto_detect_interface & find_process round-trip");
            check(!rp.rules.empty() && rp.rules.back().tls_fragment, "RoutingRule tls_fragment round-trip");
        }
    }

    if (g_failures > 0) {
        std::cerr << g_failures << " test failure(s).\n";
        return 1;
    }
    std::cout << "ALL WAVE 32 HTTP CONTROL & WORKSPACE TESTS PASSED\n";
    return 0;
}
