#include <boost/capy/buffers.hpp>
#include <boost/capy/ex/run_async.hpp>
#include <boost/capy/task.hpp>
#include <boost/corosio/endpoint.hpp>
#include <boost/corosio/io_context.hpp>
#include <boost/corosio/ipv4_address.hpp>
#include <boost/corosio/udp_socket.hpp>
#if !defined(_WIN32)
#include <arpa/inet.h>
#include <cerrno>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

import std;
import capy;
import corosio;
import config;
import cli.dns_cache_state;
import cli.dns_cache_unified;
import cli.dns_message_runtime;
import cli.dns_transports;
import dns.message;
import dns.message_cache;
import dns.message_exchange;
import dns.message_program;
import dns.policy;
import logging.cli;
import platform.socket_options;
import relay;
import rules;
import state.dns_cache;

namespace io = ::corosio;
namespace fs = std::filesystem;
using Clock = std::chrono::steady_clock;

namespace {
    void require(bool cond, std::string_view msg) {
        if (!cond) { std::cerr << "FAIL [wave36-dns-udp]: " << msg << '\n'; std::exit(1); }
    }

    struct TempDir {
        fs::path path;
        explicit TempDir(std::string_view tag) {
            static std::atomic<std::uint64_t> seq{0};
            path = fs::temp_directory_path() / (std::string(tag) + "-" +
                std::to_string(static_cast<unsigned long>(::getpid())) + "-" + std::to_string(++seq));
            fs::create_directories(path);
#if !defined(_WIN32)
            ::chmod(path.c_str(), 0700);
#endif
        }
        ~TempDir() { std::error_code ec; fs::remove_all(path, ec); }
    };

    struct UdpFd {
        int fd = -1;
        explicit UdpFd(int v = -1) noexcept : fd(v) {}
        UdpFd(UdpFd&& o) noexcept : fd(std::exchange(o.fd, -1)) {}
        auto operator=(UdpFd&& o) noexcept -> UdpFd& { if (this != &o) { if (fd >= 0) ::close(fd); fd = std::exchange(o.fd, -1); } return *this; }
        ~UdpFd() { if (fd >= 0) ::close(fd); }
        UdpFd(UdpFd const&) = delete;
        auto operator=(UdpFd const&) -> UdpFd& = delete;
    };

    auto open_loopback_udp(std::uint16_t port = 0) -> std::pair<UdpFd, std::uint16_t> {
        int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
        require(fd >= 0, "socket");
        sockaddr_in addr{}; addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = htons(port);
        require(::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0, "bind loopback udp");
        socklen_t len = sizeof(addr);
        require(::getsockname(fd, reinterpret_cast<sockaddr*>(&addr), &len) == 0, "getsockname");
        timeval tv{.tv_sec = 2, .tv_usec = 0};
        ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        return {UdpFd{fd}, ntohs(addr.sin_port)};
    }

    auto make_a_reply(std::span<std::uint8_t const> req, std::array<std::uint8_t, 4> ip, std::uint32_t ttl = 60) -> std::vector<std::uint8_t> {
        auto parsed = dns::parse_query(req);
        require(parsed.has_value(), "parse mock dns query");
        auto wire = dns::make_query(parsed->id, parsed->question);
        require(wire.has_value(), "encode mock dns reply");
        (*wire)[2] = 0x81; (*wire)[3] = 0x80; (*wire)[6] = 0x00; (*wire)[7] = 0x01;
        wire->insert(wire->end(), {
            0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01,
            static_cast<std::uint8_t>(ttl >> 24), static_cast<std::uint8_t>(ttl >> 16),
            static_cast<std::uint8_t>(ttl >> 8), static_cast<std::uint8_t>(ttl),
            0x00, 0x04, ip[0], ip[1], ip[2], ip[3]
        });
        return *wire;
    }

    struct MockDnsServer {
        UdpFd sock;
        std::uint16_t port = 0;
        std::array<std::uint8_t, 4> ip{};
        std::atomic<bool> stop{false};
        std::atomic<unsigned> hits{0};
        std::thread thread;

        explicit MockDnsServer(std::array<std::uint8_t, 4> answer_ip) : ip(answer_ip) {
            auto [s, p] = open_loopback_udp(0);
            sock.fd = std::exchange(s.fd, -1);
            port = p;
            timeval tv{.tv_sec = 0, .tv_usec = 50000};
            ::setsockopt(sock.fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            thread = std::thread([this] {
                std::array<std::uint8_t, 1500> buf{};
                while (!stop.load(std::memory_order_relaxed)) {
                    sockaddr_in peer{}; socklen_t plen = sizeof(peer);
                    auto n = ::recvfrom(sock.fd, buf.data(), buf.size(), 0, reinterpret_cast<sockaddr*>(&peer), &plen);
                    if (n <= 0) continue;
                    ++hits;
                    auto reply = make_a_reply(std::span(buf.data(), static_cast<std::size_t>(n)), ip, 120);
                    (void)::sendto(sock.fd, reply.data(), reply.size(), 0, reinterpret_cast<sockaddr*>(&peer), plen);
                }
            });
        }
        ~MockDnsServer() { stop.store(true, std::memory_order_relaxed); if (thread.joinable()) thread.join(); }
    };

    auto query_dns_a(std::uint16_t port, std::string_view name, std::uint16_t id) -> std::array<std::uint8_t, 4> {
        auto [c, _] = open_loopback_udp(0);
        auto req = dns::make_query(id, dns::Question{std::string(name), 1, 1});
        require(req.has_value(), "make_query");
        sockaddr_in dst{}; dst.sin_family = AF_INET;
        dst.sin_addr.s_addr = htonl(INADDR_LOOPBACK); dst.sin_port = htons(port);
        require(::sendto(c.fd, req->data(), req->size(), 0, reinterpret_cast<sockaddr*>(&dst), sizeof(dst)) == static_cast<ssize_t>(req->size()), "sendto dns");
        std::array<std::uint8_t, 1500> rx{}; ssize_t n = -1;
        do { n = ::recvfrom(c.fd, rx.data(), rx.size(), 0, nullptr, nullptr); } while (n < 0 && errno == EINTR);
        require(n > 12, "recvfrom dns reply");
        auto parsed = dns::parse_response(std::span(rx.data(), static_cast<std::size_t>(n)), id, dns::Question{std::string(name), 1, 1});
        require(parsed.has_value() && parsed->rcode == 0 && !parsed->records.empty(), "valid dns A reply");
        for (auto const& r : parsed->records) {
            if (r.section == dns::Section::answer && r.type == 1 && r.data_length == 4) {
                std::array<std::uint8_t, 4> out{};
                std::copy_n(parsed->wire.data() + r.data_offset, 4, out.begin());
                return out;
            }
        }
        require(false, "missing A record in reply");
        return {};
    }

    auto make_udp_server(std::string name, std::uint16_t port) -> config::DnsServer {
        config::DnsServer s{}; s.name = std::move(name);
        config::DnsUpstream u{}; u.address = {127, 0, 0, 1}; u.port = port;
        s.upstream = u;
        return s;
    }

    auto make_domain_rule(std::string domain, std::size_t server) -> policy::DnsRule {
        policy::DnsRule r{}; r.domain = std::move(domain); r.server = server;
        return r;
    }

    auto reserve_free_port() -> std::uint16_t {
        auto [probe, port] = open_loopback_udp(0);
        return port;
    }

    // R2 P1-1: DNS listener with message-cache-directory must honor hot-reloaded DNS rules & isolate cache views.
    void test_r2_p1_1_message_cache_rule_reload() {
        MockDnsServer u1({198, 51, 100, 1});
        MockDnsServer u2({198, 51, 100, 2});
        TempDir cache_dir("nexus-w36-msgcache");
        auto listen_port = reserve_free_port();

        config::Config cfg{};
        config::DnsRouting dns_cfg{};
        dns_cfg.listen = config::DnsListen{{127, 0, 0, 1}, false, listen_port};
        dns_cfg.message_cache_directory = cache_dir.path.string();
        dns_cfg.message_cache_policy = "w36-policy";
        dns_cfg.servers = {make_udp_server("u1", u1.port), make_udp_server("u2", u2.port)};
        dns_cfg.rules = {make_domain_rule("switch.test", 0)};
        dns_cfg.final = 1;
        cfg.dns = dns_cfg;

        struct SharedSnap { std::mutex mu; dns::MessageRuleSnapshot snap; };
        auto shared = std::make_shared<SharedSnap>();
        auto rules_v1 = std::make_shared<std::vector<policy::DnsRule>>(std::vector{make_domain_rule("switch.test", 0)});
        shared->snap = dns::MessageRuleSnapshot{rules_v1, 1};

        logging::Runtime logs;
        cli::DnsMessageRuntime rt(logs);
        std::array<cli::DnsProtection, 2> prot{};
        auto prep = rt.prepare(cfg, prot, [shared]() -> dns::MessageRuleSnapshot {
            std::lock_guard lk(shared->mu); return shared->snap;
        });
        require(prep.has_value(), "prepare DnsMessageRuntime with message-cache-directory");
        require(rt.start(true).has_value(), "start DnsMessageRuntime");

        // Under v1 (view=1): switch.test -> u1, cached on second query.
        require(query_dns_a(listen_port, "switch.test", 101) == std::array<std::uint8_t, 4>{198, 51, 100, 1}, "v1 switch.test -> u1");
        require(query_dns_a(listen_port, "switch.test", 102) == std::array<std::uint8_t, 4>{198, 51, 100, 1}, "v1 switch.test cached");
        require(u1.hits.load() == 1 && u2.hits.load() == 0, "v1 hit u1 once");

        // Hot-reload rules to v2 (view=2): switch.test -> u2, fresh.test -> u1!
        auto rules_v2 = std::make_shared<std::vector<policy::DnsRule>>(std::vector{
            make_domain_rule("switch.test", 1), make_domain_rule("fresh.test", 0)
        });
        { std::lock_guard lk(shared->mu); shared->snap = dns::MessageRuleSnapshot{rules_v2, 2}; }

        require(query_dns_a(listen_port, "switch.test", 103) == std::array<std::uint8_t, 4>{198, 51, 100, 2}, "v2 switch.test immediately routes to u2");
        require(query_dns_a(listen_port, "fresh.test", 104) == std::array<std::uint8_t, 4>{198, 51, 100, 1}, "v2 fresh.test immediately routes to u1");
        require(u2.hits.load() == 1 && u1.hits.load() == 2, "v2 bypassed stale view=1 cache");
        rt.stop();
    }

    // R2 P1-3: Encrypted DNS using system CA (empty ca_file) + state.cache-directory must start & isolate from custom CA.
    void test_r2_p1_3_unified_cache_system_ca() {
        TempDir root("nexus-w36-sysca");
        auto ca_path = (root.path / "custom-ca.pem").string();
        std::ofstream(ca_path) << "-----BEGIN CERTIFICATE-----\nMIIBtest\n-----END CERTIFICATE-----\n";

        auto make_tls_routing = [&](std::string ca_file) {
            config::DnsRouting r{};
            r.unified_cache_root = root.path.string();
            r.unified_cache_bytes = 256 * 1024;
            r.message_cache_policy = "tls-sysca-policy";
            config::DnsServer s{}; s.name = "dot";
            config::DnsUpstream u{}; u.address = {1, 1, 1, 1}; u.port = 853; u.tcp = true;
            u.tls = config::DnsTls{"one.one.one.one", std::move(ca_file), config::DnsSecurity::tls, {}, false};
            s.upstream = std::move(u);
            r.servers = {std::move(s)};
            r.final = 0;
            return r;
        };

        std::array<dns::MessageUpstream, 1> upstreams{dns::MessageUpstream{io::endpoint{io::ipv4_address({1, 1, 1, 1}), 853}, true, nullptr}};
        auto sys_routing = make_tls_routing("");
        auto custom_routing = make_tls_routing(ca_path);

        cli::UnifiedDnsCache sys_cache(sys_routing, upstreams);
        cli::UnifiedDnsCache custom_cache(custom_routing, upstreams);
        require(sys_cache.identity_fingerprint() != custom_cache.identity_fingerprint(), "system CA vs custom CA fingerprint must differ");

        // Also test DoH (https), DoQ (quic), and DoH3 (https3) with empty ca_file.
        sys_routing.servers[0].upstream->tls->transport = config::DnsSecurity::https;
        sys_routing.servers[0].upstream->tls->path = "/dns-query";
        cli::UnifiedDnsCache doh_cache(sys_routing, upstreams);
        sys_routing.servers[0].upstream->tls->transport = config::DnsSecurity::quic;
        cli::UnifiedDnsCache doq_cache(sys_routing, upstreams);
        sys_routing.servers[0].upstream->tls->transport = config::DnsSecurity::https3;
        cli::UnifiedDnsCache doh3_cache(sys_routing, upstreams);
        (void)doh_cache; (void)doq_cache; (void)doh3_cache;
    }

    // R2 P2-1: Online clear-cache dns must reject stale pre-clear writes AND persist subsequent fresh queries under new epoch.
    void test_r2_p2_1_clear_cache_epoch_persistence() {
        TempDir root("nexus-w36-clear-epoch");
        MockDnsServer upstream({198, 51, 100, 77});
        std::array<dns::MessageUpstream, 1> upstreams{dns::MessageUpstream{io::endpoint{io::ipv4_address({127, 0, 0, 1}), upstream.port}, false, nullptr}};

        config::DnsRouting routing{};
        routing.unified_cache_root = root.path.string();
        routing.unified_cache_bytes = 256 * 1024;
        routing.message_cache_policy = "clear-epoch-policy";
        routing.servers = {make_udp_server("u1", upstream.port)};
        routing.final = 0;

        auto seed_entry = [&](dns::MessageCache& cache, std::uint64_t view, std::string_view name, std::array<std::uint8_t, 4> ip) {
            auto qwire = dns::make_query(0, dns::Question{std::string(name), 1, 1});
            require(qwire.has_value(), "seed make_query");
            auto rwire = make_a_reply(*qwire, ip, 120);
            dns::MessageCache::View v{0, upstreams[0].endpoint, false, nullptr, view};
            require(cache.restore(v, *qwire, std::move(rwire), 120, 0, Clock::now()), "seed cache.restore");
        };

        // Part A: Direct UnifiedDnsCache stale-write rejection + refresh_epoch() + post-clear save.
        cli::UnifiedDnsCache unified(routing, upstreams);
        dns::MessageCache mem;
        require(unified.restore(mem, 1).has_value(), "initial unified restore");
        require(unified.active_epoch() == 0, "initial epoch == 0");
        seed_entry(mem, 1, "before.test", {198, 51, 100, 11});
        auto stale_pending = unified.prepare_save(mem, 1);
        require(stale_pending.has_value() && stale_pending->epoch == 0, "prepare_save captured epoch 0");
        require(unified.commit_save(*stale_pending).has_value(), "initial commit_save");

        // Simulate online clear-cache dns on disk (epoch 0 -> 1, deletes shard files).
        ::state::DnsCache disk(root.path, 256 * 1024);
        require(disk.clear().has_value(), "disk.clear()");

        // Pre-clear pending write MUST be rejected as stale (must NOT resurrect before.test on disk).
        require(unified.commit_save(*stale_pending).has_value(), "stale commit ignored cleanly");
        auto after_stale = disk.lookup(unified.identity_fingerprint());
        require(after_stale.has_value() && after_stale->epoch == 1 && !after_stale->payload.has_value(), "stale write did not resurrect shard");

        // Refresh epoch after clear, populate fresh entry, save, and verify disk persistence.
        mem.clear();
        require(unified.refresh_epoch().has_value() && unified.active_epoch() == 1, "refresh_epoch updated to 1");
        seed_entry(mem, 1, "after.test", {198, 51, 100, 22});
        require(unified.save(mem, 1).has_value(), "post-clear unified.save succeeded");

        dns::MessageCache reloaded;
        cli::UnifiedDnsCache reader(routing, upstreams);
        require(reader.restore(reloaded, 1).has_value(), "reload unified cache");
        dns::MessageCache::View view{0, upstreams[0].endpoint, false, nullptr, 1};
        auto q_old = dns::parse_query(*dns::make_query(0, dns::Question{"before.test", 1, 1}));
        auto q_new = dns::parse_query(*dns::make_query(0, dns::Question{"after.test", 1, 1}));
        require(!reloaded.lookup(view, *q_old, Clock::now()).has_value(), "before.test absent after clear");
        require(reloaded.lookup(view, *q_new, Clock::now()).has_value(), "after.test persisted under epoch 1");

        // Part B: End-to-end live DnsMessageRuntime clear_live_cache() + new query + checkpoint().
        TempDir live_root("nexus-w36-live-clear");
        auto listen_port = reserve_free_port();
        config::Config cfg{};
        config::DnsRouting live_dns = routing;
        live_dns.listen = config::DnsListen{{127, 0, 0, 1}, false, listen_port};
        live_dns.unified_cache_root = live_root.path.string();
        cfg.dns = live_dns;
        logging::Runtime logs;
        cli::DnsMessageRuntime rt(logs);
        std::array<cli::DnsProtection, 1> prot{};
        require(rt.prepare(cfg, prot).has_value() && rt.start(true).has_value(), "start live unified cache runtime");

        require(query_dns_a(listen_port, "live-pre.test", 201) == std::array<std::uint8_t, 4>{198, 51, 100, 77}, "live pre-clear query");
        rt.checkpoint();
        require(::state::DnsCache(live_root.path, 256 * 1024).clear().has_value(), "live disk.clear()");
        rt.clear_live_cache();
        require(query_dns_a(listen_port, "live-post.test", 202) == std::array<std::uint8_t, 4>{198, 51, 100, 77}, "live post-clear query");
        rt.checkpoint();
        rt.stop();

        dns::MessageCache verified;
        cli::UnifiedDnsCache live_reader(live_dns, upstreams);
        require(live_reader.restore(verified, 0).has_value(), "restore live post-clear shard");
        dns::MessageCache::View v0{0, upstreams[0].endpoint, false, nullptr, 0};
        auto q_pre = dns::parse_query(*dns::make_query(0, dns::Question{"live-pre.test", 1, 1}));
        auto q_post = dns::parse_query(*dns::make_query(0, dns::Question{"live-post.test", 1, 1}));
        require(!verified.lookup(v0, *q_pre, Clock::now()).has_value(), "live-pre.test absent on disk");
        require(verified.lookup(v0, *q_post, Clock::now()).has_value(), "live-post.test persisted on disk after clear-cache dns");
    }

    // R2 P1-2 & R2 P2-2: fixed-udp direct outbound must honor SocketBinding (udp-bind-port/bind-address) AND preserve 0-byte UDP datagrams.
    void test_r2_fixed_udp_binding_and_zero_byte() {
        auto [dst, dst_port] = open_loopback_udp(0);
        auto bind_port = reserve_free_port();

        auto srv = relay::Server::create();
        require(srv.has_value(), "create relay::Server");
        platform::TcpSocketOptions direct_opts{};
        direct_opts.binding.inet4_bind_address = std::array<std::uint8_t, 4>{127, 0, 0, 1};
        direct_opts.binding.udp_bind_port = bind_port;
        require((*srv)->set_direct_tcp_options(direct_opts).has_value(), "set_direct_tcp_options(udp_bind_port)");
        require((*srv)->set_fixed_udp_target("127.0.0.1", dst_port, 10000), "set_fixed_udp_target");
        auto in_port = (*srv)->start(0, relay::Inbound::fixed_udp, 1, false, std::array<std::uint8_t, 16>{127, 0, 0, 1});
        require(in_port.has_value(), "start fixed_udp");

        std::atomic<bool> stop_io{false};
        std::thread io_thread([&] {
            while (!stop_io.load(std::memory_order_relaxed)) {
                (*srv)->executor_context().restart();
                (void)(*srv)->executor_context().run_for(std::chrono::milliseconds(20));
            }
        });
        struct StopIo {
            relay::Server& s; std::atomic<bool>& flag; std::thread& th;
            ~StopIo() { flag.store(true, std::memory_order_relaxed); s.executor_context().stop(); if (th.joinable()) th.join(); s.stop(); }
        } guard{**srv, stop_io, io_thread};

        auto [cli, _] = open_loopback_udp(0);
        sockaddr_in in_addr{}; in_addr.sin_family = AF_INET;
        in_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK); in_addr.sin_port = htons(*in_port);

        auto send_bytes = [&](int fd, sockaddr_in const& to, std::string_view data) {
            char empty = 0;
            void const* ptr = data.empty() ? static_cast<void const*>(&empty) : static_cast<void const*>(data.data());
            require(::sendto(fd, ptr, data.size(), 0, reinterpret_cast<sockaddr const*>(&to), sizeof(to)) == static_cast<ssize_t>(data.size()), "udp sendto");
        };
        auto recv_bytes = [&](int fd, sockaddr_in& from) -> std::string {
            std::array<char, 256> b{}; socklen_t flen = sizeof(from); ssize_t n = -1;
            do { n = ::recvfrom(fd, b.data(), b.size(), 0, reinterpret_cast<sockaddr*>(&from), &flen); } while (n < 0 && errno == EINTR);
            require(n >= 0, "udp recvfrom timeout/error");
            return std::string(b.data(), static_cast<std::size_t>(n));
        };

        // 1. Normal packet -> verifies R2 P1-2 configured udp_bind_port + bind address!
        sockaddr_in up_peer{}, cli_peer{};
        send_bytes(cli.fd, in_addr, "hello-1");
        require(recv_bytes(dst.fd, up_peer) == "hello-1", "dst received hello-1");
        require(ntohs(up_peer.sin_port) == bind_port && ntohl(up_peer.sin_addr.s_addr) == INADDR_LOOPBACK,
            "fixed-udp direct outbound honored udp_bind_port & inet4_bind_address");
        send_bytes(dst.fd, up_peer, "reply-1");
        require(recv_bytes(cli.fd, cli_peer) == "reply-1", "client received reply-1");

        // 2. Client -> upstream valid 0-byte UDP datagram!
        sockaddr_in zero_peer{};
        send_bytes(cli.fd, in_addr, "");
        require(recv_bytes(dst.fd, zero_peer).empty(), "dst received 0-byte UDP datagram");
        require(ntohs(zero_peer.sin_port) == bind_port, "0-byte datagram reused bound flow");

        // 3. Upstream -> client valid 0-byte UDP reply MUST arrive AND MUST NOT cancel the flow!
        send_bytes(dst.fd, up_peer, "");
        require(recv_bytes(cli.fd, cli_peer).empty(), "client received 0-byte UDP reply");

        // 4. Subsequent normal packet on same flow still works in both directions!
        send_bytes(cli.fd, in_addr, "after-zero");
        require(recv_bytes(dst.fd, up_peer) == "after-zero", "flow stayed alive after 0-byte reply");
        send_bytes(dst.fd, up_peer, "still-alive");
        require(recv_bytes(cli.fd, cli_peer) == "still-alive", "client received still-alive");

        // 5. Also verify a 0-byte UDP datagram works as the VERY FIRST packet of a fresh flow!
        auto srv2 = relay::Server::create();
        require(srv2.has_value() && (*srv2)->set_fixed_udp_target("127.0.0.1", dst_port, 10000), "srv2 setup");
        auto in_port2 = (*srv2)->start(0, relay::Inbound::fixed_udp, 1, false, std::array<std::uint8_t, 16>{127, 0, 0, 1});
        require(in_port2.has_value(), "start fixed_udp srv2");
        std::atomic<bool> stop2{false};
        std::thread th2([&] { while (!stop2.load(std::memory_order_relaxed)) { (*srv2)->executor_context().restart(); (void)(*srv2)->executor_context().run_for(std::chrono::milliseconds(20)); } });
        StopIo guard2{**srv2, stop2, th2};
        auto [cli2, _2] = open_loopback_udp(0);
        sockaddr_in in_addr2 = in_addr; in_addr2.sin_port = htons(*in_port2);
        sockaddr_in up2{}, cp2{};
        send_bytes(cli2.fd, in_addr2, "");
        require(recv_bytes(dst.fd, up2).empty(), "first-packet 0-byte UDP forwarded");
        send_bytes(dst.fd, up2, "first-ok");
        require(recv_bytes(cli2.fd, cp2) == "first-ok", "reply to first-packet 0-byte flow received");
    }

    // R2 P2-4: mDNS response builder must preserve actual rec.ttl and filter TTL==0 goodbye records.
    void test_r2_p2_4_mdns_ttl_and_goodbye() {
        auto append_name = [](std::vector<std::uint8_t>& out, std::string_view name) {
            std::size_t pos = 0;
            while (pos < name.size()) {
                auto dot = name.find('.', pos);
                auto lbl = (dot == std::string_view::npos) ? name.substr(pos) : name.substr(pos, dot - pos);
                out.push_back(static_cast<std::uint8_t>(lbl.size()));
                out.insert(out.end(), lbl.begin(), lbl.end());
                if (dot == std::string_view::npos) break;
                pos = dot + 1;
            }
            out.push_back(0);
        };
        auto append_rr = [&](std::vector<std::uint8_t>& out, std::string_view name, std::uint16_t type,
                             std::uint32_t ttl, std::span<std::uint8_t const> rdata) {
            append_name(out, name);
            out.insert(out.end(), {
                static_cast<std::uint8_t>(type >> 8), static_cast<std::uint8_t>(type & 0xff),
                0x80, 0x01, // class IN + cache-flush bit
                static_cast<std::uint8_t>(ttl >> 24), static_cast<std::uint8_t>(ttl >> 16),
                static_cast<std::uint8_t>(ttl >> 8), static_cast<std::uint8_t>(ttl),
                static_cast<std::uint8_t>(rdata.size() >> 8), static_cast<std::uint8_t>(rdata.size() & 0xff)
            });
            out.insert(out.end(), rdata.begin(), rdata.end());
        };
        auto make_mdns_pkt = [&](std::uint16_t ancount) {
            return std::vector<std::uint8_t>{0, 0, 0x84, 0x00, 0, 0, static_cast<std::uint8_t>(ancount >> 8), static_cast<std::uint8_t>(ancount), 0, 0, 0, 0};
        };

        // Case 1: A records with TTL=5, TTL=120, and TTL=0 (goodbye).
        auto pkt_a = make_mdns_pkt(3);
        std::array<std::uint8_t, 4> ip1{192, 0, 2, 10}, ip2{192, 0, 2, 11}, ip_bye{192, 0, 2, 99};
        append_rr(pkt_a, "printer.local", 1, 5, ip1);
        append_rr(pkt_a, "printer.local", 1, 120, ip2);
        append_rr(pkt_a, "printer.local", 1, 0, ip_bye);
        auto res_a = cli::convert_mdns_response(dns::Question{"printer.local", 1, 1}, 0x1234, pkt_a);
        require(res_a.has_value() && res_a->has_value(), "convert mDNS A response");
        std::vector<std::pair<std::uint32_t, std::uint8_t>> got_a;
        for (auto const& r : (**res_a).records)
            if (r.section == dns::Section::answer && r.type == 1 && r.data_length == 4)
                got_a.emplace_back(r.ttl, (**res_a).wire[r.data_offset + 3]);
        require(got_a.size() == 2 && got_a[0] == std::pair<std::uint32_t, std::uint8_t>{5, 10} &&
            got_a[1] == std::pair<std::uint32_t, std::uint8_t>{120, 11}, "A preserves TTL 5/120 and filters TTL 0");

        // Case 2: AAAA records with TTL=45 and TTL=0 (goodbye).
        auto pkt_aaaa = make_mdns_pkt(2);
        std::array<std::uint8_t, 16> v6_ok{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
        std::array<std::uint8_t, 16> v6_bye{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2};
        append_rr(pkt_aaaa, "host6.local", 28, 45, v6_ok);
        append_rr(pkt_aaaa, "host6.local", 28, 0, v6_bye);
        auto res_aaaa = cli::convert_mdns_response(dns::Question{"host6.local", 28, 1}, 0x5678, pkt_aaaa);
        require(res_aaaa.has_value() && res_aaaa->has_value(), "convert mDNS AAAA response");
        std::vector<std::pair<std::uint32_t, std::uint8_t>> got_aaaa;
        for (auto const& r : (**res_aaaa).records)
            if (r.section == dns::Section::answer && r.type == 28 && r.data_length == 16)
                got_aaaa.emplace_back(r.ttl, (**res_aaaa).wire[r.data_offset + 15]);
        require(got_aaaa.size() == 1 && got_aaaa[0] == std::pair<std::uint32_t, std::uint8_t>{45, 1}, "AAAA preserves TTL 45 and filters TTL 0");

        // Case 3: Goodbye-only mDNS response returns empty optional (ignored).
        auto pkt_bye = make_mdns_pkt(1);
        append_rr(pkt_bye, "gone.local", 1, 0, ip_bye);
        auto res_bye = cli::convert_mdns_response(dns::Question{"gone.local", 1, 1}, 0x9abc, pkt_bye);
        require(res_bye.has_value() && !res_bye->has_value(), "TTL=0 goodbye-only packet returns no answer");
    }
}

int main() {
    test_r2_p1_1_message_cache_rule_reload();
    test_r2_p1_3_unified_cache_system_ca();
    test_r2_p2_1_clear_cache_epoch_persistence();
    test_r2_fixed_udp_binding_and_zero_byte();
    test_r2_p2_4_mdns_ttl_and_goodbye();
    std::println("wave36_core_audit_dns_udp_unit: PASS");
    return 0;
}
