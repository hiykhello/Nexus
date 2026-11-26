#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

import std;
import cli.tun_owner_lookup;
import config;
import corosio;
import dns.group_snapshot;
import packet;
import platform.process_owner;
import platform.udp_batch;
import platform.uring_buf_ring;
import relay;
import relay.principal_limits;
import rules;
import tcp.connection;
import tcp.dispatch;
import tcp.receive;
import tcp.table;
import tls.corosio_application_io;
import udp;
import udp.route;

namespace {
    auto require(bool ok, std::string_view msg) -> void {
        if (!ok) {
            std::cerr << "FAIL [batch172]: " << msg << '\n';
            std::exit(1);
        }
    }

    struct FdGuard {
        int fd = -1;
        ~FdGuard() { if (fd >= 0) ::close(fd); }
    };

    auto ref_checksum(std::span<std::uint8_t const> bytes) noexcept -> std::uint16_t {
        std::uint64_t sum = 0;
        std::size_t i = 0;
        for (; i + 1 < bytes.size(); i += 2) sum += (std::uint64_t{bytes[i]} << 8) | bytes[i + 1];
        if (i < bytes.size()) sum += std::uint64_t{bytes[i]} << 8;
        while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
        return static_cast<std::uint16_t>(~sum);
    }

    auto test_172a() -> void {
        static_assert(tls::detail::ApplicationInput::kMinDirectReadBuffer <= 16640);
        corosio::io_context io;
        relay::PrincipalRegistry reg;
        std::array limits{
            relay::PrincipalLimits{.name = "free"},
            relay::PrincipalLimits{.name = "metered", .bytes = {.quota = 1024 * 1024}}
        };
        auto policy = reg.prepare("in0", limits);
        auto now_tp = std::chrono::steady_clock::now();
        policy->find("free")->publish_bytes(now_tp);
        policy->find("metered")->publish_bytes(now_tp);
        relay::Session s_free(io), s_metered(io);
        require(!s_free.meters_principal_bytes(), "default session should not meter");
        s_free.principal = policy->find("free");
        require(!s_free.meters_principal_bytes(), "unlimited principal should skip user-space copy");
        s_metered.principal = policy->find("metered");
        require(s_metered.meters_principal_bytes(), "quota principal should meter bytes");

        FdGuard rx{::socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0)};
        FdGuard tx{::socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0)};
        require(rx.fd >= 0 && tx.fd >= 0, "udp batch sockets");
        sockaddr_in addr{.sin_family = AF_INET, .sin_port = 0, .sin_addr = {htonl(INADDR_LOOPBACK)}};
        require(::bind(rx.fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0, "bind rx udp");
        socklen_t alen = sizeof(addr);
        require(::getsockname(rx.fd, reinterpret_cast<sockaddr*>(&addr), &alen) == 0, "getsockname udp");
        std::array<std::uint8_t, 5> p0{1, 2, 3, 4, 5}, p1{9, 8, 7, 6, 5};
        std::array send_slots{
            platform::UdpSendSlot{reinterpret_cast<sockaddr const*>(&addr), alen, p0.data(), p0.size()},
            platform::UdpSendSlot{reinterpret_cast<sockaddr const*>(&addr), alen, p1.data(), p1.size()}
        };
        auto sent = platform::send_udp_batch(tx.fd, send_slots);
        require(sent && *sent == 2, "send_udp_batch");
        std::array<std::uint8_t, 64> b0{}, b1{};
        std::array recv_slots{
            platform::UdpRecvSlot{.data = b0.data(), .capacity = b0.size()},
            platform::UdpRecvSlot{.data = b1.data(), .capacity = b1.size()}
        };
        std::size_t got = 0;
        for (int tries = 0; tries < 50 && got < 2; ++tries) {
            auto r = platform::recv_udp_batch(rx.fd, std::span(recv_slots).subspan(got));
            if (r) got += *r;
        }
        require(got == 2 && recv_slots[0].received == 5 && recv_slots[1].received == 5, "recv_udp_batch");

#if defined(__linux__) && defined(NEXUS_ENABLE_IO_URING)
        int sv[2]{-1, -1};
        require(::socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, sv) == 0, "socketpair");
        FdGuard sv0{sv[0]}, sv1{sv[1]};
        if (auto ring = platform::UringMultishotLoop::create({.ring_entries = 8, .buffer_size = 2048, .buffer_group_id = 3, .sq_entries = 16})) {
            auto armed = ring->arm_read_multishot(sv0.fd, 77);
            if (armed) {
                char msg[] = "uring-tun-fastpath";
                require(::write(sv1.fd, msg, sizeof(msg) - 1) == ssize_t{sizeof(msg) - 1}, "write uring pair");
                std::array<platform::MultishotEvent, 4> ev{};
                std::size_t n = 0;
                for (int tries = 0; tries < 20 && n == 0; ++tries) {
                    if (auto poll_r = ring->poll_events(ev, 1, 10); poll_r) n = *poll_r;
                }
                if (n > 0 && ev[0].has_buffer && ev[0].result > 0) {
                    auto view = ring->buffer_view(ev[0].buffer_id, static_cast<std::size_t>(ev[0].result));
                    require(view.size() == sizeof(msg) - 1, "uring multishot read length");
                    require(ring->recycle(ev[0].buffer_id), "uring recycle");
                }
            }
        }
#endif
    }

    auto test_172b() -> void {
        packet::MemoryLink link({1500, 1, 1500});
        packet::Bytes full_pkt(100, std::uint8_t{0xab});
        packet::Bytes retry_pkt(100, std::uint8_t{0xcd});
        require(link.send_owned(packet::Side::first, std::move(full_pkt)).has_value(), "move send #1");
        auto qfull = link.send_owned(packet::Side::first, std::move(retry_pkt));
        require(!qfull && qfull.error() == packet::DeviceError::queue_full && retry_pkt.size() == 100,
                "queue_full move send must preserve caller buffer");
        auto popped = link.receive(packet::Side::second);
        require(popped && *popped && (*popped)->size() == 100, "move send payload intact");
        require(link.send_owned(packet::Side::first, std::move(retry_pkt)).has_value(), "retry move send succeeds");

        std::vector<std::uint8_t> csum_buf(1403);
        for (std::size_t i = 0; i < csum_buf.size(); ++i) csum_buf[i] = static_cast<std::uint8_t>(i * 31 + 7);
        require(packet::internet_checksum(csum_buf) == ref_checksum(csum_buf), "64-bit internet_checksum odd");
        require(packet::internet_checksum(std::span(csum_buf).first(1400)) == ref_checksum(std::span(csum_buf).first(1400)),
                "64-bit internet_checksum even");
        auto u4 = packet::make_udp4({10, 0, 0, 1}, {1, 1, 1, 1}, 12345, 53, std::span(csum_buf).first(513), 1500);
        require(u4 && packet::parse_udp4(*u4).has_value(), "make/parse udp4 checksum");
        auto u6 = packet::make_udp6({0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
                                    {0x26, 0x06, 0x47, 0, 0x47, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x11, 0x11},
                                    23456, 53, std::span(csum_buf).first(513), 1500);
        require(u6 && packet::parse_udp6(*u6).has_value(), "make/parse udp6 checksum");

        auto rb = tcp::ReceiveBuffer::create(0xfffffffe, 32);
        require(rb.has_value(), "ReceiveBuffer create");
        std::array<std::uint8_t, 4> d1{'c', 'd', 'e', 'f'}, d2{'j', 'k', 'l', 'm'}, d3{'w', 'x', 'y', 'z'};
        auto r1 = rb->insert(1, d1);
        auto r2 = rb->insert(7, d2);
        auto r3 = rb->insert(15, d3);
        require(r1.accepted == 4 && r2.accepted == 4 && r3.accepted == 4, "ReceiveBuffer OOO accept");
        auto [blocks, nblocks] = rb->sack_blocks();
        require(nblocks == 3 && blocks[0].left == 1 && blocks[0].right == 5 &&
                blocks[1].left == 7 && blocks[1].right == 11 && blocks[2].left == 15 && blocks[2].right == 19,
                "ReceiveBuffer SACK interval list");
        std::array<std::uint8_t, 3> d0{'a', 'b', 'c'};
        auto r0 = rb->insert(0xfffffffe, d0);
        require(r0.accepted == 3 && rb->ready() == 7 && rb->next() == 5, "ReceiveBuffer wrap merge");
        std::array<std::uint8_t, 5> out{};
        require(rb->read(out) == 5 && rb->ready() == 2 && rb->next() == 5, "ReceiveBuffer read shift");
        auto [blocks2, nb2] = rb->sack_blocks();
        require(nb2 == 2 && blocks2[0].left == 7 && blocks2[0].right == 11, "ReceiveBuffer SACK post-read");
        require(rb->insert_fin(11) == tcp::FinResult::accepted, "ReceiveBuffer fin trims tail OOO");
        auto [blocks3, nb3] = rb->sack_blocks();
        require(nb3 == 1 && blocks3[0].left == 7 && blocks3[0].right == 11, "ReceiveBuffer tail trimmed at fin");

        auto syn = packet::make_tcp4({.source = {10, 0, 0, 2}, .destination = {1, 1, 1, 1},
            .source_port = 40000, .destination_port = 443, .sequence = 100, .flags = 0x02, .window = 8192}, 1500);
        auto sv = packet::parse_tcp4(*syn);
        auto conn = tcp::PassiveConnection::accept(*sv, 500, 4096, 1);
        require(conn.has_value(), "PassiveConnection accept");
        auto ack3 = packet::Tcp4View{.source = sv->source, .destination = sv->destination,
            .source_port = 40000, .destination_port = 443, .sequence = 101, .acknowledgement = 501, .flags = 0x10, .window = 8192};
        require(conn->input(ack3, 2).has_value(), "handshake complete");
        require(conn->close_send().has_value() && conn->fin_ready() && conn->fin_sent(3).has_value(), "fin sent");
        auto ack_fin_pair = packet::Tcp4View{.source = sv->source, .destination = sv->destination,
            .source_port = 40000, .destination_port = 443, .sequence = 101, .acknowledgement = 502, .flags = 0x11, .window = 8192};
        require(conn->input(ack_fin_pair, 4).has_value(), "enter TIME_WAIT");
        require(conn->time_wait_deadline().has_value(), "TIME_WAIT armed");
        require(conn->input(ack_fin_pair, 5).has_value(), "duplicate FIN in TIME_WAIT after release_storage");

        rules::Matcher empty_m;
        require(empty_m.empty(), "default Matcher is empty");
        udp::RoutedBridge4 rb4(std::move(empty_m), udp::Mapping::endpoint_independent, udp::Filtering::endpoint_independent);
        auto parsed_u4 = packet::parse_udp4(*u4);
        auto prep = rb4.prepare_parsed(*parsed_u4, 10);
        require(prep && prep->payload.size() == 513, "RoutedBridge4::prepare_parsed fast path");

        auto ct = tcp::ConnectionTable::create(64, 4096);
        require(ct.has_value(), "ConnectionTable create");
        auto dr = tcp::dispatch(*ct, *syn, 500, 10, 1500);
        require(dr && dr->reply.has_value(), "tcp::dispatch SYN without speculative make_tcp");
    }

    auto test_172c() -> void {
        std::vector<rules::RouteRule> route_rules;
        std::vector<rules::ProgramRule> prog_rules;
        rules::RuleSet dom_set{.version = 2}, suf_set{.version = 2}, ip_set{.version = 2}, unidx_set{.version = 2};
        for (int i = 0; i < 2000; ++i) {
            auto host = "host-" + std::to_string(i) + ".example.test";
            dom_set.rules.push_back({.type = "domain", .value = host});
        }
        for (int i = 0; i < 2000; ++i) {
            auto suf = "suf" + std::to_string(i) + ".org";
            suf_set.rules.push_back({.type = "domain-suffix", .value = suf});
        }
        for (int i = 0; i < 1200; ++i) {
            auto cidr = "10." + std::to_string(i / 256) + "." + std::to_string(i % 256) + ".0/24";
            ip_set.rules.push_back({.type = "ip-cidr", .value = cidr});
        }
        unidx_set.rules.push_back({.type = "port", .value = "8443"});
        route_rules.push_back({dom_set, 1});
        route_rules.push_back({suf_set, 2});
        route_rules.push_back({ip_set, 3});
        route_rules.push_back({unidx_set, 4});
        auto rm = rules::RouteMatcher::compile(route_rules, 0, 5);
        require(rm.has_value(), "RouteMatcher compile 5201 rules");
        auto pf_dom = rm->preflight("host-1999.example.test");
        auto pf_suf = rm->preflight("sub.suf1500.org");
        auto pf_miss = rm->preflight("unknown.invalid");
        require(pf_dom && *pf_dom == 1, "preflight indexed domain before IP conflict");
        require(pf_suf && *pf_suf == 2, "preflight indexed suffix");
        require(pf_miss && !pf_miss->has_value(), "preflight miss conflicts with trailing IP rule (outbound 3 != default 0)");
        auto pf_port = rm->preflight(rules::MatchInput{.domain = "unknown.invalid", .port = 8443});
        require(pf_port && !pf_port->has_value(), "preflight port=8443 conflicts with earlier unknown IP outbound=3");
        auto pf_port_with_ip = rm->preflight(rules::MatchInput{.domain = "unknown.invalid", .ip = "9.9.9.9", .port = 8443});
        require(pf_port_with_ip && *pf_port_with_ip == 4, "preflight with non-matching IP matches unindexed port=8443");

        prog_rules.push_back({dom_set, {rules::ProgramActionKind::route, 1}});
        prog_rules.push_back({ip_set, {rules::ProgramActionKind::route, 2}});
        prog_rules.push_back({unidx_set, {rules::ProgramActionKind::route, 3}});
        auto rp = rules::RouteProgram::compile(prog_rules, 4);
        require(rp.has_value(), "RouteProgram compile");
        auto pp_dom = rp->preflight({.explicit_domain = "host-10.example.test"});
        auto pp_unc = rp->preflight({.explicit_domain = "other.test"});
        auto pp_exh = rp->preflight({.explicit_domain = "other.test", .ip = "9.9.9.9", .port = 80});
        require(pp_dom && pp_dom->kind == rules::ProgramPreflightKind::step && pp_dom->step && pp_dom->step->action.outbound == 1,
                "RouteProgram preflight domain hit");
        require(pp_unc && pp_unc->kind == rules::ProgramPreflightKind::uncertain && pp_unc->rule_index == 1,
                "RouteProgram preflight uncertain at IP rule");
        require(pp_exh && pp_exh->kind == rules::ProgramPreflightKind::exhausted, "RouteProgram preflight exhausted");

        udp::FlowTable ft(udp::Mapping::endpoint_independent, udp::Filtering::endpoint_independent, {.flows = 8, .idle_ms = 1000});
        udp::Endpoint4 ep_a{{10, 0, 0, 1}, 1001}, ep_b{{10, 0, 0, 1}, 1002}, rem{{1, 1, 1, 1}, 53};
        auto s1 = ft.open_send(ep_a, rem, 100);
        require(s1 && ft.finish_send(s1->first, s1->second, true, 100).has_value(), "flow a send");
        auto s2 = ft.open_send(ep_b, rem, 200);
        require(s2 && ft.finish_send(s2->first, s2->second, true, 200).has_value(), "flow b send");
        require(ft.accept_reply(s1->first, rem, 900).has_value(), "touch flow a moves to LRU tail");
        auto ex1 = ft.expire(1300);
        require(ex1 && *ex1 == 1 && ft.size() == 1, "O(1) LRU expired b and kept touched a");
        require(ft.set_flow_idle_ms(s1->first, 200), "custom idle override");
        auto ex2 = ft.expire(1400);
        require(ex2 && *ex2 == 1 && ft.size() == 0, "custom idle fallback expiry");

        std::array<std::size_t, 2> caps{1, 1};
        dns_hp_experiment::GroupSnapshot gs(caps, dns_hp_experiment::GroupSnapshot::SharedCapacity{16}, 1, 5000);
        auto rdr = gs.reader(0);
        auto miss = gs.lookup(0, {1, "miss.test", 1}, 1000, rdr);
        require(miss && !miss->has_value(), "GroupSnapshot lock-free miss");
        auto tok = gs.begin_query(1, {1, "peer.test", 1});
        require(tok && gs.publish(1, {1, "peer.test", 1}, {.addresses = {{.size = 4, .bytes = {1, 2, 3, 4}}}, .ttl = 60}, 1000, *tok).has_value(),
                "GroupSnapshot publish peer group");
        auto adopt_hit = gs.lookup(0, {1, "peer.test", 1}, 1050, rdr);
        require(adopt_hit && adopt_hit->has_value(), "GroupSnapshot peer adopt on miss");

        std::string const sample_cfg =
            "log { level \"info\" }\n"
            "dns {\n  listen \"127.0.0.1:5353\"\n  server \"plain\" { address \"1.1.1.1:53\" }\n}\n"
            "inbound \"socks\" { type \"socks\"\n  listen \"127.0.0.1:1080\" }\n"
            "outbound \"direct\" { type \"direct\" }\n"
            "outbound \"grp\" { type \"selector\" selected \"direct\" { outbounds \"direct\" } }\n";
        auto ids = config::reload_identities(sample_cfg);
        auto i_full = config::reload_identity(sample_cfg, config::ReloadIdentity::full);
        auto i_dns = config::reload_identity(sample_cfg, config::ReloadIdentity::dns_policy);
        auto i_proc = config::reload_identity(sample_cfg, config::ReloadIdentity::process);
        require(ids && i_full && i_dns && i_proc, "reload_identities parse");
        require(ids->full == *i_full && ids->dns_policy == *i_dns && ids->process == *i_proc,
                "reload_identities parity with 3x reload_identity");

        FdGuard srv{::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0)};
        FdGuard cli{::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0)};
        sockaddr_in sa{.sin_family = AF_INET, .sin_port = 0, .sin_addr = {htonl(INADDR_LOOPBACK)}};
        socklen_t salen = sizeof(sa);
        require(::bind(srv.fd, reinterpret_cast<sockaddr*>(&sa), salen) == 0 && ::listen(srv.fd, 1) == 0, "tcp listen");
        require(::getsockname(srv.fd, reinterpret_cast<sockaddr*>(&sa), &salen) == 0, "getsockname tcp");
        require(::connect(cli.fd, reinterpret_cast<sockaddr const*>(&sa), salen) == 0, "connect tcp");
        sockaddr_in csa{}; socklen_t csalen = sizeof(csa);
        require(::getsockname(cli.fd, reinterpret_cast<sockaddr*>(&csa), &csalen) == 0, "getsockname client");
        std::array<std::uint8_t, 4> lo{127, 0, 0, 1};
        auto tup = platform::make_loopback_socket_tuple(false, lo, ntohs(csa.sin_port), lo, ntohs(sa.sin_port));
        require(tup.has_value(), "loopback socket tuple");
        tup->need_process = false;
        auto owner = platform::lookup_socket_owner(*tup);
        if (owner) require(owner->pid == 0 && owner->uid == static_cast<std::uint32_t>(::getuid()),
                           "NETLINK_SOCK_DIAG need_process=false returns uid without proc scan");

        cli::tun_enabled::TunUdpOwnerCache ucache;
        rules::Matcher m_uid;
        auto r_uid = rules::RouteMatcher::compile(std::array{rules::RouteRule{{.version = 2, .rules = {{.type = "source-uid", .value = std::to_string(::getuid())}}}, 0}},
            0, 1, rules::SourceMetadata::provided);
        require(r_uid.has_value(), "compile source-uid rule");
        struct DummyOrd { rules::RouteProgram const& program; };
        DummyOrd const* no_ord = nullptr;
        auto c_res = cli::tun_enabled::lookup_tun_owner_cached(ucache, 1000, lo, ntohs(csa.sin_port), lo, ntohs(sa.sin_port), *r_uid, no_ord);
        require(ucache.size() == 1, "TunUdpOwnerCache inserted entry");
        (void)cli::tun_enabled::lookup_tun_owner_cached(ucache, 2000, lo, ntohs(csa.sin_port), lo, ntohs(sa.sin_port), *r_uid, no_ord);
        require(ucache.size() == 1, "TunUdpOwnerCache hot hit keeps size");
        (void)cli::tun_enabled::lookup_tun_owner_cached(ucache, 7000, lo, ntohs(csa.sin_port), lo, ntohs(sa.sin_port), *r_uid, no_ord);
        require(ucache.size() == 1, "TunUdpOwnerCache TTL overwrite updates slot in place");
        cli::tun_enabled::TunUdpOwnerCache bounded_cache(4);
        for (std::uint16_t p = 1; p <= 6; ++p)
            (void)cli::tun_enabled::lookup_tun_owner_cached(bounded_cache, 1000, lo, p, lo, ntohs(sa.sin_port), *r_uid, no_ord);
        require(bounded_cache.size() == 4, "TunUdpOwnerCache ClockTable enforces capacity bound");
        cli::tun_enabled::TunUdpOwnerCache zero_cache(0);
        (void)cli::tun_enabled::lookup_tun_owner_cached(zero_cache, 1000, lo, 1, lo, ntohs(sa.sin_port), *r_uid, no_ord);
        require(zero_cache.size() == 0, "TunUdpOwnerCache zero capacity bypasses upsert safely");
        (void)c_res;
    }
}

int main() {
    test_172a();
    test_172b();
    test_172c();
    std::cout << "BATCH 172 FASTPATH UNIT TESTS PASSED\n";
    return 0;
}
