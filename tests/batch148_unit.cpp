import std;
import config;
import logging;
import ntp;
import platform.netlink_abi;
import platform.network_selection;
import platform.network_state;
import platform.nftables;
import platform.socket_options;
import relay;
import rules;
import sniff.tls;
import tls.record_fragment;

namespace {
    int failures = 0;

    auto expect(bool cond, std::string_view msg) -> void {
        if (!cond) {
            std::cerr << "FAIL: " << msg << '\n';
            ++failures;
        }
    }

    auto test_log_ring() -> void {
        auto tmp = std::filesystem::temp_directory_path() / "nexus-batch148-ring-sink.log";
        std::error_code ec;
        std::filesystem::remove(tmp, ec);
        logging::set_level(logging::Level::warn);
        logging::set_ring_level(logging::Level::trace);
        auto sink = logging::file_sink({tmp, 0, 1});
        expect(sink.has_value(), "148A: file_sink failed");
        if (!sink) return;
        logging::Settings settings{};
        settings.ring_capacity = 16;
        auto logger = logging::Logger::start(std::move(*sink), 1, settings);
        expect(logger.has_value(), "148A: logger start failed");
        if (!logger) return;
        auto prod = (*logger)->producer(0);
        expect(prod.has_value(), "148A: producer failed");
        for (int i = 0; i < 18; ++i) {
            auto lvl = (i % 6 == 0) ? logging::Level::warn :
                       (i % 6 == 1) ? logging::Level::error :
                       (i % 6 == 2) ? logging::Level::info :
                       (i % 6 == 3) ? logging::Level::debug : logging::Level::trace;
            auto dom = (i % 2 == 0) ? logging::Domain::route : logging::Domain::dns;
            auto st = prod->log(dom, lvl, 100 + static_cast<std::uint32_t>(i), {}, "ring-entry-{} tag=Alpha", i);
            expect(st == logging::Submit::accepted, "148A: log submit should be accepted");
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(60));
        auto snap = (*logger)->snapshot_logs({.since_seq = 0, .limit = 64});
        expect(snap.entries.size() == 16, "148A: ring must retain bounded 16 entries");
        expect(snap.evicted >= 2, "148A: ring must evict oldest entries");
        expect(snap.latest_seq >= 18, "148A: latest_seq must advance");

        auto filtered = (*logger)->snapshot_logs({
            .since_seq = snap.entries.front().seq,
            .min_level = logging::Level::warn,
            .domain = logging::Domain::route,
            .search = "alpha",
            .limit = 64,
        });
        expect(!filtered.entries.empty(), "148A: filtered query should return warn route entries");
        for (auto const& e : filtered.entries) {
            expect(e.seq > snap.entries.front().seq, "148A: since_seq filter");
            expect(static_cast<std::uint8_t>(e.level) >= static_cast<std::uint8_t>(logging::Level::warn), "148A: level filter");
            expect(e.domain == logging::Domain::route, "148A: domain filter");
        }
        (*logger)->clear_ring();
        expect((*logger)->snapshot_logs().entries.empty(), "148A: clear_ring empties backlog");
        (void)(*logger)->drain(logging::Clock::now() + std::chrono::seconds(2));
        logging::set_ring_level(logging::Level::off);
        std::ifstream in(tmp);
        std::size_t sink_count = 0;
        for (std::string line; std::getline(in, line);) {
            if (line.contains("ring-entry-")) {
                ++sink_count;
                expect(!line.contains("trace") && !line.contains("debug") && !line.contains("info"),
                    "148A: sink must not emit below warn level");
            }
        }
        expect(sink_count == 6, "148A: sink must receive exactly 6 warn/error entries");
        std::filesystem::remove(tmp, ec);
    }

    auto test_fallback_network_and_tun_config() -> void {
        using namespace platform::network;
        namespace abi = platform::netlink_abi;
        Snapshot snap{};
        auto add_iface = [&](std::uint32_t idx, std::string name, std::uint32_t metric) {
            Link link{};
            link.index = idx;
            link.name = std::move(name);
            link.flags = abi::IFF_UP | abi::IFF_LOWER_UP;
            snap.links.push_back(std::move(link));
            Address addr{};
            addr.index = idx;
            addr.family = abi::AF_INET;
            addr.scope = abi::RT_SCOPE_UNIVERSE;
            addr.local = {10, 0, static_cast<std::uint8_t>(idx), 2};
            snap.addresses.push_back(addr);
            Route route{};
            route.index = idx;
            route.family = abi::AF_INET;
            route.table = abi::RT_TABLE_MAIN;
            route.type = abi::RTN_UNICAST;
            route.priority = metric;
            snap.routes.push_back(route);
        };
        add_iface(1, "wlan0", 100);
        add_iface(2, "wwan0", 200);
        add_iface(3, "eth0", 300);

        Policy policy{};
        policy.strategy = Strategy::fallback;
        policy.preferred = Type::wifi;
        policy.fallback = Type::cellular;
        policy.fallback_delay = std::chrono::milliseconds(300);
        policy.interfaces = {
            {"eth0", Type::ethernet},
            {"wwan0", Type::cellular},
            {"wlan0", Type::wifi},
        };
        auto cands = select_interfaces(snap, policy, false);
        expect(cands.parallel_fallback, "148B: Strategy::fallback sets parallel_fallback");
        expect(cands.indices.size() == 3 && cands.indices[0] == 1 && cands.indices[1] == 2 && cands.indices[2] == 3,
            "148B: fallback tiers ordered wifi -> cellular -> other");
        expect(cands.tiers.size() == 3 && cands.tiers[0] == 0 && cands.tiers[1] == 1 && cands.tiers[2] == 2,
            "148B: select_interfaces populates tiers in lockstep");
        expect(retry_interface_error(std::make_error_code(std::errc::operation_not_permitted)),
            "148B: EPERM is retryable interface error");

        FallbackMemory mem;
        expect(!mem.is_degraded(1, 1000), "148B: initially not degraded");
        mem.mark_failed(1, 1000);
        expect(mem.is_degraded(1, 5000), "148B: degraded within 15s window");
        expect(!mem.is_degraded(1, 16001), "148B: degradation expires after 15s");
        mem.mark_failed(1, 20000);
        mem.mark_healthy(1);
        expect(!mem.is_degraded(1, 20010), "148B: mark_healthy clears degradation");
        mem.mark_failed(1, 30000, true);
        expect(mem.is_degraded(1, 31000, true), "148B: IPv6 failure degrades IPv6");
        expect(!mem.is_degraded(1, 31000, false), "148B: IPv6 failure must not degrade IPv4");
        expect(!mem.is_degraded(1, 31000), "148B: single-family failure is not full interface degradation");
        mem.mark_failed(1, 30000, false);
        expect(mem.is_degraded(1, 31000), "148B: both families failed marks interface degraded");
        mem.mark_healthy(1, false);
        expect(!mem.is_degraded(1, 31000, false) && mem.is_degraded(1, 31000, true),
            "148B: mark_healthy(v4) clears IPv4 only");

        std::array<std::size_t, 1> dns_extra{37};
        auto wide = relay::compile_routes({}, 42, 45, std::nullopt, std::nullopt, {}, dns_extra);
        expect(wide.has_value() && wide->tunnel_references.has_value(),
            "148B: compile_routes supports >32 tunnels in tunnel_references");
        if (wide && wide->tunnel_references) {
            expect(wide->tunnel_references->test(40) && wide->tunnel_references->test(35),
                "148B: fallback >32 and extra DNS outbound set in bitset");
            expect(!wide->tunnel_references->test(0) && !wide->tunnel_references->test(41),
                "148B: unreferenced tunnel bits remain clear");
        }
        auto max_wide = relay::compile_routes({}, 257, 258, std::nullopt, std::nullopt);
        expect(max_wide && max_wide->tunnel_references && max_wide->tunnel_references->test(255),
            "148B: compile_routes supports 256 tunnels (bit 255)");
        auto dist = std::make_shared<rules::OutboundDistribution>(rules::OutboundDistribution{4, {{2, 3}}});
        auto with_dist = relay::compile_routes({}, 4, 4, std::nullopt, std::nullopt, dist);
        expect(with_dist && with_dist->matcher.distribution() == dist &&
            with_dist->tunnel_references && with_dist->tunnel_references->test(0) && with_dist->tunnel_references->test(1),
            "148B: compile_routes exposes distribution() and expands group members");

        auto ok_tun = config::parse_kdl(R"(
schema-version 1
role "client"
inbounds {
    inbound "t" type="tun" {
        interface-name "utun0"
        inet4-address "172.19.0.1/30"
        exclude-package "com.android.captiveportallogin"
        multi-queue #true
    }
}
outbounds {
    outbound "direct" type="direct" {
        network strategy="fallback" type="wifi" fallback="cellular" fallback-delay-ms=350 {
            interface "wlan0" type="wifi"
            interface "wwan0" type="cellular"
        }
    }
}
routing { default-outbound "direct" }
)");
        expect(ok_tun.has_value(), ok_tun ? std::string_view("ok") : std::string_view(ok_tun.error()));
        if (ok_tun) {
            expect(ok_tun->direct_network && ok_tun->direct_network->strategy == Strategy::fallback, "148B: parsed fallback strategy");
            expect(ok_tun->inbounds[0].tun->exclude_packages.size() == 1, "148B: parsed exclude-package");
            expect(ok_tun->inbounds[0].tun->multi_queue, "148C: parsed multi-queue");
        }
        auto ok_mptcp = config::parse_kdl(R"(
schema-version 1
role "client"
inbounds {
    inbound "t" type="tun" {
        interface-name "utun0"
        inet4-address "172.19.0.1/30"
        auto-route #true
        strict-route #true
        auto-redirect #true
        socket-mark 100
        exclude-mptcp #true
        multi-queue #true
    }
}
outbounds { outbound "direct" type="direct" { routing-mark 100; }; }
routing { default-outbound "direct" }
)");
        expect(ok_mptcp.has_value(), ok_mptcp ? std::string_view("ok") : std::string_view(ok_mptcp.error()));
        if (ok_mptcp) {
            expect(ok_mptcp->inbounds[0].tun->exclude_mptcp && ok_mptcp->inbounds[0].tun->multi_queue, "148C: parsed exclude-mptcp & multi-queue");
        }
        auto bad_strict = config::parse_kdl(R"(
schema-version 1
role "client"
inbounds {
    inbound "t" type="tun" {
        interface-name "utun0"
        inet4-address "172.19.0.1/30"
        strict-route #true
        exclude-package "com.example.app"
    }
}
outbounds { outbound "direct" type="direct"; }
routing { default-outbound "direct" }
)");
        expect(!bad_strict.has_value(), "148B: strict-route + exclude-package must be rejected");
    }

    auto test_nftables_mptcp_and_reject_guard() -> void {
        platform::nftables::Redirect r{};
        r.port = 12345;
        r.ipv4 = true;
        r.socket_mark = 100;
        r.exclude_mptcp = false;
        auto base = platform::nftables::encode("nexus_auto_redirect_test", &r, 1);
        r.exclude_mptcp = true;
        auto with_mptcp = platform::nftables::encode("nexus_auto_redirect_test", &r, 1);
        expect(base.has_value() && with_mptcp.has_value(), "148C: nftables encode must succeed");
        if (base && with_mptcp) {
            expect(with_mptcp->bytes.size() > base->bytes.size(), "148C: exclude_mptcp must emit extra netlink rule");
        }

        relay::RejectStormGuard guard;
        auto t0 = std::chrono::steady_clock::now();
        expect(guard.should_drop(rules::RejectMethod::drop, false, t0), "148C: method=drop always drops");
        for (int i = 0; i < 60; ++i) {
            expect(!guard.should_drop(rules::RejectMethod::default_rst, true, t0 + std::chrono::milliseconds(i)),
                "148C: no-drop bypasses storm guard");
        }
        for (int i = 0; i < 50; ++i) {
            expect(!guard.should_drop(rules::RejectMethod::default_rst, false, t0 + std::chrono::milliseconds(i)),
                "148C: first 50 rejects send default reply");
        }
        expect(guard.should_drop(rules::RejectMethod::default_rst, false, t0 + std::chrono::seconds(1)),
            "148C: 51st reject within 30s switches to silent drop");
        expect(!guard.should_drop(rules::RejectMethod::default_rst, false, t0 + std::chrono::seconds(31)),
            "148C: window expires after 30s");

        auto cfg = config::parse_kdl(R"(
schema-version 1
role "client"
inbounds {
    inbound "socks" type="socks5" {
        listen host="127.0.0.1" port=1080
        authentication "none"
    }
}
outbounds { outbound "direct" type="direct"; }
routing {
    default-outbound "direct"
    tcp-program sniff-timeout-ms=1000 unknown="skip" {
        rule action="route-options" tls-record-fragment=#true tls-fragment-min=8 tls-fragment-max=24 tcp-prefix="47455420"
        rule action="reject" method="drop"
        rule action="reject" no-drop=#true
        rule action="route" outbound="direct"
    }
}
)");
        expect(cfg.has_value(), cfg ? std::string_view("ok") : std::string_view(cfg.error()));
        if (cfg && cfg->ordered_tcp) {
            auto const& r0 = cfg->ordered_tcp->rules[0];
            expect(r0.tls_record_fragment && r0.tls_fragment_min == 8 && r0.tls_fragment_max == 24 && r0.tcp_prefix_len == 4,
                "148D: route-options evasion fields");
            expect(cfg->ordered_tcp->rules[1].reject_method == rules::RejectMethod::drop, "148C: reject drop parsed");
            expect(cfg->ordered_tcp->rules[2].reject_no_drop, "148C: reject no-drop parsed");
        }
    }

    auto make_sample_client_hello(std::string_view sni) -> std::vector<std::uint8_t> {
        std::vector<std::uint8_t> body;
        body.push_back(0x03); body.push_back(0x03); // TLS 1.2 legacy version
        for (int i = 0; i < 32; ++i) body.push_back(static_cast<std::uint8_t>(i)); // random
        body.push_back(0); // session_id len
        body.push_back(0); body.push_back(2); body.push_back(0x13); body.push_back(0x01); // cipher suite
        body.push_back(1); body.push_back(0); // compression
        std::vector<std::uint8_t> ext;
        std::size_t list_len = 3 + sni.size();
        std::size_t ext_len = 2 + list_len;
        ext.push_back(0); ext.push_back(0); // SNI extension type 0
        ext.push_back(static_cast<std::uint8_t>(ext_len >> 8)); ext.push_back(static_cast<std::uint8_t>(ext_len));
        ext.push_back(static_cast<std::uint8_t>(list_len >> 8)); ext.push_back(static_cast<std::uint8_t>(list_len));
        ext.push_back(0); // host_name
        ext.push_back(static_cast<std::uint8_t>(sni.size() >> 8)); ext.push_back(static_cast<std::uint8_t>(sni.size()));
        ext.insert(ext.end(), sni.begin(), sni.end());
        body.push_back(static_cast<std::uint8_t>(ext.size() >> 8)); body.push_back(static_cast<std::uint8_t>(ext.size()));
        body.insert(body.end(), ext.begin(), ext.end());

        std::vector<std::uint8_t> hs;
        hs.push_back(0x01);
        hs.push_back(static_cast<std::uint8_t>(body.size() >> 16));
        hs.push_back(static_cast<std::uint8_t>(body.size() >> 8));
        hs.push_back(static_cast<std::uint8_t>(body.size()));
        hs.insert(hs.end(), body.begin(), body.end());

        std::vector<std::uint8_t> rec;
        rec.push_back(0x16); rec.push_back(0x03); rec.push_back(0x01);
        rec.push_back(static_cast<std::uint8_t>(hs.size() >> 8));
        rec.push_back(static_cast<std::uint8_t>(hs.size()));
        rec.insert(rec.end(), hs.begin(), hs.end());
        return rec;
    }

    auto test_tls_fragment_cert_pins_and_ntp() -> void {
        auto ch = make_sample_client_hello("fragment.example.test");
        expect(tls::is_tls_client_hello_record(ch), "148D: valid ClientHello detected");
        auto frag = tls::fragment_tls_client_hello(ch, 8, 20, 42);
        expect(frag.size() > ch.size() + 5, "148D: ClientHello split into multiple TLS records");
        std::size_t off = 0, records = 0;
        while (off < frag.size()) {
            expect(off + 5 <= frag.size() && frag[off] == 0x16 && frag[off + 1] == 0x03, "148D: valid TLS record header");
            auto rlen = (std::size_t{frag[off + 3]} << 8) | frag[off + 4];
            expect(rlen > 0 && off + 5 + rlen <= frag.size(), "148D: valid TLS record length");
            off += 5 + rlen;
            ++records;
        }
        expect(records >= 3, "148D: ClientHello fragmented into >= 3 records");
        std::array<std::uint8_t, 4096> scratch{};
        sniff::TlsSniffer sniffer;
        auto step = sniffer.feed(frag, scratch);
        expect(step.status == sniff::TlsStatus::matched && step.server_name == "fragment.example.test",
            "148D: fragmented ClientHello reassembles identically with exact SNI");

        std::vector<std::uint8_t> plain{'G', 'E', 'T', ' ', '/', '\r', '\n'};
        expect(tls::fragment_tls_client_hello(plain, 2, 4) == plain, "148D: non-TLS left untouched");

        auto cert_cfg = config::parse_kdl(R"(
schema-version 1
role "client"
certificate { ca-file "/etc/ssl/certs/test-ca.pem"; }
ntp {
    server host="127.0.0.1" port=1123
    interval-ms 60000
    timeout-ms 1500
}
inbounds {
    inbound "socks" type="socks5" {
        listen host="127.0.0.1" port=1080
        authentication "none"
    }
}
outbounds {
    outbound "direct" type="direct"
    outbound "vl" type="vless" {
        server host="127.0.0.1" port=443
        authentication { uuid-file "/tmp/u"; }
        tls { server-name "vl.example"; verify #true; certificate-sha256 "01:23:45:67:89:ab:cd:ef:01:23:45:67:89:ab:cd:ef:01:23:45:67:89:ab:cd:ef:01:23:45:67:89:ab:cd:ef"; }
    }
    outbound "hp" type="http-connect" {
        server host="127.0.0.1" port=8443
        tls { server-name "hp.example"; verify #true; certificate-sha256 "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"; }
    }
    outbound "hy" type="hysteria2" {
        server host="127.0.0.1" port=4433
        authentication { password-file "/tmp/p"; }
        tls { server-name "hy.example"; verify #true; certificate-sha256 "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"; }
    }
    outbound "tu" type="tuic" {
        server host="127.0.0.1" port=4434
        authentication { uuid-file "/tmp/u"; password-file "/tmp/p"; }
        tls { server-name "tu.example"; verify #true; certificate-sha256 "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"; }
    }
    outbound "mq" type="masque" {
        server host="127.0.0.1" port=4435
        authority "mq.example"
        authentication { bearer-file "/tmp/b"; }
        tls { server-name "mq.example"; verify #true; certificate-sha256 "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"; }
    }
    outbound "pool" type="selector" {
        member "vl"
        member "hp"
        member "hy"
        member "tu"
        member "mq"
        selected "vl"
    }
}
routing { default-outbound "pool" }
)");
        expect(cert_cfg.has_value(), cert_cfg ? std::string_view("ok") : std::string_view(cert_cfg.error()));
        if (cert_cfg) {
            expect(cert_cfg->ntp && cert_cfg->ntp->host == "127.0.0.1" && cert_cfg->ntp->port == 1123, "148D: ntp parsed");
            expect(cert_cfg->vless_outbounds[0].config.ca_file == "/etc/ssl/certs/test-ca.pem", "148D: vless inherited CA");
            expect(cert_cfg->vless_outbounds[0].config.certificate_sha256.size() == 1, "148D: vless pin parsed");
            expect(cert_cfg->tcp_proxy_outbounds[0].config.tls->ca_file == "/etc/ssl/certs/test-ca.pem", "148D: http inherited CA");
            expect(cert_cfg->tcp_proxy_outbounds[0].config.tls->certificate_sha256.size() == 1, "148D: http pin parsed");
            expect(cert_cfg->hysteria2_outbounds[0].config.connection.ca_file == "/etc/ssl/certs/test-ca.pem", "148D: hy2 inherited CA");
            expect(cert_cfg->hysteria2_outbounds[0].config.connection.certificate_sha256.size() == 1, "148D: hy2 pin parsed");
            expect(cert_cfg->tuic_outbounds[0].config.ca_file == "/etc/ssl/certs/test-ca.pem", "148D: tuic inherited CA");
            expect(cert_cfg->tuic_outbounds[0].config.certificate_sha256.size() == 1, "148D: tuic pin parsed");
            expect(cert_cfg->masque_outbounds[0].config.ca_file == "/etc/ssl/certs/test-ca.pem", "148D: masque inherited CA");
            expect(cert_cfg->masque_outbounds[0].config.certificate_sha256.size() == 1, "148D: masque pin parsed");
        }

        // SNTPv4 codec verification
        std::int64_t t1 = 1760000000000LL;
        std::int64_t t2 = t1 + 130; // server +120ms ahead + 10ms one-way
        std::int64_t t3 = t2 + 2;   // 2ms processing
        std::int64_t t4 = t1 + 22;  // 22ms total RTT -> delay 20ms, offset +120ms
        auto origin = ntp::unix_ms_to_ntp(t1);
        auto req = ntp::encode_request(origin);
        expect(req[0] == 0x23, "148D: SNTPv4 client request header");
        std::array<std::uint8_t, 48> resp{};
        resp[0] = 0x24; // LI=0, VN=4, Mode=4 (server)
        resp[1] = 2;    // stratum 2
        auto put32 = [&](std::size_t pos, std::uint32_t v) {
            resp[pos] = static_cast<std::uint8_t>(v >> 24);
            resp[pos + 1] = static_cast<std::uint8_t>(v >> 16);
            resp[pos + 2] = static_cast<std::uint8_t>(v >> 8);
            resp[pos + 3] = static_cast<std::uint8_t>(v);
        };
        auto ts2 = ntp::unix_ms_to_ntp(t2);
        auto ts3 = ntp::unix_ms_to_ntp(t3);
        put32(24, origin.seconds); put32(28, origin.fraction);
        put32(32, ts2.seconds);    put32(36, ts2.fraction);
        put32(40, ts3.seconds);    put32(44, ts3.fraction);
        auto decoded = ntp::decode_response(resp, origin, t1, t4);
        expect(decoded.has_value(), "148D: valid SNTPv4 response decoded");
        if (decoded) {
            expect(std::abs(decoded->offset_ms - 120) <= 2, "148D: SNTPv4 offset ~+120ms");
            expect(std::abs(decoded->delay_ms - 20) <= 2, "148D: SNTPv4 delay ~20ms");
            expect(decoded->stratum == 2, "148D: SNTPv4 stratum");
            ntp::ClockCalibrator cal;
            cal.apply(*decoded);
            expect(cal.sync_count() == 1 && std::abs(cal.offset_ms() - 120) <= 2, "148D: ClockCalibrator applied");
        }
        auto kod = resp; kod[1] = 0;
        expect(ntp::decode_response(kod, origin, t1, t4).error() == ntp::SntpError::kiss_of_death, "148D: KoD rejected");
        auto bad_origin = resp; bad_origin[24] ^= 0xff;
        expect(ntp::decode_response(bad_origin, origin, t1, t4).error() == ntp::SntpError::origin_mismatch, "148D: origin mismatch rejected");
    }
}

int main() {
    test_log_ring();
    test_fallback_network_and_tun_config();
    test_nftables_mptcp_and_reject_guard();
    test_tls_fragment_cert_pins_and_ntp();
    if (failures) {
        std::cerr << "batch148-unit failed: " << failures << " error(s)\n";
        return 1;
    }
    std::cout << "batch148-unit PASSED\n";
    return 0;
}
