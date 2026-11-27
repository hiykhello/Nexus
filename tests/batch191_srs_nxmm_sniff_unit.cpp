#include <zlib.h>
import std;
import capy;
import corosio;
import config;
import dns.policy;
import relay;
import rules;
import rules.rule_input;
import rules.srs_file;
import rules.srs_payload;
import cli.route_files;
import cli.route_files_nxmm;
import cli.tun_route_sets;
import sniff.tcp;
import sniff.tcp_io;
import sniff.route_tcp;

namespace {
    int failures = 0;
    auto check(bool ok, std::string_view msg) -> void {
        if (!ok) { ++failures; std::cerr << "FAIL: " << msg << '\n'; }
    }

    struct TempDir {
        std::filesystem::path path;
        TempDir() {
            auto stamp = std::chrono::steady_clock::now().time_since_epoch().count();
            path = std::filesystem::temp_directory_path() / ("nexus_batch191_" + std::to_string(stamp));
            std::filesystem::create_directories(path);
        }
        ~TempDir() { std::error_code ec; std::filesystem::remove_all(path, ec); }
    };

    auto push_varint(std::vector<std::uint8_t>& out, std::uint64_t v) -> void {
        while (v >= 0x80u) { out.push_back(static_cast<std::uint8_t>((v & 0x7fu) | 0x80u)); v >>= 7; }
        out.push_back(static_cast<std::uint8_t>(v));
    }
    auto push_u64_be(std::vector<std::uint8_t>& out, std::uint64_t v) -> void {
        for (int shift = 56; shift >= 0; shift -= 8) out.push_back(static_cast<std::uint8_t>((v >> shift) & 0xffu));
    }
    auto push_str(std::vector<std::uint8_t>& out, std::string_view s) -> void {
        push_varint(out, s.size()); out.insert(out.end(), s.begin(), s.end());
    }

    auto append_succinct_trie(std::vector<std::uint8_t>& out, std::vector<std::string> raw_keys) -> void {
        for (auto& k : raw_keys) std::ranges::reverse(k);
        std::ranges::sort(raw_keys);
        raw_keys.erase(std::unique(raw_keys.begin(), raw_keys.end()), raw_keys.end());
        struct Node { std::vector<std::pair<std::uint8_t, std::size_t>> edges; bool leaf = false; };
        std::vector<Node> trie(1);
        for (auto const& key : raw_keys) {
            std::size_t cur = 0;
            for (unsigned char c : key) {
                auto it = std::ranges::find(trie[cur].edges, c, &std::pair<std::uint8_t, std::size_t>::first);
                if (it == trie[cur].edges.end()) {
                    std::size_t nxt = trie.size(); trie.emplace_back();
                    trie[cur].edges.emplace_back(c, nxt); cur = nxt;
                } else cur = it->second;
            }
            trie[cur].leaf = true;
        }
        std::vector<std::size_t> order{0};
        std::vector<std::uint8_t> labels;
        std::vector<bool> bitmap_bits, leaf_bits;
        for (std::size_t qi = 0; qi < order.size(); ++qi) {
            auto const& node = trie[order[qi]];
            leaf_bits.push_back(node.leaf);
            for (auto [lbl, child] : node.edges) { labels.push_back(lbl); bitmap_bits.push_back(false); order.push_back(child); }
            bitmap_bits.push_back(true);
        }
        auto pack = [](std::vector<bool> const& bits) {
            std::vector<std::uint64_t> words((bits.size() + 63) / 64, 0);
            for (std::size_t i = 0; i < bits.size(); ++i) if (bits[i]) words[i / 64] |= (std::uint64_t{1} << (i % 64));
            return words;
        };
        auto lw = pack(leaf_bits), bw = pack(bitmap_bits);
        out.push_back(0);
        push_varint(out, lw.size()); for (auto w : lw) push_u64_be(out, w);
        push_varint(out, bw.size()); for (auto w : bw) push_u64_be(out, w);
        push_varint(out, labels.size()); out.insert(out.end(), labels.begin(), labels.end());
    }

    auto wrap_srs_file(std::uint8_t version, std::span<std::uint8_t const> payload) -> std::string {
        uLongf bound = compressBound(static_cast<uLong>(payload.size()));
        std::string out(4 + bound, '\0');
        out[0] = 'S'; out[1] = 'R'; out[2] = 'S'; out[3] = static_cast<char>(version);
        uLongf out_len = bound;
        int rc = compress2(reinterpret_cast<Bytef*>(out.data() + 4), &out_len,
            reinterpret_cast<Bytef const*>(payload.data()), static_cast<uLong>(payload.size()), Z_BEST_COMPRESSION);
        check(rc == Z_OK, "zlib compress2 for SRS fixture");
        out.resize(4 + out_len);
        return out;
    }

    auto build_dns_tcp_query(std::string_view domain, bool with_edns = false) -> std::vector<std::uint8_t> {
        std::vector<std::uint8_t> msg{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, static_cast<std::uint8_t>(with_edns ? 1 : 0)};
        for (std::size_t start = 0; start < domain.size();) {
            auto dot = domain.find('.', start);
            auto end = dot == std::string_view::npos ? domain.size() : dot;
            auto lbl = domain.substr(start, end - start);
            msg.push_back(static_cast<std::uint8_t>(lbl.size()));
            msg.insert(msg.end(), lbl.begin(), lbl.end());
            if (dot == std::string_view::npos) break;
            start = dot + 1;
        }
        msg.insert(msg.end(), {0x00, 0x00, 0x01, 0x00, 0x01});
        if (with_edns) msg.insert(msg.end(), {0x00, 0x00, 0x29, 0x04, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00});
        std::vector<std::uint8_t> frame{static_cast<std::uint8_t>(msg.size() >> 8), static_cast<std::uint8_t>(msg.size() & 0xffu)};
        frame.insert(frame.end(), msg.begin(), msg.end());
        return frame;
    }

    auto test_srs_v2_v5_and_json() -> void {
        using namespace rules;
        std::vector<std::uint8_t> p;
        push_varint(p, 4);

        // Rule 0: AdGuard succinct trie (item 16)
        p.push_back(0); p.push_back(16);
        append_succinct_trie(p, {"\nads.test", "exact.ad.test", "\n*.sub.ad.test", "\nad*.wild.test", "\rkwmark\b"});
        p.push_back(255); p.push_back(0);

        // Rule 1: package_name (13) + package_name_regex (23) + wifi_ssid (14) + wifi_bssid (15)
        p.push_back(0);
        p.push_back(13); push_varint(p, 1); push_str(p, "com.vendor.app");
        p.push_back(23); push_varint(p, 1); push_str(p, "^com\\.vendor\\.[a-z]+$");
        p.push_back(14); push_varint(p, 1); push_str(p, "OfficeWiFi");
        p.push_back(15); push_varint(p, 1); push_str(p, "AA-BB-CC-DD-EE-FF");
        p.push_back(255); p.push_back(0);

        // Rule 2: network_type (18) + expensive (19) + constrained (20) + default_interface_address (22)
        p.push_back(0);
        p.push_back(18); push_varint(p, 2); p.push_back(0); p.push_back(1);
        p.push_back(19); p.push_back(20);
        p.push_back(22); push_varint(p, 1); push_varint(p, 4); p.insert(p.end(), {10, 20, 0, 0}); p.push_back(16);
        p.push_back(255); p.push_back(0);

        // Rule 3: network_interface_address (21) with wifi + ethernet entries
        p.push_back(0); p.push_back(21); push_varint(p, 2);
        p.push_back(0); push_varint(p, 2);
        push_varint(p, 4); p.insert(p.end(), {192, 168, 1, 0}); p.push_back(24);
        push_varint(p, 4); p.insert(p.end(), {192, 168, 2, 0}); p.push_back(24);
        p.push_back(2); push_varint(p, 1);
        push_varint(p, 4); p.insert(p.end(), {172, 16, 0, 0}); p.push_back(12);
        p.push_back(255); p.push_back(0);

        auto srs_file = wrap_srs_file(5, p);
        auto span_bytes = std::span<std::uint8_t const>(reinterpret_cast<std::uint8_t const*>(srs_file.data()), srs_file.size());
        auto strict_set = decode_srs_file(span_bytes, false, false);
        check(bool(strict_set) && strict_set->rules.size() == 4, strict_set ? "SRS v5 strict ok" : "SRS v5 strict: " + strict_set.error().message);
        auto lenient_set = decode_srs_file(span_bytes, false, true);
        check(bool(lenient_set) && lenient_set->rules.size() == 4, "SRS v5 lenient ok");

        if (strict_set) {
            auto m = Matcher::compile(*strict_set);
            check(bool(m), m ? "SRS v5 compile ok" : "SRS v5 compile: " + m.error().message);
            if (m) {
                check(m->match({.domain = "ads.test"}).value() == std::optional<std::size_t>{0}, "AdGuard ||ads.test^ apex");
                check(m->match({.domain = "x.ads.test"}).value() == std::optional<std::size_t>{0}, "AdGuard ||ads.test^ sub");
                check(m->match({.domain = "exact.ad.test"}).value() == std::optional<std::size_t>{0}, "AdGuard |exact.ad.test^");
                check(!m->match({.domain = "sub.exact.ad.test"}).value().has_value(), "AdGuard |exact^ rejects sub");
                check(m->match({.domain = "a.b.sub.ad.test"}).value() == std::optional<std::size_t>{0}, "AdGuard ||*.sub.ad.test^");
                check(!m->match({.domain = "sub.ad.test"}).value().has_value(), "AdGuard ||*.sub.ad.test^ rejects apex");
                check(m->match({.domain = "ad99.wild.test"}).value() == std::optional<std::size_t>{0}, "AdGuard ||ad*.wild.test^");
                check(m->match({.domain = "my-kwmark-host.test"}).value() == std::optional<std::size_t>{0}, "AdGuard keyword");

                MacAddress bssid{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
                check(m->match({.wifi_ssid = "OfficeWiFi", .wifi_bssid = bssid, .package_name = "com.vendor.app"}).value() == std::optional<std::size_t>{1}, "SRS items 13/14/15/23");
                check(!m->match({.wifi_ssid = "OfficeWiFi", .wifi_bssid = bssid, .package_name = "com.other.app"}).value().has_value(), "SRS item 23 regex miss");

                std::array<ProgramAddress, 1> def_addrs{ProgramAddress{{10, 20, 3, 4}, 4}};
                check(m->match({.network_type = NetworkType::cellular, .network_is_expensive = true, .network_is_constrained = true, .default_interface_addresses = def_addrs}).value() == std::optional<std::size_t>{2}, "SRS items 18/19/20/22");
                check(!m->match({.network_type = NetworkType::ethernet, .network_is_expensive = true, .network_is_constrained = true, .default_interface_addresses = def_addrs}).value().has_value(), "SRS item 18 rejects ethernet");

                std::array<NetworkInterfaceAddress, 2> both_if{
                    NetworkInterfaceAddress{NetworkType::wifi, ProgramAddress{{192, 168, 2, 44}, 4}},
                    NetworkInterfaceAddress{NetworkType::ethernet, ProgramAddress{{172, 20, 1, 5}, 4}}
                };
                std::array<NetworkInterfaceAddress, 1> wifi_only{NetworkInterfaceAddress{NetworkType::wifi, ProgramAddress{{192, 168, 2, 44}, 4}}};
                check(m->match({.network_interface_addresses = both_if}).value() == std::optional<std::size_t>{3}, "SRS item 21 match");
                check(!m->match({.network_interface_addresses = wifi_only}).value().has_value(), "SRS item 21 requires all types");
                check(!m->match({}).value().has_value(), "SRS item 21 safe false/unknown when empty");
            }
        }

        std::vector<std::uint8_t> unknown_tag{1, 0, 24, 255, 0};
        check(!decode_srs_payload(unknown_tag, false, false), "strict SRS rejects unknown item 24");

        constexpr std::string_view json_v5 = R"({
            "version": 5,
            "rules": [
                {"adguard_domain": ["||banner.example^", "|one.example^"], "package_name_regex": "^org\\.demo\\.[0-9]+$"},
                {"wifi_ssid": "Cafe", "wifi_bssid": "001122334455", "network_type": ["wifi"], "network_is_expensive": true,
                 "network_is_constrained": true, "default_interface_address": "10.0.0.0/8",
                 "network_interface_address": {"wifi": ["192.168.10.0/24"]}}
            ]
        })";
        auto jset = parse_rule_input(json_v5, InputFormat::json, false, false);
        check(bool(jset) && jset->rules.size() == 2, jset ? "JSON v5 ok" : "JSON v5: " + jset.error().message);
        if (jset) {
            auto jm = Matcher::compile(*jset);
            check(bool(jm), "JSON v5 matcher compiles");
            if (jm) {
                check(jm->match({.domain = "x.banner.example", .package_name = "org.demo.42"}).value() == std::optional<std::size_t>{0}, "JSON v5 adguard + pkg regex");
                std::array<ProgramAddress, 1> def_a{ProgramAddress{{10, 1, 2, 3}, 4}};
                std::array<NetworkInterfaceAddress, 1> net_if{NetworkInterfaceAddress{NetworkType::wifi, ProgramAddress{{192, 168, 10, 5}, 4}}};
                check(jm->match({.network_type = NetworkType::wifi, .network_is_expensive = true, .network_is_constrained = true,
                    .wifi_ssid = "Cafe", .wifi_bssid = MacAddress{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
                    .default_interface_addresses = def_a, .network_interface_addresses = net_if}).value() == std::optional<std::size_t>{1}, "JSON v5 net-if + bssid");
            }
            policy::DnsRule drule{.has_rule_set = true};
            check(policy::bind_dns_rule_set(drule, *jset), "DNS policy binds package-name-regex & network-interface-address");
            auto reqs = policy::dns_context_requirements(std::span(&drule, 1));
            check(reqs.process && reqs.network_state, "DNS context requirements track process & network_state");
        }
    }

    auto test_srs_nxmm_ordered_mmap_and_tun_cap() -> void {
        TempDir tmp;
        std::vector<std::uint8_t> payload;
        push_varint(payload, 3);
        payload.push_back(0); payload.push_back(2); append_succinct_trie(payload, {"\ngeo.example"}); payload.push_back(255); payload.push_back(0);
        payload.push_back(0); payload.push_back(6); payload.push_back(1); push_u64_be(payload, 250);
        for (unsigned i = 0; i < 250; ++i) {
            std::uint8_t b1 = static_cast<std::uint8_t>((i * 2) >> 8), b2 = static_cast<std::uint8_t>((i * 2) & 0xffu);
            push_varint(payload, 4); payload.insert(payload.end(), {10, b1, b2, 0});
            push_varint(payload, 4); payload.insert(payload.end(), {10, b1, b2, 255});
        }
        payload.push_back(255); payload.push_back(0);
        payload.push_back(0); payload.push_back(9); push_varint(payload, 1); payload.push_back(0x20); payload.push_back(0xfb);
        payload.push_back(255); payload.push_back(0);

        auto srs_bytes = wrap_srs_file(3, payload);
        auto srs_path = tmp.path / "country.srs";
        { std::ofstream f(srs_path, std::ios::binary); f.write(srs_bytes.data(), static_cast<std::streamsize>(srs_bytes.size())); }
        auto cache_dir = tmp.path / "cache";

        auto make_cfg = [&](std::filesystem::path const& cdir) {
            return std::format(R"kdl(
schema-version 1
role "client"
state {{ cache-directory "{}" }}
inbounds {{
    inbound "socks" type="socks5" {{ listen host="127.0.0.1" port=1080; authentication "none"; }}
    inbound "tun0" type="tun" {{
        interface-name "utun9"
        inet4-address "172.19.0.1/30"
        auto-route #true
        strict-route #true
        route-address-set "geo"
        route-exclude-address-set "geo"
    }}
}}
outbounds {{
    outbound "direct" type="direct"
    outbound "proxy" type="socks5" {{ server host="127.0.0.1" port=1081; }}
}}
routing {{
    rulesets {{ "geo" path="{}" format="srs"; }}
    rules sniff-timeout-ms=300 unknown="skip" udp=#true {{
        - rule-set="geo" to="proxy"
    }}
    final "direct"
}}
)kdl", cdir.string(), srs_path.string());
        };

        auto cfg = config::parse_kdl(make_cfg(cache_dir));
        check(bool(cfg), cfg ? "ordered_tcp + TUN config ok" : "config: " + cfg.error());
        if (!cfg) return;

        auto files = cli::load_route_files(*cfg, (tmp.path / "cfg.kdl").string());
        check(bool(files), files ? "load_route_files ok" : "load_route_files: " + files.error());
        if (files) {
            auto sidecar = cli::nxmm_detail::sidecar_path(cache_dir, srs_bytes, false);
            check(std::filesystem::is_regular_file(sidecar), "sidecar .nxmm created in cache_dir/nxmm");
            check(files->ordered.size() == 1 && files->ordered[0].mmap != nullptr && files->ordered[0].predicates.rules.empty(),
                "ordered_tcp uses zero-copy MmapMatcher");
            auto snap = cli::project_routes(*cfg, *files).compile(*cfg, "socks");
            check(bool(snap) && snap->ordered.has_value(), snap ? "RouteProgram compiles with mmap" : snap.error());
            if (snap && snap->ordered) {
                auto const& prog = snap->ordered->program;
                auto d = prog.next({.explicit_domain = "sub.geo.example", .port = 443, .network = rules::Network::tcp});
                auto ip = prog.next({.ip = "10.1.240.5", .port = 443, .network = rules::Network::tcp});
                auto tail = prog.next({.ip = "198.51.100.1", .port = 8443, .network = rules::Network::tcp, .domain_absent = {true, true, true, true}});
                auto miss = prog.next({.explicit_domain = "other.test", .ip = "198.51.100.1", .port = 80, .network = rules::Network::tcp});
                check(d && *d && (*d)->action.outbound == 2, "ordered_tcp mmap matches domain");
                check(ip && *ip && (*ip)->action.outbound == 2, "ordered_tcp mmap matches IP CIDR");
                check(tail && *tail && (*tail)->action.outbound == 2, "ordered_tcp mmap tail_beve matches port 8443");
                check(miss && !*miss, "ordered_tcp mmap misses unrelated flow");
            }
            auto tun_copy = *cfg->inbounds[1].tun;
            check(bool(cli::apply_tun_route_sets(tun_copy, *files)), "apply_tun_route_sets ok");
            check(tun_copy.route_includes.size() == 250 && tun_copy.route_excludes.size() == 250, "TUN CIDR cap lifted > 64 (250)");
        }

        auto files2 = cli::load_route_files(*cfg, (tmp.path / "cfg.kdl").string());
        check(bool(files2) && files2->ordered.size() == 1 && files2->ordered[0].mmap != nullptr, "second load hits sidecar .nxmm");

        auto bad_cache = tmp.path / "not_a_dir";
        { std::ofstream f(bad_cache); f << "blocker"; }
        if (auto cfg_ro = config::parse_kdl(make_cfg(bad_cache))) {
            auto fb = cli::load_route_files(*cfg_ro, (tmp.path / "cfg.kdl").string());
            check(bool(fb) && fb->ordered.size() == 1 && fb->ordered[0].mmap == nullptr && !fb->ordered[0].predicates.rules.empty(),
                "unwritable cache_dir gracefully falls back to in-memory RuleSet");
            auto tun_fb = *cfg_ro->inbounds[1].tun;
            check(bool(cli::apply_tun_route_sets(tun_fb, *fb)) && tun_fb.route_includes.size() == 250, "fallback TUN holds 250 CIDRs");
        }
    }

    auto test_sniff_parity() -> void {
        // 1. TCP DNS sniffing + rejection of invalid frames.
        {
            std::array<std::uint8_t, 512> wire{}, scratch{};
            auto q = build_dns_tcp_query("Api.Example.COM", true);
            sniff::TcpSniffer sn(wire, scratch);
            check(sn.feed(std::span(q).first(2)).status == sniff::TcpStatus::need_more, "TCP DNS 2-byte need_more");
            check(sn.feed(std::span(q).subspan(2, 10)).status == sniff::TcpStatus::need_more, "TCP DNS header need_more");
            auto s3 = sn.feed(std::span(q).subspan(12));
            check(s3.status == sniff::TcpStatus::matched && s3.protocol == sniff::TcpProtocol::dns &&
                  s3.domain == std::optional<std::string_view>("api.example.com") && s3.name_kind == sniff::TcpNameKind::domain,
                  "TCP DNS query matched with lowercase QNAME");
            auto resp = q; resp[4] |= 0x80u;
            check(sniff::inspect_dns_tcp(resp, scratch).status == sniff::ExtraSniffStatus::not_recognized, "TCP DNS response rejected");
            sniff::TcpSniffer sn_bad(wire, scratch);
            sn_bad.set_allowed_protocols(sniff::TcpSniffer::protocol_bit(sniff::TcpProtocol::dns));
            check(sn_bad.feed(resp).status == sniff::TcpStatus::not_recognized, "TcpSniffer DNS-only rejects response");
            std::array<std::uint8_t, 4> short_len{0x00, 0x05, 0x00, 0x00};
            check(sniff::inspect_dns_tcp(short_len, scratch).status == sniff::ExtraSniffStatus::not_recognized, "TCP DNS length < 12 rejected");
            sniff::TcpSniffer sn_short(wire, scratch);
            sn_short.set_allowed_protocols(sniff::TcpSniffer::protocol_bit(sniff::TcpProtocol::dns));
            check(sn_short.feed(short_len).status == sniff::TcpStatus::not_recognized, "TcpSniffer DNS-only rejects length < 12");
        }

        // 2. run_tcp_route_with_reader: TCP DNS routing + server-first port skip (25/110/143/587; implicit-TLS 465/993/995 NOT skipped).
        {
            corosio::io_context io;
            auto run_sync = [&](capy::task<sniff::RouteTcpResult> task) -> sniff::RouteTcpResult {
                std::optional<sniff::RouteTcpResult> out;
                io.restart();
                capy::run_async(io.get_executor(), [&](sniff::RouteTcpResult value) noexcept { out.emplace(std::move(value)); },
                    [](std::exception_ptr) noexcept {})(std::move(task));
                io.run();
                return std::move(*out);
            };
            std::array<rules::ProgramRule, 3> prules{{
                {rules::RuleSet{.version = 2}, {rules::ProgramActionKind::sniff}},
                {rules::RuleSet{{{"protocol", "dns"}}, 2}, {rules::ProgramActionKind::route, 1}, rules::DomainSource::sniffed},
                {rules::RuleSet{.version = 2}, {rules::ProgramActionKind::route, 0}}
            }};
            auto prog = rules::RouteProgram::compile(prules, 2);
            check(bool(prog), "TCP route program compiles");

            for (std::uint16_t port : std::array<std::uint16_t, 4>{25, 110, 143, 587}) {
                std::array<std::uint8_t, 256> wire{}, scratch{};
                sniff::TcpSniffer sn(wire, scratch);
                rules::ProgramCursor cursor;
                rules::ProgramInput input{.port = port, .network = rules::Network::tcp};
                int reader_calls = 0;
                auto reader = [&](sniff::TcpSniffer&, std::chrono::steady_clock::time_point) -> capy::task<sniff::TcpReadResult> {
                    ++reader_calls;
                    co_return sniff::TcpReadResult{sniff::TcpReadStop::deadline, sn.current(), {}};
                };
                auto res = run_sync(sniff::run_tcp_route_with_reader(*prog, cursor, input, sn, reader,
                    std::chrono::steady_clock::now() + std::chrono::seconds(1), true, sniff::UnknownRoutePolicy::skip));
                check(reader_calls == 0 && res.stop == sniff::RouteTcpStop::terminal && res.step && res.step->action.outbound == 0,
                    "server-first plaintext/STARTTLS port skips client-first peek without stalling");
            }
            for (std::uint16_t port : std::array<std::uint16_t, 3>{465, 993, 995}) {
                std::array<std::uint8_t, 256> wire{}, scratch{};
                sniff::TcpSniffer sn(wire, scratch);
                rules::ProgramCursor cursor;
                rules::ProgramInput input{.port = port, .network = rules::Network::tcp};
                int reader_calls = 0;
                auto reader = [&](sniff::TcpSniffer& target, std::chrono::steady_clock::time_point) -> capy::task<sniff::TcpReadResult> {
                    ++reader_calls;
                    co_return sniff::TcpReadResult{sniff::TcpReadStop::deadline, target.current(), {}};
                };
                auto res = run_sync(sniff::run_tcp_route_with_reader(*prog, cursor, input, sn, reader,
                    std::chrono::steady_clock::now() + std::chrono::seconds(1), true, sniff::UnknownRoutePolicy::skip));
                check(reader_calls == 1 && res.stop == sniff::RouteTcpStop::terminal && res.step && res.step->action.outbound == 0,
                    "implicit-TLS port (465/993/995) is NOT skipped on unconditional sniff");
            }
            {
                std::array<std::uint8_t, 256> wire{}, scratch{};
                sniff::TcpSniffer sn(wire, scratch);
                rules::ProgramCursor cursor;
                rules::ProgramInput input{.port = 53, .network = rules::Network::tcp};
                auto q = build_dns_tcp_query("dns.tcp.test");
                int reader_calls = 0;
                auto reader = [&](sniff::TcpSniffer& target, std::chrono::steady_clock::time_point) -> capy::task<sniff::TcpReadResult> {
                    ++reader_calls;
                    co_return sniff::TcpReadResult{sniff::TcpReadStop::classified, target.feed(q), {}};
                };
                auto res = run_sync(sniff::run_tcp_route_with_reader(*prog, cursor, input, sn, reader,
                    std::chrono::steady_clock::now() + std::chrono::seconds(1), true, sniff::UnknownRoutePolicy::skip));
                check(reader_calls == 1 && res.stop == sniff::RouteTcpStop::terminal && res.step && res.step->action.outbound == 1 &&
                      input.protocol == rules::Protocol::dns && input.sniffed_domain == std::optional<std::string_view>("dns.tcp.test"),
                      "port 53 sniffs TCP DNS and matches protocol=dns");
            }
            {
                rules::ProgramAction explicit_sniff{rules::ProgramActionKind::sniff};
                explicit_sniff.sniff_protocols = rules::protocol_mask(rules::Protocol::tls);
                std::array<rules::ProgramRule, 2> erules{{
                    {rules::RuleSet{.version = 2}, explicit_sniff},
                    {rules::RuleSet{.version = 2}, {rules::ProgramActionKind::route, 0}}
                }};
                auto eprog = rules::RouteProgram::compile(erules, 2);
                std::array<std::uint8_t, 256> wire{}, scratch{};
                sniff::TcpSniffer sn(wire, scratch);
                rules::ProgramCursor cursor;
                rules::ProgramInput input{.port = 25, .network = rules::Network::tcp};
                int reader_calls = 0;
                auto reader = [&](sniff::TcpSniffer& target, std::chrono::steady_clock::time_point) -> capy::task<sniff::TcpReadResult> {
                    ++reader_calls;
                    co_return sniff::TcpReadResult{sniff::TcpReadStop::deadline, target.current(), {}};
                };
                auto res = run_sync(sniff::run_tcp_route_with_reader(*eprog, cursor, input, sn, reader,
                    std::chrono::steady_clock::now() + std::chrono::seconds(1), true, sniff::UnknownRoutePolicy::skip));
                check(reader_calls == 1 && res.stop == sniff::RouteTcpStop::terminal, "explicit sniffer allowlist on port 25 still runs reader");
            }
        }
    }
}

int main() {
    test_srs_v2_v5_and_json();
    test_srs_nxmm_ordered_mmap_and_tun_cap();
    test_sniff_parity();
    if (!failures) std::cout << "BATCH 191 SRS/NXMM/SNIFF PARITY UNIT TESTS PASSED\n";
    return failures ? 1 : 0;
}
