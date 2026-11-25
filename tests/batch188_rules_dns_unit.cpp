import std;
import capy;
import corosio;
import cli.dns_transports;
import cli.rule_explain_query;
import config;
import dns.corosio_query;
import dns.corosio_resolver;
import dns.input_budget;
import dns.message;
import dns.message_cache;
import dns.message_program;
import dns.policy;
import dns.predefined;
import dns.response_match;
import dns.reverse;
import platform.ip_address;
import rules;
import rules.kdl_predicate;
import rules.regex;
import sniff.route_tcp;
import sniff.tcp;
import sniff.tls;

namespace {
    auto require(bool ok, std::string_view msg) -> void {
        if (!ok) {
            std::cerr << "FAIL: " << msg << '\n';
            std::exit(1);
        }
    }

    auto make_tls_client_hello(std::string_view sni, std::vector<std::uint16_t> const& ciphers,
        std::vector<std::uint16_t> const& ext_types) -> std::vector<std::uint8_t> {
        auto push_u16 = [](std::vector<std::uint8_t>& out, std::uint16_t v) {
            out.push_back(static_cast<std::uint8_t>(v >> 8));
            out.push_back(static_cast<std::uint8_t>(v & 0xff));
        };
        std::vector<std::uint8_t> exts;
        if (!sni.empty()) {
            push_u16(exts, 0);
            push_u16(exts, static_cast<std::uint16_t>(sni.size() + 5));
            push_u16(exts, static_cast<std::uint16_t>(sni.size() + 3));
            exts.push_back(0);
            push_u16(exts, static_cast<std::uint16_t>(sni.size()));
            exts.insert(exts.end(), sni.begin(), sni.end());
        }
        for (auto et : ext_types) {
            push_u16(exts, et);
            push_u16(exts, 0);
        }
        std::vector<std::uint8_t> body;
        push_u16(body, 0x0303);
        body.insert(body.end(), 32, 0x11);
        body.push_back(0);
        push_u16(body, static_cast<std::uint16_t>(ciphers.size() * 2));
        for (auto cs : ciphers) push_u16(body, cs);
        body.push_back(1);
        body.push_back(0);
        push_u16(body, static_cast<std::uint16_t>(exts.size()));
        body.insert(body.end(), exts.begin(), exts.end());

        std::vector<std::uint8_t> rec{22, 3, 1, 0, 0};
        auto hs_len = body.size() + 4;
        rec[3] = static_cast<std::uint8_t>(hs_len >> 8);
        rec[4] = static_cast<std::uint8_t>(hs_len & 0xff);
        rec.push_back(1);
        rec.push_back(static_cast<std::uint8_t>(body.size() >> 16));
        rec.push_back(static_cast<std::uint8_t>(body.size() >> 8));
        rec.push_back(static_cast<std::uint8_t>(body.size() & 0xff));
        rec.insert(rec.end(), body.begin(), body.end());
        return rec;
    }

    auto run_hosts_query(dns::detail::ProtectedQuery const& qfn, corosio::io_context& io,
        std::string name, std::uint16_t type) -> capy::task<std::expected<dns::Response, dns::detail::UdpError>> {
        dns::QueryMessage msg{42, 0x0100, {std::move(name), type}, std::nullopt};
        auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
        co_return co_await qfn(io, corosio::endpoint(corosio::ipv4_address({127, 0, 0, 1}), 53),
            msg, 42, deadline, dns::default_upstream_receive_budget(), {});
    }

    auto run_msg_program(corosio::io_context& io, std::span<policy::DnsRule const> rules,
        std::span<dns::MessageUpstream const> upstreams, std::size_t fallback, dns::MessageCache* cache,
        bool independent_cache, std::string qname, std::uint16_t qtype, policy::DnsContext ctx,
        dns::ReverseCache* reverse = nullptr)
        -> capy::task<std::expected<dns::Bytes, dns::detail::ResolveError>> {
        dns::MessageProgram prog(io, rules, upstreams, fallback, cache, false, {}, nullptr, {}, reverse, independent_cache);
        dns::QueryMessage query{77, 0x0100, {std::move(qname), qtype}, std::nullopt};
        co_return co_await prog.run(std::move(query),
            std::chrono::steady_clock::now() + std::chrono::seconds(2), ctx);
    }

    template<class T>
    auto sync_run(corosio::io_context& io, capy::task<T> task) -> T {
        std::optional<T> out;
        auto wrapper = [](capy::task<T> t, std::optional<T>* dst) -> capy::task<> {
            *dst = co_await std::move(t);
        };
        capy::run_async(io.get_executor())(wrapper(std::move(task), &out));
        io.run();
        io.restart();
        require(out.has_value(), "async task completed");
        return std::move(*out);
    }

    auto make_mock_cname_upstream(std::atomic<unsigned>& hits) -> std::shared_ptr<dns::detail::ProtectedQuery const> {
        return std::make_shared<dns::detail::ProtectedQuery>([&hits](corosio::io_context&, corosio::endpoint,
            dns::QueryMessage const& query, std::uint16_t id, std::chrono::steady_clock::time_point,
            dns::InputBudget&, std::stop_token) -> capy::task<std::expected<dns::Response, dns::detail::UdpError>> {
            ++hits;
            policy::PredefinedResponse def{.rcode = 0};
            def.records.push_back({policy::ResponseSection::answer, "@", 5, 1, 120,
                {4, 'e', 'd', 'g', 'e', 3, 'c', 'd', 'n', 4, 't', 'e', 's', 't', 0}});
            def.records.push_back({policy::ResponseSection::answer, "edge.cdn.test", 1, 1, 60, {93, 184, 216, 34}});
            auto built = dns::predefined_response(def, query.question);
            if (!built) co_return std::unexpected(dns::detail::UdpError::protocol);
            auto wire = dns::encode_response(*built, id, {});
            if (!wire) co_return std::unexpected(dns::detail::UdpError::protocol);
            auto parsed = dns::parse_owned_response(std::move(*wire), id, query.question);
            if (!parsed) co_return std::unexpected(dns::detail::UdpError::protocol);
            co_return std::move(*parsed);
        });
    }

    auto test_predicates_and_config() -> void {
        rules::RuleSet set{.version = 2};
        set.rules = {
            {"network-type", "wifi"},
            {"network-is-expensive", "true"},
            {"network-is-constrained", "false"},
            {"wifi-ssid", "CorpNet"},
            {"wifi-bssid", "00:11:22:33:44:55"},
            {"default-interface-address", "10.0.0.0/24"},
            {"ip-accept-any", "true"},
            {"source-ip-accept-any", "true"},
            {"source-gid", "1001"},
            {"source-user", "alice"},
            {"package-name", "com.example.app"},
            {"client", "chromium"},
            {"route-mode", "global"},
        };
        auto matcher = rules::Matcher::compile(set);
        require(matcher.has_value(), matcher ? "" : matcher.error().message);
        std::array<rules::ProgramAddress, 1> def_if{rules::ProgramAddress{{10, 0, 0, 5}, 4}};
        rules::MatchInput full{
            .ip = "1.1.1.1", .source_ip = "192.168.1.10", .source_interface = "wlan0",
            .route_mode = rules::RouteMode::global, .network_type = rules::NetworkType::wifi,
            .network_is_expensive = true, .network_is_constrained = false,
            .wifi_ssid = "CorpNet", .wifi_bssid = rules::MacAddress{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
            .default_interface_addresses = def_if, .source_gid = 1001, .source_user = "alice",
            .package_name = "com.example.app", .client = "chromium",
        };
        require(*matcher->match(full) == 0, "network-type wifi matches");
        require(*matcher->match({.network_is_expensive = true}) == 1, "expensive true matches");
        require(*matcher->match({.network_is_constrained = false}) == 2, "constrained false matches");
        require(*matcher->match({.wifi_ssid = "CorpNet"}) == 3, "wifi-ssid matches");
        require(*matcher->match({.wifi_bssid = rules::MacAddress{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}}) == 4, "wifi-bssid matches");
        require(*matcher->match({.default_interface_addresses = def_if}) == 5, "default-interface-address matches");
        require(*matcher->match({.ip = "8.8.8.8"}) == 6, "ip-accept-any matches");
        require(*matcher->match({.source_ip = "10.1.1.1"}) == 7, "source-ip-accept-any matches");
        require(*matcher->match({.source_gid = 1001}) == 8, "source-gid matches");
        require(*matcher->match({.source_user = "alice"}) == 9, "source-user matches");
        require(*matcher->match({.package_name = "com.example.app"}) == 10, "package-name matches");
        require(*matcher->match({.client = "Chromium"}) == 11, "client case-insensitive matches");
        require(*matcher->match({.route_mode = rules::RouteMode::global}) == 12, "route-mode global matches");
        require(!rules::Matcher::compile(rules::RuleSet{{{"clash-mode", "global"}}, 2}), "legacy clash-mode alias rejected");

        auto cfg = config::parse_kdl(R"kdl(
schema-version 1
role "client"
inbound "socks" type="socks5" {
    listen host="127.0.0.1" port=1080
    authentication "none"
}
outbound "direct" type="direct"
outbound "proxy" type="socks5" {
    server host="127.0.0.1" port=1081
}
dns {
    independent-cache #true
    server "main" type="local"
    server "doh" type="udp" host="127.0.0.1" port=5353
    rules {
        - domain-regex="^api-[0-9]+\\.test$" action="route" server="doh" strategy="ipv4-only" client="chromium" package-name="com.example.app"
        - domain="blocked.test" action="reject" reject-rcode="NXDOMAIN"
        - "domain-regex" "^v6only\\.test$" action="route" to="main" strategy="ipv6-only"
    }
    final "main"
}
routing {
    rules sniff-timeout-ms=300 unknown="skip" udp=#true {
        - sniff sniffer="http,tls" override-destination=#true sniff-timeout-ms=250
        - resolve strategy="prefer-ipv4" server="doh" disable-cache=#true rewrite-ttl=180 client-subnet="198.51.100.5/24"
        - route-options udp-disable-domain-unmapping=#true
        - client "chromium" to="proxy"
        - network-type "wifi" to="proxy"
        - package-name "com.example.app" to="proxy"
        - route-mode "direct" to="direct"
    }
    default "proxy"
}
)kdl");
        require(cfg.has_value(), cfg ? "" : cfg.error());
        require(cfg->dns && cfg->dns->independent_cache, "dns independent-cache parsed");
        require(cfg->dns->rules[0].pattern == policy::DnsPattern::regex, "dns domain-regex parsed");
        require(cfg->dns->rules[0].strategy == rules::DnsRuleStrategy::ipv4_only, "dns rule strategy parsed");
        require(cfg->dns->rules[1].reject_rcode == std::optional<std::uint8_t>{3}, "dns reject-rcode NXDOMAIN parsed");
        require(cfg->ordered_tcp && cfg->ordered_tcp->rules.size() == 7, "ergonomic tcp-program rules parsed");
        auto const& sniff_act = cfg->ordered_tcp->rules[0].extra;
        require(sniff_act.sniff_override_destination && sniff_act.sniff_timeout_ms == 250 &&
            (sniff_act.sniff_protocols & rules::protocol_mask(rules::Protocol::tls)) &&
            !(sniff_act.sniff_protocols & rules::protocol_mask(rules::Protocol::ssh)), "sniff options parsed");
        auto const& res_act = cfg->ordered_tcp->rules[1].extra;
        require(res_act.resolve_strategy == rules::DnsRuleStrategy::prefer_ipv4 && res_act.resolve_server == 1 &&
            res_act.resolve_disable_cache == true && res_act.resolve_rewrite_ttl == 180 &&
            res_act.resolve_client_subnet && res_act.resolve_client_subnet->bits == 24 &&
            res_act.resolve_client_subnet->address[3] == 0, "resolve options & bound server parsed");
        require(cfg->ordered_tcp->rules[2].extra.udp_disable_domain_unmapping, "udp-disable-domain-unmapping parsed");
    }

    auto test_sniff_fingerprints() -> void {
        std::array<std::uint8_t, 512> wire{}, scratch{};
        // 1. Chromium TLS (GREASE + ALPS 0x44cd)
        auto ch_chrome = make_tls_client_hello("app.test", {0x0a0au, 0x1301u}, {0x44cdu});
        {
            sniff::TcpSniffer sn(wire, scratch);
            auto st = sn.feed(ch_chrome);
            require(st.status == sniff::TcpStatus::matched && st.protocol == sniff::TcpProtocol::tls &&
                st.domain == "app.test" && st.client == "chromium", "TLS chromium fingerprint");
        }
        // 2. Safari TLS (GREASE without ALPS/cert-compress)
        auto ch_safari = make_tls_client_hello("saf.test", {0x2a2au, 0x1301u}, {0x0010u});
        {
            sniff::TcpSniffer sn(wire, scratch);
            auto st = sn.feed(ch_safari);
            require(st.status == sniff::TcpStatus::matched && st.client == "safari", "TLS safari fingerprint");
        }
        // 3. Firefox TLS (no GREASE + 0x001c record_size_limit)
        auto ch_ff = make_tls_client_hello("ff.test", {0x1301u}, {0x001cu});
        {
            sniff::TcpSniffer sn(wire, scratch);
            auto st = sn.feed(ch_ff);
            require(st.status == sniff::TcpStatus::matched && st.client == "firefox", "TLS firefox fingerprint");
        }
        // 4. Protocol allowlist gating: HTTP-only rejects TLS
        {
            sniff::TcpSniffer sn(wire, scratch);
            sn.set_allowed_protocols(sniff::TcpSniffer::protocol_bit(sniff::TcpProtocol::http));
            auto st = sn.feed(ch_chrome);
            require(st.status == sniff::TcpStatus::not_recognized, "HTTP-only allowlist ignores TLS");
        }
        // 5. HTTP User-Agent + SSH + BitTorrent client fingerprints
        auto feed_text = [&](std::string_view s) {
            sniff::TcpSniffer sn(wire, scratch);
            return sn.feed(std::span<std::uint8_t const>(reinterpret_cast<std::uint8_t const*>(s.data()), s.size()));
        };
        require(feed_text("GET / HTTP/1.1\r\nHost: ex.test\r\nUser-Agent: curl/8.5.0\r\n\r\n").client == "curl", "HTTP curl");
        require(feed_text("GET / HTTP/1.1\r\nHost: ex.test\r\nUser-Agent: Go-http-client/1.1\r\n\r\n").client == "go-http", "HTTP go-http");
        require(feed_text("GET / HTTP/1.1\r\nHost: ex.test\r\nUser-Agent: Mozilla/5.0 Firefox/124.0\r\n\r\n").client == "firefox", "HTTP firefox");
        require(feed_text("GET / HTTP/1.1\r\nHost: ex.test\r\nUser-Agent: Version/17.0 Safari/605.1.15\r\n\r\n").client == "safari", "HTTP safari");
        require(feed_text("SSH-2.0-OpenSSH_9.6\r\n").client == "openssh", "SSH openssh");
        require(feed_text("SSH-2.0-PuTTY_Release_0.80\r\n").client == "putty", "SSH putty");
        require(feed_text("SSH-2.0-Go\r\n").client == "golang-ssh", "SSH golang-ssh");
        require(feed_text("SSH-2.0-libssh_0.10.6\r\n").client == "libssh", "SSH libssh");
        std::string bt("\x13" "BitTorrent protocol");
        require(feed_text(bt).client == "bittorrent", "BT client");
    }

    auto test_dns_engine_and_hosts() -> void {
        corosio::io_context io;
        // 1. Hosts wildcard, suffix, exact override, and CNAME chasing
        auto cfg = config::parse_kdl(R"kdl(
schema-version 1
role "client"
inbound "socks" type="socks5" {
    listen host="127.0.0.1" port=1080
    authentication "none"
}
outbound "direct" type="direct"
dns {
    server "hosts" type="hosts" {
        entry host="exact.wild.test" ip="192.0.2.1"
        entry host="*.wild.test" ip="192.0.2.2"
        entry host=".sfx.test" ip="192.0.2.3,2001:db8::3"
        entry host="alias.test" cname="sub.wild.test"
    }
    final "hosts"
}
routing { default-outbound "direct" }
)kdl");
        require(cfg.has_value(), cfg ? "" : cfg.error());
        auto transports = cli::prepare_dns_transports(*cfg);
        require(transports.has_value() && (*transports)[0], "hosts prepared");
        auto const& hq = *(*transports)[0];
        auto r_exact = sync_run(io, run_hosts_query(hq, io, "exact.wild.test", 1));
        require(r_exact && r_exact->rcode == 0 && r_exact->records.size() == 1 &&
            r_exact->wire.size() >= 4, "exact overrides wildcard");
        auto r_wild = sync_run(io, run_hosts_query(hq, io, "sub.wild.test", 1));
        require(r_wild && r_wild->rcode == 0 && r_wild->records.size() == 1, "wildcard matched");
        auto r_sfx = sync_run(io, run_hosts_query(hq, io, "sfx.test", 28));
        require(r_sfx && r_sfx->rcode == 0 && r_sfx->records.size() == 1, "suffix AAAA matched base");
        auto r_cname = sync_run(io, run_hosts_query(hq, io, "alias.test", 1));
        require(r_cname && r_cname->rcode == 0 && r_cname->records.size() == 2 &&
            r_cname->records[0].type == 5 && r_cname->records[0].cname == std::optional<std::string>("sub.wild.test") &&
            r_cname->records[1].type == 1, "hosts CNAME chased to A record");

        // 2. Response CNAME condition matching (suffix + regex)
        policy::ResponseCondition cname_cond;
        cname_cond.cname.push_back({"cdn.test", policy::DnsPattern::name, true, false, {}});
        auto re = rules::BoundedRegex::compile("^edge\\.cdn\\.");
        require(re.has_value(), "compile cname regex");
        cname_cond.cname.push_back({"^edge\\.cdn\\.", policy::DnsPattern::regex, false, false, std::move(*re)});
        std::atomic<unsigned> hits{0};
        auto mock_q = make_mock_cname_upstream(hits);
        dns::QueryMessage sample{1, 0x0100, {"alias.test", 1}, std::nullopt};
        auto mock_resp = sync_run(io, (*mock_q)(io, corosio::endpoint(corosio::ipv4_address({127, 0, 0, 1}), 53),
            sample, 1, std::chrono::steady_clock::now() + std::chrono::seconds(1), dns::default_upstream_receive_budget(), {}));
        require(mock_resp.has_value(), "mock cname response");
        require(dns::match_response(cname_cond, &*mock_resp) == dns::ResponseTruth::yes, "CNAME suffix + regex match");

        // 3. MessageProgram: reject-rcode, strategy ipv4-only synthetic NODATA, independent-cache isolation
        hits.store(0);
        std::vector<policy::DnsRule> drules;
        {
            policy::DnsRule r0{.domain = "^shared\\.test$", .server = 0, .pattern = policy::DnsPattern::regex,
                .action = policy::DnsAction::route, .strategy = rules::DnsRuleStrategy::ipv4_only};
            r0.context.push_back({"client", "chromium"});
            require(policy::normalize_dns_rule(r0, 1), "norm r0");
            drules.push_back(std::move(r0));

            policy::DnsRule r1{.domain = "^shared\\.test$", .server = 0, .pattern = policy::DnsPattern::regex,
                .action = policy::DnsAction::route};
            r1.context.push_back({"client", "curl"});
            require(policy::normalize_dns_rule(r1, 1), "norm r1");
            drules.push_back(std::move(r1));

            policy::DnsRule r2{.domain = "nx.test", .action = policy::DnsAction::reject, .reject_rcode = std::uint8_t{3}};
            require(policy::normalize_dns_rule(r2, 1), "norm r2");
            drules.push_back(std::move(r2));
        }
        std::array<dns::MessageUpstream, 1> upstreams{dns::MessageUpstream{
            .endpoint = corosio::endpoint(corosio::ipv4_address({127, 0, 0, 1}), 53),
            .tcp = false, .local = nullptr, .host = "", .port = 53, .resolver = {}, .protection = mock_q}};
        auto cache = std::make_shared<dns::MessageCache>(std::chrono::seconds(0), 64);

        // reject-rcode returns NXDOMAIN (rcode=3) without hitting upstream
        auto w_nx = sync_run(io, run_msg_program(io, drules, upstreams, 0, cache.get(), true, "nx.test", 1, {}));
        require(w_nx.has_value() && (w_nx->at(3) & 0x0f) == 3 && hits.load() == 0, "reject-rcode NXDOMAIN synthetic reply");

        // strategy=ipv4-only returns NODATA on AAAA without hitting upstream
        auto w_nodata = sync_run(io, run_msg_program(io, drules, upstreams, 0, cache.get(), true, "shared.test", 28, {.client = "chromium"}));
        require(w_nodata.has_value() && (w_nodata->at(3) & 0x0f) == 0 && w_nodata->at(7) == 0 && hits.load() == 0, "strategy=ipv4-only NODATA on AAAA");

        // independent-cache: r0 misses (hits=1), r0 again hits cache (hits=1), r1 misses because rule index differs (hits=2)!
        auto w1 = sync_run(io, run_msg_program(io, drules, upstreams, 0, cache.get(), true, "shared.test", 1, {.client = "chromium"}));
        require(w1.has_value() && hits.load() == 1, "r0 miss -> upstream");
        auto w2 = sync_run(io, run_msg_program(io, drules, upstreams, 0, cache.get(), true, "shared.test", 1, {.client = "chromium"}));
        require(w2.has_value() && hits.load() == 1, "r0 second query hits r0 cache");
        auto w3 = sync_run(io, run_msg_program(io, drules, upstreams, 0, cache.get(), true, "shared.test", 1, {.client = "curl"}));
        require(w3.has_value() && hits.load() == 2, "r1 isolated from r0 cache by independent-cache");

        // 3b. ReverseCache records fresh upstream answers, NOT predefined synthetic or optimistic stale hits
        {
            dns::ReverseCache reverse(64, 1, {0x123456789abcdef0ULL, 0xfedcba9876543210ULL});
            auto now_ms = [] {
                return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now().time_since_epoch()).count());
            };
            policy::DnsRule predef{.domain = "predef.test", .action = policy::DnsAction::predefined};
            policy::PredefinedResponse p_resp{.rcode = 0};
            p_resp.records.push_back({policy::ResponseSection::answer, "@", 1, 1, 60, {198, 51, 100, 77}});
            predef.predefined = std::move(p_resp);
            require(policy::normalize_dns_rule(predef, 1), "norm predef");
            std::vector<policy::DnsRule> rev_rules;
            rev_rules.push_back(std::move(predef));

            auto opt_cache = std::make_shared<dns::MessageCache>(std::chrono::seconds(600), 64);
            auto w_pre = sync_run(io, run_msg_program(io, rev_rules, upstreams, 0, opt_cache.get(), false, "predef.test", 1, {}, &reverse));
            require(w_pre.has_value(), "predefined answer");
            dns::Address pre_ip{.bytes = {198, 51, 100, 77}, .size = 4};
            require(!reverse.lookup(0, pre_ip, now_ms()).has_value(), "predefined response must not populate ReverseCache");

            // Seed expired optimistic cache entry for stale.test -> 198.51.100.88
            dns::Question stale_q{"stale.test", 1};
            auto qwire = dns::make_query(0, stale_q);
            policy::PredefinedResponse stale_def{.rcode = 0};
            stale_def.records.push_back({policy::ResponseSection::answer, "@", 1, 1, 60, {198, 51, 100, 88}});
            auto built_stale = dns::predefined_response(stale_def, stale_q);
            require(qwire && built_stale, "build stale seed");
            auto rwire = dns::encode_response(*built_stale, 0, {});
            require(rwire.has_value(), "encode stale seed");
            dns::MessageCache::View view(0, upstreams[0].endpoint, false, {}, 0, 0);
            auto past = std::chrono::steady_clock::now() - std::chrono::seconds(120);
            require(opt_cache->restore(view, *qwire, *rwire, 60, 0, past), "seed expired optimistic entry");
            auto w_stale = sync_run(io, run_msg_program(io, rev_rules, upstreams, 0, opt_cache.get(), false, "stale.test", 1, {}, &reverse));
            require(w_stale.has_value(), "optimistic stale hit returned");
            dns::Address stale_ip{.bytes = {198, 51, 100, 88}, .size = 4};
            require(!reverse.lookup(0, stale_ip, now_ms()).has_value(), "optimistic stale hit must not populate ReverseCache");

            // Fresh upstream query for fresh.test -> 93.184.216.34 DOES populate ReverseCache
            auto w_fresh = sync_run(io, run_msg_program(io, rev_rules, upstreams, 0, opt_cache.get(), false, "fresh.test", 1, {}, &reverse));
            require(w_fresh.has_value(), "fresh upstream answer");
            dns::Address fresh_ip{.bytes = {93, 184, 216, 34}, .size = 4};
            auto looked = reverse.lookup(0, fresh_ip, now_ms());
            require(looked.has_value() && looked->view() == "fresh.test", "fresh upstream answer populates ReverseCache");
        }

        // 4. rule_explain_query metadata parsing
        std::array args_storage{
            std::string("network-type=wifi"), std::string("wifi-ssid=Office"), std::string("client=chromium"),
            std::string("package-name=com.example.app"), std::string("route-mode=global"),
            std::string("default-interface-address=10.0.0.2"), std::string("source-gid=1001"),
            std::string("source-user=alice"), std::string("network-is-expensive=false"),
            std::string("network-is-constrained=false"), std::string("wifi-bssid=00:11:22:33:44:55"),
            std::string("process-name=curl")
        };
        std::vector<char*> argv_ptrs;
        for (auto& s : args_storage) argv_ptrs.push_back(s.data());
        auto parsed_q = cli::explain::parse_query_args("tcp", "example.com:443", argv_ptrs);
        require(parsed_q.has_value() && parsed_q->input.network_type == rules::NetworkType::wifi &&
            parsed_q->input.client == "chromium" && parsed_q->input.route_mode == rules::RouteMode::global &&
            parsed_q->default_if_addrs.size() == 1 && parsed_q->input.source_gid == 1001, "rule explain metadata parsed");
    }
}

int main() {
    test_predicates_and_config();
    test_sniff_fingerprints();
    test_dns_engine_and_hosts();
    std::cout << "BATCH 188 FINE-GRAINED RULES & DNS UNIT TESTS PASSED\n";
    return 0;
}
