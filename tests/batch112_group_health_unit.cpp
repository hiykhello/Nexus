#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <functional>
#include <iostream>
#include <memory>
#include <optional>
#include <ranges>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace socks5 {
    enum class Status : std::uint8_t { accepted, rejected };
    struct Request {
        Status status = Status::accepted;
        std::uint8_t address_type = 1;
        std::uint8_t address_length = 4;
        std::array<std::uint8_t, 255> address{};
        std::uint16_t port = 80;
    };
}

namespace http {
    enum class HostKind : std::uint8_t { domain, ipv4, ipv6 };
    enum class ConnectStatus : std::uint8_t { accepted, rejected };
    struct ParsedAuthority {
        ConnectStatus status = ConnectStatus::accepted;
        HostKind kind = HostKind::domain;
        std::string host;
        std::array<std::uint8_t, 16> address{};
        std::uint16_t port = 80;
    };
    inline auto parse_destination_authority(std::string_view dial) -> ParsedAuthority {
        ParsedAuthority out;
        auto colon = dial.rfind(':');
        if (colon == dial.npos || colon == 0) {
            out.status = ConnectStatus::rejected;
            return out;
        }
        out.host = std::string(dial.substr(0, colon));
        out.port = static_cast<std::uint16_t>(std::stoi(std::string(dial.substr(colon + 1))));
        return out;
    }
}

namespace rules {
    struct RouteMatcher {
        std::size_t outbound = 0;
        static auto compile(std::initializer_list<int>, std::size_t out, std::size_t)
            -> std::expected<RouteMatcher, std::string> {
            return RouteMatcher{out};
        }
    };
}

namespace state {
    inline auto fingerprint(std::span<std::byte const>) -> std::array<std::byte, 32> { return {}; }
}

namespace config {
    enum class OutboundProbeMode : std::uint8_t { http, h2_ping };
    enum class OutboundGroupMode : std::uint8_t { selector, fallback, url_test };
    struct StatusRange { std::uint16_t low = 204; std::uint16_t high = 204; };
    struct ProbeConfig {
        std::string url = "http://probe.test/generate_204";
        OutboundProbeMode mode = OutboundProbeMode::http;
        std::string server_name;
        std::string ca_file;
        std::uint32_t interval_ms = 2000;
        std::uint32_t timeout_ms = 1000;
        std::uint32_t tolerance_ms = 30;
        std::vector<StatusRange> expected_status{{204, 204}};
    };
    struct SelectorConfig {
        std::string name = "auto";
        OutboundGroupMode mode = OutboundGroupMode::url_test;
        std::vector<std::string> members{"a", "b"};
        std::string selected = "a";
        std::string selected_leaf = "a";
        ProbeConfig probe;
    };
    struct DnsFakeIp { bool unified = false; };
    struct DnsConfig {
        std::string message_cache_policy;
        std::string cache_rule_fingerprints;
        std::optional<DnsFakeIp> fakeip;
        int rules = 0;
    };
    struct InboundConfig { std::string name; };
    struct Config {
        std::vector<SelectorConfig> selectors;
        std::optional<DnsConfig> dns;
        std::vector<InboundConfig> inbounds;
        auto tunnel_count() const noexcept -> std::size_t { return 2; }
    };
    inline auto configured_outbound_index(Config const&, std::string_view name) -> std::optional<std::size_t> {
        if (name == "a") return 2;
        if (name == "b") return 3;
        return {};
    }
}

namespace proxy {
    enum class OutboundProbeMode : std::uint8_t { http, h2_ping };
    struct OutboundProbe {
        rules::RouteMatcher route;
        socks5::Request target;
        std::string request;
        OutboundProbeMode mode = OutboundProbeMode::http;
        std::vector<std::pair<std::uint16_t, std::uint16_t>> expected_status;
        bool use_tls = false;
        std::string tls_server_name;
        std::string tls_ca_file;
        std::chrono::steady_clock::time_point deadline{};
        std::atomic<std::uint32_t> result{0};
        std::atomic<std::uint16_t> status_code{0};
    };
    struct DnsRuleSnapshot { DnsRuleSnapshot(int, std::uint64_t) {} };
    struct RouteSnapshot {
        std::shared_ptr<DnsRuleSnapshot> dns;
        std::shared_ptr<int> dns_transports;
        std::uint64_t generation = 0;
    };
    using RouteSnapshots = std::atomic<std::shared_ptr<std::vector<RouteSnapshot>>>;
}

namespace cli::run_detail {
    struct RouteFiles {};
    struct ProjectedRoutes {
        int indexed = 0;
        int default_outbound = 0;
        int distribution = 0;
        auto program(config::Config const&) const -> int { return 0; }
    };
    inline auto project_routes(config::Config const&, RouteFiles const&) -> ProjectedRoutes { return {}; }
    inline auto prepare_dns_transport_snapshot(config::Config const&, std::uint64_t, std::shared_ptr<int>, bool)
        -> std::expected<std::shared_ptr<int>, std::string> { return std::make_shared<int>(0); }
}

#include "../src/tools/proxy_group_health.hpp"

namespace {
    auto run_round(cli::run_detail::OutboundGroupHealth& health, config::Config& cfg,
                   std::uint64_t gen, std::uint32_t a_result, std::uint32_t b_result)
        -> std::optional<cli::run_detail::OutboundGroupHealth::Selection> {
        std::array<std::uint32_t, 2> results{a_result, b_result};
        std::size_t idx = 0;
        std::shared_ptr<proxy::OutboundProbe> current;
        for (int step = 0; step < 8; ++step) {
            auto sel = health.poll([&](std::shared_ptr<proxy::OutboundProbe> p) {
                current = std::move(p);
                return true;
            }, cfg, gen);
            if (current) {
                current->status_code.store(results[idx] > 1 ? 204 : 0, std::memory_order_relaxed);
                current->result.store(results[idx++], std::memory_order_release);
                current.reset();
                continue;
            }
            if (sel) {
                cfg.selectors[0].selected = std::string(sel->member);
                return sel;
            }
            if (idx == 2) return {};
        }
        return {};
    }
}

int main() {
    config::Config cfg;
    cfg.selectors.push_back(config::SelectorConfig{});
    cfg.selectors[0].probe.interval_ms = 0; // Immediate rounds for deterministic unit test.
    cfg.selectors[0].probe.tolerance_ms = 30;

    auto created = cli::run_detail::OutboundGroupHealth::create(cfg);
    if (!created) { std::cerr << "create failed: " << created.error() << "\n"; return 1; }
    auto health = std::move(*created);

    // 1. Initial baseline: a=100ms, b=120ms -> stays on a.
    auto s1 = run_round(health, cfg, 1, 102, 122);
    if (s1.has_value() || cfg.selectors[0].selected != "a") {
        std::cerr << "expected stay on a after baseline\n";
        return 2;
    }

    // 2. Single spike on a (200ms) while b=120ms:
    // EWMA(a) = (3*200 + 7*100 + 5)/10 = 130ms; EWMA(b) = 120ms.
    // 120 + 30(tolerance) >= 130 -> MUST NOT flap to b!
    auto s2 = run_round(health, cfg, 1, 202, 122);
    if (s2.has_value() || cfg.selectors[0].selected != "a") {
        std::cerr << "EWMA failed to damp single latency spike\n";
        return 3;
    }

    // 3. Sustained faster b (40ms) over multiple rounds eventually beats a beyond tolerance:
    // Round 3: a=100 -> EWMA(a)=121; b=40 -> EWMA(b)=(3*40+7*120+5)/10=96 -> 96+30=126 >= 121 (still damped)
    // Round 4: a=100 -> EWMA(a)=115; b=40 -> EWMA(b)=(3*40+7*96+5)/10=79 -> 79+30=109 < 115 -> switches to b!
    auto s3 = run_round(health, cfg, 1, 102, 42);
    if (s3.has_value()) { std::cerr << "switched too early on round 3\n"; return 4; }
    auto s4 = run_round(health, cfg, 1, 102, 42);
    if (!s4 || s4->member != "b") {
        std::cerr << "failed to switch to sustained faster member b on round 4\n";
        return 5;
    }

    // 4. Circuit breaker on b: 3 consecutive failures (measurement==1) trip breaker cooldown >= 5000ms.
    // On first failure, b is down so it switches back to healthy a.
    auto f1 = run_round(health, cfg, 1, 102, 1);
    if (!f1 || f1->member != "a") { std::cerr << "failed failover to a on b down\n"; return 6; }
    (void)run_round(health, cfg, 1, 102, 1); // 2nd failure
    (void)run_round(health, cfg, 1, 102, 1); // 3rd failure -> breaker_until = now + 5000ms

    // Even if b is still quarantined, best_up_member must never return b while breaker active (and a is up).
    auto obs_b_tripped = health.observe(cfg, 0, 1, 1);
    if (!obs_b_tripped.breaker_open || obs_b_tripped.consecutive_failures != 3 || !obs_b_tripped.ewma_ms) {
        std::cerr << "observe() did not report breaker_open/consecutive_failures/ewma_ms on tripped member b\n";
        return 7;
    }
    auto best_during_breaker = health.best_up_member(cfg, 0, 1);
    if (!best_during_breaker || *best_during_breaker != "a") {
        std::cerr << "expected a while b is tripped\n";
        return 7;
    }

    // 4b. Manual trigger_probe(0) immediately clears breaker state so operators can force re-test.
    if (!health.trigger_probe(0) || health.trigger_probe(99)) {
        std::cerr << "trigger_probe return value mismatch\n";
        return 7;
    }
    auto obs_b_cleared = health.observe(cfg, 0, 1, 1);
    if (obs_b_cleared.breaker_open || obs_b_cleared.consecutive_failures != 0) {
        std::cerr << "trigger_probe did not clear breaker_open on member b\n";
        return 7;
    }

    // 5. Probe recovery clears circuit breaker immediately and switches to much faster b (10ms vs 100ms).
    // b's previous EWMA was 79ms -> next EWMA = (3*10 + 7*79 + 5)/10 = 58ms; 58 + 30 = 88 < 102 -> switches!
    auto rec = run_round(health, cfg, 1, 102, 12);
    if (!rec || rec->member != "b") {
        std::cerr << "probe recovery did not clear breaker and restore faster member b\n";
        return 8;
    }

    // 6. Network change invalidation clears EWMA history & breaker so first sample on new gen takes immediate effect.
    health.invalidate_network();
    // On gen 2: a=20ms, b=100ms -> without stale EWMA from gen 1, a=20 vs b=100 immediately switches to a!
    auto net_sw = run_round(health, cfg, 2, 22, 102);
    if (!net_sw || net_sw->member != "a") {
        std::cerr << "invalidate_network did not reset EWMA for new network generation\n";
        return 9;
    }

    std::cout << "BATCH 112 EWMA SMOOTHING, HYSTERESIS, CIRCUIT BREAKER & NETWORK RESET UNIT TESTS PASSED\n";
    return 0;
}
