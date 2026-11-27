// Pure header-only Wave 35 flagship helpers (GroupLatencySpectrum, palette fuzzy matching, domain detection, onset tracker).
// Zero Slint dependencies so headless C++26 unit tests (ui_ops_test.cpp) can directly test every algorithm.
#pragma once

namespace desktop_ui_helpers {
    struct GroupLatencySpectrum {
        float fast_ratio = 0.0f;    // < 80ms
        float good_ratio = 0.0f;    // 80..179ms
        float mid_ratio = 0.0f;     // 180..349ms
        float slow_ratio = 0.0f;    // >= 350ms
        float timeout_ratio = 0.0f; // failed/timeout
        int p50_ms = -1;
        int max_ms = 0;
        bool has_data = false;
    };

    inline auto is_timeout_member_state(std::string_view st) noexcept -> bool {
        return st == "timeout" || st == "unreachable" || st == "error" || st == "failed";
    }

    inline auto compute_group_latency_spectrum(std::span<const desktop::OutboundMemberSnapshot> members) -> GroupLatencySpectrum {
        GroupLatencySpectrum out{};
        if (members.empty()) return out;
        int fast = 0, good = 0, mid = 0, slow = 0, timeout = 0;
        std::vector<int> healthy_ms;
        healthy_ms.reserve(members.size());
        for (auto const& m : members) {
            if (m.latency_ms > 0) {
                int ms = static_cast<int>(m.latency_ms);
                healthy_ms.push_back(ms);
                out.max_ms = std::max(out.max_ms, ms);
                if (ms < 80) ++fast;
                else if (ms < 180) ++good;
                else if (ms < 350) ++mid;
                else ++slow;
            } else if (is_timeout_member_state(m.state)) {
                ++timeout;
            }
        }
        int const counted = fast + good + mid + slow + timeout;
        if (counted == 0) return out;
        float const denom = static_cast<float>(counted);
        out.fast_ratio = static_cast<float>(fast) / denom;
        out.good_ratio = static_cast<float>(good) / denom;
        out.mid_ratio = static_cast<float>(mid) / denom;
        out.slow_ratio = static_cast<float>(slow) / denom;
        out.timeout_ratio = static_cast<float>(timeout) / denom;
        out.has_data = true;
        if (!healthy_ms.empty()) {
            std::ranges::sort(healthy_ms);
            std::size_t const n = healthy_ms.size();
            out.p50_ms = (n % 2 == 1)
                ? healthy_ms[n / 2]
                : (healthy_ms[n / 2 - 1] + healthy_ms[n / 2]) / 2;
        }
        return out;
    }

    inline auto trim_palette_ws(std::string_view s) -> std::string_view {
        while (!s.empty() && std::isspace(static_cast<unsigned char>(s.front()))) s.remove_prefix(1);
        while (!s.empty() && std::isspace(static_cast<unsigned char>(s.back()))) s.remove_suffix(1);
        return s;
    }

    inline auto normalize_domain_candidate(std::string_view raw) -> std::string {
        auto trimmed = trim_palette_ws(raw);
        std::string low;
        low.reserve(trimmed.size());
        for (unsigned char c : trimmed) low.push_back(static_cast<char>(std::tolower(c)));
        std::string_view s{low};
        if (s.starts_with("https://")) s.remove_prefix(8);
        else if (s.starts_with("http://")) s.remove_prefix(7);
        if (auto slash = s.find('/'); slash != std::string_view::npos) s = s.substr(0, slash);
        if (auto colon = s.rfind(':'); colon != std::string_view::npos && s.find(':') == colon) {
            auto port_part = s.substr(colon + 1);
            bool all_digits = !port_part.empty() && std::ranges::all_of(port_part, [](unsigned char c) { return std::isdigit(c) != 0; });
            if (all_digits) s = s.substr(0, colon);
        }
        while (!s.empty() && s.back() == '.') s.remove_suffix(1);
        return std::string{s};
    }

    inline auto looks_like_domain_query(std::string_view raw) -> bool {
        auto s = trim_palette_ws(raw);
        if (s.empty() || s.front() == '>') return false;
        for (unsigned char c : s) {
            if (std::isspace(c)) return false;
        }
        auto dom = normalize_domain_candidate(s);
        if (dom.size() < 4 || dom.size() > 253) return false;
        auto dot = dom.find('.');
        if (dot == std::string::npos || dot == 0 || dot + 2 > dom.size()) return false;
        if (dom.contains("..")) return false;
        for (unsigned char c : dom) {
            if (!(std::isalnum(c) || c == '-' || c == '.')) return false;
        }
        auto last_dot = dom.rfind('.');
        auto tld = std::string_view(dom).substr(last_dot + 1);
        if (tld.size() < 2) return false;
        return std::ranges::any_of(tld, [](unsigned char c) { return std::isalpha(c) != 0; });
    }

    // Subsequence + substring fuzzy scorer (-1 = no match, higher = better match)
    inline auto palette_fuzzy_score(std::string_view query_raw, std::string_view target_raw) -> int {
        auto q = trim_palette_ws(query_raw);
        if (q.empty()) return 1;
        auto to_low = [](std::string_view sv) {
            std::string r;
            r.reserve(sv.size());
            for (unsigned char c : sv) r.push_back(static_cast<char>(std::tolower(c)));
            return r;
        };
        auto ql = to_low(q);
        auto tl = to_low(target_raw);
        if (tl == ql) return 1000;
        if (tl.starts_with(ql)) return 750 - static_cast<int>(tl.size() - ql.size());
        if (auto pos = tl.find(ql); pos != std::string::npos) {
            return 500 - static_cast<int>(pos * 4);
        }
        std::size_t qi = 0;
        int score = 100;
        int streak = 0;
        for (std::size_t ti = 0; ti < tl.size() && qi < ql.size(); ++ti) {
            if (tl[ti] == ql[qi]) {
                ++qi;
                ++streak;
                score += 12 + streak * 6;
            } else {
                streak = 0;
            }
        }
        return qi == ql.size() ? score : -1;
    }

    struct ExplainSummary {
        std::string rule;
        std::string outbound;
    };

    inline auto truncate_utf8_bytes(std::string_view s, std::size_t max_bytes) noexcept -> std::string_view {
        if (s.size() <= max_bytes) return s;
        std::size_t end = max_bytes;
        while (end > 0 && (static_cast<unsigned char>(s[end]) & 0xC0u) == 0x80u) --end;
        if (end > 0) {
            std::size_t i = end - 1;
            while (i > 0 && (static_cast<unsigned char>(s[i]) & 0xC0u) == 0x80u) --i;
            unsigned char lead = static_cast<unsigned char>(s[i]);
            std::size_t seq_len = (lead < 0x80u) ? 1 : (lead < 0xE0u) ? 2 : (lead < 0xF0u) ? 3 : 4;
            if (i + seq_len > end) end = i;
        }
        return s.substr(0, end);
    }

    inline auto parse_explain_summary(std::string_view raw) -> ExplainSummary {
        ExplainSummary out{};
        std::size_t pos = 0;
        auto grab_after = [](std::string_view line, std::string_view key) -> std::string_view {
            auto idx = line.find(key);
            if (idx == std::string_view::npos) return {};
            auto rest = trim_palette_ws(line.substr(idx + key.size()));
            if (!rest.empty() && (rest.front() == ':' || rest.front() == '=')) {
                rest.remove_prefix(1);
                rest = trim_palette_ws(rest);
            }
            if (auto sep = rest.find_first_of(" \t,;|"); sep != std::string_view::npos) {
                rest = rest.substr(0, sep);
            }
            return rest;
        };
        while (pos <= raw.size()) {
            auto nl = raw.find('\n', pos);
            auto line = trim_palette_ws(nl == std::string_view::npos ? raw.substr(pos) : raw.substr(pos, nl - pos));
            if (!line.empty()) {
                if (out.outbound.empty()) {
                    for (std::string_view k : {"outbound", "target", "action"}) {
                        if (auto v = grab_after(line, k); !v.empty()) { out.outbound = std::string(v); break; }
                    }
                }
                if (out.rule.empty()) {
                    for (std::string_view k : {"matched-rule", "matched_rule", "rule", "match"}) {
                        if (auto v = grab_after(line, k); !v.empty()) { out.rule = std::string(v); break; }
                    }
                }
            }
            if (nl == std::string_view::npos) break;
            pos = nl + 1;
        }
        if (out.rule.empty() && !raw.empty()) {
            auto first = trim_palette_ws(raw.substr(0, raw.find('\n')));
            first = truncate_utf8_bytes(first, 48);
            out.rule = std::string(first);
        }
        return out;
    }

    inline auto is_fakeip_address(std::string_view addr) noexcept -> bool {
        return addr.starts_with("198.18.") || addr.starts_with("198.19.") || addr.starts_with("fc00:") || addr.starts_with("fd00:");
    }

    // Track single active event onset marker across a 24-slot 1Hz ring window
    struct OnsetMarkerTracker {
        int age = -1;
        std::string label;

        auto mark(std::string text) -> void {
            label.assign(truncate_utf8_bytes(text, 14));
            age = 0;
        }

        auto reset() -> void {
            age = -1;
            label.clear();
        }

        auto advance(std::size_t capacity = 24) -> void {
            if (age < 0) return;
            ++age;
            if (age >= static_cast<int>(capacity)) reset();
        }

        [[nodiscard]] auto active() const noexcept -> bool { return age >= 0; }

        [[nodiscard]] auto ratio(std::size_t capacity = 24) const noexcept -> float {
            if (age < 0 || capacity < 2) return -1.0f;
            float r = 1.0f - static_cast<float>(age) / static_cast<float>(capacity - 1);
            return std::clamp(r, 0.0f, 1.0f);
        }
    };
}
