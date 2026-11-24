module desktop.ui_actions;

import std;
import desktop.http_control;

namespace desktop {
    namespace {
        auto to_lower_ascii(std::string_view s) -> std::string {
            std::string out;
            out.reserve(s.size());
            for (unsigned char c : s) out.push_back(static_cast<char>(std::tolower(c)));
            return out;
        }

        auto is_ipv4_literal(std::string_view s) -> bool {
            if (s.empty()) return false;
            int dots = 0;
            int digits = 0;
            for (char c : s) {
                if (c == '.') {
                    if (digits == 0) return false;
                    ++dots;
                    digits = 0;
                } else if (c >= '0' && c <= '9') {
                    ++digits;
                    if (digits > 3) return false;
                } else {
                    return false;
                }
            }
            return dots == 3 && digits > 0;
        }

        auto is_ipv6_literal(std::string_view s) -> bool {
            if (s.size() < 2 || !s.contains(':')) return false;
            for (char c : s) {
                bool hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
                if (!hex && c != ':' && c != '.') return false;
            }
            return true;
        }

        auto strip_host_from_target(std::string_view target) -> std::string {
            while (!target.empty() && (target.front() == ' ' || target.front() == '\t')) target.remove_prefix(1);
            while (!target.empty() && (target.back() == ' ' || target.back() == '\t')) target.remove_suffix(1);
            if (target.empty()) return {};
            if (target.front() == '[') {
                if (auto close = target.find(']'); close != std::string_view::npos && close > 1) {
                    return std::string(target.substr(1, close - 1));
                }
            }
            auto first_colon = target.find(':');
            auto last_colon = target.rfind(':');
            if (first_colon != std::string_view::npos && first_colon == last_colon) {
                return std::string(target.substr(0, last_colon));
            }
            return std::string(target);
        }
    }

    auto extract_rule_match_from_connection(
        std::string_view target,
        int port,
        std::string_view protocol,
        std::string_view outbound,
        std::string_view default_proxy_outbound,
        std::string_view rule_action) -> RuleMatchDraft {
        (void)protocol;
        RuleMatchDraft out{};
        auto host = strip_host_from_target(target);
        if (is_ipv4_literal(host)) {
            out.kind = "ip-cidr";
            out.value = host + "/32";
        } else if (is_ipv6_literal(host)) {
            out.kind = "ip-cidr";
            out.value = host + "/128";
        } else if (!host.empty()) {
            out.kind = "domain-suffix";
            out.value = host;
        } else if (port > 0 && port <= 65535) {
            out.kind = "port";
            out.value = std::to_string(port);
        } else {
            out.kind = "domain-suffix";
            out.value = "example.com";
        }

        std::string clean_out(outbound);
        if (auto slash = clean_out.find('/'); slash != std::string::npos && slash > 0) {
            clean_out = clean_out.substr(0, slash);
        }
        while (!clean_out.empty() && clean_out.back() == ' ') clean_out.pop_back();
        std::string fallback_proxy = default_proxy_outbound.empty() ? "proxy" : std::string(default_proxy_outbound);
        if (rule_action == "reject") {
            out.action = "reject";
            out.outbound.clear();
        } else if (rule_action == "direct") {
            out.action = "route";
            out.outbound = "direct";
        } else if (rule_action == "proxy") {
            out.action = "route";
            out.outbound = std::move(fallback_proxy);
        } else {
            out.action = "route";
            out.outbound = (clean_out.empty() || clean_out == "direct") ? std::move(fallback_proxy) : "direct";
        }
        return out;
    }

    auto sort_outbound_members(
        std::vector<OutboundMemberSnapshot> members,
        std::string_view sort_mode,
        std::unordered_set<std::string> const& pinned_names) -> std::vector<OutboundMemberSnapshot> {
        auto is_pinned = [&](OutboundMemberSnapshot const& m) { return pinned_names.contains(m.name); };
        if (sort_mode == "latency") {
            std::stable_sort(members.begin(), members.end(), [&](auto const& a, auto const& b) {
                bool pa = is_pinned(a), pb = is_pinned(b);
                if (pa != pb) return pa > pb;
                bool ha = a.latency_ms > 0, hb = b.latency_ms > 0;
                if (ha != hb) return ha > hb;
                if (ha && a.latency_ms != b.latency_ms) return a.latency_ms < b.latency_ms;
                return to_lower_ascii(a.name) < to_lower_ascii(b.name);
            });
        } else if (sort_mode == "name") {
            std::stable_sort(members.begin(), members.end(), [&](auto const& a, auto const& b) {
                bool pa = is_pinned(a), pb = is_pinned(b);
                if (pa != pb) return pa > pb;
                return to_lower_ascii(a.name) < to_lower_ascii(b.name);
            });
        } else {
            std::stable_partition(members.begin(), members.end(), is_pinned);
        }
        return members;
    }

    auto pick_quick_nodes(
        std::vector<OutboundMemberSnapshot> const& members,
        std::unordered_set<std::string> const& pinned_names,
        std::size_t max_count) -> std::vector<OutboundMemberSnapshot> {
        if (members.empty() || max_count == 0) return {};
        auto ranked = members;
        std::stable_sort(ranked.begin(), ranked.end(), [&](auto const& a, auto const& b) {
            if (a.selected != b.selected) return a.selected > b.selected;
            bool pa = pinned_names.contains(a.name), pb = pinned_names.contains(b.name);
            if (pa != pb) return pa > pb;
            bool ha = a.latency_ms > 0, hb = b.latency_ms > 0;
            if (ha != hb) return ha > hb;
            if (ha && a.latency_ms != b.latency_ms) return a.latency_ms < b.latency_ms;
            return to_lower_ascii(a.name) < to_lower_ascii(b.name);
        });
        std::vector<OutboundMemberSnapshot> out;
        out.reserve(std::min(max_count, ranked.size()));
        std::unordered_set<std::string> seen;
        for (auto& m : ranked) {
            if (out.size() >= max_count) break;
            if (seen.insert(m.name).second) out.push_back(std::move(m));
        }
        return out;
    }

    namespace {
        auto trim_ascii_ws(std::string_view s) -> std::string_view {
            while (!s.empty() && (s.front() == ' ' || s.front() == '\t' || s.front() == '\r' || s.front() == '\n')) s.remove_prefix(1);
            while (!s.empty() && (s.back() == ' ' || s.back() == '\t' || s.back() == '\r' || s.back() == '\n')) s.remove_suffix(1);
            return s;
        }

        auto sanitize_proxy_host(std::string_view raw) -> std::optional<std::string> {
            auto s = trim_ascii_ws(raw);
            if (s.empty() || s == "0.0.0.0" || s == "::" || s == "[::]") return std::string("127.0.0.1");
            bool bracketed = false;
            std::string_view inner = s;
            if (s.front() == '[' || s.back() == ']') {
                if (s.size() < 3 || s.front() != '[' || s.back() != ']') return std::nullopt;
                inner = s.substr(1, s.size() - 2);
                if (!inner.contains(':')) return std::nullopt;
                bracketed = true;
            }
            if (inner.empty() || inner.front() == '-') return std::nullopt;
            for (unsigned char c : inner) {
                bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
                          c == '.' || c == '-' || c == ':';
                if (!ok) return std::nullopt;
            }
            if (!bracketed && inner.contains(':')) return std::format("[{}]", inner);
            return std::string(s);
        }
    }

    auto format_host_port(std::string_view host, std::string_view port) -> std::string {
        auto h = sanitize_proxy_host(host);
        auto p = trim_ascii_ws(port);
        if (!h || p.empty()) return {};
        for (unsigned char c : p) {
            if (c < '0' || c > '9') return {};
        }
        return std::format("{}:{}", *h, p);
    }

    auto build_proxy_export_command(
        std::string_view host,
        std::uint16_t http_port,
        std::uint16_t socks_port,
        std::string_view socks_host) -> std::string {
        if (http_port == 0 && socks_port == 0) return {};
        std::optional<std::string> hh;
        if (http_port > 0 || trim_ascii_ws(socks_host).empty()) {
            hh = sanitize_proxy_host(host);
            if (!hh) return {};
        }
        std::optional<std::string> sh;
        if (socks_port > 0) {
            sh = trim_ascii_ws(socks_host).empty() ? hh : sanitize_proxy_host(socks_host);
            if (!sh) return {};
        }
        std::string cmd = "export";
        if (http_port > 0) {
            cmd += std::format(" http_proxy=http://{0}:{1} https_proxy=http://{0}:{1}", *hh, http_port);
        }
        if (socks_port > 0) {
            cmd += std::format(" all_proxy=socks5://{}:{}", *sh, socks_port);
        } else if (http_port > 0) {
            cmd += std::format(" all_proxy=http://{}:{}", *hh, http_port);
        }
        return cmd;
    }
}
