// Pure Workspace UI draft/validation/builder helpers included by workspace_ui_flow.hpp and unit-tested directly.
#pragma once

namespace desktop_ui_helpers {
    inline auto trim_ascii_ws(std::string_view sv) noexcept -> std::string_view {
        while (!sv.empty() && std::isspace(static_cast<unsigned char>(sv.front()))) sv.remove_prefix(1);
        while (!sv.empty() && std::isspace(static_cast<unsigned char>(sv.back()))) sv.remove_suffix(1);
        return sv;
    }

    inline auto join_csv(std::vector<std::string> const& items) -> std::string {
        std::string out;
        for (std::size_t i = 0; i < items.size(); ++i) {
            if (i > 0) out += ", ";
            out += items[i];
        }
        return out;
    }

    inline auto split_csv_trim(std::string_view sv) -> std::vector<std::string> {
        std::vector<std::string> out;
        while (!sv.empty()) {
            auto c = sv.find(',');
            auto tok = trim_ascii_ws(c == std::string_view::npos ? sv : sv.substr(0, c));
            sv = c == std::string_view::npos ? std::string_view{} : sv.substr(c + 1);
            if (!tok.empty()) out.emplace_back(tok);
        }
        return out;
    }

    inline auto normalize_node_transport_type(std::string_view raw) -> std::string {
        auto sv = trim_ascii_ws(raw);
        std::string out(sv.size(), '\0');
        for (std::size_t i = 0; i < sv.size(); ++i) {
            out[i] = static_cast<char>(std::tolower(static_cast<unsigned char>(sv[i])));
        }
        if (out == "tcp" || out == "raw" || out == "none") return {};
        return out;
    }

    inline auto scheme_to_protocol_name(desktop::OutboundScheme s) noexcept -> std::string_view {
        switch (s) {
        case desktop::OutboundScheme::vless: return "vless";
        case desktop::OutboundScheme::trojan: return "trojan";
        case desktop::OutboundScheme::anytls: return "anytls";
        case desktop::OutboundScheme::hysteria2: return "hysteria2";
        case desktop::OutboundScheme::tuic: return "tuic";
        case desktop::OutboundScheme::snell: return "snell";
        case desktop::OutboundScheme::shadowsocks: return "shadowsocks";
        case desktop::OutboundScheme::ssh: return "ssh";
        case desktop::OutboundScheme::naive: return "naive";
        case desktop::OutboundScheme::http_connect: return "http";
        }
        return "vless";
    }

    inline auto is_ipv4_literal(std::string_view sv) noexcept -> bool {
        if (sv.empty() || sv.size() > 15) return false;
        int parts = 0;
        std::size_t pos = 0;
        while (pos <= sv.size()) {
            auto dot = sv.find('.', pos);
            auto seg = (dot == std::string_view::npos) ? sv.substr(pos) : sv.substr(pos, dot - pos);
            if (seg.empty() || seg.size() > 3) return false;
            unsigned val = 0;
            for (char c : seg) {
                if (c < '0' || c > '9') return false;
                val = val * 10u + static_cast<unsigned>(c - '0');
            }
            if (val > 255u) return false;
            ++parts;
            if (dot == std::string_view::npos) break;
            pos = dot + 1;
        }
        return parts == 4;
    }

    inline auto is_ipv6_literal(std::string_view sv) noexcept -> bool {
        if (sv.size() < 2 || !sv.contains(':')) return false;
        for (char c : sv) {
            bool ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') || c == ':' || c == '.';
            if (!ok) return false;
        }
        return true;
    }

    inline auto is_ip_or_cidr_rule_token(std::string_view raw) noexcept -> bool {
        auto tok = trim_ascii_ws(raw);
        if (tok.empty()) return false;
        if (tok == "private" || tok == "PRIVATE") return true;
        auto slash = tok.find('/');
        if (slash != std::string_view::npos) {
            auto addr = tok.substr(0, slash);
            auto mask = tok.substr(slash + 1);
            if (mask.empty() || mask.size() > 3) return false;
            int prefix = -1;
            auto [p, ec] = std::from_chars(mask.data(), mask.data() + mask.size(), prefix);
            if (ec != std::errc{} || p != mask.data() + mask.size()) return false;
            if (is_ipv4_literal(addr)) return prefix >= 0 && prefix <= 32;
            if (is_ipv6_literal(addr)) return prefix >= 0 && prefix <= 128;
            return false;
        }
        return is_ipv4_literal(tok) || is_ipv6_literal(tok);
    }

    inline auto parse_host_port_literal(std::string_view raw) -> std::expected<std::pair<std::string, std::int64_t>, std::string> {
        auto sv = trim_ascii_ws(raw);
        if (sv.empty()) return std::unexpected("empty host:port");
        std::string host;
        std::int64_t port = 443;
        if (sv.front() == '[') {
            auto close = sv.find(']');
            if (close == std::string_view::npos || close <= 1) return std::unexpected("invalid bracketed IPv6 address");
            host = std::string(sv.substr(1, close - 1));
            auto rest = sv.substr(close + 1);
            if (!rest.empty()) {
                if (rest.front() != ':' || rest.size() == 1) return std::unexpected("invalid IPv6 port syntax");
                auto ps = rest.substr(1);
                auto [p, ec] = std::from_chars(ps.data(), ps.data() + ps.size(), port);
                if (ec != std::errc{} || p != ps.data() + ps.size() || port < 1 || port > 65535) {
                    return std::unexpected("port must be 1..65535");
                }
            }
        } else {
            auto first_colon = sv.find(':');
            auto last_colon = sv.rfind(':');
            if (first_colon != std::string_view::npos && first_colon != last_colon) {
                return std::unexpected("wrap IPv6 literal in [brackets]:port");
            }
            if (last_colon != std::string_view::npos) {
                host = std::string(trim_ascii_ws(sv.substr(0, last_colon)));
                auto ps = trim_ascii_ws(sv.substr(last_colon + 1));
                auto [p, ec] = std::from_chars(ps.data(), ps.data() + ps.size(), port);
                if (ec != std::errc{} || p != ps.data() + ps.size() || port < 1 || port > 65535) {
                    return std::unexpected("port must be 1..65535");
                }
            } else {
                host = std::string(sv);
            }
        }
        if (host.empty()) return std::unexpected("server host required");
        return std::pair<std::string, std::int64_t>{std::move(host), port};
    }

    inline auto parse_positive_i64_prefix(std::string_view raw) noexcept -> std::int64_t {
        auto sv = trim_ascii_ws(raw);
        if (sv.empty()) return 0;
        std::size_t end = 0;
        while (end < sv.size() && sv[end] >= '0' && sv[end] <= '9') ++end;
        if (end == 0) return 0;
        std::int64_t val = 0;
        auto [ptr, ec] = std::from_chars(sv.data(), sv.data() + end, val);
        return (ec == std::errc{} && ptr == sv.data() + end && val > 0) ? val : 0;
    }

    inline auto ensure_default_workspace_profile(
        desktop::WorkspaceDocument& doc,
        desktop::TelemetryStoreData& telemetry) -> bool {
        bool seeded = false;
        if (doc.profiles.empty()) {
            desktop::WorkspaceProfileItem def{};
            def.id = "direct-default";
            def.remarks = "Direct";
            def.subscription_id = "manual";
            def.kind = "custom_outbound";
            def.custom_outbound_kdl = "outbound \"{{tag}}\" type=\"direct\" {}\n";
            doc.profiles.push_back(std::move(def));
            seeded = true;
        }
        bool active_found = false;
        for (auto const& p : doc.profiles) {
            if (p.id == telemetry.active_profile_id) { active_found = true; break; }
        }
        if (!active_found && !doc.profiles.empty()) {
            telemetry.active_profile_id = doc.profiles.front().id;
        }
        return seeded;
    }

    inline auto populate_node_from_parsed_share_link(
        desktop::WorkspaceProfileItem& item,
        desktop::ParsedOutbound const& parsed) -> void {
        item.node.protocol = std::string(scheme_to_protocol_name(parsed.scheme));
        item.node.server = parsed.host;
        item.node.port = parsed.port;
        item.node.username = parsed.username;
        item.node.password = parsed.secret;
        item.node.method = parsed.method;
        item.node.flow = parsed.flow;
        bool const inherent_tls = parsed.scheme == desktop::OutboundScheme::trojan ||
                                  parsed.scheme == desktop::OutboundScheme::anytls ||
                                  parsed.scheme == desktop::OutboundScheme::hysteria2 ||
                                  parsed.scheme == desktop::OutboundScheme::tuic ||
                                  parsed.scheme == desktop::OutboundScheme::naive;
        item.node.tls.enabled = inherent_tls || !parsed.sni.empty() || !parsed.reality_public_key.empty();
        item.node.tls.sni = parsed.sni;
        item.node.tls.fingerprint = parsed.fingerprint;
        if (!parsed.certificate_sha256.empty()) item.node.tls.cert_sha256 = {parsed.certificate_sha256};
        item.node.tls.reality_public_key = parsed.reality_public_key;
        item.node.tls.reality_short_id = parsed.reality_short_id;
        item.node.transport.type = normalize_node_transport_type(parsed.transport);
        if (item.node.transport.type == "grpc") {
            item.node.transport.service_name = parsed.path;
            item.node.transport.authority = parsed.host_header;
        } else {
            item.node.transport.path = parsed.path;
            item.node.transport.host = parsed.host_header;
        }
        item.node.transport.xhttp_mode = parsed.xhttp_mode;
        item.node.extra.tuic_congestion_control = parsed.congestion_control;
        item.node.extra.naive_protocol = parsed.protocol;
        item.node.extra.snell_version = parsed.snell_version;
        item.node.extra.snell_obfs = parsed.obfs;
        item.node.extra.snell_obfs_host = parsed.obfs_host;
    }

    inline auto build_workspace_profile_from_draft(
        std::string_view kind_sv,
        std::string_view remarks_sv,
        std::string_view payload_sv,
        std::string_view fallback_full_cfg,
        std::unordered_set<std::string> const& existing_ids,
        std::size_t current_count) -> std::expected<desktop::WorkspaceProfileItem, std::string> {
        std::string kind(trim_ascii_ws(kind_sv));
        if (kind.empty()) kind = "node";
        std::string payload(trim_ascii_ws(payload_sv));
        std::string remarks(trim_ascii_ws(remarks_sv));

        desktop::WorkspaceProfileItem item{};
        item.subscription_id = "manual";
        item.kind = kind;

        if (kind == "node") {
            if (payload.empty()) return std::unexpected("Node URI or host:port is required");
            if (payload.contains("://")) {
                auto parsed = desktop::parse_share_link(payload);
                if (!parsed) return std::unexpected(parsed.error());
                populate_node_from_parsed_share_link(item, *parsed);
                if (remarks.empty() && !parsed->tag.empty()) remarks = parsed->tag;
            } else {
                auto hp = parse_host_port_literal(payload);
                if (!hp) return std::unexpected(hp.error());
                item.node.protocol = "vless";
                item.node.server = std::move(hp->first);
                item.node.port = hp->second;
            }
        } else if (kind == "policy_group") {
            if (payload.empty()) return std::unexpected("Policy group requires strategy:member1,member2");
            auto colon = payload.find(':');
            item.policy_group.strategy = (colon == std::string::npos) ? "url-test" : std::string(trim_ascii_ws(std::string_view(payload).substr(0, colon)));
            item.policy_group.member_ids = split_csv_trim(colon == std::string::npos ? std::string_view(payload) : std::string_view(payload).substr(colon + 1));
            if (item.policy_group.member_ids.empty()) return std::unexpected("Policy group requires at least one member ID");
        } else if (kind == "proxy_chain") {
            item.proxy_chain.hop_ids = split_csv_trim(payload);
            if (item.proxy_chain.hop_ids.size() < 2) return std::unexpected("Proxy chain requires at least 2 hop IDs");
        } else if (kind == "custom_outbound") {
            if (payload.empty()) return std::unexpected("Custom outbound definition is required");
            item.custom_outbound_kdl = payload;
        } else {
            item.full_custom_kdl = payload.empty() ? std::string(fallback_full_cfg) : payload;
            if (trim_ascii_ws(item.full_custom_kdl).empty()) return std::unexpected("Custom full configuration is required");
        }

        if (remarks.empty()) remarks = kind + "-" + std::to_string(current_count + 1);
        item.remarks = remarks;
        auto base = desktop::sanitize_workspace_id(remarks);
        item.id = base;
        for (int n = 2; existing_ids.contains(item.id); ++n) item.id = base + "-" + std::to_string(n);
        return item;
    }
}

#include "workspace_form_builders.hpp"
