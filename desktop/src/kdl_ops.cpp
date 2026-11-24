module desktop.kdl_ops;

import std;

namespace desktop {
    namespace {
        constexpr std::string_view kSavedDefaultMarker = "// nexus-desktop saved-default-outbound ";

        auto trim_ws(std::string_view sv) -> std::string_view {
            while (!sv.empty() && std::isspace(static_cast<unsigned char>(sv.front()))) sv.remove_prefix(1);
            while (!sv.empty() && std::isspace(static_cast<unsigned char>(sv.back()))) sv.remove_suffix(1);
            return sv;
        }

        auto is_safe_kdl_token(std::string_view sv) -> bool {
            if (sv.empty()) return false;
            for (unsigned char ch : sv) {
                if (ch < 0x20 || ch == 0x7F || std::isspace(ch) || ch == '"' || ch == '\\' || ch == '{' || ch == '}' || ch == ';') return false;
            }
            return true;
        }

        auto strip_managed_block(std::string& doc, std::string_view start_marker, std::string_view end_marker) -> bool {
            auto start = doc.find(start_marker);
            if (start == std::string::npos) return false;
            while (start > 0 && (doc[start - 1] == ' ' || doc[start - 1] == '\t')) --start;
            auto end = doc.find(end_marker, start);
            if (end == std::string::npos) return false;
            doc.erase(start, (end + end_marker.size()) - start);
            while (start < doc.size() && start > 0 && doc[start] == '\n' && doc[start - 1] == '\n') {
                doc.erase(start, 1);
            }
            return true;
        }

        auto find_matching_brace(std::string_view sv, std::size_t open_pos) -> std::size_t {
            int depth = 0;
            bool in_quote = false;
            bool escaped = false;
            for (std::size_t i = open_pos; i < sv.size(); ++i) {
                char ch = sv[i];
                if (in_quote) {
                    if (escaped) { escaped = false; continue; }
                    if (ch == '\\') { escaped = true; continue; }
                    if (ch == '"') in_quote = false;
                    continue;
                }
                if (ch == '/' && i + 1 < sv.size() && sv[i + 1] == '/') {
                    auto nl = sv.find('\n', i + 2);
                    if (nl == std::string_view::npos) return std::string_view::npos;
                    i = nl;
                    continue;
                }
                if (ch == '/' && i + 1 < sv.size() && sv[i + 1] == '*') {
                    auto end_c = sv.find("*/", i + 2);
                    if (end_c == std::string_view::npos) return std::string_view::npos;
                    i = end_c + 1;
                    continue;
                }
                if (ch == '"') { in_quote = true; continue; }
                if (ch == '{') ++depth;
                else if (ch == '}') {
                    if (--depth == 0) return i;
                }
            }
            return std::string_view::npos;
        }

        auto find_top_level_block(std::string_view kdl, std::string_view keyword)
            -> std::optional<std::pair<std::size_t, std::size_t>> {
            int depth = 0;
            bool in_quote = false;
            bool escaped = false;
            std::size_t i = 0;
            while (i < kdl.size()) {
                char ch = kdl[i];
                if (in_quote) {
                    if (escaped) { escaped = false; ++i; continue; }
                    if (ch == '\\') { escaped = true; ++i; continue; }
                    if (ch == '"') in_quote = false;
                    ++i;
                    continue;
                }
                if (ch == '/' && i + 1 < kdl.size() && kdl[i + 1] == '/') {
                    auto nl = kdl.find('\n', i + 2);
                    i = nl == std::string_view::npos ? kdl.size() : nl + 1;
                    continue;
                }
                if (ch == '/' && i + 1 < kdl.size() && kdl[i + 1] == '*') {
                    auto end_c = kdl.find("*/", i + 2);
                    i = end_c == std::string_view::npos ? kdl.size() : end_c + 2;
                    continue;
                }
                if (ch == '"') { in_quote = true; ++i; continue; }
                if (ch == '{') { ++depth; ++i; continue; }
                if (ch == '}') { if (depth > 0) --depth; ++i; continue; }
                if (depth == 0 && kdl.substr(i).starts_with(keyword)) {
                    bool at_node_start = true;
                    for (std::size_t k = i; k > 0; --k) {
                        char prev = kdl[k - 1];
                        if (prev == '\n' || prev == ';' || prev == '}') break;
                        if (prev != ' ' && prev != '\t' && prev != '\r') { at_node_start = false; break; }
                    }
                    std::size_t after_kw = i + keyword.size();
                    if (at_node_start && after_kw < kdl.size() &&
                        (kdl[after_kw] == ' ' || kdl[after_kw] == '\t' || kdl[after_kw] == '{')) {
                        bool q = false, esc = false;
                        std::size_t open = std::string_view::npos;
                        for (std::size_t j = after_kw; j < kdl.size(); ++j) {
                            char c2 = kdl[j];
                            if (q) {
                                if (esc) { esc = false; continue; }
                                if (c2 == '\\') { esc = true; continue; }
                                if (c2 == '"') q = false;
                                continue;
                            }
                            if (c2 == '"') { q = true; continue; }
                            if (c2 == '\\') {
                                while (j + 1 < kdl.size() && (kdl[j + 1] == ' ' || kdl[j + 1] == '\t' || kdl[j + 1] == '\r')) ++j;
                                if (j + 1 < kdl.size() && kdl[j + 1] == '\n') ++j;
                                continue;
                            }
                            if (c2 == '/' && j + 1 < kdl.size() && kdl[j + 1] == '/') break;
                            if (c2 == '/' && j + 1 < kdl.size() && kdl[j + 1] == '*') {
                                auto ec2 = kdl.find("*/", j + 2);
                                if (ec2 == std::string_view::npos) break;
                                j = ec2 + 1;
                                continue;
                            }
                            if (c2 == '\n' || c2 == ';' || c2 == '}') break;
                            if (c2 == '{') { open = j; break; }
                        }
                        if (open != std::string_view::npos) {
                            auto close = find_matching_brace(kdl, open);
                            if (close != std::string_view::npos) return std::pair{open, close};
                        }
                    }
                }
                ++i;
            }
            return std::nullopt;
        }

        auto indent_lines(std::string_view text, std::string_view pad) -> std::string {
            std::string out;
            std::size_t pos = 0;
            while (pos < text.size()) {
                auto nl = text.find('\n', pos);
                auto line = nl == std::string_view::npos ? text.substr(pos) : text.substr(pos, nl - pos);
                if (!line.empty() && line.back() == '\r') line.remove_suffix(1);
                if (!trim_ws(line).empty()) {
                    out.append(pad);
                    out.append(line);
                    out.push_back('\n');
                }
                if (nl == std::string_view::npos) break;
                pos = nl + 1;
            }
            return out;
        }

        auto extract_quoted_attr(std::string_view block, std::string_view key) -> std::optional<std::string> {
            auto pos = block.find(key);
            if (pos == std::string_view::npos) return std::nullopt;
            pos += key.size();
            auto end = block.find('"', pos);
            if (end == std::string_view::npos) return std::nullopt;
            return std::string(block.substr(pos, end - pos));
        }

        auto extract_port_attr(std::string_view block) -> std::optional<std::uint16_t> {
            auto pos = block.find("port=");
            if (pos == std::string_view::npos) return std::nullopt;
            pos += 5;
            auto end = pos;
            while (end < block.size() && std::isdigit(static_cast<unsigned char>(block[end]))) ++end;
            return parse_port_u16(block.substr(pos, end - pos));
        }

        auto scan_inbound_type(std::string_view kdl, std::string_view proto, InboundEndpointSpec& spec) -> void {
            std::string needle = std::format("type=\"{}\"", proto);
            std::size_t search_from = 0;
            while (search_from < kdl.size()) {
                auto hit = kdl.find(needle, search_from);
                if (hit == std::string_view::npos) break;
                auto line_start = kdl.rfind('\n', hit);
                line_start = (line_start == std::string_view::npos) ? 0 : line_start + 1;
                auto head = trim_ws(kdl.substr(line_start, hit - line_start));
                search_from = hit + needle.size();
                if (!head.starts_with("inbound ")) continue;
                auto open = kdl.find('{', hit);
                if (open == std::string_view::npos) continue;
                auto close = find_matching_brace(kdl, open);
                if (close == std::string_view::npos) continue;
                auto body = kdl.substr(open + 1, close - open - 1);
                if (auto listen_pos = body.find("listen"); listen_pos != std::string_view::npos) {
                    auto listen_slice = body.substr(listen_pos);
                    if (auto host = extract_quoted_attr(listen_slice, "host=\"")) spec.host = *host;
                    if (auto port = extract_port_attr(listen_slice)) {
                        spec.port = *port;
                        spec.enabled = true;
                        return;
                    }
                }
            }
        }

        auto find_inbounds_container_close(std::string_view kdl) -> std::size_t {
            std::size_t pos = 0;
            while (pos < kdl.size()) {
                auto hit = kdl.find("inbounds", pos);
                if (hit == std::string_view::npos) return std::string_view::npos;
                bool at_start = hit == 0 || kdl[hit - 1] == '\n' || std::isspace(static_cast<unsigned char>(kdl[hit - 1]));
                auto after = trim_ws(kdl.substr(hit + 8));
                if (at_start && after.starts_with("{")) {
                    auto open = kdl.find('{', hit);
                    return open != std::string_view::npos ? find_matching_brace(kdl, open) : std::string_view::npos;
                }
                pos = hit + 8;
            }
            return std::string_view::npos;
        }

        auto normalize_client_host(std::string_view host) -> std::string {
            auto t = trim_ws(host);
            if (t.empty() || t == "0.0.0.0" || t == "::" || t == "[::]") return "127.0.0.1";
            return std::string(t);
        }

        auto read_saved_default_outbound(std::string_view kdl) -> std::optional<std::string> {
            auto pos = kdl.find(kSavedDefaultMarker);
            if (pos == std::string_view::npos) return std::nullopt;
            pos += kSavedDefaultMarker.size();
            auto eol = kdl.find('\n', pos);
            auto val = trim_ws(eol == std::string_view::npos ? kdl.substr(pos) : kdl.substr(pos, eol - pos));
            return is_safe_kdl_token(val) ? std::optional<std::string>(val) : std::nullopt;
        }

        auto find_default_outbound_span(std::string_view kdl) -> std::optional<std::pair<std::size_t, std::size_t>> {
            auto rpos = kdl.find("routing");
            while (rpos != std::string_view::npos) {
                bool at_start = rpos == 0 || kdl[rpos - 1] == '\n';
                auto rest = trim_ws(kdl.substr(rpos + 7));
                if (at_start && rest.starts_with("{")) {
                    auto open = kdl.find('{', rpos);
                    auto close = find_matching_brace(kdl, open);
                    if (close == std::string_view::npos) return std::nullopt;
                    auto inner = kdl.substr(open, close - open);
                    auto dpos = inner.find("default-outbound");
                    if (dpos == std::string_view::npos) return std::nullopt;
                    auto q1 = inner.find('"', dpos + 16);
                    if (q1 == std::string_view::npos) return std::nullopt;
                    auto q2 = inner.find('"', q1 + 1);
                    if (q2 == std::string_view::npos) return std::nullopt;
                    return std::pair{open + q1 + 1, open + q2};
                }
                rpos = kdl.find("routing", rpos + 7);
            }
            return std::nullopt;
        }
    }

    auto parse_port_u16(std::string_view text) -> std::optional<std::uint16_t> {
        auto clean = trim_ws(text);
        if (clean.empty()) return std::nullopt;
        unsigned long val = 0;
        auto [ptr, ec] = std::from_chars(clean.data(), clean.data() + clean.size(), val);
        if (ec != std::errc{} || ptr != clean.data() + clean.size() || val == 0 || val > 65535) return std::nullopt;
        return static_cast<std::uint16_t>(val);
    }

    auto parse_inbound_endpoints(std::string_view kdl) -> CoexistingInbounds {
        CoexistingInbounds out;
        scan_inbound_type(kdl, "mixed", out.mixed);
        scan_inbound_type(kdl, "socks5", out.socks5);
        scan_inbound_type(kdl, "http", out.http);
        return out;
    }

    auto upsert_managed_inbound(std::string_view kdl,
                                std::string_view proto,
                                bool enabled,
                                std::string_view host,
                                std::uint16_t port) -> std::pair<bool, std::string> {
        if (proto != "mixed" && proto != "socks5" && proto != "http") {
            return {false, "不支持的入站协议"};
        }
        std::string start_marker = std::format("// nexus-desktop managed-inbound {}\n", proto);
        std::string end_marker = std::format("// /nexus-desktop managed-inbound {}\n", proto);
        std::string out(kdl);
        strip_managed_block(out, start_marker, end_marker);
        if (!enabled) {
            return {true, std::move(out)};
        }
        auto clean_host = trim_ws(host);
        if (!is_safe_kdl_token(clean_host) || port == 0) {
            return {false, "入站监听地址或端口无效"};
        }
        bool in_container = find_inbounds_container_close(out) != std::string_view::npos;
        std::string pad = in_container ? "    " : "";
        std::string block = std::format(
            "{}// nexus-desktop managed-inbound {}\n"
            "{}inbound \"local-{}\" type=\"{}\" {{\n"
            "{}    listen host=\"{}\" port={}\n"
            "{}    authentication \"none\"\n"
            "{}}}\n"
            "{}// /nexus-desktop managed-inbound {}\n",
            pad, proto, pad, proto, proto, pad, clean_host, port, pad, pad, pad, proto);

        if (auto close_pos = find_inbounds_container_close(out); close_pos != std::string_view::npos) {
            if (close_pos > 0 && out[close_pos - 1] != '\n') block.insert(block.begin(), '\n');
            out.insert(close_pos, block);
            return {true, std::move(out)};
        }
        if (!out.empty() && out.back() != '\n') out.push_back('\n');
        if (!out.empty()) out.push_back('\n');
        out.append(block);
        return {true, std::move(out)};
    }

    auto select_system_proxy_endpoint(CoexistingInbounds const& inb)
        -> std::optional<std::pair<std::string, std::uint16_t>> {
        if (inb.mixed.enabled && inb.mixed.port > 0) {
            return std::pair{normalize_client_host(inb.mixed.host), inb.mixed.port};
        }
        if (inb.http.enabled && inb.http.port > 0) {
            return std::pair{normalize_client_host(inb.http.host), inb.http.port};
        }
        if (inb.socks5.enabled && inb.socks5.port > 0) {
            return std::pair{normalize_client_host(inb.socks5.host), inb.socks5.port};
        }
        return std::nullopt;
    }

    auto apply_outbound_mode(std::string_view kdl,
                             std::string_view mode,
                             std::string_view proxy_group) -> std::pair<bool, std::string> {
        if (mode != "rule" && mode != "global" && mode != "direct") {
            return {false, "无效的出站模式"};
        }
        auto span = find_default_outbound_span(kdl);
        if (!span) {
            return {false, "当前配置缺少 routing { default-outbound ... } 节点"};
        }
        std::string current(kdl.substr(span->first, span->second - span->first));
        auto saved = read_saved_default_outbound(kdl);
        std::string target;
        if (mode == "direct") target = "direct";
        else if (mode == "global") target = is_safe_kdl_token(proxy_group) ? std::string(proxy_group) : "proxy";
        else target = saved ? *saved : (current == "direct" ? "proxy" : current);

        std::string out(kdl);
        out.replace(span->first, span->second - span->first, target);
        if (mode != "rule" && !saved && current != "direct" && is_safe_kdl_token(current)) {
            if (!out.empty() && out.back() != '\n') out.push_back('\n');
            out += std::format("{}{}\n", kSavedDefaultMarker, current);
        } else if (mode == "rule" && saved) {
            if (auto m = out.find(kSavedDefaultMarker); m != std::string::npos) {
                auto eol = out.find('\n', m);
                out.erase(m, eol == std::string::npos ? out.size() - m : (eol - m + 1));
            }
        }
        return {true, std::move(out)};
    }

    auto detect_outbound_mode(std::string_view kdl) -> std::string {
        auto span = find_default_outbound_span(kdl);
        auto saved = read_saved_default_outbound(kdl);
        if (span && saved) {
            auto cur = kdl.substr(span->first, span->second - span->first);
            if (cur == "direct") return "direct";
            return "global";
        }
        return "rule";
    }

    auto escape_kdl_string(std::string_view text) -> std::string {
        std::string out;
        out.reserve(text.size() + 2);
        out.push_back('"');
        for (std::size_t i = 0; i < text.size(); ++i) {
            unsigned char c = static_cast<unsigned char>(text[i]);
            if (c == 0xC2 && i + 1 < text.size() && static_cast<unsigned char>(text[i + 1]) == 0x85) { ++i; continue; }
            if (c == 0xE2 && i + 2 < text.size() && static_cast<unsigned char>(text[i + 1]) == 0x80 &&
                (static_cast<unsigned char>(text[i + 2]) == 0xA8 || static_cast<unsigned char>(text[i + 2]) == 0xA9)) {
                i += 2;
                continue;
            }
            if (c < 0x20 || c == 0x7F) continue;
            if (c == '\\' || c == '"') out.push_back('\\');
            out.push_back(static_cast<char>(c));
        }
        out.push_back('"');
        return out;
    }

    auto merge_raw_kdl_snippet(std::string_view kdl, std::string_view snippet) -> std::string {
        auto clean = trim_ws(snippet);
        std::string out(kdl);
        if (clean.empty()) return out;
        if (!out.empty() && out.back() != '\n') out.push_back('\n');
        if (!out.empty()) out.push_back('\n');
        out.append(clean);
        out.push_back('\n');
        return out;
    }

    auto insert_route_rule_kdl(std::string_view kdl, std::string_view rule_block) -> std::pair<bool, std::string> {
        auto clean = trim_ws(rule_block);
        if (clean.empty()) return {false, "empty route rule"};
        std::string out(kdl);
        if (auto routing = find_top_level_block(out, "routing")) {
            auto inner = std::string_view(out).substr(routing->first + 1, routing->second - routing->first - 1);
            if (auto tcp_prog = find_top_level_block(inner, "tcp-program")) {
                std::size_t insert_at = routing->first + 1 + tcp_prog->second;
                std::string block = indent_lines(clean, "        ");
                if (insert_at > 0 && out[insert_at - 1] != '\n') block.insert(block.begin(), '\n');
                block.append("    ");
                out.insert(insert_at, block);
                return {true, std::move(out)};
            }
            std::size_t insert_at = routing->second;
            std::string block = "    tcp-program sniff-timeout-ms=300 unknown=\"skip\" {\n" + indent_lines(clean, "        ") + "    }\n";
            if (insert_at > 0 && out[insert_at - 1] != '\n') block.insert(block.begin(), '\n');
            out.insert(insert_at, block);
            return {true, std::move(out)};
        }
        std::string block =
            "routing {\n    default-outbound \"direct\"\n    tcp-program sniff-timeout-ms=300 unknown=\"skip\" {\n"
            + indent_lines(clean, "        ") + "    }\n}";
        return {true, merge_raw_kdl_snippet(out, block)};
    }

    auto insert_dns_rule_kdl(std::string_view kdl, std::string_view rule_line) -> std::pair<bool, std::string> {
        auto clean = trim_ws(rule_line);
        if (clean.empty()) return {false, "empty dns rule"};
        std::string out(kdl);
        if (auto dns_block = find_top_level_block(out, "dns")) {
            std::size_t insert_at = dns_block->second;
            std::string block = indent_lines(clean, "    ");
            if (insert_at > 0 && out[insert_at - 1] != '\n') block.insert(block.begin(), '\n');
            out.insert(insert_at, block);
            return {true, std::move(out)};
        }
        std::string block = "dns {\n" + indent_lines(clean, "    ") + "}";
        return {true, merge_raw_kdl_snippet(out, block)};
    }
}
