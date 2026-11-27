module rules.convert_external;
import std;
import rules.regex;
import rules.srs_domain;

namespace rules {
    namespace {
        struct JsonParser {
            std::string_view src;
            std::size_t pos = 0;

            auto skip_ws() noexcept -> void {
                while (pos < src.size() && (src[pos] == ' ' || src[pos] == '\t' || src[pos] == '\n' || src[pos] == '\r'))
                    ++pos;
            }
            auto peek() noexcept -> char { skip_ws(); return pos < src.size() ? src[pos] : '\0'; }
            auto take(char ch) noexcept -> bool {
                skip_ws();
                if (pos >= src.size() || src[pos] != ch) return false;
                ++pos;
                return true;
            }
            static auto fail(std::string msg) -> std::unexpected<Error> {
                return std::unexpected(Error{ErrorCode::syntax, std::move(msg)});
            }

            auto read_string() -> std::expected<std::string, Error> {
                if (!take('"')) return fail("expected JSON string");
                std::string out;
                while (pos < src.size()) {
                    char c = src[pos++];
                    if (c == '"') return out;
                    if (static_cast<unsigned char>(c) < 0x20) return fail("unescaped JSON control character");
                    if (c != '\\') { out.push_back(c); continue; }
                    if (pos >= src.size()) return fail("truncated JSON escape");
                    char esc = src[pos++];
                    switch (esc) {
                    case '"': case '\\': case '/': out.push_back(esc); break;
                    case 'b': out.push_back('\b'); break;
                    case 'f': out.push_back('\f'); break;
                    case 'n': out.push_back('\n'); break;
                    case 'r': out.push_back('\r'); break;
                    case 't': out.push_back('\t'); break;
                    case 'u': {
                        if (pos + 4 > src.size()) return fail("truncated JSON unicode escape");
                        unsigned cp = 0;
                        auto [end, ec] = std::from_chars(src.data() + pos, src.data() + pos + 4, cp, 16);
                        if (ec != std::errc{} || end != src.data() + pos + 4) return fail("invalid JSON unicode escape");
                        pos += 4;
                        if (cp < 0x80) out.push_back(static_cast<char>(cp));
                        else if (cp < 0x800) {
                            out.push_back(static_cast<char>(0xc0 | (cp >> 6)));
                            out.push_back(static_cast<char>(0x80 | (cp & 0x3f)));
                        } else {
                            out.push_back(static_cast<char>(0xe0 | (cp >> 12)));
                            out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3f)));
                            out.push_back(static_cast<char>(0x80 | (cp & 0x3f)));
                        }
                        break;
                    }
                    default: return fail("invalid JSON escape sequence");
                    }
                }
                return fail("unterminated JSON string");
            }

            auto read_bool() -> std::expected<bool, Error> {
                skip_ws();
                if (src.substr(pos).starts_with("true")) { pos += 4; return true; }
                if (src.substr(pos).starts_with("false")) { pos += 5; return false; }
                return fail("expected JSON boolean");
            }

            auto read_uint() -> std::expected<std::uint64_t, Error> {
                skip_ws();
                auto start = pos;
                while (pos < src.size() && src[pos] >= '0' && src[pos] <= '9') ++pos;
                if (pos == start) return fail("expected non-negative JSON integer");
                std::uint64_t v = 0;
                auto [end, ec] = std::from_chars(src.data() + start, src.data() + pos, v);
                if (ec != std::errc{} || end != src.data() + pos) return fail("JSON integer out of range");
                return v;
            }

            auto skip_value(unsigned depth) -> std::expected<void, Error> {
                if (depth > 64) return fail("JSON nesting too deep");
                char c = peek();
                if (c == '"') return read_string().transform([](auto const&) {});
                if (c == 't' || c == 'f') return read_bool().transform([](auto) {});
                if (c == 'n') {
                    if (!src.substr(pos).starts_with("null")) return fail("invalid JSON literal");
                    pos += 4; return {};
                }
                if (c == '[') {
                    ++pos;
                    if (take(']')) return {};
                    for (;;) {
                        if (auto ok = skip_value(depth + 1); !ok) return ok;
                        if (take(']')) return {};
                        if (!take(',')) return fail("expected ',' or ']' in JSON array");
                    }
                }
                if (c == '{') {
                    ++pos;
                    if (take('}')) return {};
                    for (;;) {
                        if (!read_string()) return fail("expected JSON key");
                        if (!take(':')) return fail("expected ':' in JSON object");
                        if (auto ok = skip_value(depth + 1); !ok) return ok;
                        if (take('}')) return {};
                        if (!take(',')) return fail("expected ',' or '}' in JSON object");
                    }
                }
                if (c == '-' || (c >= '0' && c <= '9')) {
                    if (src[pos] == '-') ++pos;
                    while (pos < src.size() && std::string_view("0123456789.eE+-").contains(src[pos])) ++pos;
                    return {};
                }
                return fail("unexpected token in JSON value");
            }

            auto read_string_or_list(bool also_int = false) -> std::expected<std::vector<std::string>, Error> {
                std::vector<std::string> out;
                auto one = [&]() -> std::expected<std::string, Error> {
                    if (peek() == '"') return read_string();
                    if (also_int) return read_uint().transform([](auto v) { return std::to_string(v); });
                    return fail("expected string element");
                };
                if (peek() == '[') {
                    ++pos;
                    if (take(']')) return out;
                    for (;;) {
                        auto item = one();
                        if (!item) return std::unexpected(std::move(item.error()));
                        out.push_back(std::move(*item));
                        if (take(']')) return out;
                        if (!take(',')) return fail("expected ',' or ']' in JSON array");
                    }
                }
                auto item = one();
                if (!item) return std::unexpected(std::move(item.error()));
                out.push_back(std::move(*item));
                return out;
            }
        };

        auto lower_ascii(std::string& text) -> void {
            for (auto& c : text) if (c >= 'A' && c <= 'Z') c = static_cast<char>(c + ('a' - 'A'));
        }

        auto qtype_value(std::string_view text) -> std::optional<std::string> {
            unsigned v = 0;
            auto [end, ec] = std::from_chars(text.data(), text.data() + text.size(), v);
            if (ec == std::errc{} && end == text.data() + text.size() && v > 0 && v <= 65535) return std::string(text);
            std::string up(text);
            for (auto& c : up) if (c >= 'a' && c <= 'z') c = static_cast<char>(c - ('a' - 'A'));
            if (up == "A") return "1"; if (up == "NS") return "2"; if (up == "CNAME") return "5";
            if (up == "SOA") return "6"; if (up == "PTR") return "12"; if (up == "MX") return "15";
            if (up == "TXT") return "16"; if (up == "AAAA") return "28"; if (up == "SRV") return "33";
            if (up == "SVCB") return "64"; if (up == "HTTPS") return "65";
            return std::nullopt;
        }

        auto make_suffix_rule(std::string value) -> Rule {
            lower_ascii(value);
            if (value.starts_with('.')) {
                auto bare = value.substr(1);
                return Rule{"and", {}, {Rule{"domain-suffix", bare, {}}, Rule{"not", {}, {Rule{"domain", std::move(bare), {}}}}}};
            }
            return Rule{"domain-suffix", std::move(value), {}};
        }

        auto parse_rule_object(JsonParser& p, unsigned depth, bool lenient, std::size_t& nodes)
            -> std::expected<std::optional<Rule>, Error> {
            if (depth > max_rule_depth) return std::unexpected(Error{ErrorCode::limit, "rule nesting exceeds limit"});
            if (!p.take('{')) return JsonParser::fail("expected JSON rule object");
            std::string rtype = "default", mode;
            bool invert = false;
            std::vector<Rule> logical_children;
            std::array<std::vector<Rule>, 23> groups;
            auto take_node = [&](std::size_t n = 1) -> std::expected<void, Error> {
                if (nodes + n > max_rules) return std::unexpected(Error{ErrorCode::limit, "rule count exceeds limit"});
                nodes += n;
                return {};
            };
            auto group_for_key = [](std::string_view k) noexcept -> std::size_t {
                if (k == "network") return 0;
                if (k == "domain" || k == "domain_suffix" || k == "domain_keyword" || k == "domain_regex" ||
                    k == "ip_cidr" || k == "adguard_domain") return 1;
                if (k == "source_port" || k == "source_port_range") return 2;
                if (k == "port" || k == "port_range") return 3;
                if (k == "source_ip_cidr") return 4;
                if (k == "query_type") return 5;
                if (k == "process_name") return 6;
                if (k == "process_path") return 7;
                if (k == "process_path_regex") return 8;
                if (k == "package_name") return 9;
                if (k == "package_name_regex") return 10;
                if (k == "wifi_ssid") return 11;
                if (k == "wifi_bssid") return 12;
                if (k == "network_type") return 13;
                if (k == "default_interface_address") return 16;
                if (k == "protocol") return 21;
                return 22;
            };
            if (!p.take('}')) {
                for (;;) {
                    auto key = p.read_string();
                    if (!key) return std::unexpected(std::move(key.error()));
                    if (!p.take(':')) return JsonParser::fail("expected ':' in JSON rule");
                    if (*key == "type") {
                        auto v = p.read_string(); if (!v) return std::unexpected(std::move(v.error())); rtype = std::move(*v);
                    } else if (*key == "mode") {
                        auto v = p.read_string(); if (!v) return std::unexpected(std::move(v.error())); mode = std::move(*v);
                    } else if (*key == "invert") {
                        auto v = p.read_bool(); if (!v) return std::unexpected(std::move(v.error())); invert = *v;
                    } else if (*key == "network_is_expensive" || *key == "network_is_constrained") {
                        auto v = p.read_bool(); if (!v) return std::unexpected(std::move(v.error()));
                        if (*v) {
                            if (auto ok = take_node(); !ok) return std::unexpected(std::move(ok.error()));
                            bool exp = *key == "network_is_expensive";
                            groups[exp ? 14 : 15].push_back({exp ? "network-is-expensive" : "network-is-constrained", "true", {}});
                        }
                    } else if (*key == "network_interface_address") {
                        if (!p.take('{')) return JsonParser::fail("expected JSON object for network_interface_address");
                        if (!p.take('}')) {
                            for (;;) {
                                auto ifk = p.read_string(); if (!ifk) return std::unexpected(std::move(ifk.error()));
                                if (!p.take(':')) return JsonParser::fail("expected ':' in network_interface_address");
                                lower_ascii(*ifk);
                                auto nt = parse_network_type(*ifk);
                                auto vals = p.read_string_or_list(false);
                                if (!vals) return std::unexpected(std::move(vals.error()));
                                if (!nt) {
                                    if (!lenient) return std::unexpected(Error{ErrorCode::schema, "invalid network_interface_address type: " + *ifk});
                                } else {
                                    auto slot = 17u + static_cast<unsigned>(*nt);
                                    for (auto const& cidr : *vals) {
                                        if (auto ok = take_node(); !ok) return std::unexpected(std::move(ok.error()));
                                        groups[slot].push_back({"network-interface-address", *ifk + ":" + cidr, {}});
                                    }
                                }
                                if (p.take('}')) break;
                                if (!p.take(',')) return JsonParser::fail("expected ',' or '}' in network_interface_address");
                            }
                        }
                    } else if (*key == "rules") {
                        if (!p.take('[')) return JsonParser::fail("expected JSON logical rules array");
                        if (!p.take(']')) {
                            for (;;) {
                                auto child = parse_rule_object(p, depth + 1, lenient, nodes);
                                if (!child) return std::unexpected(std::move(child.error()));
                                if (*child) logical_children.push_back(std::move(**child));
                                if (p.take(']')) break;
                                if (!p.take(',')) return JsonParser::fail("expected ',' in JSON logical rules array");
                            }
                        }
                    } else if (*key == "domain" || *key == "domain_suffix" || *key == "domain_keyword" ||
                               *key == "domain_regex" || *key == "adguard_domain" || *key == "ip_cidr" ||
                               *key == "source_ip_cidr" || *key == "port" || *key == "port_range" ||
                               *key == "source_port" || *key == "source_port_range" || *key == "network" ||
                               *key == "protocol" || *key == "query_type" || *key == "process_name" ||
                               *key == "process_path" || *key == "process_path_regex" || *key == "package_name" ||
                               *key == "package_name_regex" || *key == "wifi_ssid" || *key == "wifi_bssid" ||
                               *key == "network_type" || *key == "default_interface_address" ||
                               *key == "source_interface") {
                        bool ints = (*key == "port" || *key == "source_port" || *key == "query_type");
                        auto vals = p.read_string_or_list(ints);
                        if (!vals) return std::unexpected(std::move(vals.error()));
                        std::vector<Rule> items;
                        for (auto& val : *vals) {
                            std::string mapped = *key;
                            for (auto& ch : mapped) if (ch == '_') ch = '-';
                            if (mapped == "domain-suffix") {
                                if (auto ok = take_node(val.starts_with('.') ? 4 : 1); !ok) return std::unexpected(std::move(ok.error()));
                                items.push_back(make_suffix_rule(std::move(val)));
                            } else if (mapped == "adguard-domain") {
                                auto conv = srs_detail::convert_adguard_domain_line(val, lenient);
                                if (!conv) return std::unexpected(std::move(conv.error()));
                                if (!*conv) continue;
                                if (auto ok = take_node((*conv)->type == "and" ? 4u : 1u); !ok) return std::unexpected(std::move(ok.error()));
                                items.push_back(std::move(**conv));
                            } else if (mapped == "port-range" || mapped == "source-port-range") {
                                auto colon = val.find(':');
                                if (colon != std::string::npos) {
                                    if (colon + 1 == val.size()) val.append("65535");
                                    if (colon == 0) val = "1" + val;
                                    for (auto& ch : val) if (ch == ':') ch = '-';
                                }
                                if (auto ok = take_node(); !ok) return std::unexpected(std::move(ok.error()));
                                items.push_back(Rule{std::move(mapped), std::move(val), {}});
                            } else if (mapped == "query-type") {
                                auto q = qtype_value(val);
                                if (!q) { if (lenient) continue; return std::unexpected(Error{ErrorCode::schema, "unsupported query_type: " + val}); }
                                if (auto ok = take_node(); !ok) return std::unexpected(std::move(ok.error()));
                                items.push_back(Rule{"query-type", std::move(*q), {}});
                            } else if (mapped == "wifi-bssid") {
                                auto mac = srs_detail::normalize_bssid(val);
                                if (!mac) { if (lenient) continue; return std::unexpected(Error{ErrorCode::schema, "invalid wifi_bssid: " + val}); }
                                if (auto ok = take_node(); !ok) return std::unexpected(std::move(ok.error()));
                                items.push_back(Rule{"wifi-bssid", std::move(*mac), {}});
                            } else if ((mapped == "domain-regex" || mapped == "process-path-regex" || mapped == "package-name-regex") &&
                                       lenient && !BoundedRegex::compile(val)) {
                                continue;
                            } else {
                                if (mapped == "domain" || mapped == "domain-keyword" || mapped == "network-type") lower_ascii(val);
                                if (auto ok = take_node(); !ok) return std::unexpected(std::move(ok.error()));
                                items.push_back(Rule{std::move(mapped), std::move(val), {}});
                            }
                        }
                        auto& target = groups[group_for_key(*key)];
                        target.insert(target.end(), std::make_move_iterator(items.begin()), std::make_move_iterator(items.end()));
                    } else if (lenient) {
                        if (auto ok = p.skip_value(depth + 1); !ok) return std::unexpected(std::move(ok.error()));
                    } else {
                        return std::unexpected(Error{ErrorCode::schema, "unsupported JSON rule key: " + *key});
                    }
                    if (p.take('}')) break;
                    if (!p.take(',')) return JsonParser::fail("expected ',' or '}' in JSON rule");
                }
            }
            if (rtype == "logical") {
                if (mode != "and" && mode != "or") return std::unexpected(Error{ErrorCode::schema, "logical rule requires mode and/or"});
                if (logical_children.empty()) { if (lenient) return std::optional<Rule>{}; return JsonParser::fail("empty logical rule"); }
                if (auto ok = take_node(); !ok) return std::unexpected(std::move(ok.error()));
                Rule out = logical_children.size() == 1 ? std::move(logical_children.front()) : Rule{std::move(mode), {}, std::move(logical_children)};
                if (invert) {
                    if (auto ok = take_node(); !ok) return std::unexpected(std::move(ok.error()));
                    return std::optional<Rule>{Rule{"not", {}, {std::move(out)}}};
                }
                return std::optional<Rule>{std::move(out)};
            }
            if (rtype != "default") return std::unexpected(Error{ErrorCode::schema, "unsupported JSON rule type: " + rtype});
            std::vector<Rule> parts;
            for (auto& g : groups) {
                if (g.empty()) continue;
                if (g.size() == 1) { parts.push_back(std::move(g.front())); continue; }
                if (auto ok = take_node(); !ok) return std::unexpected(std::move(ok.error()));
                parts.push_back(Rule{"or", {}, std::move(g)});
            }
            if (parts.empty()) {
                if (lenient) return std::optional<Rule>{};
                return JsonParser::fail("empty JSON rule");
            }
            Rule out = parts.size() == 1 ? std::move(parts.front()) : Rule{"and", {}, std::move(parts)};
            if (parts.size() > 1) if (auto ok = take_node(); !ok) return std::unexpected(std::move(ok.error()));
            if (invert) {
                if (auto ok = take_node(); !ok) return std::unexpected(std::move(ok.error()));
                return std::optional<Rule>{Rule{"not", {}, {std::move(out)}}};
            }
            return std::optional<Rule>{std::move(out)};
        }
    }

    auto parse_json_ruleset(std::string_view input, bool lenient) -> std::expected<RuleSet, Error> {
        if (input.size() > max_input_bytes) return std::unexpected(Error{ErrorCode::limit, "JSON rule-set exceeds 256 MiB"});
        JsonParser p{input, 0};
        RuleSet set{{}, 2};
        std::size_t nodes = 0;
        if (p.peek() == '[') {
            p.take('[');
            if (!p.take(']')) {
                for (;;) {
                    auto r = parse_rule_object(p, 1, lenient, nodes);
                    if (!r) return std::unexpected(std::move(r.error()));
                    if (*r) set.rules.push_back(std::move(**r));
                    if (p.take(']')) break;
                    if (!p.take(',')) return JsonParser::fail("expected ',' in JSON rule array");
                }
            }
        } else {
            if (!p.take('{')) return JsonParser::fail("expected JSON rule-set object");
            bool rules_seen = false;
            if (!p.take('}')) {
                for (;;) {
                    auto key = p.read_string();
                    if (!key) return std::unexpected(std::move(key.error()));
                    if (!p.take(':')) return JsonParser::fail("expected ':' in JSON rule-set");
                    if (*key == "version") {
                        auto v = p.read_uint();
                        if (!v || *v < 1 || *v > 5) return std::unexpected(Error{ErrorCode::schema, "unsupported JSON rule-set version"});
                    } else if (*key == "rules") {
                        rules_seen = true;
                        if (!p.take('[')) return JsonParser::fail("expected JSON rules array");
                        if (!p.take(']')) {
                            for (;;) {
                                auto r = parse_rule_object(p, 1, lenient, nodes);
                                if (!r) return std::unexpected(std::move(r.error()));
                                if (*r) set.rules.push_back(std::move(**r));
                                if (p.take(']')) break;
                                if (!p.take(',')) return JsonParser::fail("expected ',' in JSON rules array");
                            }
                        }
                    } else if (lenient) {
                        if (auto ok = p.skip_value(1); !ok) return std::unexpected(std::move(ok.error()));
                    } else {
                        return std::unexpected(Error{ErrorCode::schema, "unsupported JSON rule-set key: " + *key});
                    }
                    if (p.take('}')) break;
                    if (!p.take(',')) return JsonParser::fail("expected ',' or '}' in JSON rule-set");
                }
            }
            if (!rules_seen) return JsonParser::fail("JSON rule-set missing rules array");
        }
        p.skip_ws();
        if (p.pos != input.size()) return JsonParser::fail("trailing data after JSON rule-set");
        return normalize_set(std::move(set));
    }
}
