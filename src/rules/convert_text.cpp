module rules.convert_external;
import std;
import platform.ip_address;
import rules.regex;

namespace rules {
    namespace {
        auto trim_ws(std::string_view s) noexcept -> std::string_view {
            while (!s.empty() && (s.front() == ' ' || s.front() == '\t' || s.front() == '\r')) s.remove_prefix(1);
            while (!s.empty() && (s.back() == ' ' || s.back() == '\t' || s.back() == '\r')) s.remove_suffix(1);
            return s;
        }

        auto strip_quotes(std::string_view s) noexcept -> std::string_view {
            s = trim_ws(s);
            if (s.size() >= 2 && ((s.front() == '\'' && s.back() == '\'') || (s.front() == '"' && s.back() == '"'))) {
                s.remove_prefix(1);
                s.remove_suffix(1);
            }
            return trim_ws(s);
        }

        auto lower_copy(std::string_view s) -> std::string {
            std::string out(s);
            for (auto& c : out) if (c >= 'A' && c <= 'Z') c = static_cast<char>(c + ('a' - 'A'));
            return out;
        }

        auto unwrap_yaml_payload_line(std::string_view raw, bool& seen_payload) -> std::optional<std::string_view> {
            auto line = trim_ws(raw);
            if (line.empty() || line.starts_with('#') || line.starts_with("//") || line == "---") return std::nullopt;
            if (!seen_payload && (line == "payload:" || line.starts_with("payload:"))) {
                seen_payload = true;
                return std::nullopt;
            }
            if (line.starts_with("- ")) line.remove_prefix(2);
            else if (line == "-") return std::nullopt;
            line = strip_quotes(line);
            // Remove trailing inline comment when unquoted
            if (auto hash = line.find(" #"); hash != std::string_view::npos) line = trim_ws(line.substr(0, hash));
            if (line.empty() || line.starts_with('#')) return std::nullopt;
            return line;
        }

        auto make_sub_suffix(std::string bare) -> Rule {
            return Rule{"and", {}, {Rule{"domain-suffix", bare, {}}, Rule{"not", {}, {Rule{"domain", std::move(bare), {}}}}}};
        }

        auto append_rule_key(Rule const& r, std::string& out) -> void {
            out.append(r.type);
            out.push_back('\x1f');
            out.append(r.value);
            out.push_back('\x1e');
            for (auto const& c : r.children) append_rule_key(c, out);
            out.push_back('\x1d');
        }
    }

    auto parse_domain_list(std::string_view input, bool lenient) -> std::expected<RuleSet, Error> {
        if (input.size() > max_input_bytes) return std::unexpected(Error{ErrorCode::limit, "domain list exceeds 32 MiB"});
        RuleSet set{{}, 2};
        bool seen_payload = false;
        while (!input.empty()) {
            auto nl = input.find('\n');
            auto line = input.substr(0, nl);
            input = nl == std::string_view::npos ? std::string_view{} : input.substr(nl + 1);
            auto item = unwrap_yaml_payload_line(line, seen_payload);
            if (!item) continue;
            if (set.rules.size() >= max_rules) return std::unexpected(Error{ErrorCode::limit, "rule count exceeds limit"});
            auto s = *item;
            if (s.starts_with("+.")) {
                set.rules.push_back({"domain-suffix", lower_copy(s.substr(2)), {}});
            } else if (s.starts_with("*.")) {
                set.rules.push_back({"domain-wildcard", lower_copy(s), {}});
            } else if (s.starts_with('.')) {
                set.rules.push_back(make_sub_suffix(lower_copy(s.substr(1))));
            } else if (s.starts_with("domain:")) {
                set.rules.push_back({"domain-suffix", lower_copy(s.substr(7)), {}});
            } else if (s.starts_with("full:")) {
                set.rules.push_back({"domain", lower_copy(s.substr(5)), {}});
            } else if (s.starts_with("keyword:")) {
                set.rules.push_back({"domain-keyword", lower_copy(s.substr(8)), {}});
            } else if (s.starts_with("regexp:")) {
                auto pat = std::string(s.substr(7));
                if (lenient && !BoundedRegex::compile(pat)) continue;
                set.rules.push_back({"domain-regex", std::move(pat), {}});
            } else if (lenient && !valid_domain(s)) {
                continue;
            } else {
                set.rules.push_back({"domain", lower_copy(s), {}});
            }
        }
        return normalize_set(std::move(set));
    }

    auto parse_ipcidr_list(std::string_view input, bool lenient) -> std::expected<RuleSet, Error> {
        if (input.size() > max_input_bytes) return std::unexpected(Error{ErrorCode::limit, "IP CIDR list exceeds 32 MiB"});
        RuleSet set{{}, 2};
        bool seen_payload = false;
        while (!input.empty()) {
            auto nl = input.find('\n');
            auto line = input.substr(0, nl);
            input = nl == std::string_view::npos ? std::string_view{} : input.substr(nl + 1);
            auto item = unwrap_yaml_payload_line(line, seen_payload);
            if (!item) continue;
            if (set.rules.size() >= max_rules) return std::unexpected(Error{ErrorCode::limit, "rule count exceeds limit"});
            std::string val(*item);
            if (auto comma = val.find(','); comma != std::string::npos) val.resize(comma);
            if (!val.contains('/')) {
                auto parsed = platform::parse_ip_address(val);
                if (!parsed) {
                    if (lenient) continue;
                    return std::unexpected(Error{ErrorCode::invalid_rule, "invalid IP CIDR entry: " + val});
                }
                val.append(parsed->size == 4 ? "/32" : "/128");
            }
            set.rules.push_back({"ip-cidr", std::move(val), {}});
        }
        return normalize_set(std::move(set));
    }

    auto parse_classical_list(std::string_view input, bool lenient) -> std::expected<RuleSet, Error> {
        if (input.size() > max_input_bytes) return std::unexpected(Error{ErrorCode::limit, "classical list exceeds 32 MiB"});
        RuleSet set{{}, 2};
        bool seen_payload = false;
        while (!input.empty()) {
            auto nl = input.find('\n');
            auto line = input.substr(0, nl);
            input = nl == std::string_view::npos ? std::string_view{} : input.substr(nl + 1);
            auto item = unwrap_yaml_payload_line(line, seen_payload);
            if (!item) continue;
            if (set.rules.size() >= max_rules) return std::unexpected(Error{ErrorCode::limit, "rule count exceeds limit"});
            auto s = *item;
            auto c1 = s.find(',');
            if (c1 == std::string_view::npos) {
                if (lenient) continue;
                return std::unexpected(Error{ErrorCode::schema, "classical rule requires KIND,VALUE"});
            }
            auto kind = trim_ws(s.substr(0, c1));
            auto rest = s.substr(c1 + 1);
            auto c2 = rest.find(',');
            auto val = trim_ws(c2 == std::string_view::npos ? rest : rest.substr(0, c2));
            std::string up;
            for (char ch : kind) up.push_back(ch >= 'a' && ch <= 'z' ? static_cast<char>(ch - ('a' - 'A')) : ch);
            auto map_port = [&](std::string_view base, std::string_view range) -> std::string_view {
                return val.contains('-') ? range : base;
            };
            if (up == "DOMAIN") set.rules.push_back({"domain", lower_copy(val), {}});
            else if (up == "DOMAIN-SUFFIX") set.rules.push_back({"domain-suffix", lower_copy(val), {}});
            else if (up == "DOMAIN-KEYWORD") set.rules.push_back({"domain-keyword", lower_copy(val), {}});
            else if (up == "DOMAIN-WILDCARD") set.rules.push_back({"domain-wildcard", lower_copy(val), {}});
            else if (up == "DOMAIN-REGEX") {
                if (lenient && !BoundedRegex::compile(val)) continue;
                set.rules.push_back({"domain-regex", std::string(val), {}});
            } else if (up == "IP-CIDR" || up == "IP-CIDR6") {
                std::string cidr(val);
                if (!cidr.contains('/')) if (auto ip = platform::parse_ip_address(cidr)) cidr += ip->size == 4 ? "/32" : "/128";
                set.rules.push_back({"ip-cidr", std::move(cidr), {}});
            } else if (up == "SRC-IP-CIDR" || up == "SRC-IP-CIDR6") {
                std::string cidr(val);
                if (!cidr.contains('/')) if (auto ip = platform::parse_ip_address(cidr)) cidr += ip->size == 4 ? "/32" : "/128";
                set.rules.push_back({"source-ip-cidr", std::move(cidr), {}});
            } else if (up == "DST-PORT") set.rules.push_back({std::string(map_port("port", "port-range")), std::string(val), {}});
            else if (up == "SRC-PORT") set.rules.push_back({std::string(map_port("source-port", "source-port-range")), std::string(val), {}});
            else if (up == "PROCESS-NAME") set.rules.push_back({"process-name", std::string(val), {}});
            else if (up == "PROCESS-PATH") set.rules.push_back({"process-path", std::string(val), {}});
            else if (up == "PROCESS-PATH-REGEX") {
                if (lenient && !BoundedRegex::compile(val)) continue;
                set.rules.push_back({"process-path-regex", std::string(val), {}});
            } else if (up == "NETWORK" || up == "PROTOCOL") {
                std::string mapped = lower_copy(val);
                if (up == "NETWORK") set.rules.push_back({"network", std::move(mapped), {}});
                else set.rules.push_back({"protocol", std::move(mapped), {}});
            } else if (!lenient) {
                return std::unexpected(Error{ErrorCode::schema, "unsupported classical rule type: " + up});
            }
        }
        return normalize_set(std::move(set));
    }

    auto parse_adguard_list(std::string_view input, bool lenient) -> std::expected<RuleSet, Error> {
        if (input.size() > max_input_bytes) return std::unexpected(Error{ErrorCode::limit, "AdGuard filter exceeds 32 MiB"});
        std::vector<Rule> allow, block;
        std::unordered_set<std::string> seen;
        auto push_unique = [&](std::vector<Rule>& dst, Rule r) -> bool {
            if (seen.size() >= max_rules) return false;
            std::string key;
            append_rule_key(r, key);
            if (seen.insert(std::move(key)).second) dst.push_back(std::move(r));
            return true;
        };
        while (!input.empty()) {
            auto nl = input.find('\n');
            auto line = trim_ws(input.substr(0, nl));
            input = nl == std::string_view::npos ? std::string_view{} : input.substr(nl + 1);
            if (line.empty() || line.starts_with('!') || line.starts_with('#') || line.starts_with('[')) continue;
            if (line.contains("##") || line.contains("#@#") || line.contains("#?#")) continue;
            bool is_allow = false;
            if (line.starts_with("@@")) { is_allow = true; line.remove_prefix(2); }
            if (auto mod = line.find('$'); mod != std::string_view::npos && !line.starts_with('/')) {
                auto params = line.substr(mod + 1);
                line = line.substr(0, mod);
                bool ok_mod = params == "important";
                if (!ok_mod) {
                    if (!lenient && !params.empty()) continue; // AdGuard converter ignores unknown modifiers instead of failing file
                    continue;
                }
            }
            if (line.starts_with('/') && line.ends_with('/') && line.size() > 2) {
                auto pat = std::string(line.substr(1, line.size() - 2));
                if (!BoundedRegex::compile(pat)) continue;
                if (!push_unique(is_allow ? allow : block, {"domain-regex", std::move(pat), {}}))
                    return std::unexpected(Error{ErrorCode::limit, "rule count exceeds limit"});
                continue;
            }
            bool suffix = false, exact = false;
            if (line.starts_with("||")) { line.remove_prefix(2); suffix = true; }
            else if (line.starts_with('|')) { line.remove_prefix(1); exact = true; }
            if (line.ends_with('|')) line.remove_suffix(1);
            if (line.ends_with('^')) { line.remove_suffix(1); if (!suffix) exact = true; }
            if (auto sep = line.find("://"); sep != std::string_view::npos) { line.remove_prefix(sep + 3); suffix = true; }
            if (line.empty() || line.find_first_of("/?&=*[]()!#~:") != std::string_view::npos) continue;
            if (line.starts_with('.')) line.remove_prefix(1);
            if (!valid_domain(line)) continue;
            Rule rule{suffix ? "domain-suffix" : exact ? "domain" : "domain-suffix", lower_copy(line), {}};
            if (!push_unique(is_allow ? allow : block, std::move(rule)))
                return std::unexpected(Error{ErrorCode::limit, "rule count exceeds limit"});
        }
        RuleSet set{{}, 2};
        if (allow.empty()) {
            set.rules = std::move(block);
        } else if (!block.empty()) {
            Rule allow_group = allow.size() == 1 ? std::move(allow.front()) : Rule{"or", {}, std::move(allow)};
            Rule block_group = block.size() == 1 ? std::move(block.front()) : Rule{"or", {}, std::move(block)};
            set.rules.push_back(Rule{"and", {}, {std::move(block_group), Rule{"not", {}, {std::move(allow_group)}}}});
        }
        return normalize_set(std::move(set));
    }

    auto merge_rule_sets(std::span<RuleSet const> sets) -> std::expected<RuleSet, Error> {
        RuleSet out{{}, 2};
        std::unordered_set<std::string> seen;
        std::string key;
        for (auto const& set : sets) {
            for (auto const& rule : set.rules) {
                key.clear();
                append_rule_key(rule, key);
                if (!seen.insert(key).second) continue;
                if (out.rules.size() >= max_rules)
                    return std::unexpected(Error{ErrorCode::limit, "merged rule count exceeds limit"});
                out.rules.push_back(rule);
            }
        }
        return normalize_set(std::move(out));
    }
}
