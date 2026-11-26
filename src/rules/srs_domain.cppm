// SRS stream reader, succinct domain/AdGuard trie decoders & BSSID normalizer.
export module rules.srs_domain;
import std;
import rules;
import rules.regex;

export namespace rules::srs_detail {
    struct Reader {
        std::span<std::uint8_t const> input;
        std::size_t offset = 0, nodes = 0;
        bool ip_cidr_match_source = false;
        bool lenient = false;

        auto byte() -> std::optional<std::uint8_t> {
            if (offset == input.size()) return {};
            return input[offset++];
        }
        auto varint() -> std::optional<std::uint64_t> {
            std::uint64_t value = 0;
            for (unsigned shift = 0; shift < 70; shift += 7) {
                auto b = byte();
                if (!b || (shift == 63 && *b > 1)) return {};
                value |= std::uint64_t(*b & 127) << shift;
                if (!(*b & 128)) {
                    if (shift && !*b) return {};
                    return value;
                }
            }
            return {};
        }
        auto string(std::size_t limit) -> std::optional<std::string> {
            auto length = varint();
            if (!length || *length > limit || *length > input.size() - offset) return {};
            std::string value(reinterpret_cast<char const*>(input.data() + offset), static_cast<std::size_t>(*length));
            offset += static_cast<std::size_t>(*length);
            return value;
        }
        auto take_node(std::size_t n = 1) -> bool {
            if (n > max_rules - nodes) return false;
            nodes += n;
            return true;
        }
    };

    inline auto failure(std::string message) -> std::unexpected<Error> {
        return std::unexpected(Error{ErrorCode::schema, std::move(message)});
    }

    inline auto normalize_bssid(std::string_view raw) -> std::optional<std::string> {
        while (!raw.empty() && (raw.front() == ' ' || raw.front() == '\t' || raw.front() == '\r' || raw.front() == '\n'))
            raw.remove_prefix(1);
        while (!raw.empty() && (raw.back() == ' ' || raw.back() == '\t' || raw.back() == '\r' || raw.back() == '\n'))
            raw.remove_suffix(1);
        auto hex_val = [](char c) noexcept -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        };
        std::array<std::uint8_t, 6> mac{};
        if (raw.size() == 17) {
            char sep = raw[2];
            if (sep != ':' && sep != '-') return {};
            for (std::size_t i = 0; i < 6; ++i) {
                if (i < 5 && raw[i * 3 + 2] != sep) return {};
                int hi = hex_val(raw[i * 3]), lo = hex_val(raw[i * 3 + 1]);
                if (hi < 0 || lo < 0) return {};
                mac[i] = static_cast<std::uint8_t>((hi << 4) | lo);
            }
        } else if (raw.size() == 12) {
            for (std::size_t i = 0; i < 6; ++i) {
                int hi = hex_val(raw[i * 2]), lo = hex_val(raw[i * 2 + 1]);
                if (hi < 0 || lo < 0) return {};
                mac[i] = static_cast<std::uint8_t>((hi << 4) | lo);
            }
        } else return {};
        return std::format("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    }

    inline auto adguard_parts_to_rule(std::string key, bool is_suffix, bool has_start, bool has_end, bool lenient)
        -> std::expected<std::optional<Rule>, Error> {
        for (auto& c : key) if (c >= 'A' && c <= 'Z') c = static_cast<char>(c + ('a' - 'A'));
        if (key.empty()) {
            if (lenient) return std::optional<Rule>{};
            return failure("empty AdGuard domain rule");
        }
        auto make_sub = [](std::string bare) -> Rule {
            return Rule{"and", {}, {Rule{"domain-suffix", bare, {}}, Rule{"not", {}, {Rule{"domain", std::move(bare), {}}}}}};
        };
        bool has_star = key.contains('*');
        if (!has_star && is_suffix && has_end) {
            if (key.starts_with('.')) {
                auto bare = key.substr(1);
                if (valid_domain(bare)) return std::optional<Rule>{make_sub(std::move(bare))};
            } else if (valid_domain(key)) {
                return std::optional<Rule>{Rule{"domain-suffix", std::move(key), {}}};
            }
        } else if (!has_star && has_start && has_end) {
            if (valid_domain(key)) return std::optional<Rule>{Rule{"domain", std::move(key), {}}};
        } else if (!has_star && !is_suffix && !has_start && !has_end) {
            bool valid_kw = key.size() <= 253 && std::ranges::all_of(key, [](char c) {
                return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '.';
            });
            if (valid_kw) return std::optional<Rule>{Rule{"domain-keyword", std::move(key), {}}};
        } else if ((is_suffix || has_start) && has_end && key.starts_with("*.") &&
                   !std::string_view(key).substr(2).contains('*')) {
            auto bare = key.substr(2);
            if (valid_domain(bare)) return std::optional<Rule>{make_sub(std::move(bare))};
        }
        std::string pattern;
        if (is_suffix) pattern.append("(^|\\.)");
        else if (has_start) pattern.push_back('^');
        for (char c : key) {
            auto u = static_cast<unsigned char>(c);
            if (c == '*') pattern.append(".*");
            else if (std::string_view(R"(\.^$|?+()[]{}-)").contains(c)) { pattern.push_back('\\'); pattern.push_back(c); }
            else if (u >= 0x21 && u <= 0x7e) pattern.push_back(c);
            else {
                if (lenient) return std::optional<Rule>{};
                return failure("unsupported AdGuard domain character");
            }
        }
        if (has_end) pattern.push_back('$');
        if (pattern.size() > 255 || !BoundedRegex::compile(pattern)) {
            if (lenient) return std::optional<Rule>{};
            return failure("unsupported AdGuard domain pattern");
        }
        return std::optional<Rule>{Rule{"domain-regex", std::move(pattern), {}}};
    }

    inline auto convert_adguard_domain_line(std::string_view raw, bool lenient)
        -> std::expected<std::optional<Rule>, Error> {
        bool is_suffix = false, has_start = false, has_end = false;
        if (raw.starts_with("||")) { raw.remove_prefix(2); is_suffix = true; }
        else if (raw.starts_with('|')) { raw.remove_prefix(1); has_start = true; }
        if (raw.ends_with('^')) { raw.remove_suffix(1); has_end = true; }
        if (!has_end && raw.ends_with('.')) raw.remove_suffix(1);
        return adguard_parts_to_rule(std::string(raw), is_suffix, has_start, has_end, lenient);
    }

    struct SuccinctLeaf { std::string key; bool has_children = false; };

    // SRS stores a breadth-first trie as zero-labelled edges and one terminator
    // per node. Rebuild parent links once; never repeatedly scan the bitmap.
    inline auto decode_succinct_trie(Reader& reader) -> std::expected<std::vector<SuccinctLeaf>, Error> {
        auto version = reader.byte();
        if (!version || *version != 0) return failure("unsupported SRS domain set version");
        auto words = [&]() -> std::expected<std::vector<std::uint64_t>, Error> {
            auto count = reader.varint();
            if (!count || *count > (reader.input.size() - reader.offset) / 8)
                return failure("truncated SRS domain bitmap");
            std::vector<std::uint64_t> result;
            result.reserve(static_cast<std::size_t>(*count));
            for (std::uint64_t i = 0; i < *count; ++i) {
                std::uint64_t word = 0;
                for (unsigned j = 0; j < 8; ++j) word = (word << 8) | *reader.byte();
                result.push_back(word);
            }
            return result;
        };
        auto leaves = words();
        if (!leaves) return std::unexpected(std::move(leaves.error()));
        auto bitmap = words();
        if (!bitmap) return std::unexpected(std::move(bitmap.error()));
        auto count = reader.varint();
        if (!count || *count > reader.input.size() - reader.offset || *count >= max_input_bytes)
            return failure("invalid SRS domain labels");
        auto labels = reader.input.subspan(reader.offset, static_cast<std::size_t>(*count));
        reader.offset += static_cast<std::size_t>(*count);
        if (labels.empty() || bitmap->empty()) return failure("empty SRS domain trie");
        auto bit = [](std::vector<std::uint64_t> const& values, std::size_t index) {
            return index / 64 < values.size() && (values[index / 64] & (std::uint64_t{1} << (index % 64))) != 0;
        };
        struct Node { std::uint32_t parent; std::uint16_t depth; std::uint8_t label; bool children = false; };
        std::vector<Node> nodes;
        nodes.reserve(labels.size() + 1);
        nodes.push_back({0, 0, 0});
        std::size_t pos = 0, edge = 0;
        for (std::size_t parent = 0; parent < nodes.size(); ++parent) {
            std::array<bool, 256> seen{};
            while (pos < bitmap->size() * 64 && !bit(*bitmap, pos)) {
                if (edge >= labels.size() || nodes[parent].depth >= 255)
                    return failure("invalid SRS domain trie topology");
                auto label = labels[edge++];
                if (seen[label]) return failure("duplicate SRS domain edge");
                seen[label] = true;
                nodes[parent].children = true;
                nodes.push_back({static_cast<std::uint32_t>(parent),
                    static_cast<std::uint16_t>(nodes[parent].depth + 1), label});
                ++pos;
            }
            if (pos == bitmap->size() * 64) return failure("unterminated SRS domain node");
            ++pos;
        }
        if (edge != labels.size()) return failure("unreachable SRS domain edges");
        for (auto i = pos; i < bitmap->size() * 64; ++i)
            if (bit(*bitmap, i)) return failure("extra SRS domain nodes");
        for (auto i = nodes.size(); i < leaves->size() * 64; ++i)
            if (bit(*leaves, i)) return failure("extra SRS domain leaves");
        if (bit(*leaves, 0)) return failure("empty SRS domain");
        std::vector<SuccinctLeaf> out;
        for (std::size_t i = 1; i < nodes.size(); ++i) {
            if (!bit(*leaves, i)) continue;
            std::string name;
            name.reserve(nodes[i].depth);
            for (auto cursor = i; cursor; cursor = nodes[cursor].parent)
                name.push_back(static_cast<char>(nodes[cursor].label));
            out.push_back({std::move(name), nodes[i].children});
        }
        if (out.empty()) return failure("SRS domain set has no leaves");
        return out;
    }

    inline auto read_domain_set(Reader& reader, std::vector<Rule>& group) -> std::expected<void, Error> {
        auto keys = decode_succinct_trie(reader);
        if (!keys) return std::unexpected(std::move(keys.error()));
        for (auto& leaf : *keys) {
            auto& name = leaf.key;
            bool root = name.front() == '\n', subdomains = name.front() == '\r';
            if (root || subdomains) {
                if (leaf.has_children) return failure("nonterminal SRS suffix marker");
                name.erase(0, 1);
                if (subdomains) {
                    if (name.empty() || name.front() != '.') return failure("invalid SRS subdomain suffix");
                    name.erase(0, 1);
                }
            }
            if (reader.lenient) {
                for (auto& c : name) if (c >= 'A' && c <= 'Z') c = static_cast<char>(c + ('a' - 'A'));
                if (!valid_domain(name)) return failure("unsupported SRS domain name");
            } else {
                if (!valid_domain(name) || std::ranges::any_of(name, [](char c) { return c >= 'A' && c <= 'Z'; }))
                    return failure("unsupported SRS domain name or uppercase condition");
            }
            if (!reader.take_node()) return std::unexpected(Error{ErrorCode::limit, "SRS rule count exceeds limit"});
            Rule suffix{root || subdomains ? "domain-suffix" : "domain", name, {}};
            if (subdomains) {
                // A leading-dot suffix excludes the apex. Nexus suffix includes it.
                if (!reader.take_node(3))
                    return std::unexpected(Error{ErrorCode::limit, "SRS rule count exceeds limit"});
                Rule exact{"domain", name, {}};
                Rule negated{"not", {}, std::vector<Rule>{std::move(exact)}};
                group.push_back({"and", {}, std::vector<Rule>{std::move(suffix), std::move(negated)}});
            } else {
                group.push_back(std::move(suffix));
            }
        }
        return {};
    }

    inline auto read_adguard_domain_set(Reader& reader, std::vector<Rule>& group) -> std::expected<void, Error> {
        auto initial_size = group.size();
        auto keys = decode_succinct_trie(reader);
        if (!keys) return std::unexpected(std::move(keys.error()));
        for (auto& leaf : *keys) {
            auto& key = leaf.key;
            bool is_suffix = false, has_start = false, has_end = false;
            if (key.front() == '\n') { is_suffix = true; key.erase(0, 1); }
            else if (key.front() == '\r') { key.erase(0, 1); }
            else { has_start = true; }
            if (!key.empty() && key.back() == '\b') key.pop_back();
            else has_end = true;
            auto converted = adguard_parts_to_rule(std::move(key), is_suffix, has_start, has_end, reader.lenient);
            if (!converted) return std::unexpected(std::move(converted.error()));
            if (!*converted) continue;
            std::size_t cost = (*converted)->type == "and" ? 4u : 1u;
            if (!reader.take_node(cost)) return std::unexpected(Error{ErrorCode::limit, "SRS rule count exceeds limit"});
            group.push_back(std::move(**converted));
        }
        if (group.size() == initial_size && !reader.lenient)
            return failure("SRS AdGuard domain set has no usable rules");
        return {};
    }
}
