// Predefined response & RR type/rcode parsing module for DNS config.
export module config.dns_predefined;
import std;
import glaze;
import config;
import config.kdl_common;
import platform.ip_address;
import rules;

export namespace config::dns_detail {
    using namespace config::kdl;

#ifdef NEXUS_DNS_RESPONSE
    inline auto hex_bytes(std::string_view text) -> std::optional<std::vector<std::uint8_t>> {
        if (text.size() % 2 || text.size() > 8192) return {};
        auto digit = [](char c) -> int {
            return c >= '0' && c <= '9' ? c - '0' :
                   c >= 'a' && c <= 'f' ? c - 'a' + 10 :
                   c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1;
        };
        std::vector<std::uint8_t> bytes;
        bytes.reserve(text.size() / 2);
        for (std::size_t i = 0; i < text.size(); i += 2) {
            auto high = digit(text[i]), low = digit(text[i + 1]);
            if (high < 0 || low < 0) return {};
            bytes.push_back(static_cast<std::uint8_t>((high << 4) | low));
        }
        return bytes;
    }

    inline auto dns_wire_name(std::string name) -> std::optional<std::vector<std::uint8_t>> {
        if (!policy::normalize_dns_owner(name)) return {};
        std::vector<std::uint8_t> result;
        if (name != ".") {
            std::string_view remaining = name;
            while (!remaining.empty()) {
                auto dot = remaining.find('.');
                auto label = remaining.substr(0, dot);
                result.push_back(static_cast<std::uint8_t>(label.size()));
                result.insert(result.end(), label.begin(), label.end());
                if (dot == remaining.npos) break;
                remaining.remove_prefix(dot + 1);
            }
        }
        result.push_back(0);
        return result;
    }
#endif

    inline auto parse_dns_rrtype(Value const& input) -> std::optional<std::uint16_t> {
        if (auto number = integer(input))
            return (*number && *number <= 65535) ? std::optional(static_cast<std::uint16_t>(*number)) : std::nullopt;
        auto text = string(input);
        if (!text || text->empty() || text->size() > 12) return {};
        std::string upper(*text);
        for (char& ch : upper) if (ch >= 'a' && ch <= 'z') ch = static_cast<char>(ch - 'a' + 'A');
        static constexpr std::array<std::pair<std::string_view, std::uint16_t>, 20> table{{
            {"A", 1}, {"NS", 2}, {"CNAME", 5}, {"SOA", 6}, {"PTR", 12}, {"MX", 15}, {"TXT", 16}, {"AAAA", 28},
            {"SRV", 33}, {"NAPTR", 35}, {"DNAME", 39}, {"DS", 43}, {"RRSIG", 46}, {"NSEC", 47}, {"DNSKEY", 48},
            {"SVCB", 64}, {"HTTPS", 65}, {"SPF", 99}, {"ANY", 255}, {"CAA", 257}
        }};
        for (auto [name, code] : table) if (upper == name) return code;
        return {};
    }

    inline auto parse_dns_rcode(Value const& input) -> std::optional<std::uint8_t> {
        if (auto number = integer(input))
            return *number <= 15 ? std::optional(static_cast<std::uint8_t>(*number)) : std::nullopt;
        auto text = string(input);
        if (!text || text->empty() || text->size() > 12) return {};
        std::string upper(*text);
        for (char& ch : upper) if (ch >= 'a' && ch <= 'z') ch = static_cast<char>(ch - 'a' + 'A');
        static constexpr std::array<std::pair<std::string_view, std::uint8_t>, 6> table{{
            {"NOERROR", 0}, {"FORMERR", 1}, {"SERVFAIL", 2}, {"NXDOMAIN", 3}, {"NOTIMP", 4}, {"REFUSED", 5}
        }};
        for (auto [name, code] : table) if (upper == name) return code;
        return {};
    }

    inline auto parse_dns_predefined(Node const& child, Value const* predefined_rcode, DnsRule& rule)
        -> std::expected<void, std::string> {
#ifdef NEXUS_DNS_RESPONSE
        if (rule.action == policy::DnsAction::predefined) {
            rule.predefined.emplace();
            if (predefined_rcode) {
                auto value = parse_dns_rcode(*predefined_rcode);
                if (!value) return error("invalid predefined DNS rcode");
                rule.predefined->rcode = *value;
            }
            for (auto const& node : child.children) {
                if (node.name != "record") continue;
                auto section = text_property(node, "section"), name = text_property(node, "name"), data = text_property(node, "data-hex");
                auto address = text_property(node, "address"), target = text_property(node, "target");
                auto type_value = property(node, "type"), class_value = property(node, "class"), ttl_value = property(node, "ttl");
                auto record_type = type_value ? parse_dns_rrtype(*type_value) : std::nullopt;
                auto record_class = class_value ? integer(*class_value) : std::optional<std::uint64_t>{1};
                auto ttl = ttl_value ? integer(*ttl_value) : std::optional<std::uint64_t>{60};
                if (node.tag || !node.arguments.empty() || !node.children.empty() ||
                    !section || !name || (bool(data) + bool(address) + bool(target) != 1) || !record_type || !*record_type || *record_type > 65535 ||
                    !record_class || !*record_class || *record_class > 65535 || !ttl || *ttl > 0xffffffffu ||
                    node.properties.size() != 4u + bool(class_value) + bool(ttl_value) ||
                    rule.predefined->records.size() >= 128) return error("invalid predefined DNS record");
                policy::ResponseSection where;
                if (*section == "answer") where = policy::ResponseSection::answer;
                else if (*section == "authority") where = policy::ResponseSection::authority;
                else if (*section == "additional") where = policy::ResponseSection::additional;
                else return error("invalid predefined DNS section");
                policy::PredefinedRecord record{where, *name, static_cast<std::uint16_t>(*record_type),
                    static_cast<std::uint16_t>(*record_class), static_cast<std::uint32_t>(*ttl), {}};
                if (data) {
                    auto bytes = hex_bytes(*data);
                    if (!bytes) return error("invalid predefined DNS record data");
                    record.data = std::move(*bytes);
                } else if (address) {
                    auto expected_size = record.type == 1 ? 4u : record.type == 28 ? 16u : 0u;
                    auto parsed = expected_size ? platform::parse_ip_address(*address) : std::nullopt;
                    if (!parsed || parsed->size != expected_size) return error("invalid predefined DNS address");
                    record.data.assign(parsed->bytes.begin(), parsed->bytes.begin() + expected_size);
                } else {
                    if (record.type != 2 && record.type != 5 && record.type != 12 && record.type != 39)
                        return error("predefined DNS target requires a name record");
                    auto encoded = dns_wire_name(*target);
                    if (!encoded) return error("invalid predefined DNS target");
                    record.data = std::move(*encoded);
                }
                rule.predefined->records.push_back(std::move(record));
            }
        } else if (predefined_rcode || std::ranges::any_of(child.children, [](auto const& n) { return n.name == "record"; }))
            return error("predefined DNS fields require predefined action");
#else
        (void)rule;
        if (predefined_rcode || std::ranges::any_of(child.children, [](auto const& n) { return n.name == "record"; }))
            return error("DNS response rules are unavailable in this build");
#endif
        return {};
    }
}
