module rules;
import std;
import glaze;

namespace rules {
    namespace g = ::glaze;

    auto valid_beve_profile(std::string_view payload) -> bool;
    auto normalize_set(RuleSet set) -> std::expected<RuleSet, Error>;

    // Glaze's reflection requires the mapped type to have linkage on Clang.
    struct WireSetV2 {
        std::uint32_t schema_version{};
        std::string kind;
        std::vector<Rule> rules;
    };

    namespace {
        constexpr std::string_view magic{"NXRULES\0", 8};
        constexpr std::size_t header_size = 16;

        struct LimitedContext : g::Context {
            std::size_t max_string_length = 255;
            std::size_t max_array_size = max_rules;
        };

        auto invalid(std::string message) -> std::unexpected<Error> {
            return std::unexpected(Error{ErrorCode::schema, std::move(message)});
        }

        auto payload_size(std::string_view input) -> std::uint32_t {
            auto byte = [&](std::size_t i) { return static_cast<std::uint8_t>(input[i]); };
            return (std::uint32_t(byte(12)) << 24) | (std::uint32_t(byte(13)) << 16) |
                   (std::uint32_t(byte(14)) << 8) | byte(15);
        }

    }

    auto parse_beve(std::string_view input) -> std::expected<RuleSet, Error> {
        if (input.size() > max_input_bytes) return std::unexpected(Error{ErrorCode::limit, "BEVE input exceeds 256 MiB"});
        if (input.size() < header_size || input.substr(0, magic.size()) != magic) return invalid("invalid rule-set header");
        if (input[8] != '\0' || input[9] != '\1' || input[10] != '\0' || input[11] != '\0')
            return invalid("unsupported container version or flags");
        auto size = payload_size(input);
        if (size == 0 || size != input.size() - header_size) return invalid("invalid payload length");
        auto payload = input.substr(header_size);
        constexpr g::opts options{.error_on_unknown_keys = true, .error_on_missing_keys = true};
        if (!valid_beve_profile(payload)) return invalid("invalid BEVE profile or duplicate field");
        WireSetV2 wire;
        LimitedContext context;
        auto consumed=g::read_beve_at<options>(wire,payload,0,context);
        if (!consumed || *consumed!=payload.size() || wire.schema_version!=2 || wire.kind!="predicate")
            return invalid("unsupported rule schema or kind");
        return normalize_set(RuleSet{std::move(wire.rules),2});
    }

    auto write_beve(RuleSet const& set) -> std::expected<std::string, Error> {
        if (set.rules.size() > max_rules)
            return std::unexpected(Error{ErrorCode::limit, "rule nesting or count exceeds limit"});
        std::size_t min_bytes = header_size;
        auto estimate = [&](auto&& self, Rule const& r, unsigned depth) -> bool {
            if (depth > max_rule_depth) return true;
            std::size_t add = 24u + r.type.size() + r.value.size();
            if (add > max_input_bytes - min_bytes) return false;
            min_bytes += add;
            for (auto const& c : r.children) if (!self(self, c, depth + 1)) return false;
            return true;
        };
        for (auto const& r : set.rules)
            if (!estimate(estimate, r, 1))
                return std::unexpected(Error{ErrorCode::limit, "BEVE output exceeds 256 MiB"});
        auto normalized = normalize_set(set);
        if (!normalized) return std::unexpected(std::move(normalized.error()));
        std::string payload;
        WireSetV2 wire{2,"predicate",std::move(normalized->rules)};
        if (auto error=g::write_beve(wire,payload); error) return invalid("cannot encode BEVE payload");
        if (payload.empty() || payload.size() > max_input_bytes - header_size)
            return std::unexpected(Error{ErrorCode::limit, "BEVE output exceeds 256 MiB"});
        auto length = static_cast<std::uint32_t>(payload.size());
        std::string output(magic);
        output.push_back('\0'); output.push_back('\1');
        output.push_back('\0'); output.push_back('\0');
        for (int shift = 24; shift >= 0; shift -= 8) output.push_back(static_cast<char>((length >> shift) & 0xffU));
        output += payload;
        return output;
    }
}
