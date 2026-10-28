module nexus.rules;
import std;
import nexus.thirdparty.glaze;

namespace nexus::rules {
    namespace g = nex::glaze;

    auto valid_beve_profile(std::string_view payload) -> bool;

    // Glaze's reflection requires the mapped type to have linkage on Clang.
    struct WireSet {
        std::uint32_t schema_version{};
        std::string kind;
        std::vector<Rule> rules;
    };

    namespace {
        constexpr std::string_view magic{"NXRULES\0", 8};
        constexpr std::size_t header_size = 16;

        struct LimitedContext : g::Context {
            std::size_t max_string_length = 253;
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

        auto validated(std::vector<Rule> const& entries) -> std::expected<RuleSet, Error> {
            if (entries.size() > max_rules) return std::unexpected(Error{ErrorCode::limit, "too many rules"});
            RuleSet result;
            result.rules.reserve(entries.size());
            for (auto const& entry : entries) {
                auto rule = normalize_rule(entry);
                if (!rule) return std::unexpected(std::move(rule.error()));
                result.rules.push_back(std::move(*rule));
            }
            return result;
        }
    }

    auto parse_beve(std::string_view input) -> std::expected<RuleSet, Error> {
        if (input.size() > max_input_bytes) return std::unexpected(Error{ErrorCode::limit, "BEVE input exceeds 1 MiB"});
        if (input.size() < header_size || input.substr(0, magic.size()) != magic) return invalid("invalid rule-set header");
        if (input[8] != '\0' || input[9] != '\1' || input[10] != '\0' || input[11] != '\0')
            return invalid("unsupported container version or flags");
        auto size = payload_size(input);
        if (size == 0 || size != input.size() - header_size) return invalid("invalid payload length");
        auto payload = input.substr(header_size);
        if (!valid_beve_profile(payload)) return invalid("invalid BEVE profile or duplicate field");
        WireSet wire;
        LimitedContext context;
        constexpr g::opts options{.error_on_unknown_keys = true, .error_on_missing_keys = true};
        auto consumed = g::read_beve_at<options>(wire, payload, 0, context);
        if (!consumed || *consumed != payload.size()) return invalid("invalid or trailing BEVE payload");
        if (wire.schema_version != 1 || wire.kind != "predicate") return invalid("unsupported rule schema or kind");
        return validated(wire.rules);
    }

    auto write_beve(RuleSet const& set) -> std::expected<std::string, Error> {
        auto normalized = validated(set.rules);
        if (!normalized) return std::unexpected(std::move(normalized.error()));
        WireSet wire{1, "predicate", std::move(normalized->rules)};
        std::string payload;
        if (auto error = g::write_beve(wire, payload); error) return invalid("cannot encode BEVE payload");
        if (payload.empty() || payload.size() > max_input_bytes - header_size)
            return std::unexpected(Error{ErrorCode::limit, "BEVE output exceeds 1 MiB"});
        auto length = static_cast<std::uint32_t>(payload.size());
        std::string output(magic);
        output.push_back('\0'); output.push_back('\1');
        output.push_back('\0'); output.push_back('\0');
        for (int shift = 24; shift >= 0; shift -= 8) output.push_back(static_cast<char>((length >> shift) & 0xffU));
        output += payload;
        return output;
    }
}
