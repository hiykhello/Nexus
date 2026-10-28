module nexus.rules;
import std;
import nexus.thirdparty.glaze;

namespace nexus::rules {
    namespace g = nex::glaze;

    namespace {
        auto schema_error(std::string message) -> std::unexpected<Error> {
            return std::unexpected(Error{ErrorCode::schema, std::move(message)});
        }

        auto scalar_string(g::KdlValue const& value) -> std::string const* {
            if (value.tag) return nullptr;
            return std::get_if<std::string>(&value.data);
        }

        auto single_string(g::KdlNode const& node) -> std::string const* {
            if (node.tag || !node.properties.empty() || !node.children.empty() || node.arguments.size() != 1) return nullptr;
            return scalar_string(node.arguments.front());
        }

        auto version_is_one(g::KdlNode const& node) -> bool {
            if (node.tag || !node.properties.empty() || !node.children.empty() || node.arguments.size() != 1) return false;
            auto const& value = node.arguments.front();
            if (value.tag) return false;
            if (auto p = std::get_if<std::int64_t>(&value.data)) return *p == 1;
            if (auto p = std::get_if<std::uint64_t>(&value.data)) return *p == 1;
            return false;
        }

        auto decode_rule(g::KdlNode const& node) -> std::expected<Rule, Error> {
            if (node.tag || !node.arguments.empty() || !node.children.empty() || node.properties.size() != 2)
                return schema_error("rule requires only type and value properties");
            Rule rule;
            bool has_type = false, has_value = false;
            for (auto const& [key, value] : node.properties) {
                auto text = scalar_string(value);
                if (!text) return schema_error("rule properties must be untagged strings");
                if (key == "type") { rule.type = *text; has_type = true; }
                else if (key == "value") { rule.value = *text; has_value = true; }
                else return schema_error("unknown rule property: " + key);
            }
            if (!has_type || !has_value) return schema_error("rule requires type and value");
            return normalize_rule(std::move(rule));
        }
    }

    auto parse_kdl(std::string_view input) -> std::expected<RuleSet, Error> {
        if (input.size() > max_input_bytes) return std::unexpected(Error{ErrorCode::limit, "KDL input exceeds 1 MiB"});
        auto document = g::read_kdl<g::KdlDocument>(input);
        if (!document) return std::unexpected(Error{ErrorCode::syntax, g::format_error(document.error(), input)});
        bool version_seen = false, kind_seen = false;
        RuleSet result;
        for (auto const& node : *document) {
            if (node.name == "schema-version") {
                if (version_seen || !version_is_one(node)) return schema_error("expected one schema-version 1");
                version_seen = true;
            } else if (node.name == "kind") {
                auto value = single_string(node);
                if (kind_seen || !value || *value != "predicate") return schema_error("expected one kind predicate");
                kind_seen = true;
            } else if (node.name == "rule") {
                if (result.rules.size() >= max_rules) return std::unexpected(Error{ErrorCode::limit, "too many rules"});
                auto rule = decode_rule(node);
                if (!rule) return std::unexpected(std::move(rule.error()));
                result.rules.push_back(std::move(*rule));
            } else return schema_error("unknown node: " + node.name);
        }
        if (!version_seen || !kind_seen) return schema_error("schema-version and kind are required");
        return result;
    }

    auto write_kdl(RuleSet const& set) -> std::expected<std::string, Error> {
        if (set.rules.size() > max_rules) return std::unexpected(Error{ErrorCode::limit, "too many rules"});
        g::KdlDocument document;
        g::KdlNode version; version.name = "schema-version";
        version.arguments.push_back({std::uint64_t{1}, {}});
        document.push_back(std::move(version));
        g::KdlNode kind; kind.name = "kind";
        kind.arguments.push_back({std::string("predicate"), {}});
        document.push_back(std::move(kind));
        for (auto const& entry : set.rules) {
            auto rule = normalize_rule(entry);
            if (!rule) return std::unexpected(std::move(rule.error()));
            g::KdlNode node; node.name = "rule";
            node.properties.push_back({"type", {rule->type, {}}});
            node.properties.push_back({"value", {rule->value, {}}});
            document.push_back(std::move(node));
        }
        auto encoded = g::write_kdl(document);
        if (!encoded) return std::unexpected(Error{ErrorCode::syntax, "could not encode KDL"});
        if (encoded->size() > max_input_bytes) return std::unexpected(Error{ErrorCode::limit, "KDL output exceeds 1 MiB"});
        return *std::move(encoded);
    }
}
