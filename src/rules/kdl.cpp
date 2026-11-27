module rules;
import std;
import glaze;
import rules.kdl_predicate;

namespace rules {
    namespace g = ::glaze;
    auto normalize_set(RuleSet set) -> std::expected<RuleSet, Error>;

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

        auto version(g::KdlNode const& node) -> std::optional<unsigned> {
            if (node.tag || !node.properties.empty() || !node.children.empty() || node.arguments.size() != 1) return {};
            auto const& value = node.arguments.front();
            if (value.tag) return {};
            if (auto p = std::get_if<std::int64_t>(&value.data); p && *p==2) return static_cast<unsigned>(*p);
            if (auto p = std::get_if<std::uint64_t>(&value.data); p && *p==2) return static_cast<unsigned>(*p);
            return {};
        }


    }

    auto parse_kdl(std::string_view input) -> std::expected<RuleSet, Error> {
        if (input.size() > max_input_bytes) return std::unexpected(Error{ErrorCode::limit, "KDL input exceeds 256 MiB"});
        auto document = g::read_kdl<g::KdlDocument>(input);
        if (!document) return std::unexpected(Error{ErrorCode::syntax, g::format_error(document.error(), input)});
        bool version_seen = false, kind_seen = false;
        std::size_t count=0;
        RuleSet result;
        for (auto const& node : *document) {
            if (node.name == "schema-version") {
                auto value=version(node);
                if (version_seen || !value) return schema_error("expected one supported schema-version");
                result.version=*value;
                version_seen = true;
            } else if (node.name == "kind") {
                auto value = single_string(node);
                if (kind_seen || !value || *value != "predicate") return schema_error("expected one kind predicate");
                kind_seen = true;
            } else {
                auto rule = decode_kdl_predicate(node,1,count);
                if (!rule) return std::unexpected(std::move(rule.error()));
                result.rules.push_back(std::move(*rule));
            }
        }
        if (!version_seen || !kind_seen) return schema_error("schema-version and kind are required");
        return normalize_set(std::move(result));
    }

    auto write_kdl(RuleSet const& set) -> std::expected<std::string, Error> {
        if (set.rules.size() > max_rules)
            return std::unexpected(Error{ErrorCode::limit, "rule nesting or count exceeds limit"});
        std::size_t min_bytes = 32;
        auto estimate = [&](auto&& self, Rule const& r, unsigned depth) -> bool {
            if (depth > max_rule_depth) return true;
            std::size_t add = 12u + r.type.size() + r.value.size();
            if (add > max_input_bytes - min_bytes) return false;
            min_bytes += add;
            for (auto const& c : r.children) if (!self(self, c, depth + 1)) return false;
            return true;
        };
        for (auto const& r : set.rules)
            if (!estimate(estimate, r, 1))
                return std::unexpected(Error{ErrorCode::limit, "KDL output exceeds 256 MiB"});
        auto normalized=normalize_set(set);
        if (!normalized) return std::unexpected(std::move(normalized.error()));
        g::KdlDocument document;
        g::KdlNode version; version.name = "schema-version";
        version.arguments.push_back({static_cast<std::uint64_t>(normalized->version), {}});
        document.push_back(std::move(version));
        g::KdlNode kind; kind.name = "kind";
        kind.arguments.push_back({std::string("predicate"), {}});
        document.push_back(std::move(kind));
        auto encode_rule=[&](auto&& self,Rule const& rule) -> g::KdlNode {
            g::KdlNode node; node.name = "rule";
            node.properties.push_back({"type", {rule.type, {}}});
            if (rule.children.empty()) node.properties.push_back({"value", {rule.value, {}}});
            else for (auto const& child:rule.children) node.children.push_back(self(self,child));
            return node;
        };
        for (auto const& entry:normalized->rules) document.push_back(encode_rule(encode_rule,entry));
        auto encoded = g::write_kdl(document);
        if (!encoded) return std::unexpected(Error{ErrorCode::syntax, "could not encode KDL"});
        if (encoded->size() > max_input_bytes) return std::unexpected(Error{ErrorCode::limit, "KDL output exceeds 256 MiB"});
        return *std::move(encoded);
    }
}
