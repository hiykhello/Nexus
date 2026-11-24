module config;
import std;
import logging.options;
import config.kdl_common;
import glaze;

namespace config {
    namespace {
        using namespace kdl;

        auto parse_sink(Node const& node) -> std::expected<logging::Destination, std::string> {
            using logging::SinkKind;
            auto type = argument(node);
            if (!type || !node.children.empty()) return error("log sink requires one type and no child nodes");
            if (*type != "file") {
                if (!node.properties.empty()) return error("log sink properties require a file sink");
                if (*type == "stderr") return logging::Destination{SinkKind::stderr, {}};
                if (*type == "off") return logging::Destination{SinkKind::off, {}};
                if (*type == "journald") return logging::Destination{SinkKind::journald, {}};
                return error("unknown log sink type");
            }
            auto path = text_property(node, "path");
            auto size = property(node, "max-size-mib");
            auto files = property(node, "max-files");
            if (!path || !absolute_path(*path) || path->ends_with('/') || path->size() > 4095 ||
                std::ranges::any_of(*path, [](unsigned char ch) { return ch < 32 || ch == 127; }) ||
                node.properties.size() != 1u + bool(size) + bool(files))
                return error("log file sink requires an absolute file path and known rotation options");
            auto normalized = std::filesystem::path(*path).lexically_normal();
            if (normalized != std::filesystem::path(*path) || normalized.filename().empty() ||
                normalized.filename().string().size() > 248)
                return error("log file path must be normalized with a valid filename");
            auto mib = size ? integer(*size) : std::optional<std::uint64_t>(0);
            auto keep = files ? integer(*files) : std::optional<std::uint64_t>(1);
            if (!mib || (size && (*mib == 0 || *mib > 4096)) ||
                !keep || *keep == 0 || *keep > 128 || (files && !size))
                return error("log file rotation requires max-size-mib 1..4096 and optional max-files 1..128");
            return logging::Destination{SinkKind::file, std::move(*path), *mib * 1024 * 1024,
                static_cast<std::size_t>(*keep)};
        }

        auto parse_domains(Node const& node, logging::Config& config) -> std::expected<void, std::string> {
            if (node.tag || !node.arguments.empty() || !node.properties.empty())
                return error("invalid log domain-levels block");
            for (auto const& child : node.children) {
                auto domain = logging::parse_domain(child.name);
                auto text = scalar(child);
                auto level = text ? logging::parse_level(*text) : std::nullopt;
                if (!domain || !level) return error("invalid log domain or level");
                auto& slot = config.domains[std::to_underlying(*domain)];
                if (slot) return error("duplicate log domain level");
                slot = level;
            }
            return {};
        }

        auto path_field(std::string_view name) noexcept -> bool {
            return name == "file" || name == "socket" || name == "ca" || name == "certificate" ||
                name == "private-key" || name == "public-key" || name.ends_with("-file") ||
                name.ends_with("-directory");
        }

        auto collect_paths(Node const& node, std::vector<std::string>& paths) -> void {
            if (node.name == "log") return;
            auto remember = [&](Value const& value) {
                if (auto text = string(value); text && !text->empty()) paths.push_back(*text);
            };
            if ((path_field(node.name) || node.name=="directory") && !node.arguments.empty()) remember(node.arguments.front());
            for (auto const& [key, value] : node.properties)
                if (path_field(key) || (node.name == "rule-set" && key == "path")) remember(value);
            for (auto const& child : node.children) collect_paths(child, paths);
        }
    }

    auto parse_logging(glaze::KdlNode const& node) -> std::expected<logging::Config, std::string> {
        using namespace kdl;
        if (node.tag || !node.arguments.empty() || !node.properties.empty())
            return error("log accepts only child nodes");
        logging::Config config;
        config.sinks.clear();
        std::array<bool, 7> seen{};
        constexpr std::array<std::string_view, 7> fields{
            "level", "format", "timestamp", "privacy", "domain-levels", "ring-level", "ring-capacity"
        };
        for (auto const& child : node.children) {
            if (child.name == "sink") {
                if (config.sinks.size() == 4) return error("log supports at most four sinks");
                auto sink = parse_sink(child);
                if (!sink) return std::unexpected(sink.error());
                if (std::ranges::any_of(config.sinks, [&](auto const& existing) {
                    return existing.kind == sink->kind && existing.path == sink->path;
                })) return error("duplicate log sink");
                config.sinks.push_back(std::move(*sink));
                continue;
            }
            auto which = std::ranges::find(fields, child.name);
            if (which == fields.end()) return error("unknown log option");
            auto index = static_cast<std::size_t>(which - fields.begin());
            if (std::exchange(seen[index], true)) return error("duplicate log option");
            if (child.name == "domain-levels") {
                auto result = parse_domains(child, config);
                if (!result) return std::unexpected(result.error());
                continue;
            }
            if (child.name == "ring-capacity") {
                auto cap = child.arguments.size() == 1 ? integer(child.arguments.front()) : std::nullopt;
                if (child.tag || !child.properties.empty() || !child.children.empty() || !cap || *cap > 16384)
                    return error("log ring-capacity must be 0..16384");
                config.settings.ring_capacity = static_cast<std::size_t>(*cap);
                continue;
            }
            auto text = scalar(child);
            if (!text) return error("log option requires one string");
            if (child.name == "level") {
                auto level = logging::parse_level(*text);
                if (!level) return error("invalid log level");
                config.level = *level;
            } else if (child.name == "ring-level") {
                auto level = logging::parse_level(*text);
                if (!level) return error("invalid log ring-level");
                config.ring_level = *level;
            } else if (child.name == "format") {
                if (*text == "jsonl") config.settings.output.format = logging::Format::jsonl;
                else if (*text != "text") return error("log format must be text or jsonl");
            } else if (child.name == "timestamp") {
                if (*text == "monotonic") config.settings.output.timestamp = logging::Timestamp::monotonic;
                else if (*text == "none") config.settings.output.timestamp = logging::Timestamp::none;
                else if (*text != "rfc3339") return error("invalid log timestamp");
            } else {
                if (*text == "verbose") config.settings.privacy = logging::Privacy::verbose;
                else if (*text != "redacted") return error("invalid log privacy");
            }
        }
        if (config.sinks.empty()) config.sinks.push_back({logging::SinkKind::stderr, {}});
        if (config.sinks.size() != 1 && std::ranges::any_of(config.sinks, [](auto const& sink) {
            return sink.kind == logging::SinkKind::off;
        })) return error("log off sink must be the only sink");
        return config;
    }

    auto logging_paths(glaze::KdlDocument const& document) -> std::vector<std::string> {
        std::vector<std::string> paths;
        for (auto const& node : document) collect_paths(node, paths);
        return paths;
    }
}
