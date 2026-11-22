// KDL field helpers shared by the DNS parser implementation files.
#pragma once

    using Node = g::KdlNode;
    using Value = g::KdlValue;
    auto error(std::string text) -> std::unexpected<std::string> { return std::unexpected(std::move(text)); }
    auto string(Value const& value) -> std::string const* {
        return value.tag ? nullptr : std::get_if<std::string>(&value.data);
    }
    auto argument(Node const& node) -> std::string const* {
        if (node.tag || node.arguments.size() != 1) return nullptr;
        return string(node.arguments.front());
    }
    auto property(Node const& node, std::string_view name) -> Value const* {
        for (auto const& [key, value] : node.properties) if (key == name) return &value;
        return nullptr;
    }
    auto text_property(Node const& node, std::string_view name) -> std::string const* {
        auto value = property(node, name);
        return value ? string(*value) : nullptr;
    }
    auto scalar(Node const& node) -> std::string const* {
        return node.properties.empty() && node.children.empty() ? argument(node) : nullptr;
    }
    auto integer(Value const& value) -> std::optional<std::uint64_t> {
        if (value.tag) return {};
        if (auto number = std::get_if<std::uint64_t>(&value.data)) return *number;
        if (auto number = std::get_if<std::int64_t>(&value.data); number && *number >= 0)
            return static_cast<std::uint64_t>(*number);
        return {};
    }
    auto valid_name(std::string_view name) -> bool {
        return !name.empty() && name.size() <= 255 && name.find('\0') == std::string_view::npos;
    }
