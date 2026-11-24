export module config.kdl_common;
import std;
import glaze;

export namespace config::kdl {
    namespace g = ::glaze;
    using Node = g::KdlNode;
    using Value = g::KdlValue;
    inline auto error(std::string text) -> std::unexpected<std::string> { return std::unexpected(std::move(text)); }
    inline auto string(Value const& value) -> std::string const* {
        return value.tag ? nullptr : std::get_if<std::string>(&value.data);
    }
    inline auto argument(Node const& node) -> std::string const* {
        if (node.tag || node.arguments.size() != 1) return nullptr;
        return string(node.arguments.front());
    }
    inline auto property(Node const& node, std::string_view name) -> Value const* {
        for (auto const& [key, value] : node.properties) if (key == name) return &value;
        return nullptr;
    }
    inline auto text_property(Node const& node, std::string_view name) -> std::string const* {
        auto value = property(node, name);
        return value ? string(*value) : nullptr;
    }
    inline auto scalar(Node const& node) -> std::string const* {
        return node.properties.empty() && node.children.empty() ? argument(node) : nullptr;
    }
    inline auto integer(Value const& value) -> std::optional<std::uint64_t> {
        if (value.tag) return {};
        if (auto number = std::get_if<std::uint64_t>(&value.data)) return *number;
        if (auto number = std::get_if<std::int64_t>(&value.data); number && *number >= 0)
            return static_cast<std::uint64_t>(*number);
        return {};
    }
    inline auto connect_timeout(Node const& node) -> std::optional<std::uint32_t> {
        if (node.tag || node.arguments.size()!=1 || !node.properties.empty() || !node.children.empty()) return {};
        auto value=integer(node.arguments.front());
        if (!value || !*value || *value>3600000) return {};
        return static_cast<std::uint32_t>(*value);
    }
    inline auto valid_name(std::string_view name) -> bool {
        return !name.empty() && name.size() <= 255 && name.find('\0') == std::string_view::npos;
    }
    inline auto absolute_path(std::string_view path) -> bool {
        return !path.empty() && path.front() == '/' && path.find('\0') == path.npos;
    }
    inline auto endpoint_name(std::string_view name) -> bool {
        return !name.empty() && name.size() <= 253 && std::all_of(name.begin(), name.end(),
            [](unsigned char c) { return c >= 33 && c <= 126; });
    }
    inline auto version(Node const& node) -> bool {
        return !node.tag && node.properties.empty() && node.children.empty() && node.arguments.size() == 1 &&
               integer(node.arguments.front()) == 1;
    }

    inline auto value(Node const& node) -> Value const* {
        return !node.tag && node.properties.empty() && node.children.empty() && node.arguments.size()==1 && !node.arguments.front().tag ? &node.arguments.front() : nullptr;
    }
    inline auto integer(Node const& node) -> std::optional<std::uint64_t> { auto item=value(node); return item ? integer(*item) : std::nullopt; }
    inline auto boolean(Node const& node) -> std::optional<bool> { auto item=value(node); auto flag=item ? std::get_if<bool>(&item->data) : nullptr; return flag ? std::optional(*flag) : std::nullopt; }
    inline auto deployment_role(Node const& node) -> std::optional<std::string_view> {
        auto role=scalar(node); if (!role || (*role!="client" && *role!="server")) return {}; return *role;
    }
    inline auto read_document(std::string_view input,std::size_t limit=1024*1024) -> std::expected<glaze::KdlDocument,std::string> {
        if (input.size()>limit) return error("configuration exceeds 1 MiB");
        auto document=glaze::read_kdl<glaze::KdlDocument>(input);
        if (!document) return error(glaze::format_error(document.error(),input));
        return std::move(*document);
    }
    inline auto parse_certificate_sha256(Node const& field,std::vector<std::array<std::uint8_t,32>>& out)
        -> std::expected<void,std::string> {
        if (field.tag || !field.properties.empty() || !field.children.empty() ||
            field.arguments.empty() || field.arguments.size()>16-out.size())
            return error("certificate-sha256 requires up to 16 hexadecimal fingerprints");
        for (auto const& arg : field.arguments) {
            auto text=string(arg);
            if (!text || (text->size()!=64 && text->size()!=95))
                return error("invalid certificate-sha256 fingerprint length");
            std::array<std::uint8_t,32> bytes{};
            auto stride=text->size()==64 ? 2u : 3u;
            for (std::size_t i=0;i<bytes.size();++i) {
                auto begin=text->data()+i*stride;
                auto [end,ec]=std::from_chars(begin,begin+2,bytes[i],16);
                if (ec!=std::errc{} || end!=begin+2 || (stride==3 && i+1<bytes.size() && begin[2]!=':'))
                    return error("invalid certificate-sha256 fingerprint");
            }
            out.push_back(bytes);
        }
        return {};
    }
    inline auto parse_hex_bytes(std::string_view text,std::span<std::uint8_t> out) -> std::optional<std::size_t> {
        if (text.empty() || (text.size()%2)!=0 || text.size()/2>out.size()) return {};
        for (std::size_t i=0;i<text.size()/2;++i) {
            auto begin=text.data()+i*2;
            auto [end,ec]=std::from_chars(begin,begin+2,out[i],16);
            if (ec!=std::errc{} || end!=begin+2) return {};
        }
        return text.size()/2;
    }
}
