module config;
import std;
import glaze;
import config.kdl_common;

namespace config {
    namespace {
        auto equal_ci_ascii(std::string_view a, std::string_view b) noexcept -> bool {
            if (a.size() != b.size()) return false;
            for (std::size_t i = 0; i < a.size(); ++i) {
                char x = a[i] >= 'A' && a[i] <= 'Z' ? char(a[i] + ('a' - 'A')) : a[i];
                char y = b[i] >= 'A' && b[i] <= 'Z' ? char(b[i] + ('a' - 'A')) : b[i];
                if (x != y) return false;
            }
            return true;
        }
        auto valid_ws_early_header(std::string_view name) noexcept -> bool {
            if (name.empty() || name.size() > 128) return false;
            for (char c : name) {
                bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
                          std::string_view("!#$%&'*+-.^_`|~").contains(c);
                if (!ok) return false;
            }
            if (equal_ci_ascii(name, "host") || equal_ci_ascii(name, "connection") || equal_ci_ascii(name, "upgrade") ||
                equal_ci_ascii(name, "content-length") || equal_ci_ascii(name, "transfer-encoding") ||
                equal_ci_ascii(name, "expect") || equal_ci_ascii(name, "trailer") ||
                equal_ci_ascii(name, "proxy-connection") || equal_ci_ascii(name, "sec-websocket-key") ||
                equal_ci_ascii(name, "sec-websocket-version") || equal_ci_ascii(name, "sec-websocket-accept") ||
                equal_ci_ascii(name, "sec-websocket-extensions"))
                return false;
            return true;
        }
        // Extract optional ?ed=<0..8192> query parameter on WebSocket paths.
        auto extract_ed_query(std::string& path, std::optional<std::uint32_t>& out_ed) -> bool {
            auto q = path.find('?');
            if (q == std::string::npos) return true;
            std::string_view query(path.data() + q + 1, path.size() - q - 1);
            std::string rebuilt;
            bool found = false;
            std::size_t pos = 0;
            while (pos <= query.size()) {
                auto amp = query.find('&', pos);
                auto part = amp == std::string_view::npos ? query.substr(pos) : query.substr(pos, amp - pos);
                if (part.starts_with("ed=")) {
                    if (found) return false;
                    auto val = part.substr(3);
                    std::uint32_t parsed = 0;
                    auto [end, ec] = std::from_chars(val.data(), val.data() + val.size(), parsed);
                    if (val.empty() || ec != std::errc{} || end != val.data() + val.size() || parsed > 8192)
                        return false;
                    out_ed = parsed;
                    found = true;
                } else if (!part.empty()) {
                    if (!rebuilt.empty()) rebuilt.push_back('&');
                    rebuilt.append(part);
                }
                if (amp == std::string_view::npos) break;
                pos = amp + 1;
            }
            if (found) {
                path.resize(q);
                if (!rebuilt.empty()) {
                    path.push_back('?');
                    path.append(rebuilt);
                }
            }
            return true;
        }
    }

    // Parse owned configuration values. The transport compiles and validates
    // the complete HTTP wire profile before any listener is opened.
    auto parse_httpupgrade_transport(glaze::KdlNode const& node) -> std::expected<HttpUpgradeTransport,std::string> {
        auto text=[](auto const& value) -> std::string const* {
            return value.tag ? nullptr : std::get_if<std::string>(&value.data);
        };
        if (node.tag || node.arguments.size()!=1 || !node.properties.empty() ||
            !text(node.arguments[0]))
            return std::unexpected("transport requires httpupgrade or websocket");
        auto const& type=*text(node.arguments[0]);
        if (type!="httpupgrade" && type!="websocket")
            return std::unexpected("transport requires httpupgrade or websocket");
        HttpUpgradeTransport result;
        result.websocket=type=="websocket";
        bool host_seen=false,path_seen=false,max_ed_seen=false,ed_hdr_seen=false;
        std::size_t bytes=0;
        for (auto const& field:node.children) {
            if (field.tag || !field.properties.empty() || !field.children.empty()) return std::unexpected("invalid HTTPUpgrade field");
            if (field.name=="header") {
                if (field.arguments.size()!=2 || !text(field.arguments[0]) || !text(field.arguments[1]) || result.headers.size()==64)
                    return std::unexpected("HTTPUpgrade header requires a name and value");
                auto const& name=*text(field.arguments[0]); auto const& value=*text(field.arguments[1]);
                if (name.empty() || name.size()>4096 || value.size()>4096 || bytes+name.size()+value.size()+4>16384 ||
                    name.find_first_of("\r\n\0",0,3)!=name.npos || value.find_first_of("\r\n\0",0,3)!=value.npos)
                    return std::unexpected("invalid HTTPUpgrade header");
                bytes+=name.size()+value.size()+4; result.headers.push_back({name,value});
                continue;
            }
            if (field.name=="max-early-data") {
                if (!result.websocket || max_ed_seen || field.arguments.size()!=1)
                    return std::unexpected("invalid or duplicate WebSocket max-early-data");
                auto v=kdl::integer(field.arguments[0]);
                if (!v || *v>8192) return std::unexpected("WebSocket max-early-data must be 0..8192");
                result.max_early_data=static_cast<std::uint32_t>(*v);
                max_ed_seen=true;
                continue;
            }
            if (field.arguments.size()!=1 || !text(field.arguments[0])) return std::unexpected("invalid HTTPUpgrade scalar field");
            auto const& value=*text(field.arguments[0]);
            if (value.find_first_of("\r\n\0",0,3)!=value.npos) return std::unexpected("invalid HTTPUpgrade field value");
            if (field.name=="host" && !host_seen && value.size()<=512) { result.host=value; host_seen=true; }
            else if (field.name=="path" && !path_seen && !value.empty() && value.front()=='/' && value.size()<=4096) {
                result.path=value; path_seen=true;
            } else if (field.name=="early-data-header-name" && result.websocket && !ed_hdr_seen && valid_ws_early_header(value)) {
                result.early_data_header_name=value; ed_hdr_seen=true;
            } else return std::unexpected("unsupported or duplicate HTTPUpgrade field: "+field.name);
        }
        if (result.websocket) {
            std::optional<std::uint32_t> query_ed;
            if (!extract_ed_query(result.path, query_ed))
                return std::unexpected("invalid WebSocket ?ed= query parameter");
            if (query_ed && !max_ed_seen) result.max_early_data=*query_ed;
        }
        return result;
    }
}
