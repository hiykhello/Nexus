module config;
import std;
import glaze;

namespace config {
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
        bool host_seen=false,path_seen=false;
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
            if (field.arguments.size()!=1 || !text(field.arguments[0])) return std::unexpected("invalid HTTPUpgrade scalar field");
            auto const& value=*text(field.arguments[0]);
            if (value.find_first_of("\r\n\0",0,3)!=value.npos) return std::unexpected("invalid HTTPUpgrade field value");
            if (field.name=="host" && !host_seen && value.size()<=512) { result.host=value; host_seen=true; }
            else if (field.name=="path" && !path_seen && !value.empty() && value.front()=='/' && value.size()<=4096) {
                result.path=value; path_seen=true;
            } else return std::unexpected("unsupported or duplicate HTTPUpgrade field: "+field.name);
        }
        return result;
    }
}
