module config;
import std;
import containers.inplace_vector;
import glaze;
import config.kdl_common;

namespace config {
    auto parse_httpupgrade_transport(glaze::KdlNode const&) -> std::expected<HttpUpgradeTransport,std::string>;
    auto parse_xhttp(glaze::KdlNode const&,bool) -> std::expected<xhttp::Profile,std::string>;
    auto parse_vless_transport(glaze::KdlNode const& node,bool outbound)
        -> std::expected<std::variant<HttpUpgradeTransport,GrpcTransport,xhttp::Profile>,std::string> {
        if (node.tag || node.arguments.size()!=1 || !node.properties.empty() || !kdl::string(node.arguments[0]))
            return std::unexpected("transport requires exactly one untagged type");
        auto type=*kdl::string(node.arguments[0]);
        if (type=="httpupgrade" || type=="websocket") {
            auto parsed=parse_httpupgrade_transport(node);if (!parsed) return std::unexpected(parsed.error());
            return std::move(*parsed);
        }
        if (type=="xhttp") {
            auto parsed=parse_xhttp(node,outbound);
            if (!parsed) return std::unexpected(parsed.error());
            return std::move(*parsed);
        }
        if (type!="grpc") return std::unexpected("transport must be httpupgrade, websocket, grpc or xhttp");
        GrpcTransport result;
        containers::inplace_vector<std::string_view,16> seen;
        for (auto const& field:node.children) {
            if (field.tag || !field.properties.empty() || !field.children.empty() || field.arguments.size()!=1 || field.arguments[0].tag ||
                std::ranges::find(seen,field.name)!=seen.end() || seen.size()==seen.capacity()) return std::unexpected("invalid or duplicate gRPC field");
            seen.push_back(field.name);
            if (field.name=="service-name" || field.name=="authority" || field.name=="response-policy") {
                auto value=kdl::string(field.arguments[0]);if (!value) return std::unexpected("gRPC string field required");
                if (field.name=="service-name") {
                    if (value->size()>255 || !std::ranges::all_of(*value,[](char c) {
                        return (c>='a' && c<='z') || (c>='A' && c<='Z') || (c>='0' && c<='9') || c=='_' || c=='-' || c=='.';
                    })) return std::unexpected("invalid gRPC service name");
                    result.service_name=*value;
                } else if (field.name=="authority") {
                    if (value->empty() || value->size()>512 || std::ranges::any_of(*value,[](unsigned char c) {
                        return c<33 || c>126 || std::string_view("/?#@\\").contains(static_cast<char>(c));
                    })) return std::unexpected("invalid gRPC authority");
                    result.authority=*value;
                } else {
                    if (!outbound || (*value!="standard" && *value!="sing-box-lite")) return std::unexpected("invalid gRPC response policy");
                    result.response_policy=*value=="standard" ? GrpcTransport::ResponsePolicy::standard : GrpcTransport::ResponsePolicy::sing_box_lite;
                }
                continue;
            }
            if (field.name=="permit-without-stream") {
                auto flag=std::get_if<bool>(&field.arguments[0].data);
                if (!flag) return std::unexpected("boolean gRPC permit-without-stream required");
                result.permit_without_stream=*flag;
                continue;
            }
            if (field.name=="idle-timeout-ms" || field.name=="ping-timeout-ms") {
                auto value=kdl::integer(field.arguments[0]);
                if (!value || *value>3600000) return std::unexpected("invalid gRPC keepalive timeout");
                if (field.name=="idle-timeout-ms") result.idle_timeout_ms=static_cast<std::uint32_t>(*value);
                else result.ping_timeout_ms=static_cast<std::uint32_t>(*value);
                continue;
            }
            auto value=kdl::integer(field.arguments[0]);
            if (!value || !*value) return std::unexpected("positive gRPC integer field required");
            std::size_t* destination=nullptr;
            if (field.name=="input-window") destination=&result.input_window;
            else if (field.name=="message-bytes") destination=&result.message_bytes;
            else if (field.name=="hunk-bytes") destination=&result.hunk_bytes;
            else if (field.name=="output-bytes") destination=&result.output_bytes;
            else if (field.name=="output-messages") destination=&result.output_messages;
            else if (field.name=="library-bytes") destination=&result.library_bytes;
            else if (field.name=="max-sessions" && outbound) destination=&result.max_sessions;
            if (!destination) return std::unexpected("unsupported gRPC field: "+field.name);
            *destination=static_cast<std::size_t>(*value);
        }
        if (result.authority.empty() && !outbound) return std::unexpected("gRPC inbound requires explicit authority");
        if (result.hunk_bytes>1024*1024 || result.message_bytes>4*1024*1024 || result.message_bytes<result.hunk_bytes+4 ||
            result.input_window<result.message_bytes+5 || result.input_window>std::size_t(std::numeric_limits<std::int32_t>::max()) ||
            result.output_bytes<5 || result.output_bytes>64*1024*1024 || result.output_messages>64 ||
            result.library_bytes>64*1024*1024 || result.max_sessions>256) return std::unexpected("invalid gRPC resource limits");
        return result;
    }
}
