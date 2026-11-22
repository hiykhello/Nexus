module config;
import std;
import config.kdl_common;
import xhttp.wire;

namespace config {
    namespace {
        using namespace kdl;

        auto version(std::string_view value) noexcept -> std::optional<xhttp::HttpVersion> {
            if (value=="h1") return xhttp::HttpVersion::http1;
            if (value=="h2") return xhttp::HttpVersion::http2;
            if (value=="h3") return xhttp::HttpVersion::http3;
            return {};
        }

        auto mode(std::string_view value) noexcept -> std::optional<xhttp::Mode> {
            if (value=="auto") return xhttp::Mode::automatic;
            if (value=="stream-one") return xhttp::Mode::stream_one;
            if (value=="packet-up") return xhttp::Mode::packet_up;
            if (value=="stream-up") return xhttp::Mode::stream_up;
            return {};
        }

        auto authority(std::string_view value) noexcept -> bool {
            return !value.empty() && value.size()<=512 && std::ranges::all_of(value,[](unsigned char c) {
                return c>32 && c<127 && !std::string_view("/?#@\\").contains(static_cast<char>(c));
            });
        }

        auto block(Node const& node) noexcept -> bool {
            return !node.tag && node.arguments.empty() && node.properties.empty();
        }

        auto scalar_number(Node const& node) -> std::optional<std::uint64_t> {
            auto item=value(node);
            return item ? integer(*item) : std::nullopt;
        }

        auto padding_range(Node const& field,xhttp::Padding& settings) -> bool {
            constexpr auto maximum=8192u;
            if (auto fixed=scalar_number(field);fixed && *fixed<=maximum) {
                settings.minimum=settings.maximum=static_cast<std::uint16_t>(*fixed);
                return true;
            }
            auto text=scalar(field);
            if (!text) return false;
            auto delimiter=text->find('-');
            if (delimiter==text->npos) return false;
            auto parse=[](std::string_view part) -> std::optional<unsigned> {
                unsigned result=0;
                auto [end,err]=std::from_chars(part.data(),part.data()+part.size(),result);
                if (err!=std::errc{} || end!=part.data()+part.size() || result>maximum) return {};
                return result;
            };
            auto lo=parse(std::string_view(*text).substr(0,delimiter));
            auto hi=parse(std::string_view(*text).substr(delimiter+1));
            if (!lo || !hi || *lo>*hi) return false;
            settings.minimum=static_cast<std::uint16_t>(*lo);
            settings.maximum=static_cast<std::uint16_t>(*hi);
            return true;
        }

        auto endpoint_field(Node const& field,xhttp::Endpoint& endpoint) -> bool {
            auto text=scalar(field);
            if (!text) return false;
            if (field.name=="host" && authority(*text)) {endpoint.authority=*text;return true;}
            if (field.name=="path") {
                auto path=xhttp::normalize_path(*text);
                if (path) {endpoint.path=std::move(*path);return true;}
            }
            if (field.name=="protocol") {
                auto parsed=version(*text);
                if (parsed) {endpoint.version=*parsed;return true;}
            }
            return false;
        }

        auto mux_block(Node const& node) -> std::optional<xhttp::MuxLimits> {
            if (!block(node)) return {};
            xhttp::MuxLimits out;
            std::set<std::string_view> seen;
            for (auto const& item:node.children) {
                auto number=scalar_number(item);
                if (!number || *number>100000000 || !seen.insert(item.name).second) return {};
                auto n=static_cast<std::uint32_t>(*number);
                if (item.name=="max-concurrency" && n<=256) out.concurrency=static_cast<std::uint16_t>(n);
                else if (item.name=="max-connections" && n<=64) out.connections=static_cast<std::uint16_t>(n);
                else if (item.name=="c-max-reuse-times") out.reuse_times=n;
                else if (item.name=="c-max-lifetime-ms") out.lifetime_ms=n;
                else if (item.name=="h-max-request-times") out.requests=n;
                else if (item.name=="h-max-reusable-secs") out.reusable_seconds=n;
                else return {};
            }
            if (!out.valid()) return {};
            return out;
        }

        auto download_block(Node const& node) -> std::optional<xhttp::Download> {
            if (!block(node)) return {};
            xhttp::Download out;
            std::set<std::string_view> seen;
            for (auto const& field:node.children) {
                if (!seen.insert(field.name).second) return {};
                if (field.name=="server") {
                    auto host=text_property(field,"host");
                    auto port=property(field,"port");
                    auto number=port ? integer(*port) : std::nullopt;
                    if (field.tag || !field.arguments.empty() || !field.children.empty() ||
                        field.properties.size()!=2 || !host || !endpoint_name(*host) ||
                        !number || !*number || *number>65535) return {};
                    out.host=*host;
                    out.port=static_cast<std::uint16_t>(*number);
                } else if (field.name=="tls") {
                    if (!block(field)) return {};
                    std::set<std::string_view> tls_fields;
                    bool verify=false;
                    for (auto const& option:field.children) {
                        if (!tls_fields.insert(option.name).second) return {};
                        auto text=scalar(option);
                        if (option.name=="server-name" && text && endpoint_name(*text)) out.server_name=*text;
                        else if (option.name=="ca-file" && text && absolute_path(*text)) out.ca_file=*text;
                        else if (option.name=="verify" && boolean(option).value_or(false)) verify=true;
                        else return {};
                    }
                    if (!verify || out.server_name.empty() || out.ca_file.empty()) return {};
                } else if (!endpoint_field(field,out.endpoint)) return {};
            }
            if (out.host.empty()) return {};
            if (out.endpoint.authority.empty()) out.endpoint.authority=out.server_name.empty() ? out.host : out.server_name;
            if (out.endpoint.version==xhttp::HttpVersion::http3 && out.ca_file.empty()) return {};
            return out;
        }

        auto resource(Node const& field,xhttp::Limits& limits) -> bool {
            auto n=scalar_number(field);
            if (!n || *n>64u*1024*1024) return false;
            if (field.name=="sc-max-each-post-bytes") limits.post_bytes=*n;
            else if (field.name=="sc-max-buffered-posts" && *n<=256) limits.buffered_posts=static_cast<std::uint16_t>(*n);
            else if (field.name=="max-sessions" && *n<=1024) limits.sessions=static_cast<std::uint16_t>(*n);
            else if (field.name=="buffer-bytes") limits.buffer_bytes=*n;
            else if (field.name=="sc-min-posts-interval-ms") limits.post_interval=std::chrono::milliseconds(*n);
            else if (field.name=="pair-timeout-ms") limits.pair_timeout=std::chrono::milliseconds(*n);
            else return false;
            return true;
        }
    }

    auto parse_xhttp(Node const& node,bool outbound) -> std::expected<xhttp::Profile,std::string> {
        xhttp::Profile out;
        std::set<std::string_view> seen;
        std::size_t header_bytes=0;
        for (auto const& field:node.children) {
            if (field.name=="header") {
                if (field.tag || !field.properties.empty() || !field.children.empty() || field.arguments.size()!=2)
                    return error("XHTTP header requires a lowercase name and value");
                auto name=string(field.arguments[0]),data=string(field.arguments[1]);
                if (!name || !data || !xhttp::valid_header(*name,*data) || out.headers.size()==32 ||
                    std::ranges::contains(out.headers,*name,&xhttp::Field::first) || *name=="content-type")
                    return error("invalid or duplicate XHTTP header");
                header_bytes+=name->size()+data->size()+32;
                if (header_bytes>8192) return error("XHTTP custom headers exceed 8192 bytes");
                out.headers.emplace_back(*name,*data);
                continue;
            }
            if (!seen.insert(field.name).second) return error("duplicate XHTTP field: "+field.name);
            if (endpoint_field(field,out.endpoint) || resource(field,out.limits)) continue;
            auto text=scalar(field);
            if (field.name=="mode" && text && mode(*text)) out.mode=*mode(*text);
            else if (field.name=="no-grpc-header" && boolean(field)) out.no_grpc_header=*boolean(field);
            else if (field.name=="x-padding-bytes" && padding_range(field,out.padding)) {}
            else if (field.name=="x-padding-placement" && text && (*text=="referer" || *text=="query" || *text=="header"))
                out.padding.placement=*text=="referer" ? xhttp::Placement::referer : *text=="query" ? xhttp::Placement::query : xhttp::Placement::header;
            else if (field.name=="x-padding-header" && text) out.padding.header=*text;
            else if (outbound && field.name=="xmux") {
                auto mux=mux_block(field);
                if (!mux) return error("invalid XHTTP xmux settings");
                out.mux=*mux;
            } else if (outbound && field.name=="download-settings") {
                auto download=download_block(field);
                if (!download) return error("invalid XHTTP download-settings");
                out.download=std::move(download);
            } else return error("invalid XHTTP field: "+field.name);
        }
        if (!out.limits.valid() || !xhttp::valid_padding(out.padding) ||
            (out.padding.placement==xhttp::Placement::header &&
                (out.padding.header=="content-type" ||
                 std::ranges::contains(out.headers,out.padding.header,&xhttp::Field::first))))
            return error("invalid XHTTP limits or padding");
        if (out.mode!=xhttp::Mode::automatic && !xhttp::mode_supported(out.mode,out.endpoint.version,
                out.download ? out.download->endpoint.version : out.endpoint.version,out.download.has_value()))
            return error("XHTTP mode is incompatible with the chosen HTTP protocol or download-settings");
        return out;
    }
}
