module config;
import std;
import nexus.thirdparty.glaze;

namespace config {
    auto parse_password_tls_inbound(nex::glaze::KdlNode const&,std::string_view,Inbound,std::string_view extra={}) -> std::expected<InboundConfig,std::string>;
    auto parse_password_tls_outbound(nex::glaze::KdlNode const&,std::string_view,std::string_view) -> std::expected<PasswordTlsOutbound,std::string>;
    auto validate_password_tls_outbound(PasswordTlsOutbound&,Config const&,std::string_view) -> std::expected<void,std::string>;
    auto parse_anytls_inbound(nex::glaze::KdlNode const& node) -> std::expected<InboundConfig,std::string> {
        return parse_password_tls_inbound(node,"anytls",Inbound::anytls);
    }
    auto parse_anytls_outbound(nex::glaze::KdlNode const& node) -> std::expected<AnyTlsOutbound,std::string> {
        auto connection=parse_password_tls_outbound(node,"AnyTLS","pool");
        if (!connection) return std::unexpected(connection.error());
        AnyTlsOutbound result{std::move(*connection)};
        bool seen=false;
        for (auto const& child:node.children) {
            if (child.name!="pool") continue;
            if (seen || child.tag || !child.arguments.empty() || !child.properties.empty()) return std::unexpected("invalid or duplicate AnyTLS pool");
            seen=true;
            std::array<bool,4> fields{};
            for (auto const& field:child.children) {
                if (field.tag || !field.properties.empty() || !field.children.empty() || field.arguments.size()!=1 || field.arguments[0].tag)
                    return std::unexpected("invalid AnyTLS pool field");
                std::optional<std::uint64_t> value;
                auto const& data=field.arguments[0].data;
                if (auto number=std::get_if<std::uint64_t>(&data)) value=*number;
                else if (auto number=std::get_if<std::int64_t>(&data); number && *number>=0) value=static_cast<std::uint64_t>(*number);
                std::size_t index;
                if (field.name=="max-sessions") index=0;
                else if (field.name=="min-idle") index=1;
                else if (field.name=="idle-timeout-ms") index=2;
                else if (field.name=="check-interval-ms") index=3;
                else return std::unexpected("unsupported AnyTLS pool field: "+field.name);
                if (!value || fields[index] || (index<2 ? *value>256 || (index==0 && !*value) : !*value || *value>86400000))
                    return std::unexpected("invalid or duplicate AnyTLS pool field");
                fields[index]=true;
                if (index==0) result.pool.max_sessions=static_cast<std::size_t>(*value);
                else if (index==1) result.pool.min_idle=static_cast<std::size_t>(*value);
                else if (index==2) result.pool.idle_timeout_ms=static_cast<std::uint32_t>(*value);
                else result.pool.check_interval_ms=static_cast<std::uint32_t>(*value);
            }
        }
        if (result.pool.min_idle>result.pool.max_sessions) return std::unexpected("AnyTLS min-idle exceeds max-sessions");
        return result;
    }
    auto validate_anytls(Config& result,std::string_view direct,std::optional<std::string> const& block) -> std::expected<void,std::string> {
        for (std::size_t i=0;i<result.anytls_outbounds.size();++i) {
            auto& entry=result.anytls_outbounds[i];
            if (entry.name==direct || (block && entry.name==*block) ||
                std::ranges::any_of(result.vless_outbounds,[&](auto const& other) { return other.name==entry.name; }) ||
                std::ranges::any_of(result.shadowsocks_outbounds,[&](auto const& other) { return other.name==entry.name; }) ||
                std::ranges::any_of(result.trojan_outbounds,[&](auto const& other) { return other.name==entry.name; }) ||
                std::ranges::any_of(std::span(result.anytls_outbounds).first(i),[&](auto const& other) { return other.name==entry.name; }))
                return std::unexpected("outbound names must be unique");
            if (auto valid=validate_password_tls_outbound(entry.config.connection,result,"AnyTLS"); !valid) return valid;
        }
        return {};
    }
}
