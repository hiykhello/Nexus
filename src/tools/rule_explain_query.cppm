export module cli.rule_explain_query;
import std;
import dns.policy;
import http.connect;
import platform.ip_address;
import rules;

export namespace cli::explain {
    inline constexpr std::string_view usage=
        "usage: nexus rule explain <config> <inbound> <tcp|udp|icmp> <host[:port]> "
        "[--oneline] [dns-qtype=TYPE] [--expect-outbound=NAME] [--expect-action=ACTION] [--expect-dns=RESULT] "
        "[source-ip=IP] [source-port=PORT] [source-uid=UID] [source-gid=GID] [source-user=NAME] "
        "[process-name=NAME] [process-path=PATH] [package-name=NAME] [source-interface=NAME] "
        "[network-type=wifi|cellular|ethernet|other] [network-is-expensive=true|false] [network-is-constrained=true|false] "
        "[wifi-ssid=NAME] [wifi-bssid=MAC] [default-interface-address=IP] [route-mode=rule|global|direct] "
        "[resolved-ip=IP] [auth-user=NAME] [protocol=http|tls|dns|ssh|stun|quic|bittorrent|dtls|rdp|ntp] [client=NAME] "
        "[tls-ech=true|false] [dscp=0..63] [source-mac=MAC] [gateway-mac=MAC] [sniffed-domain=NAME|-] [fakeip-domain=NAME|-] [reverse-domain=NAME|-]\n";

    struct Query {
        rules::ProgramInput input;
        std::vector<rules::ProgramAddress> resolved;
        std::vector<std::string_view> resolved_text;
        std::vector<rules::ProgramAddress> default_if_addrs;
        std::optional<std::string_view> process_name;
        bool oneline=false, show_dns=false;
        std::uint16_t dns_qtype=1;
        std::optional<std::string_view> expect_outbound, expect_action, expect_dns;
    };

    struct ExplainOutcome {
        std::string route_label{"default"};
        std::string action{"route"};
        std::string outbound;
        std::uint32_t udp_timeout_ms=0;
        bool udp_adaptive=false;
        std::optional<rules::Protocol> protocol;
    };

    inline auto argument_port(std::string_view text) -> std::optional<std::uint16_t> {
        std::uint16_t port=0;
        auto [end,error]=std::from_chars(text.data(),text.data()+text.size(),port);
        if (end==text.data()+text.size() && error==std::errc{} && port) return port;
        return {};
    }

    inline auto parse_dns_qtype(std::string_view text) -> std::optional<std::uint16_t> {
        std::string up(text);
        for (auto& c : up) c=static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
        if (up=="A") return 1;
        if (up=="NS") return 2;
        if (up=="CNAME") return 5;
        if (up=="SOA") return 6;
        if (up=="PTR") return 12;
        if (up=="MX") return 15;
        if (up=="TXT") return 16;
        if (up=="AAAA") return 28;
        if (up=="SRV") return 33;
        if (up=="SVCB") return 64;
        if (up=="HTTPS") return 65;
        if (up=="ANY") return 255;
        return argument_port(text);
    }

    inline auto parse_bool_flag(std::string_view value) -> std::optional<bool> {
        if (value=="true") return true;
        if (value=="false") return false;
        return {};
    }

    inline auto parse_query_args(std::string_view network,std::string_view authority,std::span<char*> options)
        -> std::expected<Query,std::string> {
        using Kind=http::HostKind;
        Query result;
        auto& input=result.input;
        if (network=="tcp") input.network=rules::Network::tcp;
        else if (network=="udp") input.network=rules::Network::udp;
        else if (network=="icmp") input.network=rules::Network::icmp;
        else return std::unexpected("invalid network");
        if (auto target=http::parse_destination_authority(authority); target.status==http::ConnectStatus::accepted) {
            input.port=target.port;
            if (target.kind==Kind::domain)
                input.explicit_domain=authority.substr(0,authority.find(':'));
            else {
                auto open=authority.starts_with('[');
                input.ip=authority.substr(open ? 1 : 0,authority.rfind(open ? ']' : ':')-(open ? 1 : 0));
                input.domain_absent[0]=true;
            }
        } else if (input.network==rules::Network::icmp) {
            if (platform::parse_ip_address(authority)) {
                input.ip=authority;
                input.domain_absent[0]=true;
            } else if (rules::valid_domain(authority)) {
                input.explicit_domain=authority;
            } else return std::unexpected("invalid target authority");
        } else return std::unexpected("invalid target authority");
        auto domain=[&](std::optional<std::string_view>& slot,std::size_t source,std::string_view value) {
            if (slot || input.domain_absent[source]) return false;
            if (value=="-") {input.domain_absent[source]=true;return true;}
            if (!rules::valid_domain(value)) return false;
            slot=value;
            return true;
        };
        for (std::string_view option : options) {
            if (option=="--oneline") { result.oneline=true; continue; }
            auto separator=option.find('=');
            if (separator==option.npos || separator+1==option.size()) return std::unexpected("expected option=value");
            auto key=option.substr(0,separator);
            auto value=option.substr(separator+1);
            if (key=="--expect-outbound" && !result.expect_outbound) result.expect_outbound=value;
            else if (key=="--expect-action" && !result.expect_action) result.expect_action=value;
            else if (key=="--expect-dns" && !result.expect_dns) { result.expect_dns=value; result.show_dns=true; }
            else if (key=="dns-qtype") {
                auto qt=parse_dns_qtype(value);
                if (!qt) return std::unexpected("invalid dns-qtype");
                result.dns_qtype=*qt; result.show_dns=true;
            } else if (key=="source-ip" && !input.source_ip && ::platform::parse_ip_address(value))
                input.source_ip=value;
            else if (key=="source-port" && !input.source_port && argument_port(value))
                input.source_port=argument_port(value);
            else if (key=="source-uid" && !input.source_uid) {
                input.source_uid=rules::parse_source_uid(value);
                if (!input.source_uid) return std::unexpected("invalid source UID");
            } else if (key=="source-gid" && !input.source_gid) {
                input.source_gid=rules::parse_source_uid(value);
                if (!input.source_gid) return std::unexpected("invalid source GID");
            } else if (key=="source-user" && !input.source_user) input.source_user=value;
            else if (key=="process-name" && !result.process_name) {
                result.process_name=value;
                if (!input.process_path) input.process_path=value;
            } else if (key=="process-path" && (!input.process_path || result.process_name) && value.starts_with('/') && !value.ends_with('/') && value.size()<=4095)
                input.process_path=value;
            else if (key=="package-name" && !input.package_name) input.package_name=value;
            else if (key=="source-interface" && !input.source_interface && rules::valid_source_interface(value))
                input.source_interface=value;
            else if (key=="network-type" && !input.network_type && rules::parse_network_type(value))
                input.network_type=rules::parse_network_type(value);
            else if (key=="network-is-expensive" && !input.network_is_expensive && parse_bool_flag(value))
                input.network_is_expensive=parse_bool_flag(value);
            else if (key=="network-is-constrained" && !input.network_is_constrained && parse_bool_flag(value))
                input.network_is_constrained=parse_bool_flag(value);
            else if (key=="wifi-ssid" && !input.wifi_ssid) input.wifi_ssid=value;
            else if (key=="wifi-bssid" && !input.wifi_bssid && rules::parse_mac(value))
                input.wifi_bssid=rules::parse_mac(value);
            else if (key=="default-interface-address" && result.default_if_addrs.size()<64) {
                auto ip=::platform::parse_ip_address(value);
                if (!ip) return std::unexpected("invalid default-interface-address");
                result.default_if_addrs.push_back({ip->bytes,ip->size});
            } else if (key=="route-mode" && !input.route_mode && rules::parse_route_mode(value))
                input.route_mode=rules::parse_route_mode(value);
            else if (key=="client" && !input.client && rules::valid_client_name(value))
                input.client=value;
            else if (key=="dscp" && !input.dscp && rules::parse_dscp(value)) input.dscp=rules::parse_dscp(value);
            else if (key=="source-mac" && !input.source_mac && rules::parse_mac(value)) input.source_mac=rules::parse_mac(value);
            else if (key=="gateway-mac" && !input.gateway_mac && rules::parse_mac(value)) input.gateway_mac=rules::parse_mac(value);
            else if (key=="auth-user" && !input.auth_user) input.auth_user=value;
            else if (key=="protocol" && !input.protocol) {
                input.protocol=rules::parse_protocol(value);
                if (!input.protocol) return std::unexpected("invalid protocol");
                if (input.protocol==rules::Protocol::tls_ech) {
                    if (input.tls_ech==false) return std::unexpected("conflicting TLS ECH metadata");
                    input.protocol=rules::Protocol::tls;
                    input.tls_ech=true;
                }
            } else if (key=="tls-ech" && !input.tls_ech && parse_bool_flag(value)) {
                input.tls_ech=parse_bool_flag(value);
            } else if (key=="sniffed-domain" && domain(input.sniffed_domain,3,value)) {}
            else if (key=="fakeip-domain" && domain(input.fakeip_domain,1,value)) {}
            else if (key=="reverse-domain" && domain(input.reverse_domain,2,value)) {}
            else if (key=="resolved-ip" && input.explicit_domain && result.resolved.size()<64) {
                auto ip=::platform::parse_ip_address(value);
                if (!ip) return std::unexpected("invalid resolved-ip");
                result.resolved.push_back({ip->bytes,ip->size});
                result.resolved_text.push_back(value);
            } else return std::unexpected("invalid or duplicate option "+std::string(key));
        }
        if (input.tls_ech && input.protocol!=rules::Protocol::tls)
            return std::unexpected("tls-ech requires protocol=tls");
        return result;
    }
}
