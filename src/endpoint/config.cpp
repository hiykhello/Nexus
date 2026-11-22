module endpoint.config;
import std;
import config.kdl_common;
import nexus.thirdparty.glaze;
import dns.local_config;
import net.udp_socket;
import packet.tun_network_types;
import platform.socket_options;
import wireguard.routing;
import wireguard;
import endpoint.host_dns_types;

namespace endpoint {
    namespace {
        namespace k=config::kdl;
        using Node=nex::glaze::KdlNode;
        auto server(Node const& node,bool listen) -> std::expected<Server,std::string> {
            auto host=k::text_property(node,"host"); auto field=k::property(node,"port"); auto port=field ? k::integer(*field) : std::nullopt;
            if (node.tag || !node.arguments.empty() || !node.children.empty() || node.properties.size()!=2 || !host || !port || *port>65535 || (!listen && !*port))
                return k::error("endpoint/listen requires one host and port");
            Server result{*host,static_cast<std::uint16_t>(*port)};
            if (auto address=dns::parse_local_address(*host)) result.numeric=net::UdpEndpoint{address->ipv6 ? std::uint8_t{6} : std::uint8_t{4},address->address,result.port};
            else if (listen || !config_detail::hostname(*host)) return k::error("listen requires numeric unscoped IP; endpoint requires numeric IP or ASCII hostname");
            if (result.numeric && result.numeric->family==6 && std::ranges::all_of(std::span(result.numeric->address).first(10),[](auto byte) { return !byte; }) &&
                result.numeric->address[10]==255 && result.numeric->address[11]==255) return k::error("IPv4-mapped IPv6 endpoints are unsupported");
            if (!listen && result.numeric) {
                auto const& value=*result.numeric;
                bool zero=std::ranges::all_of(value.address,[](auto byte) { return !byte; });
                if (zero || (value.family==4 && value.address[0]>=224) || (value.family==6 && (value.address[0]==255 || (value.address[0]==254 && (value.address[1]&192)==128))))
                    return k::error("peer endpoint requires a unicast unscoped address");
            }
            return result;
        }
        auto peer(Node const& node) -> std::expected<Peer,std::string> {
            auto name=k::argument(node);
            if (!name || !k::valid_name(*name) || !node.properties.empty()) return k::error("peer requires one name and no properties");
            Peer result; result.name=*name; bool keepalive_seen=false;
            for (auto const& child:node.children) {
                auto text=k::scalar(child);
                if (child.name=="public-key-file") {
                    if (!result.public_key_file.empty() || !text || !k::absolute_path(*text)) return k::error("peer requires one absolute public-key-file");
                    result.public_key_file=*text;
                } else if (child.name=="preshared-key-file") {
                    if (result.preshared_key_file || !text || !k::absolute_path(*text)) return k::error("invalid or duplicate preshared-key-file");
                    result.preshared_key_file=*text;
                } else if (child.name=="endpoint") {
                    if (result.server) return k::error("duplicate peer endpoint");
                    auto parsed=server(child,false); if (!parsed) return std::unexpected(parsed.error()); result.server=std::move(*parsed);
                } else if (child.name=="bootstrap-resolver") {
                    if (result.local_bootstrap || !text || *text!="local") return k::error("bootstrap-resolver supports only one local value");
                    result.local_bootstrap=true;
                } else if (child.name=="address-strategy") {
                    if (result.strategy || !text) return k::error("invalid or repeated address-strategy");
                    if (*text=="prefer-ipv4") result.strategy=AddressStrategy::prefer_ipv4;
                    else if (*text=="prefer-ipv6") result.strategy=AddressStrategy::prefer_ipv6;
                    else if (*text=="ipv4-only") result.strategy=AddressStrategy::ipv4_only;
                    else if (*text=="ipv6-only") result.strategy=AddressStrategy::ipv6_only;
                    else return k::error("unsupported address-strategy");
                } else if (child.name=="allowed-ip") {
                    auto value=text ? config_detail::address(*text,true,true) : std::nullopt;
                    // Cryptokey default prefixes are allowed; OS default route
                    // capture is separately rejected below.
                    if (!value || result.allowed_ips.size()>=1024) return k::error("allowed-ip requires canonical numeric CIDR");
                    result.allowed_ips.push_back({value->family,value->bytes,value->prefix});
                } else if (child.name=="persistent-keepalive-seconds") {
                    auto value=k::integer(child);
                    if (keepalive_seen || !value || *value>65535) return k::error("persistent-keepalive-seconds requires one integer 0..65535");
                    result.persistent_keepalive_seconds=static_cast<std::uint16_t>(*value); keepalive_seen=true;
                } else return k::error("unsupported peer field: "+child.name);
            }
            if (result.public_key_file.empty()) return k::error("peer requires public-key-file");
            return result;
        }
        auto queue(Node const& node,Wireguard& result) -> std::expected<void,std::string> {
            if (node.tag || !node.arguments.empty() || !node.properties.empty() || node.children.empty()) return k::error("queue requires packets and/or bytes children");
            bool packets=false,bytes=false;
            for (auto const& child:node.children) {
                auto value=k::integer(child);
                if (!value || *value>std::numeric_limits<std::size_t>::max()) return k::error("queue fields require unsigned integers");
                if (child.name=="packets" && !packets) { result.queue_packets=static_cast<std::size_t>(*value); packets=true; }
                else if (child.name=="bytes" && !bytes) { result.queue_bytes=static_cast<std::size_t>(*value); bytes=true; }
                else return k::error("unknown or repeated queue field");
            }
            return {};
        }
        auto host_dns(Node const& node) -> std::expected<HostDnsOptions,std::string> {
            if(node.tag || !node.arguments.empty() || !node.properties.empty() || node.children.empty())return k::error("host-dns requires backend and server children");
            HostDnsOptions result;bool backend=false;
            for(auto const& child:node.children) {
                auto text=k::scalar(child);
                if(child.name=="backend") {
                    if(backend || !text || *text!="resolved")return k::error("host-dns backend requires one resolved value");
                    backend=true;result.backend=HostDnsBackend::resolved;
                } else if(child.name=="server") {
                    auto address=text ? dns::parse_local_address(*text) : std::nullopt;
                    if(!address || result.server_count==result.servers.size())return k::error("host-dns supports one to three numeric unicast servers");
                    result.servers[result.server_count++]=*address;
                } else return k::error("unsupported host-dns field: "+child.name);
            }
            if(!backend || !result.valid())return k::error("host-dns requires resolved backend and one to three distinct numeric unicast servers");return result;
        }
        auto wireguard(Node const& node) -> std::expected<Wireguard,std::string> {
            auto name=k::argument(node),type=k::text_property(node,"type");
            if (!name || !k::valid_name(*name) || !type || *type!="wireguard" || node.properties.size()!=1) return k::error("endpoint requires one name and type wireguard");
            Wireguard result; result.name=*name;
            bool listen_seen=false,device_seen=false,timeout_seen=false,queue_seen=false,cookie_seen=false,auto_cookie_seen=false,route_mode_seen=false,provider_seen=false,reserved_seen=false,dns_seen=false;
            for (auto const& child:node.children) {
                auto text=k::scalar(child);
                if (child.name=="private-key-file") {
                    if (!result.private_key_file.empty() || !text || !k::absolute_path(*text)) return k::error("endpoint requires one absolute private-key-file");
                    result.private_key_file=*text;
                } else if (child.name=="listen") {
                    if (listen_seen) return k::error("duplicate listen");
                    auto parsed=server(child,true); if (!parsed) return std::unexpected(parsed.error()); result.listen=*parsed->numeric; listen_seen=true;
                } else if (child.name=="device") {
                    auto device=k::text_property(child,"name"); auto field=k::property(child,"mtu"); auto mtu=field ? k::integer(*field) : std::nullopt;
                    if (device_seen || child.tag || !child.arguments.empty() || !child.children.empty() || child.properties.size()!=2 || !device || device->empty() ||
                        device->size()>15 || !mtu || *mtu>2016 || *mtu<68) return k::error("device requires literal name up to 15 bytes and MTU 68..2016");
                    result.device=*device; result.network.mtu=static_cast<std::uint32_t>(*mtu); device_seen=true;
                } else if (child.name=="local-address" || child.name=="route-include") {
                    auto route=child.name=="route-include"; auto value=text ? config_detail::address(*text,route) : std::nullopt;
                    auto& count=route ? result.network.route_count : result.network.address_count;
                    auto size=route ? result.network.routes.size() : result.network.addresses.size();
                    if (!value || count>=size) return k::error("invalid, noncanonical, default or over-capacity "+child.name);
                    if (route) result.network.routes[count++]=*value; else result.network.addresses[count++]=*value;
                } else if (child.name=="route-mode") {
                    if(route_mode_seen || !text || (*text!="split" && *text!="default"))return k::error("route-mode requires one split or default value");
                    result.default_route=*text=="default";route_mode_seen=true;
                } else if (child.name=="startup-timeout-ms") {
                    auto value=k::connect_timeout(child);
                    if (timeout_seen || !value) return k::error("startup-timeout-ms requires one integer 1..3600000");
                    result.startup_timeout_ms=*value; timeout_seen=true;
                } else if (child.name=="queue") {
                    if (queue_seen) return k::error("duplicate queue");
                    auto parsed=queue(child,result); if (!parsed) return std::unexpected(parsed.error()); queue_seen=true;
                } else if (child.name=="require-cookie") {
                    auto value=k::boolean(child);
                    if (cookie_seen || !value) return k::error("require-cookie requires one boolean");
                    result.require_cookie=*value; cookie_seen=true;
                } else if (child.name=="auto-cookie") {
                    auto value=k::boolean(child);
                    if (auto_cookie_seen || !value) return k::error("auto-cookie requires one boolean");
                    result.auto_cookie=*value; auto_cookie_seen=true;
                } else if(child.name=="provider-profile") {
                    if(provider_seen || !text || (*text!="standard" && *text!="warp"))return k::error("provider-profile requires one standard or warp value");
                    result.provider_profile=*text=="warp"?wireguard::Provider::warp:wireguard::Provider::standard;provider_seen=true;
                } else if(child.name=="reserved") {
                    if(reserved_seen || child.tag || !child.properties.empty() || !child.children.empty() || child.arguments.size()!=3)return k::error("reserved requires exactly three integers 0..255");
                    for(std::size_t i=0;i<3;++i) {
                        auto value=k::integer(child.arguments[i]);
                        if(!value || *value>255)return k::error("reserved requires exactly three integers 0..255");
                        result.reserved[i]=static_cast<std::uint8_t>(*value);
                    }
                    reserved_seen=true;
                } else if(child.name=="host-dns") {
                    if(dns_seen)return k::error("duplicate host-dns");auto parsed=host_dns(child);if(!parsed)return std::unexpected(parsed.error());result.host_dns=*parsed;dns_seen=true;
                } else if (child.name=="bind-interface") {
                    if (!text || text->empty() || text->size()>15 || result.binding.bind_interface.front() || text->find('\0')!=text->npos) return k::error("invalid or repeated bind-interface");
                    std::ranges::copy(*text,result.binding.bind_interface.begin());
                } else if (child.name=="routing-mark") {
                    auto value=k::integer(child);
                    if (!value || *value>std::numeric_limits<std::uint32_t>::max() || result.binding.routing_mark) return k::error("invalid or repeated routing-mark");
                    result.binding.routing_mark=static_cast<std::uint32_t>(*value);
                } else if (child.name=="reuse-addr") {
                    auto value=k::boolean(child);
                    if (!value || *value || result.binding.reuse_addr) return k::error("reuse-addr supports only one false value for an exclusive endpoint");
                    result.binding.reuse_addr=*value;
                } else if (child.name=="udp-fragment") {
                    auto value=k::boolean(child);
                    if (!value || result.binding.udp_fragment) return k::error("udp-fragment requires one boolean and cannot repeat");
                    result.binding.udp_fragment=*value;
                } else if (child.name=="peer") {
                    if (result.peers.size()>=32) return k::error("endpoint exceeds 32 peers");
                    auto parsed=peer(child); if (!parsed) return std::unexpected(parsed.error());
                    if (std::ranges::any_of(result.peers,[&](auto const& value) { return value.name==parsed->name; })) return k::error("duplicate peer name");
                    result.peers.push_back(std::move(*parsed));
                } else return k::error("unsupported wireguard endpoint field: "+child.name);
            }
            if(!wireguard::ReservedProfile::create(result.provider_profile,result.reserved))return k::error("nonzero reserved bytes require explicit provider-profile warp");
            if (result.private_key_file.empty() || !listen_seen || !device_seen || result.peers.empty()) return k::error("endpoint requires private key, listen, device and peers");
            if(result.default_route && !result.binding.routing_mark)result.binding.routing_mark=0x6e780001;
            return result;
        }
    }
    auto parse_kdl(std::string_view input) -> std::expected<Document,std::string> {
        auto document=k::read_document(input); if (!document) return std::unexpected(document.error());
        Document result; bool version_seen=false,role_seen=false,endpoint_seen=false;
        for (auto const& node:*document) {
            if (node.name=="schema-version") {
                if (version_seen || !k::version(node)) return k::error("expected one schema-version 1"); version_seen=true;
            } else if (node.name=="role") {
                auto role=k::deployment_role(node); if (role_seen || !role) return k::error("expected one client or server role");
                result.server=*role=="server"; role_seen=true;
            } else if (node.name=="endpoint") {
                if (endpoint_seen) return k::error("exactly one endpoint is supported");
                auto parsed=wireguard(node); if (!parsed) return std::unexpected(parsed.error()); result.wireguard=std::move(*parsed); endpoint_seen=true;
            } else return k::error("unsupported endpoint document field: "+node.name);
        }
        if (!version_seen || !role_seen || !endpoint_seen) return k::error("schema-version, role and endpoint are required");
        auto validated=config_detail::validate(result); if (!validated) return std::unexpected(validated.error());
        return result;
    }
}
