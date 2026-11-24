module config;
import std;
import config.kdl_common;
import glaze;
namespace config {
    auto dns_ipv4(std::string_view) -> std::optional<std::array<std::uint8_t,4>>;
    auto dns_ipv6(std::string_view) -> std::optional<std::array<std::uint8_t,16>>;
    namespace {
        auto parse_ip_tun(kdl::Node const& node) -> std::expected<MasqueIpInbound,std::string> {
            if(node.tag || !node.arguments.empty() || !node.properties.empty())return kdl::error("invalid MASQUE connect-ip block");
            MasqueIpInbound options;
            for(auto const& field:node.children) {
                auto value=kdl::scalar(field);
                if(!value || value->empty() || value->size()>64)return kdl::error("invalid MASQUE connect-ip field");
                if(field.name=="interface-name" && options.interface.empty())options.interface=*value;
                else if(field.name=="local-address" && options.local_addresses.size()<2)options.local_addresses.push_back(*value);
                else if(field.name=="client-address" && options.client_addresses.size()<2)options.client_addresses.push_back(*value);
                else if(field.name=="allow-ip" && options.allowed_routes.size()<16)options.allowed_routes.push_back(*value);
                else return kdl::error("invalid or duplicate MASQUE connect-ip field: "+field.name);
            }
            if(options.interface.empty() || options.local_addresses.empty() ||
               options.local_addresses.size()!=options.client_addresses.size() || options.allowed_routes.empty())
                return kdl::error("MASQUE connect-ip requires interface-name, paired local-address/client-address and allow-ip");
            return options;
        }
    }
    auto parse_masque_inbound(kdl::Node const& node) -> std::expected<InboundConfig,std::string> {
        using namespace config::kdl;
        auto tag=argument(node),type=text_property(node,"type");
        if(!tag || !valid_name(*tag) || node.properties.size()!=1 || !type || *type!="masque")return error("invalid MASQUE inbound");
        InboundConfig result{*tag,0,Inbound::masque};MasqueInbound config;
        bool listen=false,auth=false,tls=false,policy=false,authority=false,dns_timeout=false,native=false;
        for(auto const& child:node.children) {
            if(child.name=="listen") {
                auto host=text_property(child,"host");auto value=property(child,"port");auto port=value ? integer(*value) : std::nullopt;
                if(listen || child.tag || !child.arguments.empty() || !child.children.empty() || child.properties.size()!=2 || !host || !port || !*port || *port>65535)return error("invalid MASQUE listen");
                if(auto ip=dns_ipv4(*host))std::ranges::copy(*ip,config.listen_address.begin());
                else if(auto ip=dns_ipv6(*host)){config.listen_address=*ip;result.listen_ipv6=true;}
                else return error("MASQUE listen requires numeric IP without zone");
                config.listen_host=*host;result.port=*port;listen=true;
            } else if(child.name=="authority") {
                auto value=scalar(child);if(authority || !value || !endpoint_name(*value) || std::ranges::any_of(*value,[](unsigned char c){return c=='/' || c=='?' || c=='#' || c=='@' || c=='\\';}))return error("invalid MASQUE authority");
                config.authority=*value;authority=true;
            } else if(child.name=="authentication") {
                if(auth || child.tag || !child.arguments.empty() || !child.properties.empty() || child.children.size()!=1 || child.children[0].name!="bearer-file")return error("MASQUE requires one bearer-file");
                auto file=scalar(child.children[0]);if(!file || !absolute_path(*file))return error("MASQUE bearer-file must be absolute");config.bearer_file=*file;auth=true;
            } else if(child.name=="tls") {
                if(tls || child.tag || !child.arguments.empty() || !child.properties.empty())return error("invalid MASQUE TLS");
                for(auto const& field:child.children) {
                    auto file=scalar(field);if(!file || !absolute_path(*file))return error("MASQUE TLS file must be absolute");
                    if(field.name=="certificate-file" && config.certificate_file.empty())config.certificate_file=*file;
                    else if(field.name=="private-key-file" && config.private_key_file.empty())config.private_key_file=*file;
                    else return error("unsupported or duplicate MASQUE TLS field");
                }
                if(config.certificate_file.empty() || config.private_key_file.empty())return error("MASQUE TLS requires certificate and key");tls=true;
            } else if(child.name=="connect-ip") {
                if(config.ip)return error("duplicate MASQUE connect-ip block");
                auto options=parse_ip_tun(child);if(!options)return std::unexpected(options.error());
                config.ip=std::move(*options);
            } else if(child.name=="allow") {
                if(child.tag || !child.arguments.empty() || !child.children.empty() || child.properties.size()!=3 || config.destinations.size()>=256)return error("invalid MASQUE destination allow rule");
                auto cidr=text_property(child,"cidr");auto first=property(child,"first-port"),last=property(child,"last-port");
                auto low=first ? integer(*first) : std::nullopt,high=last ? integer(*last) : std::nullopt;
                if(!cidr || !low || !high || !*low || *low>*high || *high>65535)return error("invalid MASQUE destination ports");
                auto slash=cidr->find('/');if(slash==std::string::npos)return error("MASQUE allow requires CIDR");
                auto text=std::string_view(*cidr).substr(0,slash),bits=std::string_view(*cidr).substr(slash+1);unsigned prefix=0;
                auto [end,ec]=std::from_chars(bits.data(),bits.data()+bits.size(),prefix);
                if(bits.empty() || ec!=std::errc{} || end!=bits.data()+bits.size())return error("invalid MASQUE CIDR prefix");
                MasqueDestination rule;
                if(auto ip=dns_ipv4(text)){rule.family=4;std::ranges::copy(*ip,rule.network.begin());}
                else if(auto ip=dns_ipv6(text)){rule.family=6;rule.network=*ip;}
                else return error("invalid MASQUE CIDR address");
                if(prefix>(rule.family==4 ? 32u : 128u))return error("invalid MASQUE CIDR prefix");
                for(unsigned bit=prefix;bit<(rule.family==4 ? 32u : 128u);++bit)if(rule.network[bit/8]&(0x80u>>(bit%8)))return error("MASQUE CIDR has host bits");
                rule.prefix=prefix;rule.first_port=*low;rule.last_port=*high;config.destinations.push_back(rule);policy=true;
            } else if(child.name=="dns-timeout-ms") {
                auto value=integer(child);if(dns_timeout || !value || !*value || *value>60000)return error("invalid MASQUE DNS timeout");config.dns_timeout_ms=*value;dns_timeout=true;
            } else if(child.name=="native-bytes") {
                auto value=integer(child);if(native || !value || *value<65536 || *value>1024ull*1024*1024)return error("invalid MASQUE native budget");config.native_bytes=*value;native=true;
            } else return error("unsupported MASQUE inbound field: "+child.name);
        }
        if(!listen || !auth || !tls || !authority || (!policy && !config.ip))
            return error("MASQUE requires listen, authority, authentication, TLS and an allow rule or connect-ip");
        result.masque=std::move(config);return result;
    }
}
