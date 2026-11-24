module config;
import std;
import config.kdl_common;
import glaze;
namespace config {
    auto dns_ipv4(std::string_view) -> std::optional<std::array<std::uint8_t,4>>;
    auto dns_ipv6(std::string_view) -> std::optional<std::array<std::uint8_t,16>>;
    auto parse_tcp_dial_option(glaze::KdlNode const&,TcpSocketOptions&)->std::expected<bool,std::string>;
    auto parse_outbound_multiplex(glaze::KdlNode const&)->std::expected<MultiplexConfig,std::string>;
    auto parse_snell_inbound(kdl::Node const& node)->std::expected<InboundConfig,std::string> {
        using namespace config::kdl;auto name=argument(node);auto type=text_property(node,"type");
        if(!name||!valid_name(*name)||!type||*type!="snell"||node.properties.size()!=1)return error("invalid Snell inbound");
        SnellInbound cfg;bool listen=false,version=false,window=false,obfs=false;InboundConfig result{*name,0,Inbound::snell};
        for(auto const& c:node.children){
            if(c.name=="listen"){auto host=text_property(c,"host");auto v=property(c,"port");auto port=v?integer(*v):std::nullopt;
                if(listen||c.tag||!c.arguments.empty()||!c.children.empty()||c.properties.size()!=2||!host||!port||!*port||*port>65535)return error("invalid Snell listen");
                if(auto address=dns_ipv4(*host))std::ranges::copy(*address,cfg.listen_address.begin());
                else if(auto address=dns_ipv6(*host)){cfg.listen_address=*address;result.listen_ipv6=true;}
                else return error("Snell listen host must be a numeric IP without a zone");
                cfg.listen_host=*host;result.port=*port;listen=true;
            }else if(c.name=="version"){auto v=integer(c);if(version||!v||*v!=5)return error("Snell inbound requires version 5");version=true;
            }else if(c.name=="psk-file"){auto v=scalar(c);if(!cfg.psk_file.empty()||!v||!absolute_path(*v))return error("invalid Snell PSK file");cfg.psk_file=*v;
            }else if(c.name=="userkey-file"){auto v=scalar(c);if(cfg.user_file||!v||!absolute_path(*v))return error("invalid Snell user key file");cfg.user_file=*v;
            }else if(c.name=="replay-window-seconds"){auto v=integer(c);if(window||!v||!*v||*v>86400)return error("invalid Snell replay window");cfg.replay_window_seconds=*v;window=true;
            }else if(c.name=="obfs"){auto v=scalar(c);if(obfs||!v||*v!="http")return error("Snell obfs requires http");cfg.http_obfs=true;obfs=true;
            }else return error("unsupported Snell inbound field: "+c.name);
        }
        if(!listen||!version||cfg.psk_file.empty()||!window)return error("Snell inbound requires listen, version, PSK and replay window");result.snell=std::move(cfg);return result;
    }
    auto parse_snell_outbound(kdl::Node const& node)->std::expected<SnellOutbound,std::string> {
        using namespace config::kdl;SnellOutbound out;bool server=false,version_seen=false,psk=false,timeout=false,obfs=false,obfs_host=false,obfs_uri=false,reuse=false;
        for(auto const& c:node.children){
            if(c.name=="server") {auto host=text_property(c,"host");auto v=property(c,"port");auto port=v?integer(*v):std::nullopt;
                if(server||c.tag||!c.arguments.empty()||!c.children.empty()||c.properties.size()!=2||!host||!endpoint_name(*host)||!port||!*port||*port>65535)return error("invalid Snell server");out.host=*host;out.port=*port;server=true;
            }else if(c.name=="version") {auto v=integer(c);if(version_seen||!v||(*v!=4&&*v!=5))return error("Snell outbound requires version 4 or 5");out.version=static_cast<std::uint8_t>(*v);version_seen=true;
            }else if(c.name=="psk-file") {auto v=scalar(c);if(psk||!v||!absolute_path(*v))return error("invalid Snell PSK file");out.psk_file=*v;psk=true;
            }else if(c.name=="userkey-file") {auto v=scalar(c);if(out.user_file||!v||!absolute_path(*v))return error("invalid Snell user key file");out.user_file=*v;
            }else if(c.name=="detour") {auto v=scalar(c);if(out.detour||!v||!valid_name(*v))return error("invalid Snell detour");out.detour=*v;
            }else if(c.name=="bootstrap-resolver" || c.name=="domain-resolver") {auto v=scalar(c);if(out.bootstrap_resolver||!v||!valid_name(*v))return error("invalid Snell resolver");out.bootstrap_resolver=*v;
            }else if(c.name=="connect-timeout-ms") {auto v=connect_timeout(c);if(timeout||!v)return error("invalid Snell timeout");out.connect_timeout_ms=*v;timeout=true;
            }else if(c.name=="obfs") {auto v=scalar(c);if(obfs||!v||*v!="http")return error("Snell obfs requires http");out.http_obfs=true;obfs=true;
            }else if(c.name=="obfs-host") {auto v=scalar(c);if(obfs_host||!v||v->empty()||v->size()>253||!std::ranges::all_of(*v,[](unsigned char ch){return ch>32&&ch<127;}))return error("invalid Snell obfs host");out.obfs_host=*v;obfs_host=true;
            }else if(c.name=="obfs-uri") {auto v=scalar(c);if(obfs_uri||!v||v->empty()||v->size()>1024||v->front()!='/'||!std::ranges::all_of(*v,[](unsigned char ch){return ch>32&&ch<127;}))return error("invalid Snell obfs URI");out.obfs_uri=*v;obfs_uri=true;
            }else if(c.name=="reuse") {
                if(reuse||c.tag||!c.properties.empty()||!c.children.empty()||c.arguments.size()!=1||c.arguments[0].tag||
                   !std::holds_alternative<bool>(c.arguments[0].data))return error("Snell reuse requires one boolean and cannot repeat");
                out.reuse=std::get<bool>(c.arguments[0].data);reuse=true;
            }else if(c.name=="tcp-fast-open") {
                if(out.tcp_fast_open||c.tag||!c.properties.empty()||!c.children.empty()||c.arguments.size()!=1||c.arguments[0].tag||
                   !std::holds_alternative<bool>(c.arguments[0].data))return error("tcp-fast-open requires one boolean and cannot repeat");
                out.tcp_fast_open=std::get<bool>(c.arguments[0].data);
            }else if(c.name=="multiplex") {
                if(out.multiplex)return error("duplicate Snell multiplex");
                auto parsed=parse_outbound_multiplex(c);if(!parsed)return std::unexpected(parsed.error());
                out.multiplex=std::move(*parsed);
            }else {auto option=parse_tcp_dial_option(c,out.tcp_options);if(!option)return std::unexpected(option.error());if(!*option)return error("unsupported Snell outbound field: "+c.name);}
        }
        if(!server||!psk||!version_seen)return error("Snell outbound requires server, version and PSK file");
        if((obfs_host||obfs_uri)&&!obfs)return error("Snell obfs host/URI require HTTP obfs");
        if(out.detour&&out.tcp_fast_open)return error("tcp-fast-open belongs to the physical outbound, not a layered node");return out;
    }
}
