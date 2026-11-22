import std;
import http.header;
import masque.connect_ip;
import masque.ip_control;
namespace m=masque;
namespace h=http;

auto header_tests() -> int {
    std::array fields{h::HeaderField{":method","CONNECT"},h::HeaderField{":protocol","connect-ip"},
        h::HeaderField{":scheme","https"},h::HeaderField{":authority","proxy.example:443"},
        h::HeaderField{":path","/.well-known/masque/ip/*/*/"},h::HeaderField{"capsule-protocol","?1"}};
    auto request=m::parse_connect_ip_request(fields);
    if(!request || request->authority!="proxy.example:443" || request->scheme!="https")return 1;
    fields[1].value="connect-udp";auto other=m::parse_connect_ip_request(fields);if(other || other.error()!=m::ConnectIpError::not_connect_ip)return 2;
    fields[1].value="connect-ip";fields[5]={":method","CONNECT"};if(m::parse_connect_ip_request(fields))return 3;
    fields[5]={"content-length","0"};if(m::parse_connect_ip_request(fields))return 4;
    fields[5]={"capsule-protocol","?1"};fields[4].value="relative";if(m::parse_connect_ip_request(fields))return 5;
    std::array ok{h::HeaderField{":status","200"}};
    if(!m::parse_connect_ip_response(ok))return 6;
    ok[0].value="403";auto rejected=m::parse_connect_ip_response(ok);if(rejected || rejected.error()!=m::ConnectIpError::failed_response)return 7;
    ok[0].value="204";auto invalid=m::parse_connect_ip_response(ok);if(invalid || invalid.error()!=m::ConnectIpError::malformed)return 8;
    std::array duplicate{h::HeaderField{":status","200"},h::HeaderField{":status","200"}};
    if(m::parse_connect_ip_response(duplicate))return 9;
    std::array content{h::HeaderField{":status","200"},h::HeaderField{"content-type","text/plain"}};
    if(m::parse_connect_ip_response(content))return 10;
    return 0;
}
auto path_tests() -> int {
    auto any=m::parse_default_ip_path("/.well-known/masque/ip/*/*/");
    if(!any || any->kind!=m::IpTargetKind::any || any->protocol)return 11;
    auto ipv4=m::parse_default_ip_path("/.well-known/masque/ip/192.0.2.0%2F24/17/");
    if(!ipv4 || ipv4->kind!=m::IpTargetKind::prefix || ipv4->prefix.version!=4 || ipv4->prefix.prefix_length!=24 || ipv4->protocol!=17)return 12;
    auto ipv6=m::parse_default_ip_path("/.well-known/masque/ip/2001%3Adb8%3A%3A%2F32/6/");
    if(!ipv6 || ipv6->prefix.version!=6 || ipv6->prefix.prefix_length!=32 || ipv6->prefix.address[0]!=0x20 || ipv6->protocol!=6)return 13;
    auto host=m::parse_default_ip_path("/.well-known/masque/ip/Example.org./%31%37/");
    if(!host || host->kind!=m::IpTargetKind::hostname || host->hostname!="Example.org." || host->protocol!=17)return 14;
    auto zero=m::parse_default_ip_path("/.well-known/masque/ip/0.0.0.0%2F0/0/");
    if(!zero || zero->kind!=m::IpTargetKind::prefix || zero->prefix.prefix_length!=0 || zero->protocol!=0)return 24;
    auto encoded=m::write_default_ip_path(*ipv6);if(!encoded)return 15;
    auto round=m::parse_default_ip_path(*encoded);
    if(!round || round->kind!=m::IpTargetKind::prefix || round->prefix.address!=ipv6->prefix.address || round->prefix.prefix_length!=32 || round->protocol!=6)return 16;
    for(auto const& scope:{*any,*ipv4,*host}) {
        auto text=m::write_default_ip_path(scope);auto parsed=text ? m::parse_default_ip_path(*text) : std::expected<m::ConnectIpScope,m::ConnectIpError>{std::unexpected(m::ConnectIpError::malformed)};
        if(!parsed || parsed->kind!=scope.kind || parsed->protocol!=scope.protocol || parsed->hostname!=scope.hostname ||
           parsed->prefix.version!=scope.prefix.version || parsed->prefix.prefix_length!=scope.prefix.prefix_length || parsed->prefix.address!=scope.prefix.address)return 17;
    }
    std::array bad_targets{
        "/.well-known/masque/ip//*/", "/.well-known/masque/ip/192.0.2.1%2F24/*/", "/.well-known/masque/ip/192.0.2.0%2F33/*/",
        "/.well-known/masque/ip/2001:db8::1/*/", "/.well-known/masque/ip/2001%3Adb8%3A%3A1%2F64/*/",
        "/.well-known/masque/ip/fe80%3A%3A1%25eth0/*/", "/.well-known/masque/ip/01.02.03.04/*/",
        "/.well-known/masque/ip/example.com%2Fevil/*/", "/.well-known/masque/ip/example.com%00/*/", "/.well-known/masque/ip/%2F24/*/",
        "/.well-known/masque/ip/example..org/*/", "/.well-known/masque/ip/example.com%252Ffoo/*/"};
    for(auto text:bad_targets)if(m::parse_default_ip_path(text))return 18;
    std::array bad_paths{"/.well-known/masque/ip/", "/.well-known/masque/ip/*/*", "/.well-known/masque/ip/*/*/extra/", "/.well-known/masque/ip/*/*/?x=1"};
    for(auto text:bad_paths)if(m::parse_default_ip_path(text))return 19;
    std::array bad_protocols{"/.well-known/masque/ip/*//", "/.well-known/masque/ip/*/256/", "/.well-known/masque/ip/*/-1/", "/.well-known/masque/ip/*/0000/", "/.well-known/masque/ip/*/%2F/"};
    for(auto text:bad_protocols)if(m::parse_default_ip_path(text))return 20;
    for(auto proto:{"0","255","000","%2A"})if(!m::parse_default_ip_path(std::string("/.well-known/masque/ip/*/")+proto+"/"))return 21;
    auto malformed=*ipv4;malformed.prefix.address[3]=1;if(m::write_default_ip_path(malformed))return 22;
    malformed=*host;malformed.hostname="name/escape";if(m::write_default_ip_path(malformed))return 23;
    return 0;
}
auto main() -> int {
    if(auto result=header_tests())return result;
    if(auto result=path_tests())return result;
    std::println("CONNECT-IP request, response and default URI scope passed");
}
