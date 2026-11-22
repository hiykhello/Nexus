import std;
import http.connect;
namespace h=http;
auto main()->int{
    for(auto bad:{"", "example.com", "example.com:","example.com:0","example.com:65536","example.com:+1","example.com:1extra","user@example.com:443","http://example.com:443","example.com:443/path","1.2.3:443","0127.0.0.1:443","[::1%lo]:443","::1:443","[::1]","[::1]extra:443","[::1]:443\r\nx: bad"})if(h::parse_destination_authority(bad).status==h::ConnectStatus::accepted)return 1;
    for(auto [wire,kind,host,port]:{std::tuple{"example.com:443",h::HostKind::domain,"example.com",443},std::tuple{"127.0.0.1:80",h::HostKind::ipv4,"127.0.0.1",80},std::tuple{"[::1]:65535",h::HostKind::ipv6,"::1",65535}}){
        auto direct=h::parse_destination_authority(wire);auto header=h::parse_connect(std::string("CONNECT ")+wire+" HTTP/1.1\r\nHost: "+wire+"\r\n\r\n");
        if(direct.status!=h::ConnectStatus::accepted || direct.kind!=kind || direct.host!=host || direct.port!=port || direct.address!=header.address || direct.port!=header.port || direct.host!=header.host || header.status!=h::ConnectStatus::accepted)return 2;
    }
    std::println("Shared destination authority: domain/IPv4/bracket-IPv6/port/alternate-numeric/injection rules exactly match existing CONNECT parser");
}
