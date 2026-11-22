import std;
import masque.connect_udp;
import masque.bearer;
import http.header;
namespace m=masque;
namespace h=http;
auto main() -> int {
    std::vector<h::HeaderField> request{{":method","CONNECT"},{":protocol","connect-udp"},{":scheme","https"},{":authority","proxy.example"},{":path","/.well-known/masque/udp/a/53/"}};
    auto parsed=m::parse_connect_udp_request(request);if(!parsed || parsed->authority!="proxy.example" || parsed->path!="/.well-known/masque/udp/a/53/")return 1;
    request.push_back({"content-length","0"});if(m::parse_connect_udp_request(request))return 2;request.pop_back();
    request.push_back({":path","/other"});if(m::parse_connect_udp_request(request))return 3;request.pop_back();
    request[1].value="websocket";if(m::parse_connect_udp_request(request).error()!=m::ConnectUdpError::not_connect_udp)return 4;
    for(auto [status,accepted]:std::array<std::pair<std::string_view,bool>,7>{{{"200",true},{"299",true},{"204",false},{"205",false},{"206",false},{"403",false},{"20a",false}}}) {
        std::array<h::HeaderField,1> fields{{{":status",status}}};if(bool(m::parse_connect_udp_response(fields))!=accepted)return 5;
    }
    std::array<h::HeaderField,2> invalid{{{":status","200"},{"content-type","x"}}};if(m::parse_connect_udp_response(invalid))return 6;
    constexpr std::string_view secret="approved";
    auto credential=m::BearerCredential::create({reinterpret_cast<std::uint8_t const*>(secret.data()),secret.size()});if(!credential)return 7;
    std::array<h::HeaderField,1> auth{{{"proxy-authorization","bEaReR approved"}}};
    if(!credential->authenticate(auth))return 8;
    auth[0].value="Bearer rejected";if(credential->authenticate(auth))return 9;
    std::array<h::HeaderField,2> duplicate{{{"proxy-authorization","Bearer approved"},{"proxy-authorization","Bearer approved"}}};if(credential->authenticate(duplicate))return 10;
    constexpr std::string_view invalid_token="bad=token";
    if(m::BearerCredential::create({reinterpret_cast<std::uint8_t const*>(invalid_token.data()),invalid_token.size()}))return 11;
    std::println("CONNECT-UDP request/response structural policy passed");
}
