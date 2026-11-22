module masque.connect_udp;
import std;
import http.header;

namespace masque {
    auto parse_connect_udp_request(std::span<http::HeaderField const> fields) noexcept -> std::expected<ConnectUdpRequest,ConnectUdpError> {
        std::string_view method,protocol,scheme,authority,path;
        bool seen_method=false,seen_protocol=false,seen_scheme=false,seen_authority=false,seen_path=false;
        for(auto const& field:fields) {
            auto set=[&](bool& seen,std::string_view& value) {if(seen)return false;seen=true;value=field.value;return true;};
            if(field.name==":method") {if(!set(seen_method,method))return std::unexpected(ConnectUdpError::malformed);}
            else if(field.name==":protocol") {if(!set(seen_protocol,protocol))return std::unexpected(ConnectUdpError::malformed);}
            else if(field.name==":scheme") {if(!set(seen_scheme,scheme))return std::unexpected(ConnectUdpError::malformed);}
            else if(field.name==":authority") {if(!set(seen_authority,authority))return std::unexpected(ConnectUdpError::malformed);}
            else if(field.name==":path") {if(!set(seen_path,path))return std::unexpected(ConnectUdpError::malformed);}
            else if(field.name=="content-length" || field.name=="content-type" || field.name=="transfer-encoding")return std::unexpected(ConnectUdpError::malformed);
            else if(!field.name.empty() && field.name.front()==':')return std::unexpected(ConnectUdpError::malformed);
        }
        if(!seen_method || !seen_protocol || !seen_scheme || !seen_authority || !seen_path || scheme!="https" || authority.empty() || path.empty())return std::unexpected(ConnectUdpError::malformed);
        if(method!="CONNECT" || protocol!="connect-udp")return std::unexpected(ConnectUdpError::not_connect_udp);
        return ConnectUdpRequest{authority,path};
    }
    auto parse_connect_udp_response(std::span<http::HeaderField const> fields) noexcept -> std::expected<unsigned,ConnectUdpError> {
        std::string_view status;bool seen=false;
        for(auto const& field:fields) {
            if(field.name==":status") {if(seen)return std::unexpected(ConnectUdpError::malformed);seen=true;status=field.value;}
            else if(field.name=="content-length" || field.name=="content-type" || field.name=="transfer-encoding")return std::unexpected(ConnectUdpError::malformed);
            else if(!field.name.empty() && field.name.front()==':')return std::unexpected(ConnectUdpError::malformed);
        }
        if(!seen || status.size()!=3 || !std::ranges::all_of(status,[](char c){return c>='0' && c<='9';}))return std::unexpected(ConnectUdpError::malformed);
        unsigned code=(status[0]-'0')*100+(status[1]-'0')*10+(status[2]-'0');
        if(code<200 || code>=300)return std::unexpected(ConnectUdpError::failed_response);
        if(code==204 || code==205 || code==206)return std::unexpected(ConnectUdpError::malformed);
        return code;
    }
}
