module masque.target;
import std;
import platform.ip_address;

namespace masque {
    auto parse_well_known_udp_target(std::string_view path) -> std::expected<UdpTarget,TargetError> {
        constexpr std::string_view prefix="/.well-known/masque/udp/";
        if(path.size()<=prefix.size() || !path.starts_with(prefix) || !path.ends_with('/'))return std::unexpected(TargetError::invalid_path);
        path.remove_prefix(prefix.size());path.remove_suffix(1);
        auto slash=path.find('/');
        if(slash==std::string_view::npos || path.find('/',slash+1)!=std::string_view::npos)return std::unexpected(TargetError::invalid_path);
        auto encoded=path.substr(0,slash),port_text=path.substr(slash+1);
        if(encoded.empty() || encoded.size()>765)return std::unexpected(TargetError::invalid_host);
        std::string host;host.reserve(std::min<std::size_t>(encoded.size(),255));
        auto hex=[](char c) -> int {if(c>='0' && c<='9')return c-'0';if(c>='a' && c<='f')return c-'a'+10;if(c>='A' && c<='F')return c-'A'+10;return -1;};
        for(std::size_t i=0;i<encoded.size();++i) {
            unsigned char c=encoded[i];
            if(c=='%') {if(i+2>=encoded.size())return std::unexpected(TargetError::invalid_host);auto a=hex(encoded[i+1]),b=hex(encoded[i+2]);if(a<0 || b<0)return std::unexpected(TargetError::invalid_host);c=static_cast<unsigned char>((a<<4)|b);i+=2;}
            else if(c==':')return std::unexpected(TargetError::invalid_host);
            if(c<=0x20 || c>=0x7f || c=='%' || c=='/' || c=='?' || c=='#' || c=='[' || c==']' || c=='@' || c=='\\' || host.size()==255)return std::unexpected(TargetError::invalid_host);
            host.push_back(static_cast<char>(c));
        }
        if(host.find(':')!=std::string::npos) {
            auto parsed=platform::parse_ip_address(host);
            if(!parsed || parsed->size!=16)return std::unexpected(TargetError::invalid_host);
        } else {
            // Limit registered names to DNS-safe ASCII labels; do not pass
            // URI escapes, ambiguous punctuation or zone IDs to a resolver.
            auto name=std::string_view(host);if(name.ends_with('.'))name.remove_suffix(1);
            if(name.empty() || name.size()>253 || name.ends_with('.'))return std::unexpected(TargetError::invalid_host);
            while(!name.empty()) {
                auto pos=name.find('.');auto label=name.substr(0,pos);
                if(label.empty() || label.size()>63 || label.front()=='-' || label.back()=='-' ||
                   !std::ranges::all_of(label,[](unsigned char c){return (c>='a' && c<='z') || (c>='A' && c<='Z') || (c>='0' && c<='9') || c=='-';}))return std::unexpected(TargetError::invalid_host);
                if(pos==std::string_view::npos)break;name.remove_prefix(pos+1);
            }
        }
        if(port_text.empty() || port_text.size()>5 || !std::ranges::all_of(port_text,[](unsigned char c){return c>='0' && c<='9';}))return std::unexpected(TargetError::invalid_port);
        unsigned port=0;auto [end,error]=std::from_chars(port_text.data(),port_text.data()+port_text.size(),port);
        if(error!=std::errc{} || end!=port_text.data()+port_text.size() || !port || port>65535)return std::unexpected(TargetError::invalid_port);
        return UdpTarget{std::move(host),static_cast<std::uint16_t>(port)};
    }
}
