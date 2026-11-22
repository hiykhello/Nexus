module snell.http_obfs;
import std;
import crypto;

namespace snell {
    auto http_obfs_websocket_key() -> std::optional<std::string> {
        std::array<std::uint8_t,16> random{};
        if(!crypto::random_bytes(random))return {};
        constexpr std::string_view alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        std::string result;result.reserve(24);
        for(std::size_t i=0;i<random.size();i+=3){
            auto value=std::uint32_t(random[i])<<16;
            if(i+1<random.size())value|=std::uint32_t(random[i+1])<<8;
            if(i+2<random.size())value|=random[i+2];
            result.push_back(alphabet[(value>>18)&63]);result.push_back(alphabet[(value>>12)&63]);
            result.push_back(i+1<random.size()?alphabet[(value>>6)&63]:'=');result.push_back(i+2<random.size()?alphabet[value&63]:'=');
        }
        return result;
    }
}
