module shadowsocks.header;
import std;
import crypto;
namespace shadowsocks {
    namespace {
        auto address_size(std::span<std::uint8_t const> bytes) -> std::optional<std::size_t> {
            if (bytes.empty()) return {};
            std::size_t size=0;
            switch (bytes[0]) {
                case 1: size=7; break;
                case 4: size=19; break;
                case 3:
                    if (bytes.size()<2 || bytes[1]==0) return {};
                    size=static_cast<std::size_t>(bytes[1])+4; break;
                default: return {};
            }
            if (bytes.size()<size) return {};
            return size;
        }
        auto valid_salt(bool response, std::span<std::uint8_t const> salt) -> bool {
            return response ? salt.size()==16 || salt.size()==32 : salt.empty();
        }
    }
    auto make_request_header(std::span<std::uint8_t const> address, std::span<std::uint8_t const> padding,
                             std::span<std::uint8_t const> payload) -> std::expected<std::vector<std::uint8_t>,HeaderError> {
        auto size=address_size(address);
        if (!size || *size!=address.size()) return std::unexpected(HeaderError::invalid_address);
        if (padding.size()>900 || (padding.empty() && payload.empty())) return std::unexpected(HeaderError::invalid_padding);
        if (address.size()+2+padding.size()>65535 || payload.size()>65535-address.size()-2-padding.size())
            return std::unexpected(HeaderError::invalid_length);
        std::vector<std::uint8_t> result; result.reserve(address.size()+2+padding.size()+payload.size());
        result.insert(result.end(),address.begin(),address.end());
        result.push_back(static_cast<std::uint8_t>(padding.size()>>8)); result.push_back(static_cast<std::uint8_t>(padding.size()));
        result.insert(result.end(),padding.begin(),padding.end()); result.insert(result.end(),payload.begin(),payload.end());
        return result;
    }
    auto parse_request_header(std::span<std::uint8_t const> bytes) -> std::expected<RequestHeader,HeaderError> {
        if (bytes.size()>65535) return std::unexpected(HeaderError::invalid_length);
        auto size=address_size(bytes);
        if (!size) return std::unexpected(HeaderError::invalid_address);
        if (bytes.size()-*size<2) return std::unexpected(HeaderError::invalid_length);
        auto padding=(static_cast<std::size_t>(bytes[*size])<<8)|bytes[*size+1];
        auto start=*size+2;
        if (padding>900 || padding>bytes.size()-start || (padding==0 && bytes.size()==start))
            return std::unexpected(HeaderError::invalid_padding);
        return RequestHeader{std::vector<std::uint8_t>(bytes.begin(),bytes.begin()+*size),
            std::vector<std::uint8_t>(bytes.begin()+start+padding,bytes.end())};
    }
    auto make_fixed_header(bool response, std::uint64_t timestamp, std::uint16_t length,
                           std::span<std::uint8_t const> request_salt) -> std::expected<std::vector<std::uint8_t>,HeaderError> {
        if (!valid_salt(response,request_salt)) return std::unexpected(HeaderError::invalid_salt);
        std::vector<std::uint8_t> result; result.reserve(11+request_salt.size()); result.push_back(response ? 1 : 0);
        for (int shift=56;shift>=0;shift-=8) result.push_back(static_cast<std::uint8_t>(timestamp>>shift));
        result.insert(result.end(),request_salt.begin(),request_salt.end());
        result.push_back(static_cast<std::uint8_t>(length>>8)); result.push_back(static_cast<std::uint8_t>(length));
        return result;
    }
    auto parse_fixed_header(std::span<std::uint8_t const> bytes, bool response, std::uint64_t now,
                            std::span<std::uint8_t const> request_salt) -> std::expected<FixedHeader,HeaderError> {
        if (!valid_salt(response,request_salt)) return std::unexpected(HeaderError::invalid_salt);
        if (bytes.size()!=11+request_salt.size()) return std::unexpected(HeaderError::invalid_length);
        if (bytes[0]!=(response ? 1 : 0)) return std::unexpected(HeaderError::invalid_type);
        std::uint64_t timestamp=0; for (std::size_t i=1;i<9;++i) timestamp=(timestamp<<8)|bytes[i];
        if ((timestamp>now ? timestamp-now : now-timestamp)>30) return std::unexpected(HeaderError::invalid_timestamp);
        if (response && !crypto::constant_time_equal(bytes.subspan(9,request_salt.size()),request_salt))
            return std::unexpected(HeaderError::invalid_salt);
        auto offset=9+request_salt.size();
        return FixedHeader{timestamp,static_cast<std::uint16_t>((static_cast<unsigned>(bytes[offset])<<8)|bytes[offset+1])};
    }
}
