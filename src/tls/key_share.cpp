module nexus.tls.key_share;
import std;

namespace nexus::tls {
    namespace {
        auto u16(std::span<std::uint8_t const> b, std::size_t p) -> std::uint16_t { return static_cast<std::uint16_t>(b[p]<<8|b[p+1]); }
        auto add_u16(std::vector<std::uint8_t>& out, std::size_t n) -> bool { if (n>0xffff) return false; out.push_back(static_cast<std::uint8_t>(n>>8)); out.push_back(static_cast<std::uint8_t>(n)); return true; }
        auto valid_entry_size(KeyShareEntry const& e) -> bool { return !e.key_exchange.empty() && e.key_exchange.size()<=0xffff; }
    }
    auto KeyShare::parse_client(std::span<std::uint8_t const> data, std::size_t max_size)
        -> std::expected<std::vector<KeyShareEntry>, KeyShareError> {
        if (data.size()>max_size || data.size()<2) return std::unexpected(data.size()>max_size ? KeyShareError::message_too_large : KeyShareError::truncated);
        auto list_size=static_cast<std::size_t>(u16(data,0)); if (list_size!=data.size()-2) return std::unexpected(KeyShareError::invalid_length);
        std::vector<KeyShareEntry> result; std::size_t pos=2; std::bitset<65536> groups;
        while (pos<data.size()) {
            if (data.size()-pos<4) return std::unexpected(KeyShareError::truncated);
            auto group=u16(data,pos); auto size=static_cast<std::size_t>(u16(data,pos+2)); pos+=4;
            if (size==0) return std::unexpected(KeyShareError::empty);
            if (size>data.size()-pos) return std::unexpected(KeyShareError::truncated);
            if (groups.test(group)) return std::unexpected(KeyShareError::duplicate_group);
            groups.set(group);
            result.push_back({group,std::vector<std::uint8_t>(data.begin()+static_cast<std::ptrdiff_t>(pos),data.begin()+static_cast<std::ptrdiff_t>(pos+size))}); pos+=size;
        }
        return result;
    }
    auto KeyShare::parse_server(std::span<std::uint8_t const> data) -> std::expected<KeyShareEntry, KeyShareError> {
        if (data.size()<4) return std::unexpected(KeyShareError::truncated);
        auto size=static_cast<std::size_t>(u16(data,2)); if (size==0) return std::unexpected(KeyShareError::empty);
        if (size!=data.size()-4) return std::unexpected(KeyShareError::invalid_length);
        return KeyShareEntry{u16(data,0),std::vector<std::uint8_t>(data.begin()+4,data.end())};
    }
    auto KeyShare::parse_retry(std::span<std::uint8_t const> data) -> std::expected<std::uint16_t, KeyShareError> {
        if (data.size()!=2) return std::unexpected(data.size()<2 ? KeyShareError::truncated : KeyShareError::invalid_length); return u16(data,0);
    }
    auto KeyShare::encode_client(std::span<KeyShareEntry const> entries, std::size_t max_size)
        -> std::expected<std::vector<std::uint8_t>, KeyShareError> {
        if (max_size < 2) return std::unexpected(KeyShareError::message_too_large);
        std::vector<std::uint8_t> list; std::bitset<65536> groups;
        for (auto const& entry: entries) {
            if (!valid_entry_size(entry)) return std::unexpected(KeyShareError::empty);
            if (groups.test(entry.group)) return std::unexpected(KeyShareError::duplicate_group);
            groups.set(entry.group);
            if (entry.key_exchange.size()>0xffff-4 || list.size()>0xffff-4-entry.key_exchange.size()) return std::unexpected(KeyShareError::message_too_large);
            if (!add_u16(list,entry.group) || !add_u16(list,entry.key_exchange.size())) return std::unexpected(KeyShareError::message_too_large);
            list.insert(list.end(),entry.key_exchange.begin(),entry.key_exchange.end());
        }
        if (list.size()>max_size-2 || list.size()>0xffff-2) return std::unexpected(KeyShareError::message_too_large);
        std::vector<std::uint8_t> result; result.reserve(list.size()+2); add_u16(result,list.size()); result.insert(result.end(),list.begin(),list.end()); return result;
    }
    auto KeyShare::encode_server(KeyShareEntry const& entry) -> std::expected<std::vector<std::uint8_t>, KeyShareError> {
        if (!valid_entry_size(entry)) return std::unexpected(KeyShareError::empty);
        if (entry.key_exchange.size()>0xffff-4) return std::unexpected(KeyShareError::message_too_large);
        std::vector<std::uint8_t> result; result.reserve(entry.key_exchange.size()+4); add_u16(result,entry.group); add_u16(result,entry.key_exchange.size()); result.insert(result.end(),entry.key_exchange.begin(),entry.key_exchange.end()); return result;
    }
    auto KeyShare::encode_retry(std::uint16_t group) -> std::vector<std::uint8_t> { return {static_cast<std::uint8_t>(group>>8),static_cast<std::uint8_t>(group)}; }
}
