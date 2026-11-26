module tls.encrypted_extensions;
import tls.handshake_policy;
import std;

namespace tls {
    namespace {
        auto u16(std::span<std::uint8_t const> s, std::size_t p) -> std::uint16_t { return static_cast<std::uint16_t>((std::uint16_t{s[p]}<<8)|s[p+1]); }
        auto alpn_list(std::span<std::uint8_t const> data) -> std::optional<std::vector<std::vector<std::uint8_t>>> {
            if (data.size()<3 || u16(data,0)!=data.size()-2) return {};
            std::vector<std::vector<std::uint8_t>> out;
            for (std::size_t p=2;p<data.size();) {
                auto n=data[p++]; if (!n || n>data.size()-p) return {};
                out.emplace_back(data.begin()+static_cast<std::ptrdiff_t>(p),data.begin()+static_cast<std::ptrdiff_t>(p+n)); p+=n;
            }
            if (out.empty()) return {}; return out;
        }
    }
    auto detail::validate_extensions(ClientHello const& client,std::span<std::uint8_t const> m,bool quic,std::span<std::uint8_t const>* parameters,bool* early)
        -> std::expected<EncryptedExtensions,EncryptedExtensionsError> {
        using E=EncryptedExtensionsError;
        if (m.size()<6 || m.size()>65541 || m[0]!=8 || ((std::size_t{m[1]}<<16)|(std::size_t{m[2]}<<8)|m[3])!=m.size()-4 || u16(m,4)!=m.size()-6)
            return std::unexpected(E::malformed);
        std::bitset<65536> client_seen;
        for (auto const& e:client.extensions) { if (client_seen.test(e.type)) return std::unexpected(E::duplicate); client_seen.set(e.type); }
        EncryptedExtensions result; std::bitset<65536> seen;
        for (std::size_t p=6;p<m.size();) {
            if (m.size()-p<4) return std::unexpected(E::malformed);
            auto type=u16(m,p); auto len=std::size_t{u16(m,p+2)}; p+=4;
            if (len>m.size()-p) return std::unexpected(E::malformed);
            if (seen.test(type)) return std::unexpected(E::duplicate); seen.set(type);
            auto data=m.subspan(p,len); p+=len;
            auto offered=client.extension(type);
            if (!offered) return std::unexpected(E::unoffered);
            switch (type) {
                case 0:
                    if (!data.empty()) return std::unexpected(E::malformed);
                    result.server_name_acknowledged=true; break;
                case 16: {
                    auto chosen=alpn_list(data), offers=alpn_list(offered->data);
                    if (!chosen || !offers || chosen->size()!=1) return std::unexpected(E::malformed);
                    if (!std::ranges::contains(*offers,(*chosen)[0])) return std::unexpected(E::invalid_selection);
                    result.alpn=std::move((*chosen)[0]); break;
                }
                case 10:
                    if (data.size()<4 || u16(data,0)!=data.size()-2 || (data.size()-2)%2) return std::unexpected(E::malformed);
                    for (std::size_t j=2;j<data.size();j+=2) result.peer_groups.push_back(u16(data,j));
                    break;
                case 42:
                    if (!early) return std::unexpected(E::unsupported);
                    if (!data.empty()) return std::unexpected(E::malformed);
                    *early=true; break;
                case 0x39:
                    if (!quic) return std::unexpected(E::unsupported);
                    *parameters=data; break;
                case 0x44cd:
                case 0x4469:
                    if (quic || result.application_settings_code) return std::unexpected(E::invalid_selection);
                    result.application_settings_code=type;
                    result.application_settings.assign(data.begin(),data.end());
                    break;
                case 0xfe0d:
                    // Outer ECH / GREASE offer may receive retry configs (ECHConfigList).
                    if (offered->data.size()<42 || offered->data[0]!=0 || data.size()<2 ||
                        u16(data,0)!=data.size()-2) return std::unexpected(E::malformed);
                    result.ech_retry_configs.assign(data.begin(),data.end());
                    break;
                case 28:
                    if (quic) return std::unexpected(E::unsupported);
                    if (data.size()!=2 || offered->data.size()!=2 || u16(offered->data,0)<64 || u16(offered->data,0)>16385)
                        return std::unexpected(E::malformed);
                    if (u16(data,0)<64 || u16(data,0)>16385) return std::unexpected(E::invalid_record_limit);
                    result.peer_record_size_limit=u16(data,0); break;
                default: return std::unexpected(E::unsupported);
            }
        }
        if (result.application_settings_code) {
            auto protocols=alpn_list(client.extension(*result.application_settings_code)->data);
            if (!protocols || !result.alpn || !std::ranges::contains(*protocols,*result.alpn))
                return std::unexpected(E::invalid_selection);
            // HTTP/2 settings are a sequence of 16-bit identifiers and 32-bit values.
            if (result.application_settings.size()%6) return std::unexpected(E::malformed);
        }
        if (quic && !seen.test(0x39)) return std::unexpected(E::missing_required);
        return result;
    }
    auto validate_encrypted_extensions(ClientHello const& client,std::span<std::uint8_t const> message) -> std::expected<EncryptedExtensions,EncryptedExtensionsError> {
        return detail::validate_extensions(client,message,false,nullptr);
    }


}
