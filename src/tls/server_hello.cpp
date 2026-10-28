module nexus.tls.server_hello;
import std;

namespace nexus::tls {
    namespace {
        constexpr std::array<std::uint8_t,32> retry_random{0xcf,0x21,0xad,0x74,0xe5,0x9a,0x61,0x11,0xbe,0x1d,0x8c,0x02,0x1e,0x65,0xb8,0x91,0xc2,0xa2,0x11,0x16,0x7a,0xbb,0x8c,0x5e,0x07,0x9e,0x09,0xe2,0xc8,0xa8,0x33,0x9c};
        auto get16(std::span<std::uint8_t const> b, std::size_t p) -> std::uint16_t { return static_cast<std::uint16_t>((std::uint16_t{b[p]}<<8)|b[p+1]); }
        auto put16(std::vector<std::uint8_t>& b, std::size_t n) -> void { b.push_back(static_cast<std::uint8_t>(n>>8)); b.push_back(static_cast<std::uint8_t>(n)); }
    }
    auto ServerHello::parse(std::span<std::uint8_t const> body) -> std::expected<ServerHello,ServerHelloError> {
        if (body.size()<35) return std::unexpected(ServerHelloError::truncated);
        ServerHello out; out.legacy_version=get16(body,0); std::ranges::copy(body.subspan(2,32),out.random.begin());
        auto sid=std::size_t{body[34]}; if (sid>32) return std::unexpected(ServerHelloError::invalid_session_id);
        auto pos=std::size_t{35}; if (body.size()-pos<sid+5) return std::unexpected(ServerHelloError::truncated);
        out.session_id_echo.assign(body.begin()+static_cast<std::ptrdiff_t>(pos),body.begin()+static_cast<std::ptrdiff_t>(pos+sid)); pos+=sid;
        out.cipher_suite=get16(body,pos); pos+=2; out.compression_method=body[pos++]; auto size=std::size_t{get16(body,pos)}; pos+=2;
        if (size!=body.size()-pos) return std::unexpected(ServerHelloError::invalid_length);
        std::bitset<65536> seen;
        while (pos<body.size()) {
            if (body.size()-pos<4) return std::unexpected(ServerHelloError::invalid_extension);
            auto type=get16(body,pos); auto length=std::size_t{get16(body,pos+2)}; pos+=4;
            if (length>body.size()-pos) return std::unexpected(ServerHelloError::invalid_extension);
            if (seen.test(type)) return std::unexpected(ServerHelloError::duplicate_extension); seen.set(type);
            out.extensions.push_back({type,{body.begin()+static_cast<std::ptrdiff_t>(pos),body.begin()+static_cast<std::ptrdiff_t>(pos+length)}}); pos+=length;
        }
        return out;
    }
    auto ServerHello::encode() const -> std::expected<std::vector<std::uint8_t>,ServerHelloError> {
        if (session_id_echo.size()>32) return std::unexpected(ServerHelloError::invalid_session_id);
        std::vector<std::uint8_t> ext; std::bitset<65536> seen;
        for (auto const& e:extensions) {
            if (seen.test(e.type)) return std::unexpected(ServerHelloError::duplicate_extension); seen.set(e.type);
            if (e.data.size()>65531 || ext.size()>65531-e.data.size()) return std::unexpected(ServerHelloError::invalid_length);
            put16(ext,e.type); put16(ext,e.data.size()); ext.insert(ext.end(),e.data.begin(),e.data.end());
        }
        std::vector<std::uint8_t> out; put16(out,legacy_version); out.insert(out.end(),random.begin(),random.end()); out.push_back(static_cast<std::uint8_t>(session_id_echo.size()));
        out.insert(out.end(),session_id_echo.begin(),session_id_echo.end()); put16(out,cipher_suite); out.push_back(compression_method); put16(out,ext.size()); out.insert(out.end(),ext.begin(),ext.end()); return out;
    }
    auto ServerHello::is_retry() const noexcept -> bool { return random==retry_random; }
    auto ServerHello::validate_x25519(ClientHello const& client) const -> std::expected<KeyShareEntry,ServerHelloError> {
        return validate_group(client,0x001d,32,32);
    }
    auto ServerHello::validate_x25519_mlkem768(ClientHello const& client) const -> std::expected<KeyShareEntry,ServerHelloError> {
        return validate_group(client,0x11ec,1216,1120);
    }
    auto ServerHello::validate_retry_request(ClientHello const& first) const -> std::expected<std::optional<std::uint16_t>,ServerHelloError> {
        if (!is_retry()) return std::unexpected(ServerHelloError::retry);
        if (!first.validate_tls13() || !first.validate_encoding() || first.extension(41) || first.extension(42)) return std::unexpected(ServerHelloError::unsupported);
        if (legacy_version!=0x0303 || compression_method!=0) return std::unexpected(ServerHelloError::invalid_version);
        if (session_id_echo!=first.session_id) return std::unexpected(ServerHelloError::session_mismatch);
        if (!std::ranges::contains(first.cipher_suites,cipher_suite) || (cipher_suite!=0x1301 && cipher_suite!=0x1302 && cipher_suite!=0x1303)) return std::unexpected(ServerHelloError::cipher_mismatch);
        Extension const* versions=nullptr; Extension const* share=nullptr; Extension const* cookie=nullptr; std::bitset<65536> seen;
        for (auto const& e:extensions) {
            if (seen.test(e.type)) return std::unexpected(ServerHelloError::duplicate_extension); seen.set(e.type);
            if (e.type==43) versions=&e; else if (e.type==51) share=&e; else if (e.type==44) cookie=&e; else return std::unexpected(ServerHelloError::unsupported);
        }
        if (!versions || versions->data!=std::vector<std::uint8_t>{3,4} || !first.extension(43)) return std::unexpected(ServerHelloError::invalid_version);
        if ((!share && !cookie) || first.extension(44)) return std::unexpected(ServerHelloError::invalid_extension);
        if (cookie && (cookie->data.size()<3 || get16(cookie->data,0)!=cookie->data.size()-2)) return std::unexpected(ServerHelloError::invalid_extension);
        auto first_share=first.extension(51); if (!first_share) return std::unexpected(ServerHelloError::group_mismatch);
        auto offered=KeyShare::parse_client(first_share->data); if (!offered) return std::unexpected(ServerHelloError::group_mismatch);
        if (!share) return std::optional<std::uint16_t>{};
        auto selected=KeyShare::parse_retry(share->data); auto groups=first.extension(10);
        if (!selected || !groups || groups->data.size()<4 || get16(groups->data,0)!=groups->data.size()-2 || (groups->data.size()-2)%2) return std::unexpected(ServerHelloError::group_mismatch);
        bool found=false; for (std::size_t i=2;i<groups->data.size();i+=2) if (get16(groups->data,i)==*selected) found=true;
        if (!found || std::ranges::find(*offered,*selected,&KeyShareEntry::group)!=offered->end()) return std::unexpected(ServerHelloError::group_mismatch);
        if (*selected!=0x001d && *selected!=0x11ec) return std::unexpected(ServerHelloError::unsupported);
        return std::optional<std::uint16_t>{*selected};
    }
    auto ServerHello::retry_client_hello(ClientHello const& first, std::optional<KeyShareEntry> replacement) const -> std::expected<ClientHello,ServerHelloError> {
        auto selected=validate_retry_request(first); if (!selected) return std::unexpected(selected.error());
        if (selected->has_value()) {
            auto group=**selected;
            if (!replacement || replacement->group!=group || replacement->key_exchange.size()!=(group==0x001d ? 32u : 1216u)) return std::unexpected(ServerHelloError::group_mismatch);
        } else if (replacement) return std::unexpected(ServerHelloError::group_mismatch);
        auto second=first;
        if (replacement) {
            auto encoded=KeyShare::encode_client(std::span{&*replacement,1}); if (!encoded) return std::unexpected(ServerHelloError::invalid_length);
            for (auto& e:second.extensions) if (e.type==51) e.data=std::move(*encoded);
        }
        auto cookie=std::ranges::find(extensions,std::uint16_t{44},&Extension::type);
        if (cookie!=extensions.end()) second.extensions.push_back(*cookie);
        if (!second.validate_encoding()) return std::unexpected(ServerHelloError::invalid_length);
        return second;
    }
    auto ServerHello::validate_retry(ClientHello const& first, ClientHello const& second, ServerHello const& final_hello) const -> std::expected<KeyShareEntry,ServerHelloError> {
        if (auto request=validate_retry_request(first); !request) return std::unexpected(request.error());
        if (!is_retry() || final_hello.is_retry()) return std::unexpected(ServerHelloError::retry);
        if (!first.validate_tls13() || !second.validate_tls13() || first.extension(41) || second.extension(41) || first.extension(42) || second.extension(42)) return std::unexpected(ServerHelloError::unsupported);
        if (legacy_version!=0x0303 || compression_method!=0) return std::unexpected(ServerHelloError::invalid_version);
        if (session_id_echo!=first.session_id || second.session_id!=first.session_id) return std::unexpected(ServerHelloError::session_mismatch);
        if (!std::ranges::contains(first.cipher_suites,cipher_suite) || (cipher_suite!=0x1301 && cipher_suite!=0x1302 && cipher_suite!=0x1303) || final_hello.cipher_suite!=cipher_suite) return std::unexpected(ServerHelloError::cipher_mismatch);
        if (first.legacy_version!=second.legacy_version || first.random!=second.random || first.cipher_suites!=second.cipher_suites || first.compression_methods!=second.compression_methods) return std::unexpected(ServerHelloError::invalid_extension);
        Extension const* versions=nullptr; Extension const* share=nullptr; Extension const* cookie=nullptr; std::bitset<65536> seen;
        for (auto const& e:extensions) {
            if (seen.test(e.type)) return std::unexpected(ServerHelloError::duplicate_extension); seen.set(e.type);
            if (e.type==43) versions=&e; else if (e.type==51) share=&e; else if (e.type==44) cookie=&e; else return std::unexpected(ServerHelloError::unsupported);
        }
        if (!versions || versions->data!=std::vector<std::uint8_t>{3,4} || !first.extension(43)) return std::unexpected(ServerHelloError::invalid_version);
        if (!share && !cookie) return std::unexpected(ServerHelloError::invalid_extension);
        if (first.extension(44)) return std::unexpected(ServerHelloError::invalid_extension);
        auto second_cookie=second.extension(44);
        if (cookie) {
            if (cookie->data.size()<3 || get16(cookie->data,0)!=cookie->data.size()-2 || !second_cookie || second_cookie->data!=cookie->data) return std::unexpected(ServerHelloError::invalid_extension);
        } else if (second_cookie) return std::unexpected(ServerHelloError::invalid_extension);
        auto before=first.extensions | std::views::filter([](Extension const& e) { return e.type!=51 && e.type!=21; });
        auto after=second.extensions | std::views::filter([](Extension const& e) { return e.type!=51 && e.type!=21 && e.type!=44; });
        if (!std::ranges::equal(before,after)) return std::unexpected(ServerHelloError::invalid_extension);
        auto first_share=first.extension(51), second_share=second.extension(51);
        if (!first_share || !second_share) return std::unexpected(ServerHelloError::group_mismatch);
        auto offered=KeyShare::parse_client(first_share->data), replacement=KeyShare::parse_client(second_share->data);
        if (!offered || !replacement) return std::unexpected(ServerHelloError::group_mismatch);
        std::uint16_t group=0;
        if (share) {
            auto selected=KeyShare::parse_retry(share->data); auto groups=first.extension(10);
            if (!selected || !groups || groups->data.size()<4 || get16(groups->data,0)!=groups->data.size()-2 || (groups->data.size()-2)%2) return std::unexpected(ServerHelloError::group_mismatch);
            bool found=false; for (std::size_t i=2;i<groups->data.size();i+=2) if (get16(groups->data,i)==*selected) found=true;
            if (!found || std::ranges::find(*offered,*selected,&KeyShareEntry::group)!=offered->end() || replacement->size()!=1 || (*replacement)[0].group!=*selected) return std::unexpected(ServerHelloError::group_mismatch);
            group=*selected;
        } else {
            if (first_share->data!=second_share->data) return std::unexpected(ServerHelloError::group_mismatch);
            auto final_share=std::ranges::find(final_hello.extensions,std::uint16_t{51},&Extension::type);
            if (final_share==final_hello.extensions.end()) return std::unexpected(ServerHelloError::group_mismatch);
            auto selected=KeyShare::parse_server(final_share->data); if (!selected) return std::unexpected(ServerHelloError::group_mismatch); group=selected->group;
        }
        if (group==0x001d) return final_hello.validate_x25519(second);
        if (group==0x11ec) return final_hello.validate_x25519_mlkem768(second);
        return std::unexpected(ServerHelloError::unsupported);
    }
    auto ServerHello::validate_group(ClientHello const& client, std::uint16_t group, std::size_t client_size, std::size_t server_size) const -> std::expected<KeyShareEntry,ServerHelloError> {
        if (is_retry()) return std::unexpected(ServerHelloError::retry);
        if (legacy_version!=0x0303) return std::unexpected(ServerHelloError::invalid_version);
        if (compression_method!=0) return std::unexpected(ServerHelloError::invalid_compression);
        if (session_id_echo!=client.session_id) return std::unexpected(ServerHelloError::session_mismatch);
        if (!client.validate_tls13()) return std::unexpected(ServerHelloError::unsupported);
        if (!std::ranges::contains(client.cipher_suites,cipher_suite) || (cipher_suite!=0x1301 && cipher_suite!=0x1302 && cipher_suite!=0x1303)) return std::unexpected(ServerHelloError::cipher_mismatch);
        Extension const* versions=nullptr; Extension const* share=nullptr; std::bitset<65536> seen;
        for (auto const& e:extensions) {
            if (seen.test(e.type)) return std::unexpected(ServerHelloError::duplicate_extension); seen.set(e.type);
            if (!client.extension(e.type)) return std::unexpected(ServerHelloError::invalid_extension);
            if (e.type==43) versions=&e; else if (e.type==51) share=&e; else return std::unexpected(ServerHelloError::unsupported);
        }
        if (!versions || versions->data!=std::vector<std::uint8_t>{3,4}) return std::unexpected(ServerHelloError::invalid_version);
        if (!share) return std::unexpected(ServerHelloError::invalid_extension);
        auto groups=client.extension(10);
        if (!groups || groups->data.size()<4) return std::unexpected(ServerHelloError::group_mismatch);
        auto list_size=(std::size_t{groups->data[0]}<<8)|groups->data[1];
        if (list_size!=groups->data.size()-2 || list_size%2!=0) return std::unexpected(ServerHelloError::group_mismatch);
        bool supports_group=false;
        for (std::size_t i=2;i<groups->data.size();i+=2) if (((std::uint16_t{groups->data[i]}<<8)|groups->data[i+1])==group) supports_group=true;
        if (!supports_group) return std::unexpected(ServerHelloError::group_mismatch);
        auto peer=KeyShare::parse_server(share->data); auto offer=KeyShare::parse_client(client.extension(51)->data);
        if (!peer || !offer || peer->group!=group || peer->key_exchange.size()!=server_size) return std::unexpected(ServerHelloError::group_mismatch);
        auto found=std::ranges::find(*offer,peer->group,&KeyShareEntry::group);
        if (found==offer->end() || found->key_exchange.size()!=client_size) return std::unexpected(ServerHelloError::group_mismatch);
        return std::move(*peer);
    }
}
