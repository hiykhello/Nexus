export module tls.server_hello;
export import tls.hello;
export import tls.key_share;
import crypto.ecdh;
import std;

export namespace tls {
    enum class ServerHelloError { truncated, invalid_length, invalid_version, invalid_session_id, invalid_compression,
        duplicate_extension, invalid_extension, unsupported, retry, session_mismatch, cipher_mismatch, group_mismatch };
    struct ServerHello {
        std::uint16_t legacy_version = 0x0303;
        std::array<std::uint8_t,32> random{};
        std::vector<std::uint8_t> session_id_echo;
        std::uint16_t cipher_suite = 0;
        std::uint8_t compression_method = 0;
        std::vector<Extension> extensions;
        auto operator==(ServerHello const&) const -> bool = default;
        [[nodiscard]] static auto parse(std::span<std::uint8_t const> body) -> std::expected<ServerHello,ServerHelloError>;
        [[nodiscard]] auto encode() const -> std::expected<std::vector<std::uint8_t>,ServerHelloError>;
        [[nodiscard]] auto is_retry() const noexcept -> bool;
        // Validates the supported non-PSK X25519 TLS 1.3 subset against the actual offer.
        // X25519 agreement must additionally reject low-order public keys.
        // Validate before sending ClientHello2. An empty result means a cookie-only retry.
        // The replacement must contain a fresh key for the requested group; omit it for cookie-only retries.
        // Validates the no-PSK retry subset, including ClientHello2 and the final ServerHello.
        template<bool AllowPsk=false>
        inline auto validate_nist(ClientHello const& client,std::uint16_t group) const -> std::expected<KeyShareEntry,ServerHelloError> {
            auto curve=crypto::nist_curve(group);if (!curve) return std::unexpected(ServerHelloError::unsupported);
            return validate_group<AllowPsk>(client,group,curve->public_size(),curve->public_size());
        }
        template<bool AllowPsk=false>
        inline auto validate_x25519(ClientHello const& client) const -> std::expected<KeyShareEntry,ServerHelloError> {return validate_group<AllowPsk>(client,29,32,32);}
        template<bool AllowPsk=false>
        inline auto validate_x25519_mlkem768(ClientHello const& client) const -> std::expected<KeyShareEntry,ServerHelloError> {return validate_group<AllowPsk>(client,0x11ec,1216,1120);}
        template<bool AllowPsk=false,bool AllowEarly=false>
        inline auto validate_retry_request(ClientHello const& first) const -> std::expected<std::optional<std::uint16_t>,ServerHelloError>{
        if (!is_retry()) return std::unexpected(ServerHelloError::retry);
        if (!first.validate_tls13() || !first.validate_encoding() || (!AllowPsk && first.extension(41)) || (!AllowEarly && first.extension(42))) return std::unexpected(ServerHelloError::unsupported);
        if (legacy_version!=0x0303 || compression_method!=0) return std::unexpected(ServerHelloError::invalid_version);
        if (session_id_echo!=first.session_id) return std::unexpected(ServerHelloError::session_mismatch);
        if (!std::ranges::contains(first.cipher_suites,cipher_suite) || (cipher_suite!=0x1301 && cipher_suite!=0x1302 && cipher_suite!=0x1303)) return std::unexpected(ServerHelloError::cipher_mismatch);
        Extension const* versions=nullptr; Extension const* share=nullptr; Extension const* cookie=nullptr; std::bitset<65536> seen;
        for (auto const& e:extensions) {
            if (seen.test(e.type)) return std::unexpected(ServerHelloError::duplicate_extension); seen.set(e.type);
            if (e.type==43) versions=&e; else if (e.type==51) share=&e; else if (e.type==44) cookie=&e;
            else if (!ech_retry_extension(first, e)) return std::unexpected(ServerHelloError::unsupported);
        }
        if (!tls13_version(versions) || !first.extension(43)) return std::unexpected(ServerHelloError::invalid_version);
        if ((!share && !cookie) || first.extension(44)) return std::unexpected(ServerHelloError::invalid_extension);
        if (cookie && (cookie->data.size()<3 || read16(cookie->data,0)!=cookie->data.size()-2)) return std::unexpected(ServerHelloError::invalid_extension);
        auto first_share=first.extension(51); if (!first_share) return std::unexpected(ServerHelloError::group_mismatch);
        auto offered=KeyShare::view_client(first_share->data); if (!offered) return std::unexpected(ServerHelloError::group_mismatch);
        if (!share) return std::optional<std::uint16_t>{};
        auto selected=KeyShare::parse_retry(share->data); auto groups=first.extension(10);
        if (!selected || !groups || groups->data.size()<4 || read16(groups->data,0)!=groups->data.size()-2 || (groups->data.size()-2)%2) return std::unexpected(ServerHelloError::group_mismatch);
        bool found=false; for (std::size_t i=2;i<groups->data.size();i+=2) if (read16(groups->data,i)==*selected) found=true;
        if (!found || contains_group(*offered,*selected)) return std::unexpected(ServerHelloError::group_mismatch);
        if (*selected!=0x001d && *selected!=0x11ec && !crypto::nist_curve(*selected)) return std::unexpected(ServerHelloError::unsupported);
        return std::optional<std::uint16_t>{*selected};
        }
        template<bool AllowPsk=false,bool AllowEarly=false>
        inline auto retry_client_hello(ClientHello const& first, std::optional<KeyShareEntry> replacement) const -> std::expected<ClientHello,ServerHelloError>{
        auto selected=validate_retry_request<AllowPsk,AllowEarly>(first); if (!selected) return std::unexpected(selected.error());
        if (selected->has_value()) {
            auto group=**selected;
            if (!replacement || replacement->group!=group || replacement->key_exchange.size()!=(group==0x001d ? 32u : group==0x11ec ? 1216u : crypto::nist_curve(group)->public_size())) return std::unexpected(ServerHelloError::group_mismatch);
        } else if (replacement) return std::unexpected(ServerHelloError::group_mismatch);
        auto second=first;
        if constexpr(AllowEarly) std::erase_if(second.extensions,[](auto const& extension) {return extension.type==42;});
        if (replacement) {
            auto encoded=KeyShare::encode_client(std::span{&*replacement,1}); if (!encoded) return std::unexpected(ServerHelloError::invalid_length);
            for (auto& e:second.extensions) if (e.type==51) e.data=std::move(*encoded);
        }
        auto cookie=std::ranges::find(extensions,std::uint16_t{44},&Extension::type);
        if (cookie!=extensions.end()) second.extensions.push_back(*cookie);
        if (!second.validate_encoding()) return std::unexpected(ServerHelloError::invalid_length);
        return second;
        }
        template<bool AllowPsk=false,bool AllowEarly=false>
        inline auto validate_retry(ClientHello const& first, ClientHello const& second, ServerHello const& final_hello) const -> std::expected<KeyShareEntry,ServerHelloError>{
        if (auto request=validate_retry_request<AllowPsk,AllowEarly>(first); !request) return std::unexpected(request.error());
        if (!is_retry() || final_hello.is_retry()) return std::unexpected(ServerHelloError::retry);
        if (!first.validate_tls13() || !second.validate_tls13() || (!AllowPsk && (first.extension(41) || second.extension(41))) || (!AllowEarly && first.extension(42)) || second.extension(42)) return std::unexpected(ServerHelloError::unsupported);
        if (legacy_version!=0x0303 || compression_method!=0) return std::unexpected(ServerHelloError::invalid_version);
        if (session_id_echo!=first.session_id || second.session_id!=first.session_id) return std::unexpected(ServerHelloError::session_mismatch);
        if (!std::ranges::contains(first.cipher_suites,cipher_suite) || (cipher_suite!=0x1301 && cipher_suite!=0x1302 && cipher_suite!=0x1303) || final_hello.cipher_suite!=cipher_suite) return std::unexpected(ServerHelloError::cipher_mismatch);
        if (first.legacy_version!=second.legacy_version || first.random!=second.random || first.cipher_suites!=second.cipher_suites || first.compression_methods!=second.compression_methods) return std::unexpected(ServerHelloError::invalid_extension);
        Extension const* versions=nullptr; Extension const* share=nullptr; Extension const* cookie=nullptr; std::bitset<65536> seen;
        for (auto const& e:extensions) {
            if (seen.test(e.type)) return std::unexpected(ServerHelloError::duplicate_extension); seen.set(e.type);
            if (e.type==43) versions=&e; else if (e.type==51) share=&e; else if (e.type==44) cookie=&e;
            else if (!ech_retry_extension(first, e)) return std::unexpected(ServerHelloError::unsupported);
        }
        if (!tls13_version(versions) || !first.extension(43)) return std::unexpected(ServerHelloError::invalid_version);
        if (!share && !cookie) return std::unexpected(ServerHelloError::invalid_extension);
        if (first.extension(44)) return std::unexpected(ServerHelloError::invalid_extension);
        auto second_cookie=second.extension(44);
        if (cookie) {
            if (cookie->data.size()<3 || read16(cookie->data,0)!=cookie->data.size()-2 || !second_cookie || second_cookie->data!=cookie->data) return std::unexpected(ServerHelloError::invalid_extension);
        } else if (second_cookie) return std::unexpected(ServerHelloError::invalid_extension);
        auto before=first.extensions | std::views::filter([](Extension const& e) { return e.type!=51 && e.type!=21 && (!AllowEarly || e.type!=42) && (!AllowPsk || e.type!=41); });
        auto after=second.extensions | std::views::filter([](Extension const& e) { return e.type!=51 && e.type!=21 && e.type!=44 && (!AllowPsk || e.type!=41); });
        if (!std::ranges::equal(before,after)) return std::unexpected(ServerHelloError::invalid_extension);
        auto first_share=first.extension(51), second_share=second.extension(51);
        if (!first_share || !second_share) return std::unexpected(ServerHelloError::group_mismatch);
        auto offered=KeyShare::view_client(first_share->data), replacement=KeyShare::view_client(second_share->data);
        if (!offered || !replacement) return std::unexpected(ServerHelloError::group_mismatch);
        std::uint16_t group=0;
        if (share) {
            auto selected=KeyShare::parse_retry(share->data); auto groups=first.extension(10);
            if (!selected || !groups || groups->data.size()<4 || read16(groups->data,0)!=groups->data.size()-2 || (groups->data.size()-2)%2) return std::unexpected(ServerHelloError::group_mismatch);
            bool found=false; for (std::size_t i=2;i<groups->data.size();i+=2) if (read16(groups->data,i)==*selected) found=true;
            std::size_t cursor=0; auto first_entry=replacement->next(cursor); auto second_entry=replacement->next(cursor);
            if (!found || contains_group(*offered,*selected) || !first_entry || second_entry || first_entry->group!=*selected) return std::unexpected(ServerHelloError::group_mismatch);
            group=*selected;
        } else {
            if (first_share->data!=second_share->data) return std::unexpected(ServerHelloError::group_mismatch);
            auto final_share=std::ranges::find(final_hello.extensions,std::uint16_t{51},&Extension::type);
            if (final_share==final_hello.extensions.end()) return std::unexpected(ServerHelloError::group_mismatch);
            auto selected=KeyShare::view_server(final_share->data); if (!selected) return std::unexpected(ServerHelloError::group_mismatch); group=selected->group;
        }
        if (group==0x001d) return final_hello.validate_x25519<AllowPsk>(second);
        if (group==0x11ec) return final_hello.validate_x25519_mlkem768<AllowPsk>(second);
        if (crypto::nist_curve(group)) return final_hello.validate_nist<AllowPsk>(second,group);
        return std::unexpected(ServerHelloError::unsupported);
        }
    private:
        static auto ech_retry_extension(ClientHello const& first, Extension const& extension) noexcept -> bool {
            constexpr std::uint16_t ech = 0xfe0d;
            if (extension.type != ech || extension.data.size() != 8) return false;
            auto marker = first.extension(ech);
            return marker && marker->data.size() == 1 && marker->data[0] == 1;
        }
        static inline auto read16(std::span<std::uint8_t const> b,std::size_t p) -> std::uint16_t {return static_cast<std::uint16_t>((std::uint16_t{b[p]}<<8)|b[p+1]);}
        static auto contains_group(ClientKeyShares const& shares,std::uint16_t group) noexcept -> bool {std::size_t cursor=0;while(auto entry=shares.next(cursor))if(entry->group==group)return true;return false;}
        static auto tls13_version(Extension const* versions) noexcept -> bool {return versions&&versions->data.size()==2&&versions->data[0]==3&&versions->data[1]==4;}
        template<bool AllowPsk=false>
        inline auto validate_group(ClientHello const& client, std::uint16_t group, std::size_t client_size, std::size_t server_size) const -> std::expected<KeyShareEntry,ServerHelloError>{
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
            if (e.type==43) versions=&e; else if (e.type==51) share=&e; else {
                if constexpr (AllowPsk) { if (e.type==41 && e.data.size()==2) continue; }
                return std::unexpected(ServerHelloError::unsupported);
            }
        }
        if (!tls13_version(versions)) return std::unexpected(ServerHelloError::invalid_version);
        if (!share) return std::unexpected(ServerHelloError::invalid_extension);
        auto groups=client.extension(10);
        if (!groups || groups->data.size()<4) return std::unexpected(ServerHelloError::group_mismatch);
        auto list_size=(std::size_t{groups->data[0]}<<8)|groups->data[1];
        if (list_size!=groups->data.size()-2 || list_size%2!=0) return std::unexpected(ServerHelloError::group_mismatch);
        bool supports_group=false;
        for (std::size_t i=2;i<groups->data.size();i+=2) if (((std::uint16_t{groups->data[i]}<<8)|groups->data[i+1])==group) supports_group=true;
        if (!supports_group) return std::unexpected(ServerHelloError::group_mismatch);
        auto peer=KeyShare::view_server(share->data); auto offer=KeyShare::view_client(client.extension(51)->data);
        if (!peer || !offer || peer->group!=group || peer->key_exchange.size()!=server_size) return std::unexpected(ServerHelloError::group_mismatch);
        std::size_t cursor=0; std::optional<KeyShareView> found;
        while (auto entry=offer->next(cursor)) if (entry->group==peer->group) { found=*entry; break; }
        if (!found || found->key_exchange.size()!=client_size) return std::unexpected(ServerHelloError::group_mismatch);
        return KeyShareEntry{peer->group,{peer->key_exchange.begin(),peer->key_exchange.end()}};
        }
    };
}
