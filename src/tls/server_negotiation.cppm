export module tls.server_negotiation;
export import tls.hello;
export import crypto.ecdh;
export import tls.handshake_policy;
import tls.key_share;
import tls.signature;
import std;
export namespace tls {
    enum class ServerNegotiationError { invalid_hello, unsupported_psk, missing_extension, malformed_extension,
        no_cipher, no_group, no_signature, invalid_key_share,unsupported_transport_parameters };
    enum class PeerSignaturePolicy { require_offered, authenticated_ed25519 };
    struct ServerSelection {
        std::uint16_t cipher_suite;
        std::uint16_t signature_scheme;
        std::uint16_t group;
        // An absent share for the selected group means a retry is required.
        std::optional<std::array<std::uint8_t,32>> x25519_share;
        std::optional<std::array<std::uint8_t,1216>> hybrid_share;
        std::optional<crypto::EcPublic> ec_share;
    };
    namespace detail {
        inline auto server_vector16(Extension const* extension) -> std::expected<std::span<std::uint8_t const>,ServerNegotiationError> {
            if (!extension) return std::unexpected(ServerNegotiationError::missing_extension);
            auto const& data=extension->data;
            if (data.size()<4 || ((data.size()-2)&1) || ((std::size_t{data[0]}<<8)|data[1])!=data.size()-2)
                return std::unexpected(ServerNegotiationError::malformed_extension);
            return std::span{data}.subspan(2);
        }
        inline auto server_get16(std::span<std::uint8_t const> data,std::size_t pos) noexcept -> std::uint16_t { return static_cast<std::uint16_t>((data[pos]<<8)|data[pos+1]); }
        inline auto server_contains(std::span<std::uint8_t const> data,std::uint16_t value) noexcept -> bool {
            for (std::size_t pos=0;pos<data.size();pos+=2) if (server_get16(data,pos)==value) return true;
            return false;
        }
    }
    template<bool AllowPsk=false>
    inline auto negotiate_server(ClientHello const& hello, std::span<std::uint16_t const> certificate_schemes, PeerSignaturePolicy policy,std::span<std::uint16_t const> permitted_ciphers,HandshakeTransport transport)
        -> std::expected<ServerSelection,ServerNegotiationError>{
        if (!hello.validate_tls13() || !hello.validate_encoding()) return std::unexpected(ServerNegotiationError::invalid_hello);
        if (!validate_handshake_transport(hello,transport)) return std::unexpected(ServerNegotiationError::unsupported_transport_parameters);
        if ((!AllowPsk && hello.extension(41)) || hello.extension(42)) return std::unexpected(ServerNegotiationError::unsupported_psk);
        constexpr std::array<std::uint16_t,3> ciphers{0x1301,0x1303,0x1302};
        auto cipher=std::ranges::find_if(ciphers,[&](auto x) { return std::ranges::contains(hello.cipher_suites,x) && (permitted_ciphers.empty() || std::ranges::contains(permitted_ciphers,x)); });
        if (cipher==ciphers.end()) return std::unexpected(ServerNegotiationError::no_cipher);
        auto groups=detail::server_vector16(hello.extension(10)); if (!groups) return std::unexpected(groups.error());
        auto signatures=detail::server_vector16(hello.extension(13));
        if (!signatures) {
            if constexpr(AllowPsk) {if (hello.extension(13))return std::unexpected(signatures.error());}
            else return std::unexpected(signatures.error());
        }
        auto share_ext=hello.extension(51); if (!share_ext) return std::unexpected(ServerNegotiationError::missing_extension);
        auto shares=KeyShare::view_client(share_ext->data);
        if (!shares) return std::unexpected(ServerNegotiationError::invalid_key_share);
        // Client shares must be a subset of supported_groups in the same relative order.
        std::size_t position=0,cursor=0;
        std::optional<KeyShareView> x,hybrid,ec;
        while (auto share=shares->next(cursor)) {
            while (position<groups->size() && detail::server_get16(*groups,position)!=share->group) position+=2;
            if (position==groups->size()) return std::unexpected(ServerNegotiationError::invalid_key_share);
            position+=2;
            if (share->group==0x001d) x=*share;
            if (share->group==0x11ec) hybrid=*share;
            if (auto curve=crypto::nist_curve(share->group)) {
                if (share->key_exchange.size()!=curve->public_size()) return std::unexpected(ServerNegotiationError::invalid_key_share);
                if (!ec) ec=*share;
            }
        }
        bool supports_x=detail::server_contains(*groups,0x001d);
        bool supports_hybrid=detail::server_contains(*groups,0x11ec);
        std::uint16_t ec_group=0;
        for (auto group:{23,24,25}) if (!ec_group && detail::server_contains(*groups,group)) ec_group=static_cast<std::uint16_t>(group);
        if (!supports_x && !supports_hybrid && !ec_group) return std::unexpected(ServerNegotiationError::no_group);
        auto signature=std::ranges::find_if(certificate_schemes,[&](auto x) {
            if constexpr(AllowPsk) {return signatures && signature_parameters(x).has_value() && detail::server_contains(*signatures,x);}
            else return signature_parameters(x).has_value() && detail::server_contains(*signatures,x);
        });
        if (signature==certificate_schemes.end() && policy==PeerSignaturePolicy::authenticated_ed25519 && std::ranges::contains(certificate_schemes,std::uint16_t{0x0807})) signature=std::ranges::find(certificate_schemes,std::uint16_t{0x0807});
        if (signature==certificate_schemes.end()) {
            if constexpr(AllowPsk) {if (signatures)return std::unexpected(ServerNegotiationError::no_signature);}
            else return std::unexpected(ServerNegotiationError::no_signature);
        }
        if ((x && x->key_exchange.size()!=32) || (hybrid && hybrid->key_exchange.size()!=1216))
            return std::unexpected(ServerNegotiationError::invalid_key_share);
        auto group=hybrid ? std::uint16_t{0x11ec} : x ? std::uint16_t{0x001d} : ec ? ec->group :
            supports_hybrid ? std::uint16_t{0x11ec} : supports_x ? std::uint16_t{0x001d} : ec_group;
        ServerSelection result{*cipher,signature==certificate_schemes.end() ? std::uint16_t{0} : *signature,group,{},{},{}};
        if (group==0x001d && x) {
            std::array<std::uint8_t,32> value{}; std::ranges::copy(x->key_exchange,value.begin()); result.x25519_share=value;
        } else if (group==0x11ec && hybrid) {
            std::array<std::uint8_t,1216> value{}; std::ranges::copy(hybrid->key_exchange,value.begin()); result.hybrid_share=value;
        } else if (ec && group==ec->group) {
            crypto::EcPublic value; value.size=static_cast<std::uint8_t>(ec->key_exchange.size());
            std::ranges::copy(ec->key_exchange,value.bytes.begin()); result.ec_share=value;
        }
        return result;
        }
    // Schemes must correspond to the configured certificate and private key, validated by the caller.
    // The returned peer share still requires key agreement and public-key validation.
    // The authenticated-identity policy is opt-in and requires the caller to
    // have authenticated this ClientHello before allowing unoffered Ed25519.
    // PSK and early data are not implemented here.


    [[nodiscard]] auto negotiate_server(ClientHello const& hello, std::span<std::uint16_t const> certificate_schemes,
        PeerSignaturePolicy policy = PeerSignaturePolicy::require_offered)
        -> std::expected<ServerSelection,ServerNegotiationError>;
    [[nodiscard]] auto negotiate_server(ClientHello const& hello,std::span<std::uint16_t const> certificate_schemes,
        PeerSignaturePolicy policy,std::span<std::uint16_t const> permitted_ciphers) -> std::expected<ServerSelection,ServerNegotiationError>;
}
