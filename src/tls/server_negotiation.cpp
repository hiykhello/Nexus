module nexus.tls.server_negotiation;
import nexus.tls.key_share;
import std;
namespace nexus::tls {
    namespace {
        auto vector16(Extension const* extension) -> std::expected<std::span<std::uint8_t const>,ServerNegotiationError> {
            if (!extension) return std::unexpected(ServerNegotiationError::missing_extension);
            auto const& data=extension->data;
            if (data.size()<4 || ((data.size()-2)&1) || ((std::size_t{data[0]}<<8)|data[1])!=data.size()-2)
                return std::unexpected(ServerNegotiationError::malformed_extension);
            return std::span{data}.subspan(2);
        }
        auto get16(std::span<std::uint8_t const> data,std::size_t pos) noexcept -> std::uint16_t { return static_cast<std::uint16_t>((data[pos]<<8)|data[pos+1]); }
        auto contains(std::span<std::uint8_t const> data,std::uint16_t value) noexcept -> bool {
            for (std::size_t pos=0;pos<data.size();pos+=2) if (get16(data,pos)==value) return true;
            return false;
        }
    }
    auto negotiate_server(ClientHello const& hello, std::span<std::uint16_t const> certificate_schemes)
        -> std::expected<ServerSelection,ServerNegotiationError> {
        if (!hello.validate_tls13() || !hello.validate_encoding()) return std::unexpected(ServerNegotiationError::invalid_hello);
        if (hello.extension(41) || hello.extension(42)) return std::unexpected(ServerNegotiationError::unsupported_psk);
        constexpr std::array<std::uint16_t,3> ciphers{0x1301,0x1303,0x1302};
        auto cipher=std::ranges::find_if(ciphers,[&](auto x) { return std::ranges::contains(hello.cipher_suites,x); });
        if (cipher==ciphers.end()) return std::unexpected(ServerNegotiationError::no_cipher);
        auto groups=vector16(hello.extension(10)); if (!groups) return std::unexpected(groups.error());
        auto signatures=vector16(hello.extension(13)); if (!signatures) return std::unexpected(signatures.error());
        auto share_ext=hello.extension(51); if (!share_ext) return std::unexpected(ServerNegotiationError::missing_extension);
        auto shares=KeyShare::view_client(share_ext->data);
        if (!shares) return std::unexpected(ServerNegotiationError::invalid_key_share);
        // Client shares must be a subset of supported_groups in the same relative order.
        std::size_t position=0,cursor=0;
        std::optional<KeyShareView> x,hybrid;
        while (auto share=shares->next(cursor)) {
            while (position<groups->size() && get16(*groups,position)!=share->group) position+=2;
            if (position==groups->size()) return std::unexpected(ServerNegotiationError::invalid_key_share);
            position+=2;
            if (share->group==0x001d) x=*share;
            if (share->group==0x11ec) hybrid=*share;
        }
        bool supports_x=contains(*groups,0x001d);
        bool supports_hybrid=contains(*groups,0x11ec);
        if (!supports_x && !supports_hybrid) return std::unexpected(ServerNegotiationError::no_group);
        constexpr std::array<std::uint16_t,3> supported{0x0807,0x0403,0x0804};
        auto signature=std::ranges::find_if(certificate_schemes,[&](auto x) {
            return std::ranges::contains(supported,x) && contains(*signatures,x);
        });
        if (signature==certificate_schemes.end()) return std::unexpected(ServerNegotiationError::no_signature);
        if ((x && x->key_exchange.size()!=32) || (hybrid && hybrid->key_exchange.size()!=1216))
            return std::unexpected(ServerNegotiationError::invalid_key_share);
        auto group=hybrid ? std::uint16_t{0x11ec} : x ? std::uint16_t{0x001d} :
            supports_hybrid ? std::uint16_t{0x11ec} : std::uint16_t{0x001d};
        ServerSelection result{*cipher,*signature,group,{},{}};
        if (group==0x001d && x) {
            std::array<std::uint8_t,32> value{}; std::ranges::copy(x->key_exchange,value.begin()); result.x25519_share=value;
        } else if (group==0x11ec && hybrid) {
            std::array<std::uint8_t,1216> value{}; std::ranges::copy(hybrid->key_exchange,value.begin()); result.hybrid_share=value;
        }
        return result;
    }
}
