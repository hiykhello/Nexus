module tls.server_negotiation;
import tls.key_share;
import tls.signature;
import std;
namespace tls {

    auto negotiate_server(ClientHello const& hello,std::span<std::uint16_t const> schemes,PeerSignaturePolicy policy)
        -> std::expected<ServerSelection,ServerNegotiationError> { return negotiate_server(hello,schemes,policy,{}); }

    auto negotiate_server(ClientHello const& hello,std::span<std::uint16_t const> schemes,PeerSignaturePolicy policy,std::span<std::uint16_t const> ciphers)
        -> std::expected<ServerSelection,ServerNegotiationError> { return negotiate_server(hello,schemes,policy,ciphers,HandshakeTransport::tcp); }

}
