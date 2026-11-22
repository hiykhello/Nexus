module tls.server_keys;
import tls.server_hello;
import tls.handshake;
import tls.hybrid;
import tls.traffic_records;
import std;
namespace tls {



    auto server_retry_hello(std::span<std::uint8_t const> first,std::span<std::uint16_t const> schemes) -> std::expected<crypto::Bytes,ServerKeyError> {
        return server_retry_hello(first,schemes,{});
    }



    auto server_retry_hello(std::span<std::uint8_t const> first,std::span<std::uint16_t const> schemes,std::span<std::uint16_t const> ciphers) -> std::expected<crypto::Bytes,ServerKeyError> {
        return server_retry_hello(first,schemes,ciphers,HandshakeTransport::tcp);
    }

}
