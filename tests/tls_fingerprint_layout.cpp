import std;
import tls.profiles;
import tls.client_hello_exchange;
import tls.client_hello_driver;
import tls.client_session_handshake;
import quic.tls_client;

struct Pki {
    std::span<std::uint8_t const> anchor;
    auto operator()(std::span<std::span<std::uint8_t const> const>) const -> bool {return false;}
};
int main() {
    std::println("ClientHello={} ClientHelloExchange={} ClientHelloDriver={} ClientSessionHandshake={} ClientProfile={} QuicTlsClient={}",
        sizeof(tls::ClientHello),sizeof(tls::ClientHelloExchange),sizeof(tls::ClientHelloDriver),
        sizeof(tls::ClientSessionHandshake),sizeof(tls::ClientProfile),sizeof(quic::TlsClient<Pki>));
}
