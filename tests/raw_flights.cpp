import std;
import crypto;
import tls.raw_client_flight;
import tls.raw_server_flight;
import tls.handshake;
import tls.server_hello;
import tls.server_credential;
import tls.handshake_policy;
import tls.encrypted_extensions;
import tls.client_flight;
import tls.server_flight;

namespace t=tls;
namespace c = ::crypto;
namespace {
    using View=std::span<std::uint8_t const>;
    auto bytes(std::string_view value) noexcept -> View { return {reinterpret_cast<std::uint8_t const*>(value.data()),value.size()}; }
    auto read(std::string_view path) -> c::Bytes { std::ifstream file(std::string(path),std::ios::binary); return {std::istreambuf_iterator<char>(file),{}}; }
    auto wire(t::ClientHello const& hello) -> c::Bytes { auto body=hello.encode(); if (!body) throw std::runtime_error("hello encode"); auto message=t::HandshakeDecoder::encode(1,*body); if (!message) throw std::runtime_error("hello frame"); return std::move(*message); }
    struct Ephemeral {
        std::optional<c::X25519Private> x;
        std::optional<t::HybridClient> hybrid;
        auto share(bool pq) -> t::KeyShareEntry {
            if (pq) { auto key=t::HybridClient::generate(); if (!key) throw std::runtime_error("hybrid"); auto share=key->share(); if (!share) throw std::runtime_error("hybrid share"); hybrid.emplace(std::move(*key)); return {t::x25519_mlkem768_group,{share->begin(),share->end()}}; }
            auto key=c::X25519Private::generate(); if (!key) throw std::runtime_error("x25519"); auto share=key->public_key(); if (!share) throw std::runtime_error("x25519 share"); x.emplace(std::move(*key)); return {29,{share->begin(),share->end()}};
        }
    };
    auto handshake(t::ServerCredential const& credential,c::Bytes const& anchor,std::uint16_t suite,bool hybrid,bool retry,bool quic,unsigned mutation) -> int {
        auto transport=quic ? t::HandshakeTransport::quic : t::HandshakeTransport::tcp;
        auto scheme=*credential.scheme(); std::array<std::uint16_t,1> schemes{scheme},ciphers{suite};
        Ephemeral ephemeral; auto group=hybrid ? t::x25519_mlkem768_group : std::uint16_t{29};
        t::ClientHello hello; hello.random.fill(9); hello.session_id=quic ? c::Bytes{} : c::Bytes{1,2,3}; hello.cipher_suites={suite}; hello.compression_methods={0};
        hello.extensions={{43,{2,3,4}},{10,{0,2,static_cast<std::uint8_t>(group>>8),static_cast<std::uint8_t>(group)}},{13,{0,2,static_cast<std::uint8_t>(scheme>>8),static_cast<std::uint8_t>(scheme)}},{51,{0,0}},{16,{0,3,2,'h','3'}}};
        if (quic) hello.extensions.push_back({0x39,{0x0f,0}}); // Presence only: QUIC core validates values.
        if (!retry) { auto encoded=t::KeyShare::encode_client(std::array{ephemeral.share(hybrid)}); if (!encoded) return 1; hello.extensions[3].data=std::move(*encoded); }
        auto first=wire(hello); c::Bytes hrr,last=first;
        if (retry) {
            auto response=t::server_retry_hello(first,schemes,ciphers,transport); if (!response) return 2; hrr=std::move(*response);
            auto parsed=t::ServerHello::parse(std::span(hrr).subspan(4)); if (!parsed) return 3;
            auto second=parsed->retry_client_hello(hello,ephemeral.share(hybrid)); if (!second) return 4;
            hello=std::move(*second); last=wire(hello);
        }
        auto server=retry ? t::server_handshake_secrets_retry(first,hrr,last,schemes,ciphers,transport) : t::server_handshake_secrets(last,schemes,t::PeerSignaturePolicy::require_offered,ciphers,transport);
        if (!server || server->secrets.cipher_suite!=suite) return 5;
        auto client=hybrid ?
            (retry ? t::RawClientFlight::create_hybrid_retry(first,hrr,last,server->server_hello,std::move(*ephemeral.hybrid),transport) : t::RawClientFlight::create_hybrid(last,server->server_hello,std::move(*ephemeral.hybrid),transport)) :
            (retry ? t::RawClientFlight::create_x25519_retry(first,hrr,last,server->server_hello,std::move(*ephemeral.x),transport) : t::RawClientFlight::create_x25519(last,server->server_hello,std::move(*ephemeral.x),transport));
        if (!client || client->complete()) return 6;
        auto secrets=client->handshake_secrets();
        if (!secrets || secrets->cipher_suite!=suite || !std::ranges::equal(secrets->client,server->secrets.client_traffic.view()) || !std::ranges::equal(secrets->server,server->secrets.server_traffic.view())) return 7;
        std::array<std::uint8_t,2> parameters{0x0f,0};
        std::array<c::Bytes,4> messages;
        std::optional<t::TrafficSecrets> server_application;
        auto flight=t::RawServerFlight::create(std::move(*server),credential,messages,server_application,bytes("h3"),quic ? std::optional<View>(parameters) : std::nullopt); if (!flight) return 8;
        if (messages.size()!=4) return 9;
        auto extension=messages[0]; if (mutation==4) { if (!quic) return 10; extension.back()^=1; }
        if (quic) { auto parsed=client->quic_encrypted_extensions(extension,bytes("h3")); if (!parsed || (!std::ranges::equal(parsed->transport_parameters,parameters) && mutation!=4)) return 11; }
        else if (!client->encrypted_extensions(extension)) return 12;
        if (client->handshake_secrets()) return 13;
        auto now=std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
        std::array<View,1> anchors{anchor};
        auto certificate=client->certificate_with(messages[1],[&](std::span<View const> chain) {
            return t::verify_server_certificate_chain(chain,anchors,t::PeerNameKind::dns,bytes(mutation==1 ? "wrong.example" : "localhost"),now).has_value();
        });
        if (mutation==1) return certificate || client->complete() || certificate.error().kind!=t::ClientFlightError::invalid_certificate ? 14 : 0;
        if (!certificate) return 15;
        auto signature=messages[2]; if (mutation==2) signature.back()^=1;
        auto verified=client->certificate_verify(signature);
        if (mutation==2 || mutation==4) return verified || client->complete() || verified.error().kind!=t::ClientFlightError::invalid_signature ? 16 : 0;
        if (!verified) return 17;
        auto finished=messages[3]; if (mutation==3) finished.back()^=1;
        auto accepted=client->server_finished(finished);
        if (mutation==3) return accepted || client->complete() || accepted.error().kind!=t::ClientFlightError::invalid_finished ? 18 : 0;
        if (!accepted || client->complete()) return 19;
        auto& application=accepted; if (!application || client->server_finished(finished)) return 20;
        auto client_finished=client->client_finished(); if (!client_finished || !client->complete() || client->client_finished()) return 21;
        if (!server_application || flight->complete()) return 22;
        auto completed=flight->client_finished(*client_finished); if (!completed || !flight->complete() || flight->client_finished(*client_finished)) return 23;
        if (application->cipher_suite!=suite || server_application->cipher_suite!=suite || application->hash!=server_application->hash ||
            !std::ranges::equal(application->client.view(),server_application->client.view()) || !std::ranges::equal(application->server.view(),server_application->server.view())) return 24;
        for (auto& message:messages) c::Bytes{}.swap(message);
        return 0;
    }
    auto policy_cases() -> int {
        t::ClientHello hello; hello.random.fill(9); hello.cipher_suites={0x1301}; hello.compression_methods={0};
        hello.extensions={{43,{2,3,4}},{16,{0,3,2,'h','3'}},{0x39,{0x0f,0}},{28,{0x40,1}},{0xff01,{0}}};
        auto valid=t::quic_client_parameters(hello,bytes("h3")); if (!valid || !std::ranges::equal(*valid,hello.extensions[2].data)) return 1;
        if (t::validate_handshake_transport(hello,t::HandshakeTransport::tcp).error()!=t::HandshakePolicyError::unsupported_transport_parameters) return 10;
        auto tcp=hello; tcp.extensions.erase(tcp.extensions.begin()+2);
        if (!t::validate_handshake_transport(tcp,t::HandshakeTransport::tcp)) return 11;
        auto encoded=t::encode_encrypted_extensions(bytes("h3"),std::span(hello.extensions[2].data));
        if (!encoded) return 2;
        if (t::validate_encrypted_extensions(hello,*encoded).error()!=t::EncryptedExtensionsError::unsupported || !t::validate_quic_encrypted_extensions(hello,*encoded,bytes("h3"))) return 3;
        auto absent=t::encode_encrypted_extensions(bytes("h3"));
        if (!absent || t::validate_quic_encrypted_extensions(hello,*absent,bytes("h3")).error()!=t::EncryptedExtensionsError::missing_required) return 4;
        auto bad=hello; bad.session_id={1}; if (t::quic_client_parameters(bad,bytes("h3")).error()!=t::HandshakePolicyError::invalid_session_id) return 5;
        bad=hello; bad.extensions.erase(bad.extensions.begin()+2); if (t::quic_client_parameters(bad,bytes("h3")).error()!=t::HandshakePolicyError::missing_transport_parameters) return 6;
        bad=hello; bad.extensions.push_back(hello.extensions[2]); if (t::quic_client_parameters(bad,bytes("h3"))) return 7;
        if (t::quic_client_parameters(hello,bytes("h2")).error()!=t::HandshakePolicyError::invalid_alpn || t::encode_encrypted_extensions({},std::span<std::uint8_t const>{})) return 8;
        auto record=*encoded; record.insert(record.end(),{0,28,0,2,0x40,1}); auto total=record.size()-4,extensions=record.size()-6;
        record[1]=static_cast<std::uint8_t>(total>>16); record[2]=static_cast<std::uint8_t>(total>>8); record[3]=static_cast<std::uint8_t>(total);
        record[4]=static_cast<std::uint8_t>(extensions>>8); record[5]=static_cast<std::uint8_t>(extensions);
        if (t::validate_quic_encrypted_extensions(hello,record,bytes("h3")).error()!=t::EncryptedExtensionsError::unsupported) return 9;
        return 0;
    }
}
auto main(int argc,char** argv) -> int {
    if (argc!=3) { std::println("usage: tls-raw-flights CERT.der KEY.der"); return 1; }
    try {
        auto cert=read(argv[1]),key=read(argv[2]);
        auto credential=t::ServerCredential::create(cert,key); c::cleanse(key); if (!credential) return 1;
        if (auto result=policy_cases()) { std::println("raw policy case {} failed",result); return 10+result; }
        unsigned passed=0;
        for (auto suite:{std::uint16_t{0x1301},std::uint16_t{0x1302},std::uint16_t{0x1303}})
            for (bool hybrid:{false,true}) for (bool retry:{false,true}) for (bool quic:{false,true}) for (unsigned mutation=0;mutation<(quic ? 5u : 4u);++mutation) {
                auto result=handshake(*credential,cert,suite,hybrid,retry,quic,mutation);
                if (result) { std::println("raw handshake suite={:04x} hybrid={} retry={} quic={} mutation={} case={} failed",suite,hybrid,retry,quic,mutation,result); return 40+result; }
                ++passed;
            }
        std::println("raw shared TLS flights {} cases passed; all suites/X25519/hybrid/HRR/cert name/signature/Finished/TP transcript; sizeof raw client={} TCP client={} raw server={} TCP server={}",passed,sizeof(t::RawClientFlight),sizeof(t::ClientFlight),sizeof(t::RawServerFlight),sizeof(t::ServerFlight));
    } catch (std::exception const& error) { std::println("raw flight exception: {}",error.what()); return 99; }
}
