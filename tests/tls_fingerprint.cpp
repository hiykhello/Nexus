import std;
import tls.fingerprint;
import tls.client_hello_exchange;
import tls.handshake;
import tls.server_keys;

namespace t=tls;
using Bytes=std::vector<std::uint8_t>;
auto grease(std::uint16_t value) -> bool { return t::is_grease(value); }
int main() {
    std::array<std::string_view,1> alpn{"h3"};
    std::array<std::uint8_t,2> parameters{15,0};
    std::set<Bytes> shapes;
    std::array<std::uint16_t,1> schemes{0x0807},ciphers{0x1301};
    for (auto transport:{t::HandshakeTransport::tcp,t::HandshakeTransport::quic})
        for (auto profile:{t::Fingerprint::native,t::Fingerprint::tls13_grease,t::Fingerprint::tls13_randomized})
            for (auto shares:{t::FingerprintShares::x25519,t::FingerprintShares::hybrid,t::FingerprintShares::dual,t::FingerprintShares::retry}) {
                t::FingerprintConfig config{profile,shares,1600};
                if (transport==t::HandshakeTransport::quic) config.cipher_count=2;
                auto draft=t::make_fingerprint_hello("localhost",alpn,config,transport,transport==t::HandshakeTransport::quic ? std::optional<std::span<std::uint8_t const>>(parameters) : std::nullopt);
                if (!draft) return 1;
                auto expected=draft->hello.encode(); if (!expected) return 2;
                auto exchange=t::ClientHelloExchange::create(std::move(draft->hello),draft->initial_groups(),transport); if (!exchange) return 3;
                auto initial=exchange->initial();
                if (initial.size()+(transport==t::HandshakeTransport::tcp ? 5 : 0)!=1600) return 4;
                auto parsed=t::ClientHello::parse(initial.subspan(4)); if (!parsed || !parsed->validate_tls13()) return 5;
                if (transport==t::HandshakeTransport::quic && !parsed->session_id.empty()) return 6;
                if (profile!=t::Fingerprint::native) {
                    if (!grease(parsed->cipher_suites.front()) || !grease(parsed->extensions.front().type)) return 7;
                    auto ks=t::KeyShare::parse_client(parsed->extension(51)->data); if (!ks || !grease(ks->front().group)) return 8;
                }
                auto first=Bytes(initial.begin(),initial.end()); if (!exchange->initial_sent()) return 9;
                auto server=t::server_handshake_secrets(first,schemes,t::PeerSignaturePolicy::require_offered,ciphers,transport);
                if (shares==t::FingerprintShares::retry) {
                    if (server) return 10;
                    auto retry=t::server_retry_hello(first,schemes,ciphers,transport); if (!retry) return 11;
                    auto received=exchange->receive(*retry); if (!received || received->outbound.empty()) return 12;
                    Bytes second(received->outbound.begin(),received->outbound.end());
                    if (second.size()+(transport==t::HandshakeTransport::tcp ? 5 : 0)!=1600) return 24;
                    auto retry_parsed=t::ServerHello::parse(std::span(*retry).subspan(4)); auto second_parsed=t::ClientHello::parse(std::span(second).subspan(4));
                    if (!retry_parsed || !second_parsed || second_parsed->random!=parsed->random || second_parsed->session_id!=parsed->session_id) return 13;
                    server=t::server_handshake_secrets_retry(first,*retry,second,schemes,ciphers,transport); if (!server) return 14;
                    if (!exchange->retry_sent()) return 15;
                }
                if (!server || !exchange->receive(server->server_hello)) return 16;
                auto flight=exchange->take_flight(); if (!flight) return 17;
                auto secrets=flight->handshake_secrets(); if (!secrets || !std::ranges::equal(secrets->client,server->secrets.client_traffic.view()) || !std::ranges::equal(secrets->server,server->secrets.server_traffic.view())) return 18;
            }
    for (int trial=0;trial<64;++trial) {
        t::FingerprintConfig config{t::Fingerprint::tls13_randomized,t::FingerprintShares::dual};
        auto h=t::make_fingerprint_hello("localhost",alpn,config); if (!h) return 19;
        Bytes shape; for (auto const& e:h->hello.extensions) if (!grease(e.type)) {shape.push_back(e.type>>8);shape.push_back(e.type);}
        shapes.insert(shape);
    }
    if (shapes.size()<20) return 20;
    t::FingerprintConfig bad; bad.cipher_order[1]=0x1301;
    if (t::make_fingerprint_hello("localhost",alpn,bad)) return 21;
    bad={}; bad.pad_to=65535; if (t::make_fingerprint_hello("localhost",alpn,bad)) return 22;
    if (t::make_fingerprint_hello("localhost",alpn,{},t::HandshakeTransport::quic) || t::make_fingerprint_hello("localhost",alpn,{},t::HandshakeTransport::tcp,parameters)) return 23;
    for (auto limit:{std::uint16_t{64},std::uint16_t{65},std::uint16_t{16384},std::uint16_t{16385}}) {
        for (auto profile:{t::Fingerprint::native,t::Fingerprint::tls13_grease,t::Fingerprint::tls13_randomized}) {
            t::FingerprintConfig selected;selected.profile=profile;selected.record_size_limit=limit;
            auto hello=t::make_fingerprint_hello("localhost",alpn,selected);
            if (!hello) return 25;
            auto ext=hello->hello.extension(28);
            if (!ext || ext->data.size()!=2 || ext->data[0]!=(limit>>8) || ext->data[1]!=(limit&255)) return 26;
            if (t::make_fingerprint_hello("localhost",alpn,selected,t::HandshakeTransport::quic,parameters)) return 27;
        }
    }
    for (auto limit:{std::uint16_t{0},std::uint16_t{63},std::uint16_t{16386},std::uint16_t{65535}}) {
        t::FingerprintConfig selected;selected.record_size_limit=limit;
        if (t::make_fingerprint_hello("localhost",alpn,selected)) return 28;
    }
    for (auto profile:{t::Fingerprint::chrome,t::Fingerprint::firefox,t::Fingerprint::safari,
                       t::Fingerprint::ios,t::Fingerprint::android,t::Fingerprint::edge,t::Fingerprint::random}) {
        auto parsed_name=t::parse_fingerprint(t::fingerprint_name(profile));
        if (!parsed_name || *parsed_name!=profile) return 29;
        for (auto transport:{t::HandshakeTransport::tcp,t::HandshakeTransport::quic}) {
            auto cfg=t::make_profile_fingerprint_config(profile,0x11ec,false,transport);
            auto hello=t::make_fingerprint_hello("localhost",alpn,cfg,transport,
                transport==t::HandshakeTransport::quic ? std::optional<std::span<std::uint8_t const>>(parameters) : std::nullopt);
            if (!hello) return 30;
            auto wire=hello->hello.encode();
            if (!wire || !hello->hello.validate_tls13()) return 31;
            auto exchange=t::ClientHelloExchange::create(std::move(hello->hello),hello->initial_groups(),transport);
            if (!exchange) return 32;
            auto initial=exchange->initial();
            if (!exchange->initial_sent()) return 32;
            auto reparsed=t::ClientHello::parse(initial.subspan(4));
            if (!reparsed || !reparsed->validate_tls13()) return 33;
            if (transport==t::HandshakeTransport::quic && !reparsed->session_id.empty()) return 34;
            if (profile==t::Fingerprint::firefox && transport==t::HandshakeTransport::tcp) {
                if (grease(reparsed->cipher_suites.front()) || !reparsed->extension(28) || !reparsed->extension(45)) return 35;
            }
            if ((profile==t::Fingerprint::chrome || profile==t::Fingerprint::edge || profile==t::Fingerprint::safari || profile==t::Fingerprint::ios) &&
                (!grease(reparsed->cipher_suites.front()) || !reparsed->extension(45))) return 36;
            std::array<std::uint16_t,3> bschemes{0x0403,0x0804,0x0807};
            std::array<std::uint16_t,2> bciphers{0x1301,0x1302};
            auto server=t::server_handshake_secrets(initial,bschemes,t::PeerSignaturePolicy::require_offered,bciphers,transport);
            if (!server || !exchange->receive(server->server_hello)) return 37;
            auto flight=exchange->take_flight();
            if (!flight) return 38;
        }
        auto x25519_cfg=t::make_profile_fingerprint_config(profile,0x001d,false,t::HandshakeTransport::tcp);
        auto x25519_hello=t::make_fingerprint_hello("localhost",alpn,x25519_cfg,t::HandshakeTransport::tcp);
        if (!x25519_hello) return 39;
        auto wire=x25519_hello->hello.encode();
        if (!wire) return 40;
        if (profile==t::Fingerprint::chrome || profile==t::Fingerprint::edge || profile==t::Fingerprint::safari || profile==t::Fingerprint::ios) {
            auto record_size=wire->size()+9;
            if (record_size<517 || (x25519_hello->hello.extension(21) && record_size>520)) return 41;
        }
    }
    std::println("24 fingerprint/transport/share key schedules, browser uTLS presets, exact padding, HRR transcript and 64 randomized shapes passed");
}
