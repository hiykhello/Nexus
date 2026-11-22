import std;
import tls.server_keys;
import tls.client_keys;
import tls.handshake;
import tls.key_share;
import tls.client_hello_stream;
import tls.server_hello;
import tls.hybrid_client_keys;
namespace t=tls; namespace c = ::crypto;
auto message(t::ClientHello const& hello) -> c::Bytes { return *t::HandshakeDecoder::encode(1,*hello.encode()); }
int main(int argc,char** argv) {
    if (argc==3) {
        std::ifstream in(argv[1],std::ios::binary); if (!in) return 20;
        c::Bytes bytes{std::istreambuf_iterator<char>(in),{}}; auto decoder=t::ClientHelloStream::create();
        auto part=decoder->feed(bytes); if (!part || !part->hello || part->consumed!=bytes.size()) return 21;
        constexpr std::array<std::uint16_t,1> offered{0x0804};
        auto server=t::server_handshake_keys(part->message,offered); if (!server) return 22;
        c::Bytes encrypted_extensions{8,0,0,2,0,0}; auto encrypted=server->write.seal(t::ContentType::handshake,encrypted_extensions);
        if (!encrypted) return 23;
        auto size=server->server_hello.size(); if (size>16384) return 24;
        c::Bytes output{22,3,3,static_cast<std::uint8_t>(size>>8),static_cast<std::uint8_t>(size)};
        output.insert(output.end(),server->server_hello.begin(),server->server_hello.end()); output.insert(output.end(),encrypted->begin(),encrypted->end());
        std::ofstream out(argv[2],std::ios::binary); out.write(reinterpret_cast<char const*>(output.data()),output.size()); return out ? 0 : 25;
    }
    constexpr std::array<std::uint16_t,1> schemes{0x0804};
    for (auto suite:{std::uint16_t{0x1301},std::uint16_t{0x1302},std::uint16_t{0x1303}}) {
        auto key=c::X25519Private::generate(); if (!key) return 1;
        auto pub=key->public_key(); if (!pub) return 2;
        auto share=t::KeyShare::encode_client(std::array{t::KeyShareEntry{29,{pub->begin(),pub->end()}}}); if (!share) return 3;
        t::ClientHello client; client.random.fill(9); client.session_id={1,2,3}; client.cipher_suites={suite}; client.compression_methods={0};
        client.extensions={{43,{2,3,4}},{10,{0,2,0,29}},{13,{0,2,8,4}},{51,*share}};
        auto wire=message(client); auto server=t::server_handshake_keys(wire,schemes); if (!server || server->signature_scheme!=0x0804) return 4;
        auto peer=t::client_handshake_keys(wire,server->server_hello,std::move(*key)); if (!peer || peer->hash!=server->hash) return 5;
        if (!std::ranges::equal(server->handshake_secret.view(),peer->handshake_secret.view()) ||
            !std::ranges::equal(server->client_traffic.view(),peer->client_traffic.view()) ||
            !std::ranges::equal(server->server_traffic.view(),peer->server_traffic.view()) ||
            server->transcript.snapshot()!=peer->transcript.snapshot()) return 6;
        c::Bytes payload{8,0,0,2,0,0}; auto sent=server->write.seal(t::ContentType::handshake,payload);
        if (!sent) return 7; auto opened=peer->read.open(*sent); if (!opened || opened->content!=payload) return 8;
        auto back=peer->write.seal(t::ContentType::handshake,payload); if (!back) return 9;
        auto received=server->read.open(*back); if (!received || received->content!=payload) return 10;
        auto zeros=client; zeros.extensions[3].data.assign(38,0); zeros.extensions[3].data[1]=36; zeros.extensions[3].data[3]=29; zeros.extensions[3].data[5]=32;
        if (t::server_handshake_keys(message(zeros),schemes).error()!=t::ServerKeyError::invalid_peer) return 11;
        auto retry=client; retry.extensions[3].data={0,0}; if (t::server_handshake_keys(message(retry),schemes).error()!=t::ServerKeyError::retry_required) return 12;
        auto first=message(retry); auto request=t::server_retry_hello(first,schemes); if (!request) return 30;
        auto parsed=t::ServerHello::parse(std::span{*request}.subspan(4)); if (!parsed || !parsed->is_retry()) return 31;
        auto fresh=c::X25519Private::generate(); if (!fresh) return 32;
        auto fresh_pub=fresh->public_key(); if (!fresh_pub) return 33;
        auto second=parsed->retry_client_hello(retry,t::KeyShareEntry{29,{fresh_pub->begin(),fresh_pub->end()}}); if (!second) return 34;
        auto second_wire=message(*second);
        auto resumed=t::server_handshake_keys_retry(first,*request,second_wire,schemes); if (!resumed) return 35;
        auto resumed_client=t::client_handshake_keys_retry(first,*request,second_wire,resumed->server_hello,std::move(*fresh)); if (!resumed_client) return 36;
        if (resumed->transcript.snapshot()!=resumed_client->transcript.snapshot() ||
            !std::ranges::equal(resumed->server_traffic.view(),resumed_client->server_traffic.view()) ||
            !std::ranges::equal(resumed->client_traffic.view(),resumed_client->client_traffic.view())) return 37;
        auto changed=*second; changed.random[0]^=1;
        if (t::server_handshake_keys_retry(first,*request,message(changed),schemes)) return 38;
        if (t::server_retry_hello(message(client),schemes)) return 39;
        auto altered_request=*request; altered_request.back()^=1;
        if (t::server_handshake_keys_retry(first,altered_request,second_wire,schemes)) return 40;
        auto pq=t::HybridClient::generate(); if (!pq) return 41; auto pq_share=pq->share(); if (!pq_share) return 42;
        auto pq_encoded=t::KeyShare::encode_client(std::array{t::KeyShareEntry{t::x25519_mlkem768_group,{pq_share->begin(),pq_share->end()}}}); if (!pq_encoded) return 43;
        auto pq_hello=client; pq_hello.extensions[1].data={0,2,0x11,0xec}; pq_hello.extensions[3].data=*pq_encoded;
        auto pq_wire=message(pq_hello); auto pq_server=t::server_handshake_keys(pq_wire,schemes); if (!pq_server) return 44;
        auto bad_pq=pq_hello; auto bad_share=*pq_share; bad_share[0]=0xff; bad_share[1]|=0x0f;
        bad_pq.extensions[3].data=*t::KeyShare::encode_client(std::array{t::KeyShareEntry{t::x25519_mlkem768_group,{bad_share.begin(),bad_share.end()}}});
        auto rejected_pq=t::server_handshake_keys(message(bad_pq),schemes);
        if (rejected_pq || rejected_pq.error()!=t::ServerKeyError::invalid_peer) return 53;
        std::ranges::copy(*pq_share,bad_share.begin()); std::ranges::fill(std::span{bad_share}.subspan(1184),0);
        bad_pq.extensions[3].data=*t::KeyShare::encode_client(std::array{t::KeyShareEntry{t::x25519_mlkem768_group,{bad_share.begin(),bad_share.end()}}});
        if (t::server_handshake_keys(message(bad_pq),schemes)) return 54;
        auto pq_client=t::client_hybrid_handshake_keys(pq_wire,pq_server->server_hello,std::move(*pq)); if (!pq_client) return 45;
        if (pq_client->transcript.snapshot()!=pq_server->transcript.snapshot() ||
            !std::ranges::equal(pq_client->server_traffic.view(),pq_server->server_traffic.view()) ||
            !std::ranges::equal(pq_client->client_traffic.view(),pq_server->client_traffic.view())) return 46;
        auto pq_first=pq_hello; pq_first.extensions[3].data={0,0}; auto pq_first_wire=message(pq_first);
        auto pq_request=t::server_retry_hello(pq_first_wire,schemes); if (!pq_request) return 47;
        auto pq_hrr=t::ServerHello::parse(std::span{*pq_request}.subspan(4)); auto pq_fresh=t::HybridClient::generate();
        if (!pq_hrr || !pq_fresh) return 48; auto pq_fresh_share=pq_fresh->share(); if (!pq_fresh_share) return 49;
        auto pq_second=pq_hrr->retry_client_hello(pq_first,t::KeyShareEntry{t::x25519_mlkem768_group,{pq_fresh_share->begin(),pq_fresh_share->end()}}); if (!pq_second) return 50;
        auto pq_second_wire=message(*pq_second); auto pq_resumed=t::server_handshake_keys_retry(pq_first_wire,*pq_request,pq_second_wire,schemes); if (!pq_resumed) return 51;
        auto pq_peer=t::client_hybrid_handshake_keys_retry(pq_first_wire,*pq_request,pq_second_wire,pq_resumed->server_hello,std::move(*pq_fresh));
        if (!pq_peer || pq_peer->transcript.snapshot()!=pq_resumed->transcript.snapshot() ||
            !std::ranges::equal(pq_peer->server_traffic.view(),pq_resumed->server_traffic.view())) return 52;
        wire[3]--; if (t::server_handshake_keys(wire,schemes).error()!=t::ServerKeyError::invalid_hello) return 13;
    }
    std::cout << "TLS server handshake key exchange and directional records passed\n";
}
