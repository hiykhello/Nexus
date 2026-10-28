import std;
import nexus.tls.client_flight;
import nexus.tls.server_hello;
import nexus.tls.handshake;
namespace t=nexus::tls; namespace c=nexus::crypto;
using Bytes=std::vector<std::uint8_t>; using View=std::span<std::uint8_t const>;
auto read(std::string const& file) -> Bytes { std::ifstream f("tests/fixtures/tls-trust/"+file,std::ios::binary); return Bytes(std::istreambuf_iterator<char>(f),{}); }
auto hex(std::string_view s) -> Bytes { auto n=[](char x){return x<='9'?x-'0':x-'a'+10;}; Bytes b; for (std::size_t i=0;i<s.size();i+=2) b.push_back(static_cast<std::uint8_t>((n(s[i])<<4)|n(s[i+1]))); return b; }
auto dns(std::string_view s) -> View { return {reinterpret_cast<std::uint8_t const*>(s.data()),s.size()}; }
int main() {
    auto ch=read("client_wire.bin"), sh=read("server_wire.bin"), cert=read("certificate.bin"), sig=read("flight-signature.bin"), root=read("root.der");
    if (ch.empty() || sh.empty() || cert.empty() || sig.size()!=256 || root.empty()) return 1;
    auto private_bytes=hex("49af42ba7f7994852d713ef2784bcbcaa7911de26adc5642cb634540e7ea5005");
    auto make=[&] { auto k=c::X25519Private::from_bytes(private_bytes); if (!k) std::abort(); return t::ClientFlight::create_x25519(ch,sh,std::move(*k)); };
    Bytes ee{8,0,0,2,0,0}, cv{15,0,1,4,8,4,1,0}; cv.insert(cv.end(),sig.begin(),sig.end());
    auto tr=t::Transcript::create(c::Hash::sha256); if (!tr || !tr->append(ch) || !tr->append(sh) || !tr->append(ee) || !tr->append(cert) || !tr->append(cv)) return 2;
    auto digest=tr->snapshot(); auto traffic=hex("b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38");
    auto verify=t::finished_verify_data(c::Hash::sha256,traffic,*digest); if (!verify) return 3;
    Bytes fin{20,0,0,32}; fin.insert(fin.end(),verify->view().begin(),verify->view().end()); std::array<View,1> anchors{root};
    auto skey=t::expand_label(c::Hash::sha256,traffic,"key",{},16), siv=t::expand_label(c::Hash::sha256,traffic,"iv",{},12);
    if (!skey || !siv) return 4; auto sender=t::RecordLayer::create(t::RecordDirection::send,c::Aead::aes_128_gcm,skey->view(),siv->view());
    if (!sender) return 4; auto record=sender->seal(t::ContentType::handshake,ee); if (!record) return 4;
    auto a=make(); if (!a) return 4; auto opened=a->open_handshake_record(*record);
    if (!opened || *opened!=ee || a->certificate_verify(cv) || !a->encrypted_extensions(*opened) ||
        !a->certificate(cert,anchors,t::PeerNameKind::dns,dns("server.example"),1798761600) ||
        !a->certificate_verify(cv) || !a->server_finished(fin)) return 4;
    if (a->take_application_records()) return 20;
    auto reply=a->client_finished();
    auto ct=hex("b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21");
    auto ck=t::expand_label(c::Hash::sha256,ct,"key",{},16), ci=t::expand_label(c::Hash::sha256,ct,"iv",{},12);
    if (!reply || !ck || !ci) return 5; auto reader=t::RecordLayer::create(t::RecordDirection::receive,c::Aead::aes_128_gcm,ck->view(),ci->view());
    if (!reader) return 5; auto client_plain=reader->open(*reply);
    if (!client_plain || client_plain->type!=t::ContentType::handshake || client_plain->content.size()!=36 || a->client_finished()) return 5;
    if (!tr->append(fin)) return 21; auto app_hash=tr->snapshot();
    auto master=hex("18df06843d13a08bf2a449844c5f8a478001bc4d4c627984d5a41da8d0402919");
    auto ca=t::derive_secret(c::Hash::sha256,master,"c ap traffic",*app_hash), sa=t::derive_secret(c::Hash::sha256,master,"s ap traffic",*app_hash);
    if (!ca || !sa) return 22;
    auto cak=t::expand_label(c::Hash::sha256,ca->view(),"key",{},16), cai=t::expand_label(c::Hash::sha256,ca->view(),"iv",{},12);
    auto sak=t::expand_label(c::Hash::sha256,sa->view(),"key",{},16), sai=t::expand_label(c::Hash::sha256,sa->view(),"iv",{},12);
    if (!cak || !cai || !sak || !sai) return 23;
    auto peer_read=t::RecordLayer::create(t::RecordDirection::receive,c::Aead::aes_128_gcm,cak->view(),cai->view());
    auto peer_write=t::RecordLayer::create(t::RecordDirection::send,c::Aead::aes_128_gcm,sak->view(),sai->view());
    auto app=a->take_application_records(); if (!peer_read || !peer_write || !app || a->take_application_records()) return 24;
    Bytes payload{'h','e','l','l','o'}; auto sent=app->seal(payload); if (!sent) return 25;
    auto received=peer_read->open(*sent); if (!received || received->content!=payload) return 26;
    auto inbound=peer_write->seal(t::ContentType::application_data,payload); if (!inbound) return 27;
    auto actual=app->open(*inbound); if (!actual || *actual!=payload) return 28;
    auto bad_app=peer_write->seal(t::ContentType::application_data,payload); if (!bad_app) return 29; bad_app->back()^=1;
    if (app->open(*bad_app) || app->seal(payload)) return 30;
    auto limited_write=t::RecordLayer::create(t::RecordDirection::send,c::Aead::aes_128_gcm,cak->view(),cai->view());
    auto limited_read=t::RecordLayer::create(t::RecordDirection::receive,c::Aead::aes_128_gcm,sak->view(),sai->view());
    auto limited_peer=t::RecordLayer::create(t::RecordDirection::send,c::Aead::aes_128_gcm,sak->view(),sai->view());
    if (!limited_write || !limited_read || !limited_peer) return 31;
    t::ApplicationRecords limits(std::move(*limited_write),std::move(*limited_read),64,64,t::ApplicationRole::client);
    if (limits.seal(Bytes(64,1)) || !limits.seal(Bytes(63,1))) return 32;
    auto oversized=limited_peer->seal(t::ContentType::application_data,Bytes(64,1));
    if (!oversized || limits.open(*oversized) || limits.seal(payload)) return 33;
    auto b=make(); auto bad=ee; bad[0]=9;
    if (!b || b->encrypted_extensions(bad) || b->encrypted_extensions(ee) || b->certificate(cert,anchors,t::PeerNameKind::dns,dns("server.example"),1798761600)) return 6;
    auto d=make(); auto altered=cv; altered.back()^=1;
    if (!d || !d->encrypted_extensions(ee) || !d->certificate(cert,anchors,t::PeerNameKind::dns,dns("server.example"),1798761600) ||
        d->certificate_verify(altered) || d->server_finished(fin)) return 7;
    auto tampered=*record; tampered.back()^=1; auto z=make();
    if (!z || z->open_handshake_record(tampered) || z->open_handshake_record(*record) || z->encrypted_extensions(ee)) return 19;
    auto e=make(); if (!e || !e->encrypted_extensions(ee) || e->certificate(cert,anchors,t::PeerNameKind::dns,dns("wrong.example"),1798761600) || e->certificate_verify(cv)) return 8;
    auto hybrid=t::HybridClient::generate(); if (!hybrid) return 9; auto share=hybrid->share(); if (!share) return 10;
    t::KeyShareEntry ce{t::x25519_mlkem768_group,Bytes(share->begin(),share->end())}; auto cs=t::KeyShare::encode_client(std::span{&ce,1});
    if (!cs) return 11; t::ClientHello hc; hc.random.fill(1); hc.session_id={1}; hc.cipher_suites={0x1301}; hc.compression_methods={0};
    hc.extensions={{43,{2,3,4}},{10,{0,2,0x11,0xec}},{51,*cs},{13,{0,2,8,4}}};
    auto cb=hc.encode(); if (!cb) return 12; auto cw=t::HandshakeDecoder::encode(1,*cb);
    auto sk=c::X25519Private::generate(); if (!cw || !sk) return 13; auto response=t::hybrid_server_accept(*share,std::move(*sk)); if (!response) return 14;
    t::KeyShareEntry se{t::x25519_mlkem768_group,Bytes(response->share.begin(),response->share.end())}; auto ss=t::KeyShare::encode_server(se); if (!ss) return 15;
    t::ServerHello hs; hs.random.fill(2); hs.session_id_echo={1}; hs.cipher_suite=0x1301; hs.extensions={{43,{3,4}},{51,*ss}};
    auto sb=hs.encode(); if (!sb) return 16; auto sw=t::HandshakeDecoder::encode(2,*sb); if (!sw) return 17;
    auto hf=t::ClientFlight::create_hybrid(*cw,*sw,std::move(*hybrid));
    if (!hf || !hf->encrypted_extensions(ee) || hf->certificate(cert,anchors,t::PeerNameKind::dns,dns("wrong.example"),1798761600) || hf->certificate_verify(cv)) return 18;
    std::cout << "TLS client flight combines Hello, extensions and authentication\n";
}
