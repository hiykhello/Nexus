import std;
import nexus.tls.client_handshake;
namespace t=nexus::tls; namespace c=nexus::crypto;
using Bytes=std::vector<std::uint8_t>; using View=std::span<std::uint8_t const>;
auto read(std::string const& file) -> Bytes { std::ifstream f("tests/fixtures/tls-trust/"+file,std::ios::binary); return Bytes(std::istreambuf_iterator<char>(f),{}); }
auto hex(std::string_view s) -> Bytes { auto n=[](char x){return x<='9'?x-'0':x-'a'+10;}; Bytes b; for (std::size_t i=0;i<s.size();i+=2) b.push_back(static_cast<std::uint8_t>((n(s[i])<<4)|n(s[i+1]))); return b; }
auto dns(std::string_view s) -> View { return {reinterpret_cast<std::uint8_t const*>(s.data()),s.size()}; }
int main() {
    auto ch=read("client_wire.bin"), sh=read("server_wire.bin"), cert=read("certificate.bin"), sig=read("flight-signature.bin"), root=read("root.der");
    if (ch.empty() || sh.empty() || cert.empty() || sig.size()!=256 || root.empty()) return 1;
    auto private_bytes=hex("49af42ba7f7994852d713ef2784bcbcaa7911de26adc5642cb634540e7ea5005"); std::array<View,1> anchors{root};
    auto make=[&](std::string_view name) { auto key=c::X25519Private::from_bytes(private_bytes); if (!key) std::abort();
        return t::ClientHandshake::create_x25519(ch,sh,std::move(*key),anchors,t::PeerNameKind::dns,dns(name),1798761600); };
    std::vector<View> many_anchors(1024,root);
    auto many_key=c::X25519Private::from_bytes(private_bytes);
    if (!many_key || !t::ClientHandshake::create_x25519(ch,sh,std::move(*many_key),many_anchors,t::PeerNameKind::dns,dns("server.example"),1798761600)) return 31;
    many_anchors.push_back(root); auto excess_key=c::X25519Private::from_bytes(private_bytes);
    if (!excess_key) return 32;
    auto excess=t::ClientHandshake::create_x25519(ch,sh,std::move(*excess_key),many_anchors,t::PeerNameKind::dns,dns("server.example"),1798761600);
    if (excess || excess.error()!=t::ClientHandshakeError::invalid_configuration) return 33;
    Bytes ee{8,0,0,2,0,0}, cv{15,0,1,4,8,4,1,0}; cv.insert(cv.end(),sig.begin(),sig.end());
    auto transcript=t::Transcript::create(c::Hash::sha256); if (!transcript || !transcript->append(ch) || !transcript->append(sh) || !transcript->append(ee) || !transcript->append(cert) || !transcript->append(cv)) return 2;
    auto digest=transcript->snapshot(); auto traffic=hex("b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38");
    auto finished=t::finished_verify_data(c::Hash::sha256,traffic,*digest); if (!finished) return 3;
    Bytes fin{20,0,0,32}; fin.insert(fin.end(),finished->view().begin(),finished->view().end());
    Bytes all=ee; all.insert(all.end(),cert.begin(),cert.end()); all.insert(all.end(),cv.begin(),cv.end()); all.insert(all.end(),fin.begin(),fin.end());
    auto key=t::expand_label(c::Hash::sha256,traffic,"key",{},16), iv=t::expand_label(c::Hash::sha256,traffic,"iv",{},12); if (!key || !iv) return 4;
    auto sender=t::RecordLayer::create(t::RecordDirection::send,c::Aead::aes_128_gcm,key->view(),iv->view()); if (!sender) return 5;
    Bytes wire; for (std::size_t p=0;p<all.size();) { auto n=std::min<std::size_t>(113,all.size()-p); auto r=sender->seal(t::ContentType::handshake,View(all).subspan(p,n)); if (!r) return 6; wire.insert(wire.end(),r->begin(),r->end()); p+=n; }
    auto client=make("server.example"); if (!client || client->take_application_records()) return 7;
    Bytes ccs{20,3,3,0,1,1};
    for (auto byte:ccs) { auto out=client->feed(View(&byte,1)); if (!out || out->consumed!=1 || out->client_finished_record) return 27; }
    std::optional<Bytes> response;
    for (auto byte:wire) { auto out=client->feed(View(&byte,1)); if (!out || out->consumed!=1) return 8; if (out->client_finished_record) response=std::move(out->client_finished_record); }
    if (!response || !client->negotiated() || !client->take_application_records() || client->take_application_records() || client->feed({})) return 9;
    auto client_traffic=hex("b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21");
    auto ck=t::expand_label(c::Hash::sha256,client_traffic,"key",{},16), ci=t::expand_label(c::Hash::sha256,client_traffic,"iv",{},12);
    if (!ck || !ci) return 19; auto reader=t::RecordLayer::create(t::RecordDirection::receive,c::Aead::aes_128_gcm,ck->view(),ci->view());
    if (!reader) return 20; auto client_fin=reader->open(*response);
    if (!client_fin || client_fin->type!=t::ContentType::handshake || client_fin->content.size()!=36) return 21;
    auto single_sender=t::RecordLayer::create(t::RecordDirection::send,c::Aead::aes_128_gcm,key->view(),iv->view());
    if (!single_sender) return 22; auto single=single_sender->seal(t::ContentType::handshake,all); auto single_client=make("server.example");
    if (!single || !single_client) return 23; auto single_result=single_client->feed(*single);
    if (!single_result || !single_result->client_finished_record || !single_client->take_application_records()) return 24;
    auto extra_sender=t::RecordLayer::create(t::RecordDirection::send,c::Aead::aes_128_gcm,key->view(),iv->view());
    auto extra=all; extra.push_back(1); if (!extra_sender) return 25; auto extra_record=extra_sender->seal(t::ContentType::handshake,extra); auto extra_client=make("server.example");
    if (!extra_record || !extra_client || extra_client->feed(*extra_record) || extra_client->take_application_records()) return 26;
    auto wrong=make("wrong.example"); if (!wrong) return 10;
    bool failed=false; for (std::size_t p=0;p<wire.size();) { auto out=wrong->feed(View(wire).subspan(p)); if (!out) { failed=true; break; } if (!out->consumed) return 11; p+=out->consumed; }
    if (!failed || wrong->feed({}) || wrong->take_application_records()) return 12;
    auto truncated=make("server.example"); if (!truncated) return 13;
    if (!truncated->feed(View(wire).first(3)) || truncated->finish_input() || truncated->feed(View(wire).subspan(3))) return 14;
    auto bad_sender=t::RecordLayer::create(t::RecordDirection::send,c::Aead::aes_128_gcm,key->view(),iv->view()); if (!bad_sender) return 15;
    auto bad_record=bad_sender->seal(t::ContentType::handshake,cv); auto bad=make("server.example");
    if (!bad_record || !bad || bad->feed(*bad_record) || bad->feed(*bad_record)) return 16;
    auto together=make("server.example"); if (!together) return 17;
    auto out=together->feed(wire); if (!out || out->consumed>=wire.size()) return 18;
    auto interleaved=make("server.example"); if (!interleaved) return 28;
    auto first_size=5+(std::size_t{wire[3]}<<8)+wire[4];
    if (!interleaved->feed(View(wire).first(first_size)) || interleaved->feed(ccs).error()!=t::ClientHandshakeError::invalid_record || interleaved->feed({})) return 29;
    auto invalid=make("server.example"); auto bad_ccs=ccs; bad_ccs.back()=2;
    if (!invalid || invalid->feed(bad_ccs).error()!=t::ClientHandshakeError::invalid_record || invalid->feed({})) return 30;
    std::cout << "TLS client handshake record and message reassembly passed\n";
}
