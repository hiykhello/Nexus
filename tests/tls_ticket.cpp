import std;
import nexus.tls.client_flight;
namespace t=nexus::tls; namespace c=nexus::crypto; using Bytes=c::Bytes;
auto secret(int n) -> t::Secret { return t::Secret(Bytes(32,static_cast<std::uint8_t>(n))); }
auto layer(t::RecordDirection direction,int n) -> t::RecordLayer {
    auto s=secret(n); auto key=t::expand_label(c::Hash::sha256,s.view(),"key",{},16), iv=t::expand_label(c::Hash::sha256,s.view(),"iv",{},12);
    if (!key || !iv) std::abort(); auto r=t::RecordLayer::create(direction,c::Aead::aes_128_gcm,key->view(),iv->view()); if (!r) std::abort(); return std::move(*r);
}
auto app() -> t::ApplicationRecords { return {layer(t::RecordDirection::send,1),layer(t::RecordDirection::receive,2),16385,16385,c::Hash::sha256,c::Aead::aes_128_gcm,16,secret(1),secret(2)}; }
int main() {
    // lifetime, age_add, nonce length, one-byte ticket, empty extensions
    Bytes ticket{4,0,0,14,0,0,0,1,0,0,0,2,0,0,1,7,0,0};
    auto receiver=app(); auto sender=layer(t::RecordDirection::send,2);
    auto one=sender.seal(t::ContentType::handshake,std::span{ticket}.first(3));
    Bytes rest(ticket.begin()+3,ticket.end()); rest.insert(rest.end(),ticket.begin(),ticket.end());
    auto two=sender.seal(t::ContentType::handshake,rest); if (!one || !two) return 1;
    auto a=receiver.open_event(*one), b=receiver.open_event(*two);
    if (!a || a->kind!=t::ApplicationEventKind::handshake_fragment || !b || b->kind!=t::ApplicationEventKind::ticket_discarded) return 2;
    auto bad=app(); auto p=layer(t::RecordDirection::send,2); auto malformed=ticket; malformed[14]=0;
    auto rec=p.seal(t::ContentType::handshake,malformed); if (!rec || bad.open_event(*rec)) return 3;
    auto oversized=app(); auto q=layer(t::RecordDirection::send,2); Bytes header{4,0x10,0,1}; auto huge=q.seal(t::ContentType::handshake,header);
    if (!huge || oversized.open_event(*huge)) return 4;
    auto mixed=app(); auto r=layer(t::RecordDirection::send,2); Bytes joined=ticket; joined.insert(joined.end(),{24,0,0,1,1});
    auto packet=r.seal(t::ContentType::handshake,joined); if (!packet) return 5; auto ev=mixed.open_event(*packet);
    if (!ev || ev->kind!=t::ApplicationEventKind::key_update_requested || mixed.seal(Bytes{1})) return 6;
    std::cout << "TLS ticket discard, fragmentation and malformed rejection passed\n";
}
