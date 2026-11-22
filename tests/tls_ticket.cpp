import std;
import tls.client_flight;
namespace t=tls; namespace c = ::crypto; using Bytes=c::Bytes;
auto secret(int n) -> t::Secret { return t::Secret(Bytes(32,static_cast<std::uint8_t>(n))); }
auto layer(t::RecordDirection direction,int n) -> t::RecordLayer {
    auto s=secret(n); auto key=t::expand_label(c::Hash::sha256,s.view(),"key",{},16), iv=t::expand_label(c::Hash::sha256,s.view(),"iv",{},12);
    if (!key || !iv) std::abort(); auto r=t::RecordLayer::create(direction,c::Aead::aes_128_gcm,key->view(),iv->view()); if (!r) std::abort(); return std::move(*r);
}
auto app(t::ApplicationRole role=t::ApplicationRole::client) -> t::ApplicationRecords { return {layer(t::RecordDirection::send,1),layer(t::RecordDirection::receive,2),16385,16385,c::Hash::sha256,c::Aead::aes_128_gcm,16,secret(1),secret(2),role}; }
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
    // One byte above the largest encodable ticket body must fail on its header.
    auto oversized=app(); auto q=layer(t::RecordDirection::send,2); Bytes header{4,0x02,0x01,0x0a}; auto huge=q.seal(t::ContentType::handshake,header);
    if (!huge || oversized.open_event(*huge)) return 4;
    auto mixed=app(); auto r=layer(t::RecordDirection::send,2); Bytes joined=ticket; joined.insert(joined.end(),{24,0,0,1,1});
    auto packet=r.seal(t::ContentType::handshake,joined); if (!packet) return 5; auto ev=mixed.open_event(*packet);
    if (!ev || ev->kind!=t::ApplicationEventKind::key_update_requested || mixed.seal(Bytes{1})) return 6;
    // Maximum encodable nonce, ticket and extensions, with a second ticket
    // following in the same last record.
    Bytes maximum{4,0x02,0x01,0x09}; maximum.insert(maximum.end(),8,0);
    maximum.push_back(255); maximum.insert(maximum.end(),255,0);
    maximum.insert(maximum.end(),{0xff,0xff}); maximum.insert(maximum.end(),65535,1);
    maximum.insert(maximum.end(),{0xff,0xfe,0,1,0xff,0xfa}); maximum.insert(maximum.end(),65530,0);
    maximum.insert(maximum.end(),ticket.begin(),ticket.end());
    auto large=app(); auto sender_large=layer(t::RecordDirection::send,2);
    for (std::size_t offset=0;offset<maximum.size();) {
        auto count=std::min(std::size_t{16384},maximum.size()-offset);
        auto fragment=sender_large.seal(t::ContentType::handshake,std::span{maximum}.subspan(offset,count));
        if (!fragment) return 7;
        auto event=large.open_event(*fragment); offset+=count;
        if (!event || event->kind!=(offset==maximum.size() ? t::ApplicationEventKind::ticket_discarded : t::ApplicationEventKind::handshake_fragment)) return 8;
    }
    // A server must reject a client-sent ticket, even if its header is split;
    // moving the record state must preserve the role and failure state.
    auto initial=app(t::ApplicationRole::server); auto server=std::move(initial);
    auto sender_server=layer(t::RecordDirection::send,2);
    auto first=sender_server.seal(t::ContentType::handshake,std::span{ticket}.first(3));
    auto last=sender_server.seal(t::ContentType::handshake,std::span{ticket}.subspan(3));
    if (!first || !last || !server.open_event(*first) || server.open_event(*last) || server.seal(Bytes{1})) return 9;
    // An oversized extension vector is invalid even when the overall body
    // length is below the maximum permitted ticket length.
    Bytes bad_extensions{4,1,0,13}; bad_extensions.insert(bad_extensions.end(),8,0);
    bad_extensions.insert(bad_extensions.end(),{0,0,1,7,0xff,0xff,0,1,0xff,0xfb});
    bad_extensions.insert(bad_extensions.end(),65531,0);
    auto invalid=app(); auto sender_invalid=layer(t::RecordDirection::send,2);
    for (std::size_t offset=0;offset<bad_extensions.size();) {
        auto count=std::min(std::size_t{16384},bad_extensions.size()-offset);
        auto fragment=sender_invalid.seal(t::ContentType::handshake,std::span{bad_extensions}.subspan(offset,count));
        if (!fragment) return 10;
        auto event=invalid.open_event(*fragment); offset+=count;
        if (static_cast<bool>(event)!=(offset<bad_extensions.size())) return 11;
    }
    std::cout << "TLS ticket discard, fragmentation and malformed rejection passed\n";
}
