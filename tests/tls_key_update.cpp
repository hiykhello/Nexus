import std;
import nexus.tls.client_flight;
namespace t=nexus::tls; namespace c=nexus::crypto; using Bytes=c::Bytes;
auto secret(int n) -> t::Secret { return t::Secret(Bytes(32,static_cast<std::uint8_t>(n))); }
auto layer(t::RecordDirection direction, int value, std::uint64_t limit=1u << 24) -> t::RecordLayer {
    auto s=secret(value); auto k=t::expand_label(c::Hash::sha256,s.view(),"key",{},16), iv=t::expand_label(c::Hash::sha256,s.view(),"iv",{},12);
    if (!k || !iv) std::abort(); auto l=t::RecordLayer::create(direction,c::Aead::aes_128_gcm,k->view(),iv->view(),limit); if (!l) std::abort(); return std::move(*l);
}
auto app(int send, int recv, std::uint64_t limit=1u << 24, t::ApplicationRole role=t::ApplicationRole::client) -> t::ApplicationRecords {
    return {layer(t::RecordDirection::send,send,limit),layer(t::RecordDirection::receive,recv),16385,16385,c::Hash::sha256,c::Aead::aes_128_gcm,16,secret(send),secret(recv),role};
}
int main() {
    auto a=app(1,2), b=app(2,1,1u << 24,t::ApplicationRole::server); Bytes data{1,2,3};
    auto update=a.key_update(true); if (!update) return 1; auto event=b.open_event(*update);
    if (!event || event->kind!=t::ApplicationEventKind::key_update_requested || b.seal(data) || b.key_update(true)) return 2;
    auto outgoing=a.seal(data); if (!outgoing) return 3; auto opened=b.open_event(*outgoing); if (!opened || opened->data!=data) return 4;
    auto response=b.key_update(false); if (!response) return 5; auto ack=a.open_event(*response);
    if (!ack || ack->kind!=t::ApplicationEventKind::key_update) return 6;
    auto reverse=b.seal(data); if (!reverse) return 7; auto recv=a.open_event(*reverse); if (!recv || recv->data!=data) return 8;
    auto c=app(1,2); auto sender=layer(t::RecordDirection::send,2); Bytes msg{24,0,0,1,1};
    auto p=sender.seal(t::ContentType::handshake,std::span{msg}.first(2)); auto q=sender.seal(t::ContentType::handshake,std::span{msg}.subspan(2));
    if (!p || !q) return 9; auto part=c.open_event(*p), done=c.open_event(*q);
    if (!part || part->kind!=t::ApplicationEventKind::handshake_fragment || !done || done->kind!=t::ApplicationEventKind::key_update_requested) return 10;
    // Server-side reassembly permits a KeyUpdate split across every byte.
    auto server=app(1,2,1u << 24,t::ApplicationRole::server); auto server_peer=layer(t::RecordDirection::send,2);
    for (std::size_t i=0;i<msg.size();++i) {
        auto fragment=server_peer.seal(t::ContentType::handshake,std::span{msg}.subspan(i,1));
        if (!fragment) return 19;
        auto result=server.open_event(*fragment);
        if (!result || result->kind!=(i+1==msg.size() ? t::ApplicationEventKind::key_update_requested : t::ApplicationEventKind::handshake_fragment)) return 20;
    }
    // A large authenticated client handshake record cannot be a valid KeyUpdate.
    auto server_invalid=app(1,2,1u << 24,t::ApplicationRole::server); auto invalid_peer=layer(t::RecordDirection::send,2);
    Bytes oversized(16384,0); oversized[0]=24; oversized[3]=1;
    auto invalid_wire=invalid_peer.seal(t::ContentType::handshake,oversized);
    if (!invalid_wire || server_invalid.open_event(*invalid_wire) || server_invalid.seal(data)) return 21;
    auto d=app(1,2); auto attacker=layer(t::RecordDirection::send,2); msg[4]=2; auto bad=attacker.seal(t::ContentType::handshake,msg);
    if (!bad || d.open_event(*bad) || d.seal(data)) return 11;
    auto e=app(1,2); auto wrong=layer(t::RecordDirection::send,2); msg[4]=0; msg.push_back(0); auto extra=wrong.seal(t::ContentType::handshake,msg);
    if (!extra || e.open_event(*extra)) return 12;
    auto f=app(1,2); auto interleave=layer(t::RecordDirection::send,2); auto frag=interleave.seal(t::ContentType::handshake,std::span{msg}.first(2));
    auto application=interleave.seal(t::ContentType::application_data,data);
    if (!frag || !application || !f.open_event(*frag) || f.open_event(*application)) return 13;
    auto limited=app(1,2,3), other=app(2,1); 
    for (int i=0;i<2;++i) { auto wire=limited.seal(data); if (!wire || !other.open_event(*wire)) return 14; }
    auto rejected=limited.seal(data); if (rejected || rejected.error()!=t::RecordError::key_usage_limit) return 15;
    auto change=limited.key_update(false); if (!change || !other.open_event(*change)) return 16;
    for (int i=0;i<2;++i) { auto wire=limited.seal(data); if (!wire || !other.open_event(*wire)) return 17; }
    rejected=limited.seal(data); if (rejected || rejected.error()!=t::RecordError::key_usage_limit || !limited.close_notify()) return 18;
    std::cout << "TLS KeyUpdate bidirectional rotation, fragmentation and rejection passed\n";
}
