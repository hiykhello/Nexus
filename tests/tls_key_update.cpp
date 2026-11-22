import std;
import tls.client_flight;
static thread_local int fail_after=-1;
void* operator new(std::size_t size) {
    if (fail_after==0) { fail_after=-1; throw std::bad_alloc{}; }
    if (fail_after>0) --fail_after;
    if (auto p=std::malloc(size ? size : 1)) return p;
    throw std::bad_alloc{};
}
void operator delete(void* p) noexcept { std::free(p); }
void operator delete(void* p,std::size_t) noexcept { std::free(p); }
namespace t=tls; namespace c = ::crypto; using Bytes=c::Bytes;
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
        // The only C++ allocation for a partial record is the AEAD output.
        if (i+1<msg.size()) fail_after=1;
        auto result=server.open_event(*fragment);
        fail_after=-1;
        if (!result || result->kind!=(i+1==msg.size() ? t::ApplicationEventKind::key_update_requested : t::ApplicationEventKind::handshake_fragment)) return 20;
        if (i+1<msg.size() && server.ready_for_transport()) return 26;
        if (i==1) { auto moved=std::move(server); if (moved.ready_for_transport()) return 27; server=std::move(moved); }
    }
    // A large authenticated client handshake record cannot be a valid KeyUpdate.
    auto server_invalid=app(1,2,1u << 24,t::ApplicationRole::server); auto invalid_peer=layer(t::RecordDirection::send,2);
    Bytes oversized(16384,0); oversized[0]=24; oversized[3]=1;
    auto invalid_wire=invalid_peer.seal(t::ContentType::handshake,oversized);
    if (!invalid_wire || server_invalid.open_event(*invalid_wire) || server_invalid.seal(data)) return 21;
    auto server_interleave=app(1,2,1u << 24,t::ApplicationRole::server); auto interleaved_peer=layer(t::RecordDirection::send,2);
    auto first=interleaved_peer.seal(t::ContentType::handshake,std::span{msg}.first(2));
    auto next_data=interleaved_peer.seal(t::ContentType::application_data,data);
    if (!first || !next_data || !server_interleave.open_event(*first) || server_interleave.open_event(*next_data) || server_interleave.seal(data)) return 28;
    auto server_wrong=app(1,2,1u << 24,t::ApplicationRole::server); auto wrong_peer=layer(t::RecordDirection::send,2);
    auto wrong_header=wrong_peer.seal(t::ContentType::handshake,Bytes{4,0,0,1});
    if (!wrong_header || server_wrong.open_event(*wrong_header) || server_wrong.seal(data)) return 29;
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
    int send_failures=0, receive_failures=0;
    auto reference=app(2,1); auto update_wire=reference.key_update(false); if (!update_wire) return 22;
    for (int index=0;index<40;++index) {
        auto tx=app(1,2); bool threw=false; fail_after=index;
        try { (void)tx.key_update(false); } catch (std::bad_alloc const&) { threw=true; }
        fail_after=-1;
        if (threw) { ++send_failures; auto retry=tx.seal(data); if (retry || retry.error()!=t::RecordError::invalid_state) return 23; }
        auto rx=app(1,2); threw=false; fail_after=index;
        try { (void)rx.open_event(*update_wire); } catch (std::bad_alloc const&) { threw=true; }
        fail_after=-1;
        if (threw) { ++receive_failures; auto retry=rx.open_event(*update_wire); if (retry || retry.error()!=t::RecordError::invalid_state) return 24; }
    }
    if (send_failures<3 || receive_failures<3) return 25;
    t::ApplicationRecords invalid_parameters(layer(t::RecordDirection::send,1),layer(t::RecordDirection::receive,2),16385,16385,
        c::Hash::sha256,c::Aead::aes_128_gcm,12000,secret(1),secret(2),t::ApplicationRole::server);
    fail_after=3; // The record's three allocations may succeed; rotation must reject before HKDF.
    auto invalid_update=invalid_parameters.key_update(false);
    fail_after=-1;
    if (invalid_update || invalid_update.error()!=t::RecordError::crypto_error || invalid_parameters.seal(data)) return 30;
    for (auto algorithm : {c::Aead::aes_256_gcm,c::Aead::chacha20_poly1305}) {
        auto make_secret=[](int n) { return t::Secret(Bytes(48,static_cast<std::uint8_t>(n))); };
        auto make_layer=[&](t::RecordDirection direction,int n) {
            auto s=make_secret(n); auto key=t::expand_label(c::Hash::sha384,s.view(),"key",{},32), iv=t::expand_label(c::Hash::sha384,s.view(),"iv",{},12);
            if (!key || !iv) std::abort(); auto result=t::RecordLayer::create(direction,algorithm,key->view(),iv->view());
            if (!result) std::abort(); return std::move(*result);
        };
        t::ApplicationRecords tx(make_layer(t::RecordDirection::send,1),make_layer(t::RecordDirection::receive,2),16385,16385,
            c::Hash::sha384,algorithm,32,make_secret(1),make_secret(2),t::ApplicationRole::client);
        t::ApplicationRecords rx(make_layer(t::RecordDirection::send,2),make_layer(t::RecordDirection::receive,1),16385,16385,
            c::Hash::sha384,algorithm,32,make_secret(2),make_secret(1),t::ApplicationRole::server);
        auto changed=tx.key_update(true); if (!changed) return 31;
        auto received=rx.open_event(*changed); if (!received || received->kind!=t::ApplicationEventKind::key_update_requested) return 32;
        auto reply=rx.key_update(false); if (!reply || !tx.open_event(*reply)) return 33;
        auto wire=tx.seal(data); if (!wire) return 34;
        auto decoded=rx.open_event(*wire); if (!decoded || decoded->data!=data) return 35;
    }
    std::cout << "TLS KeyUpdate bidirectional rotation, fragmentation and rejection passed\n";
}
