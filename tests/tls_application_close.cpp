import std;
import tls.client_flight;
namespace t=tls; namespace c = ::crypto; using Bytes=c::Bytes;
auto layer(t::RecordDirection d) -> t::RecordLayer { auto x=t::RecordLayer::create(d,c::Aead::aes_128_gcm,Bytes(16,1),Bytes(12,2)); if (!x) std::abort(); return std::move(*x); }
auto app() -> t::ApplicationRecords { return {layer(t::RecordDirection::send),layer(t::RecordDirection::receive),16385,16385,t::ApplicationRole::client}; }
int main() {
    auto a=app(); auto peer=layer(t::RecordDirection::send); auto peer_read=layer(t::RecordDirection::receive);
    Bytes alert{1,0}; auto close=peer.seal(t::ContentType::alert,alert); if (!close) return 1;
    auto event=a.open_event(*close); if (!event || event->kind!=t::ApplicationEventKind::close_notify || !a.finish_input() || a.open_event(*close)) return 2;
    Bytes data{1,2,3}; auto first=a.seal(data); if (!first || !peer_read.open(*first)) return 3;
    auto sent=a.close_notify(); if (!sent || a.close_notify() || a.seal(data)) return 4;
    auto decoded=peer_read.open(*sent); if (!decoded || decoded->type!=t::ContentType::alert || decoded->content!=alert) return 11;
    auto b=app(); if (b.finish_input() || b.seal(data)) return 5;
    auto c=app(); auto sender=layer(t::RecordDirection::send); Bytes fatal{1,40}; auto f=sender.seal(t::ContentType::alert,fatal);
    if (!f) return 6; auto ev=c.open_event(*f); if (!ev || ev->kind!=t::ApplicationEventKind::fatal_alert || ev->alert_description!=40 || c.seal(data)) return 7;
    auto d=app(); auto p=layer(t::RecordDirection::send); Bytes cancel{1,90}; auto cancel_record=p.seal(t::ContentType::alert,cancel); auto end=p.seal(t::ContentType::alert,alert);
    if (!cancel_record || !end) return 8; auto cancel_ev=d.open_event(*cancel_record); auto end_ev=d.open_event(*end);
    if (!cancel_ev || cancel_ev->kind!=t::ApplicationEventKind::user_canceled || !end_ev || end_ev->kind!=t::ApplicationEventKind::close_notify || !d.finish_input()) return 9;
    auto e=app(); auto q=layer(t::RecordDirection::send); Bytes malformed{1}; auto bad=q.seal(t::ContentType::alert,malformed);
    if (!bad || e.open_event(*bad) || e.close_notify()) return 10;
    std::cout << "TLS authenticated close and alert semantics passed\n";
}
