import std;
import nexus.tls.application_io;
// Track the actual allocation backing one output record, including sized delete.
static std::atomic<void*> watched_allocation{nullptr};
static std::atomic<bool> watched_freed{false};
static thread_local int fail_after=-1;
void* operator new(std::size_t size) {
    if (fail_after==0) { fail_after=-1; throw std::bad_alloc{}; }
    if (fail_after>0) --fail_after;
    if (auto p=std::malloc(size ? size : 1)) return p;
    throw std::bad_alloc{};
}
void operator delete(void* p) noexcept {
    if (p && p==watched_allocation.load()) watched_freed.store(true);
    std::free(p);
}
void operator delete(void* p, std::size_t) noexcept { ::operator delete(p); }
namespace t=nexus::tls; namespace c=nexus::crypto; using Bytes=c::Bytes;
auto secret(int n) -> t::Secret { return t::Secret(Bytes(32,static_cast<std::uint8_t>(n))); }
auto layer(t::RecordDirection direction, int value) -> t::RecordLayer {
    auto s=secret(value); auto k=t::expand_label(c::Hash::sha256,s.view(),"key",{},16), iv=t::expand_label(c::Hash::sha256,s.view(),"iv",{},12);
    if (!k || !iv) std::abort(); auto l=t::RecordLayer::create(direction,c::Aead::aes_128_gcm,k->view(),iv->view()); if (!l) std::abort(); return std::move(*l);
}
auto app(int send,int recv) -> t::ApplicationIo {
    return t::ApplicationIo(t::ApplicationRecords(layer(t::RecordDirection::send,send),layer(t::RecordDirection::receive,recv),16385,16385,c::Hash::sha256,c::Aead::aes_128_gcm,16,secret(send),secret(recv),t::ApplicationRole::client));
}
auto deliver(t::ApplicationIo& sender,t::ApplicationIo& receiver) -> std::optional<t::ApplicationEvent> {
    std::optional<t::ApplicationEvent> event;
    while (!sender.pending_output().empty()) {
        auto piece=sender.pending_output().first(1); auto result=receiver.feed(piece);
        if (!result || result->consumed!=1 || !sender.written(1)) std::abort();
        if (result->event) event=std::move(result->event);
    }
    return event;
}
int main() {
    {
        auto sender=app(1,2); Bytes payload(16384,42);
        if (!sender.send(payload)) return 38;
        auto pending=sender.pending_output();
        watched_freed=false; watched_allocation=const_cast<std::uint8_t*>(pending.data());
        if (!sender.written(pending.size()-1) || watched_freed.load()) return 39;
        if (!sender.written(1) || !watched_freed.load() || !sender.pending_output().empty()) return 40;
        watched_allocation=nullptr;
    }
    {
        Bytes data{1,2,3}; auto peer=app(2,1);
        if (!peer.request_key_update(true)) return 41;
        Bytes wire(peer.pending_output().begin(),peer.pending_output().end());
        for (int mode=0;mode<5;++mode) {
            int failures=0;
            for (int index=0;index<40;++index) {
                auto candidate=app(1,2);
                if (mode==3 || mode==4) { if (!candidate.send(data)) return 42; }
                if (mode==4) {
                    auto event=candidate.feed(wire);
                    if (!event || !event->event || event->event->kind!=t::ApplicationEventKind::key_update_requested) return 43;
                }
                auto count=candidate.pending_output().size(); bool threw=false;
                fail_after=index;
                try {
                    if (mode==0) (void)candidate.send(data);
                    else if (mode==1) (void)candidate.request_key_update(false);
                    else if (mode==2) (void)candidate.close_notify();
                    else if (mode==3) (void)candidate.feed(wire);
                    else (void)candidate.written(count);
                } catch (std::bad_alloc const&) { threw=true; }
                fail_after=-1;
                if (threw) {
                    ++failures; auto result=candidate.send(data);
                    if (!candidate.pending_output().empty() || result || result.error()!=t::ApplicationIoError::invalid_state) return 44;
                }
            }
            if (!failures) return 45;
        }
    }
    auto a=app(1,2), b=app(2,1); Bytes data{1,2,3};
    if (!a.send(data) || a.send(data) || a.written(a.pending_output().size()+1).error()!=t::ApplicationIoError::invalid_input) return 1;
    auto first=deliver(a,b); if (!first || first->kind!=t::ApplicationEventKind::data || first->data!=data) return 3;
    if (!a.request_key_update(true)) return 4; auto request=deliver(a,b);
    if (!request || request->kind!=t::ApplicationEventKind::key_update_requested || b.pending_output().empty() || b.send(data)) return 5;
    auto response=deliver(b,a); if (!response || response->kind!=t::ApplicationEventKind::key_update) return 6;
    if (!b.send(data)) return 7; auto second=deliver(b,a); if (!second || second->data!=data) return 8;
    Bytes too_large(16385,0); if (a.send(too_large).error()!=t::ApplicationIoError::invalid_input || !a.send(data)) return 9;
    auto third=deliver(a,b); if (!third || third->data!=data) return 10;
    if (!a.close_notify() || a.send(data)) return 11; auto closed=deliver(a,b);
    if (!closed || closed->kind!=t::ApplicationEventKind::close_notify || !b.finish_input() || b.feed({}) || !b.send(data)) return 12;
    auto after_close=deliver(b,a); if (!after_close || after_close->data!=data || !b.close_notify()) return 13;
    auto reverse_close=deliver(b,a); if (!reverse_close || reverse_close->kind!=t::ApplicationEventKind::close_notify || !a.finish_input()) return 14;
    auto trunc=app(1,2); if (trunc.finish_input().error()!=t::ApplicationIoError::truncated || trunc.send(data)) return 15;
    auto corrupt_sender=app(1,2), corrupt_receiver=app(2,1); if (!corrupt_sender.send(data)) return 16;
    Bytes wire(corrupt_sender.pending_output().begin(),corrupt_sender.pending_output().end()); wire.back()^=1;
    if (corrupt_receiver.feed(wire).error()!=t::ApplicationIoError::record_error || corrupt_receiver.send(data)) return 17;
    auto old=app(1,2); if (!old.send(data) || !old.written(1)) return 18; auto moved=std::move(old);
    if (!old.pending_output().empty() || old.send(data) || moved.pending_output().empty()) return 19;
    moved.cancel(); if (!moved.pending_output().empty() || moved.send(data)) return 20;
    auto concat_sender=app(1,2), concat_receiver=app(2,1); if (!concat_sender.send(data)) return 21;
    Bytes combined(concat_sender.pending_output().begin(),concat_sender.pending_output().end());
    if (!concat_sender.written(combined.size()) || !concat_sender.send(data)) return 22;
    auto first_length=combined.size(); combined.insert(combined.end(),concat_sender.pending_output().begin(),concat_sender.pending_output().end());
    auto one=concat_receiver.feed(combined); if (!one || one->consumed!=first_length || !one->event || one->event->data!=data) return 23;
    auto two=concat_receiver.feed(std::span{combined}.subspan(one->consumed)); if (!two || !two->event || two->event->data!=data) return 24;
    auto partial=app(2,1); if (!partial.feed(std::span{combined}.first(3)) || partial.finish_input().error()!=t::ApplicationIoError::truncated) return 25;
    auto x=app(1,2), y=app(2,1);
    if (!x.send(data) || !y.send(data)) return 26;
    auto received_x=deliver(x,y); if (!received_x || received_x->data!=data) return 27;
    auto received_y=deliver(y,x); if (!received_y || received_y->data!=data) return 28;
    if (!y.send(data) || !x.request_key_update(true)) return 29;
    auto before=y.pending_output().size(); auto update=deliver(x,y);
    if (!update || update->kind!=t::ApplicationEventKind::key_update_requested || y.pending_output().size()!=before || y.feed(combined)->consumed!=0) return 30;
    for (std::size_t i=0;i<before;++i) {
        auto part=y.pending_output().first(1); auto received=x.feed(part); if (!received || received->consumed!=1 || !y.written(1)) return 31;
        if (i+1==before && (!received->event || received->event->data!=data)) return 32;
    }
    if (y.pending_output().empty() || y.send(data)) return 33;
    auto ack=deliver(y,x); if (!ack || ack->kind!=t::ApplicationEventKind::key_update || !y.send(data)) return 34;
    auto final=deliver(y,x); if (!final || final->data!=data) return 35;
    auto fatal=app(1,2); auto peer=layer(t::RecordDirection::send,2); Bytes alert{2,40};
    auto alert_wire=peer.seal(t::ContentType::alert,alert); if (!alert_wire || !fatal.send(data)) return 36;
    auto fatal_event=fatal.feed(*alert_wire); if (!fatal_event || !fatal_event->event || fatal_event->event->kind!=t::ApplicationEventKind::fatal_alert || !fatal.pending_output().empty() || fatal.send(data)) return 37;
    std::cout << "TLS application record I/O, KeyUpdate and half-close passed\n";
}
