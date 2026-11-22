import std;
import tls.application_io;
namespace t=tls;namespace c = ::crypto;using Bytes=c::Bytes;
auto secret(int n) -> t::Secret { return t::Secret(Bytes(32,static_cast<std::uint8_t>(n))); }
auto layer(t::RecordDirection direction,int n) -> t::RecordLayer {
    auto s=secret(n);auto k=t::expand_label(c::Hash::sha256,s.view(),"key",{},16),iv=t::expand_label(c::Hash::sha256,s.view(),"iv",{},12);
    if (!k || !iv) std::abort();auto result=t::RecordLayer::create(direction,c::Aead::aes_128_gcm,k->view(),iv->view());
    if (!result) std::abort();return std::move(*result);
}
auto app(int send,int recv,std::size_t limit) -> t::ApplicationIo {
    return t::ApplicationIo(t::ApplicationRecords(layer(t::RecordDirection::send,send),layer(t::RecordDirection::receive,recv),16385,limit,c::Hash::sha256,c::Aead::aes_128_gcm,16,secret(send),secret(recv),t::ApplicationRole::client));
}
auto main() -> int {
    for (int pending=0;pending<4;++pending) for (bool huge_header:{false,true}) {
        auto receiver=app(1,2,64),peer=app(2,1,16385);
        if (pending==1 && !receiver.send(Bytes{1,2,3})) return 1;
        if (pending==2 && !receiver.request_key_update(false)) return 2;
        if (pending==3 && !receiver.close_notify()) return 11;
        if (!peer.send(Bytes(64,9))) return 3;
        Bytes huge{23,3,3,0x41,0x01};
        auto input=huge_header ? std::span<std::uint8_t const>(huge) : peer.pending_output();
        auto result=receiver.feed(input);
        if (result || result.error()!=t::ApplicationIoError::record_overflow || !receiver.overflow() || receiver.send(Bytes{3})) return 4;
        std::vector<t::ApplicationEventKind> events;
        while (!receiver.pending_output().empty()) {
            // Every byte is acknowledged separately, forcing partial-record ordering.
            auto next=receiver.pending_output().first(1);
            auto received=peer.feed(next);if (!received || received->consumed!=1) return 5;
            if (received->event) {
                events.push_back(received->event->kind);
                if (received->event->kind==t::ApplicationEventKind::fatal_alert && received->event->alert_description!=22) return 6;
            }
            auto wrote=receiver.written(1);
            if (!wrote && (pending!=3 || !receiver.pending_output().empty())) return 7;
        }
        if (pending==3) {
            if (events.size()!=1 || events.front()!=t::ApplicationEventKind::close_notify || receiver.overflow_alert_written()) return 12;
            continue;
        }
        if (!receiver.overflow_alert_written() || events.empty() || events.back()!=t::ApplicationEventKind::fatal_alert) return 8;
        if (pending==1 && (events.size()!=2 || events.front()!=t::ApplicationEventKind::data)) return 9;
        if (pending==2 && (events.size()!=2 || events.front()!=t::ApplicationEventKind::key_update)) return 10;
    }
    std::println("overflow alert retains record ordering across partial writes and KeyUpdate");
}
