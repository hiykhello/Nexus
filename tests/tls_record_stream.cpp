import std;
import nexus.tls.record_stream;
import nexus.tls.record;
import nexus.tls.handshake;
namespace t=nexus::tls; namespace c=nexus::crypto;
int main() {
    c::Bytes key(16,7), iv(12,9), msg{1,0,0,3,'a','b','c'};
    auto sender=t::RecordLayer::create(t::RecordDirection::send,c::Aead::aes_128_gcm,key,iv);
    auto receiver=t::RecordLayer::create(t::RecordDirection::receive,c::Aead::aes_128_gcm,key,iv);
    if (!sender || !receiver) return 1;
    auto first=sender->seal(t::ContentType::handshake,std::span{msg}.first(3)); auto second=sender->seal(t::ContentType::handshake,std::span{msg}.subspan(3));
    if (!first || !second) return 2;
    c::Bytes wire=*first; wire.insert(wire.end(),second->begin(),second->end());
    t::RecordStream stream; auto hs=t::HandshakeDecoder::create(100); if (!hs) return 3;
    for (std::size_t i=0;i<wire.size();++i) {
        auto read=stream.feed(std::span{wire}.subspan(i,1),t::RecordFraming::ciphertext);
        if (!read || read->consumed!=1) return 4;
        if (read->record) { auto plain=receiver->open(read->record->bytes); if (!plain || plain->type!=t::ContentType::handshake) return 5;
            auto messages=hs->feed(plain->content); if (!messages) return 6;
            if (i+1==wire.size() && (messages->size()!=1 || (*messages)[0].body!=c::Bytes({'a','b','c'}))) return 7;
        }
    }
    if (!stream.finish() || !hs->finish()) return 8;
    t::RecordStream coalesced; auto r=coalesced.feed(wire,t::RecordFraming::ciphertext);
    if (!r || !r->record || r->consumed!=first->size() || r->record->bytes!=*first) return 9;
    auto r2=coalesced.feed(std::span{wire}.subspan(r->consumed),t::RecordFraming::ciphertext); if (!r2 || !r2->record || r2->record->bytes!=*second || !coalesced.finish()) return 10;
    t::RecordStream trunc; if (!trunc.feed(std::span{wire}.first(2),t::RecordFraming::ciphertext) || trunc.finish().error()!=t::RecordStreamError::truncated || trunc.feed({},t::RecordFraming::ciphertext).error()!=t::RecordStreamError::invalid_state) return 11;
    t::RecordStream large; c::Bytes too{23,3,3,0x41,0x01}; if (large.feed(too,t::RecordFraming::ciphertext).error()!=t::RecordStreamError::record_too_large) return 12;
    t::RecordStream change; if (!change.feed(std::span{wire}.first(1),t::RecordFraming::ciphertext) || change.feed({},t::RecordFraming::plaintext).error()!=t::RecordStreamError::invalid_state) return 13;
    t::RecordStream switcher; c::Bytes plaintext{22,3,1,0,1,42}; plaintext.insert(plaintext.end(),first->begin(),first->end());
    auto p=switcher.feed(plaintext,t::RecordFraming::plaintext); if (!p || !p->record || p->consumed!=6) return 14;
    auto q=switcher.feed(std::span{plaintext}.subspan(p->consumed),t::RecordFraming::ciphertext); if (!q || !q->record || q->record->bytes!=*first) return 15;
    for (std::size_t split=0;split<=first->size();++split) {
        t::RecordStream d; auto a=d.feed(std::span{*first}.first(split),t::RecordFraming::ciphertext);
        if (!a || a->consumed!=split) return 16;
        auto b=d.feed(std::span{*first}.subspan(split),t::RecordFraming::ciphertext);
        if (!b || (bool(a->record)+bool(b->record)!=1) || !d.finish()) return 17;
    }
    t::RecordStream before_move; if (!before_move.feed(std::span{wire}.first(2),t::RecordFraming::ciphertext)) return 18;
    auto after_move=std::move(before_move);
    if (before_move.feed({},t::RecordFraming::ciphertext).error()!=t::RecordStreamError::invalid_state) return 19;
    auto rest=after_move.feed(std::span{wire}.subspan(2),t::RecordFraming::ciphertext); if (!rest || !rest->record || rest->record->bytes!=*first) return 20;
    std::cout << "TLS record stream fragmentation, epochs and handshake integration passed\n";
}
