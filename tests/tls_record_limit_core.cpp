import std;
import tls.client_flight;
namespace t=tls; namespace c = ::crypto;
using Bytes=c::Bytes;
auto layer(t::RecordDirection direction,int value) -> t::RecordLayer {
    std::array<std::uint8_t,16> key{};std::array<std::uint8_t,12> iv{};key.fill(value);iv.fill(value);
    auto value_layer=t::RecordLayer::create(direction,c::Aead::aes_128_gcm,key,iv);
    if (!value_layer) std::abort();return std::move(*value_layer);
}
auto main() -> int {
    for (std::size_t limit:{64,256,16385}) {
        t::ApplicationRecords receiver(layer(t::RecordDirection::send,1),layer(t::RecordDirection::receive,2),16385,limit,t::ApplicationRole::client);
        auto peer_write=layer(t::RecordDirection::send,2),peer_read=layer(t::RecordDirection::receive,1);
        Bytes fitting(limit-1,7);auto allowed=peer_write.seal(t::ContentType::application_data,fitting);
        if (!allowed) return 1;auto event=receiver.open_event(*allowed);
        if (!event || event->data!=fitting) return 2;
        auto prior=receiver.seal(Bytes{9,8,7});if (!prior) return 3;
        // Exactly one octet too many, including the TLSInnerPlaintext type.
        Bytes large(limit,1);auto oversized=peer_write.seal(t::ContentType::application_data,large);
        if (limit==16385) continue; // TLS record layer rejects this protocol maximum itself.
        if (!oversized) return 4;auto rejected=receiver.open_event(*oversized);
        if (rejected || rejected.error()!=t::RecordError::record_overflow || receiver.seal(Bytes{1})) return 5;
        auto alert=receiver.take_overflow_alert();if (!alert || receiver.take_overflow_alert()) return 6;
        // The caller sends any already-encoded prior record before the terminal alert.
        auto first=peer_read.open(*prior),second=peer_read.open(*alert);
        if (!first || first->content!=Bytes({9,8,7}) || !second || second->type!=t::ContentType::alert || second->content!=Bytes({2,22})) return 7;
    }
    std::println("TLS application record limits and ordered encrypted overflow alert passed");
}
