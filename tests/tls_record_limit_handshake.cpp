import std;
import tls.fingerprint;
import tls.client_hello_driver;
import tls.client_handshake_io;
import tls.server_keys;
namespace t=tls;namespace c = ::crypto;using Bytes=c::Bytes;
auto framed(std::span<std::uint8_t const> message) -> Bytes {
    Bytes out{22,3,3,static_cast<std::uint8_t>(message.size()>>8),static_cast<std::uint8_t>(message.size())};
    out.insert(out.end(),message.begin(),message.end());return out;
}
auto io_test(bool cancel,int invalid=0) -> bool {
    t::FingerprintConfig config;config.record_size_limit=64;
    auto shaped=t::make_fingerprint_hello("localhost",{},config);if(!shaped)return false;
    Bytes root{1},name{'l'};std::array<std::span<std::uint8_t const>,1> anchors{root};
    auto session=t::ClientSessionHandshake::create(std::move(shaped->hello),shaped->initial_groups(),anchors,t::PeerNameKind::dns,name,0);
    if(!session)return false;auto io=t::ClientHandshakeIo::create(std::move(*session),0,100);if(!io)return false;
    Bytes first(io->pending_output().begin(),io->pending_output().end());if(!io->written(first.size(),0))return false;
    constexpr std::array<std::uint16_t,1> schemes{0x0804};auto server=t::server_handshake_keys(std::span(first).subspan(5),schemes);if(!server)return false;
    auto sh=framed(server->server_hello);auto sh_result=io->feed(sh,1);if(!sh_result || sh_result->consumed!=sh.size())return false;
    Bytes ee{8,0,0,8,0,6,0,28,0,2,static_cast<std::uint8_t>(invalid==2 ? 0x40 : 0),static_cast<std::uint8_t>(invalid==2 ? 2 : invalid ? 63 : 64)};auto oversized=server->write.seal(t::ContentType::handshake,ee,65-ee.size()-1);if(!oversized)return false;
    auto failed=io->feed(*oversized,2);if(!failed || io->pending_output().empty())return false;
    auto blocked=io->feed(Bytes{1,2,3},2);if(!blocked || blocked->consumed!=0)return false;
    Bytes alert(io->pending_output().begin(),io->pending_output().end());
    auto opened=server->read.open(alert);if(!opened || opened->type!=t::ContentType::alert || opened->content!=Bytes({2,static_cast<std::uint8_t>(invalid ? 47 : 22)}))return false;
    if(cancel) {if (!io->cancel() || !io->pending_output().empty() || io->tick(3))return false;return true;}
    while (io->pending_output().size()>1) if(!io->written(1,2))return false;
    auto done=io->written(1,2);return !done && done.error()==t::ClientHandshakeIoError::protocol_error && io->pending_output().empty() && !io->tick(2);
}
auto split_test(bool negotiated,bool oversized_first) -> bool {
    t::FingerprintConfig config;config.record_size_limit=64;
    auto shape=t::make_fingerprint_hello("localhost",{},config);if(!shape)return false;
    auto client=t::ClientHelloDriver::create(std::move(shape->hello),shape->initial_groups());if(!client)return false;
    auto first=client->initial_record();if(!first || !client->initial_sent())return false;
    constexpr std::array<std::uint16_t,1> schemes{0x0804};auto server=t::server_handshake_keys(std::span(*first).subspan(5),schemes);if(!server)return false;
    auto sh=framed(server->server_hello);auto got=client->feed(sh);if(!got || !got->server_hello)return false;
    Bytes root{1},name{'l'};std::array<std::span<std::uint8_t const>,1> anchors{root};
    auto handshake=client->take_handshake(anchors,t::PeerNameKind::dns,name,0);if(!handshake)return false;
    Bytes ee=negotiated ? Bytes{8,0,0,8,0,6,0,28,0,2,0,64} : Bytes{8,0,0,2,0,0};
    auto split=ee.size()/2;auto first_size=oversized_first ? 65u : 16u,second_size=oversized_first ? 16u : 65u;
    auto first_record=server->write.seal(t::ContentType::handshake,std::span(ee).first(split),first_size-split-1);
    auto second_record=server->write.seal(t::ContentType::handshake,std::span(ee).subspan(split),second_size-(ee.size()-split)-1);
    if(!first_record || !second_record || !handshake->feed(*first_record))return false;
    auto result=handshake->feed(*second_record);
    if(!negotiated)return result.has_value();
    if(result || result.error()!=t::ClientHandshakeError::record_overflow)return false;
    auto alert=handshake->take_overflow_alert();if(!alert)return false;
    auto plain=server->read.open(*alert);return plain && plain->type==t::ContentType::alert && plain->content==Bytes({2,22});
}
auto split_header_test() -> bool {
    t::FingerprintConfig config;config.record_size_limit=64;
    auto shape=t::make_fingerprint_hello("localhost",{},config);if(!shape)return false;
    auto client=t::ClientHelloDriver::create(std::move(shape->hello),shape->initial_groups());if(!client)return false;
    auto first=client->initial_record();if(!first || !client->initial_sent())return false;
    constexpr std::array<std::uint16_t,1> schemes{0x0804};auto server=t::server_handshake_keys(std::span(*first).subspan(5),schemes);if(!server)return false;
    auto sh=framed(server->server_hello);auto got=client->feed(sh);if(!got || !got->server_hello)return false;
    Bytes root{1},name{'l'};std::array<std::span<std::uint8_t const>,1> anchors{root};
    auto handshake=client->take_handshake(anchors,t::PeerNameKind::dns,name,0);if(!handshake)return false;
    Bytes ee{8,0,0,8,0,6,0,28,0,2,0,64};
    auto header=server->write.seal(t::ContentType::handshake,std::span(ee).first(1),63); // 65-byte TLSInnerPlaintext
    auto rest=server->write.seal(t::ContentType::handshake,std::span(ee).subspan(1));if(!header || !rest || !handshake->feed(*header))return false;
    auto result=handshake->feed(*rest);if(result || result.error()!=t::ClientHandshakeError::record_overflow)return false;
    auto alert=handshake->take_overflow_alert();if(!alert)return false;auto plain=server->read.open(*alert);
    return plain && plain->content==Bytes({2,22});
}
auto main() -> int {
    for (bool negotiated:{false,true}) for (std::size_t total:{std::size_t{64},std::size_t{65}}) for (bool huge_header:{false,true}) {
        t::FingerprintConfig config;config.record_size_limit=64;
        auto shaped=t::make_fingerprint_hello("localhost",{},config);if (!shaped) return 1;
        auto client=t::ClientHelloDriver::create(std::move(shaped->hello),shaped->initial_groups());if (!client) return 2;
        auto first=client->initial_record();if (!first || !client->initial_sent()) return 3;
        constexpr std::array<std::uint16_t,1> schemes{0x0804};
        auto server=t::server_handshake_keys(std::span(*first).subspan(5),schemes);if (!server) return 4;
        auto sh=framed(server->server_hello);auto consumed=client->feed(sh);
        if (!consumed || !consumed->server_hello || consumed->consumed!=sh.size()) return 5;
        Bytes root{1},name{'l'};std::array<std::span<std::uint8_t const>,1> anchors{root};
        auto handshake=client->take_handshake(anchors,t::PeerNameKind::dns,name,0);if (!handshake) return 6;
        Bytes ee=negotiated ? Bytes{8,0,0,8,0,6,0,28,0,2,0,64} : Bytes{8,0,0,2,0,0};
        auto wire=server->write.seal(t::ContentType::handshake,ee,total-ee.size()-1);if (!wire) return 7;
        Bytes huge{23,3,3,0x41,0x01};
        auto result=handshake->feed(huge_header ? std::span<std::uint8_t const>(huge) : std::span<std::uint8_t const>(*wire));
        if (huge_header || (negotiated && total==65)) {
            if (result || result.error()!=t::ClientHandshakeError::record_overflow) return 8;
            auto alert=handshake->take_overflow_alert();if (!alert || handshake->take_overflow_alert()) return 10;
            auto plain=server->read.open(*alert);
            if (!plain || plain->type!=t::ContentType::alert || plain->content!=Bytes({2,22})) return 11;
        } else if (!result || result->consumed!=wire->size()) return 9;
    }
    if (!io_test(false) || !io_test(true) || !io_test(false,1) || !io_test(false,2)) return 12;
    for(bool negotiated:{false,true}) for(bool first:{false,true}) if(!split_test(negotiated,first)) return 13;
    if(!split_header_test()) return 14;
    std::println("EE record negotiated limit, encrypted alert, partial write and cancellation passed");
}
