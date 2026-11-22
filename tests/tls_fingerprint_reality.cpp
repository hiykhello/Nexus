import std;
import tls.fingerprint;
import reality.client;

namespace t=tls;
namespace r=reality;
namespace c = ::crypto;
int main() {
    auto server=c::X25519Private::generate();if(!server)return 1;
    auto public_key=server->public_key();if(!public_key)return 2;
    r::Identity identity{{1,8,24},123456,{1,2,3,4,5,6,7,8}};
    std::set<c::Bytes> wire_hashes;
    for(auto profile:{t::Fingerprint::tls13_grease,t::Fingerprint::tls13_randomized})
      for(auto shares:{t::FingerprintShares::x25519,t::FingerprintShares::hybrid,t::FingerprintShares::dual})
       for(unsigned trial=0;trial<8;++trial) {
        t::FingerprintConfig policy{profile,shares,1600};
        auto shape=t::make_fingerprint_hello("cover.example",{},policy);if(!shape)return 3;
        auto session=r::create_client_session(std::move(shape->hello),shape->initial_groups(),*public_key,identity);if(!session)return 4;
        auto record=session->initial_record();if(!record||record->size()!=1600)return 5;
        auto wire=std::span(*record).subspan(5);
        auto parsed=t::ClientHello::parse(wire.subspan(4));if(!parsed||parsed->session_id.size()!=32)return 6;
        auto offers=t::KeyShare::parse_client(parsed->extension(51)->data);if(!offers)return 7;
        std::optional<std::span<std::uint8_t const>> x,hybrid;
        for(auto const& entry:*offers) {
            if(entry.group==29)x=entry.key_exchange;
            if(entry.group==t::x25519_mlkem768_group)hybrid=std::span(entry.key_exchange).last(32);
        }
        auto auth_key=x ? *x : *hybrid;
        auto opened=r::open_client_hello(wire,*server,auth_key);
        if(!opened||opened->identity.version!=identity.version||opened->identity.timestamp!=identity.timestamp||opened->identity.short_id!=identity.short_id)return 8;
        auto digest=c::digest(c::Hash::sha256,wire);if(!digest||!wire_hashes.insert(*digest).second)return 9;
        auto damaged=*record;damaged.back()^=1;
        if(r::open_client_hello(std::span(damaged).subspan(5),*server,auth_key))return 10;
        if(shares==t::FingerprintShares::dual&&r::open_client_hello(wire,*server,*hybrid))return 11;
       }
    auto shape=t::make_fingerprint_hello("cover.example",{},{});if(!shape)return 12;
    if(r::create_client_session(shape->hello,std::span<std::uint16_t const>{},*public_key,identity))return 13;
    std::println("48 shaped Reality first-Hello authentications, shared dual-key preference, freshness and exact-wire tamper rejection passed");
}
