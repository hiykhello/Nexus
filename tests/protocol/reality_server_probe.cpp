import std;
import reality.auth;
import reality.server_auth;
import reality.server_probe;
import memory.budget;
import tls.hello;
import tls.key_share;
namespace r=reality; namespace c = ::crypto; namespace t=tls;
auto record(std::span<std::uint8_t const> data) -> c::Bytes {
    c::Bytes out{22,3,3,static_cast<std::uint8_t>(data.size()>>8),static_cast<std::uint8_t>(data.size())}; out.insert(out.end(),data.begin(),data.end()); return out;
}
int main() {
    std::array<std::uint8_t,32> a{},b{}; a[0]=7; b[0]=9;
    auto client=c::X25519Private::from_bytes(a),server=c::X25519Private::from_bytes(b); if (!client || !server) return 1;
    auto cp=client->public_key(),sp=server->public_key(); if (!cp || !sp) return 2;
    t::ClientHello hello; hello.session_id.resize(32); hello.cipher_suites={0x1301}; hello.compression_methods={0};
    hello.extensions.push_back({0,{0,12,0,0,9,'l','o','c','a','l','h','o','s','t'}}); hello.extensions.push_back({43,{2,3,4}});
    t::KeyShareEntry share{0x001d,c::Bytes(cp->begin(),cp->end())}; auto ext=t::KeyShare::encode_client(std::span{&share,1}); if (!ext) return 3;
    hello.extensions.push_back({51,*ext}); auto body=hello.encode(); if (!body) return 4;
    auto size=body->size(); c::Bytes message{1,static_cast<std::uint8_t>(size>>16),static_cast<std::uint8_t>(size>>8),static_cast<std::uint8_t>(size)};
    message.insert(message.end(),body->begin(),body->end()); r::Identity id{{1,0,0},1234,{1,2,3,4,5,6,7,8}};
    auto sealed=r::seal_client_hello(message,*client,*sp,id); if (!sealed) return 5;
    auto first=record(std::span(sealed->wire).first(20)),second=record(std::span(sealed->wire).subspan(20));
    c::Bytes all=first; all.insert(all.end(),second.begin(),second.end()); all.insert(all.end(),{20,3,3,0,1,1});
    std::array names{std::string("localhost")}; std::array<std::array<std::uint8_t,8>,1> ids{id.short_id}; r::ServerPolicy policy{names,ids,{}, {},10};
    for (std::size_t chunk:{std::size_t{1},std::size_t{4096}}) {
        auto probe=r::ServerProbe::create(); if (!probe) return 6;
        std::size_t pos=0;
        while (pos<all.size() && probe->status()==r::ProbeStatus::pending) {
            auto n=std::min(chunk,all.size()-pos); auto fed=probe->feed(std::span(all).subspan(pos,n),*server,policy,1234); pos+=fed.consumed;
            if (!fed.consumed) return 7;
        }
        if (probe->status()!=r::ProbeStatus::authenticated || !std::ranges::equal(probe->bytes(),std::span(all).first(pos))) return 8;
        auto auth=probe->take_authentication(); if (!auth || auth->identity.short_id!=id.short_id || probe->take_authentication()) return 9;
        if (probe->feed(std::span(all).subspan(pos),*server,policy,1234).consumed) return 10;
    }
    auto malformed=all; malformed[0]=23; auto rejected=r::ServerProbe::create();
    if (!rejected || rejected->feed(malformed,*server,policy,1234).status!=r::ProbeStatus::fallback || !std::ranges::equal(rejected->bytes(),malformed)) return 11;
    auto limited=r::ServerProbe::create(8); if (!limited) return 12;
    auto fed=limited->feed(all,*server,policy,1234);
    if (fed.status!=r::ProbeStatus::fallback || fed.consumed!=8 || !std::ranges::equal(limited->bytes(),std::span(all).first(8))) return 13;
    ids[0][0]^=1; auto denied=r::ServerProbe::create(); if (!denied || denied->feed(all,*server,policy,1234).status!=r::ProbeStatus::fallback || !std::ranges::equal(denied->bytes(),all)) return 14;
    auto charge=r::ServerProbe::charge(131072);
    auto budget=std::make_shared<::memory::Budget>(charge);
    { auto too_small=std::make_shared<::memory::Budget>(charge-1);
      if (r::ServerProbe::create(131072,too_small) || too_small->reserved()!=0) return 15;
      auto admitted=r::ServerProbe::create(131072,budget); if (!admitted || budget->reserved()!=charge) return 16;
      auto moved=std::move(*admitted); if (budget->reserved()!=charge) return 17;
      if (moved.feed(all,*server,policy,1234).status!=r::ProbeStatus::fallback) return 18;
    }
    if (budget->reserved()!=0) return 19;
    std::println("Reality bounded ClientHello probe and exact replay passed");
}
