import std;
import tls.psk;
import tls.hello;
import tls.post_handshake;

namespace t=tls;namespace c = ::crypto;
using Bytes=std::vector<std::uint8_t>;using View=std::span<std::uint8_t const>;
auto hex(View bytes) -> std::string {
    std::string out;for(auto byte:bytes){out.push_back("0123456789abcdef"[byte>>4]);out.push_back("0123456789abcdef"[byte&15]);}return out;
}
auto frame(t::ClientHello const& hello) -> Bytes {
    auto body=hello.encode();if(!body)std::abort();auto n=body->size();Bytes wire{1,static_cast<std::uint8_t>(n>>16),static_cast<std::uint8_t>(n>>8),static_cast<std::uint8_t>(n)};
    wire.insert(wire.end(),body->begin(),body->end());return wire;
}
auto hello() -> t::ClientHello {
    t::ClientHello result;for(std::size_t i=0;i<result.random.size();++i)result.random[i]=static_cast<std::uint8_t>(i);
    result.cipher_suites={0x1301,0x1302,0x1303};result.compression_methods={0};
    result.extensions={{43,{2,3,4}},{10,{0,2,0,29}},{51,{0,0}},{13,{0,2,8,7}}};return result;
}
auto ticket(char tag='a') -> Bytes {
    return {0,9,58,129,0xff,0xff,0xff,0xf0,3,0,1,2,0,3,static_cast<std::uint8_t>(tag),'b','c',0,8,0,42,0,4,0,0,0,25};
}
int main() {
    for(auto hash:{c::Hash::sha256,c::Hash::sha384})for(auto kind:{t::PskKind::resumption,t::PskKind::external}) {
        auto n=t::psk_hash_size(hash);Bytes secret(n);for(std::size_t i=0;i<n;++i)secret[i]=static_cast<std::uint8_t>(0x41+i);
        Bytes identity{'p','s','k',0,'i','d'};t::PskOfferView offer{identity,secret,hash,kind,kind==t::PskKind::external ? 0u : 0xfedcba98u};
        auto first=hello();if(!t::prepare_psk_hello(first,std::span(&offer,1)))return 1;auto first_wire=frame(first);
        if(!t::seal_psk_binders(first,first_wire,std::span(&offer,1)))return 2;
        Bytes retry{2,0,0,3,2,3,4};
        for(bool hrr:{false,true}) {
            auto current=first;if(hrr)current.random.back()^=0x55;auto wire=frame(current);
            if(!t::seal_psk_binders(current,wire,std::span(&offer,1),hrr ? View(first_wire) : View{},hrr ? View(retry) : View{}))return 3;
            auto const& data=current.extensions.back().data;auto count=(std::size_t{data[0]}<<8)|data[1];auto binder=View(data).subspan(2+count+3);
            std::println("{{\"hash\":\"{}\",\"kind\":\"{}\",\"secret\":\"{}\",\"wire\":\"{}\",\"first\":\"{}\",\"retry\":\"{}\",\"binder\":\"{}\"}}",n==32 ? "sha256" : "sha384",kind==t::PskKind::resumption ? "resumption" : "external",hex(secret),hex(wire),hrr ? hex(first_wire) : "",hrr ? hex(retry) : "",hex(binder));
        }
    }
    // Simultaneous tickets can use different transcript hashes. Every binder
    // covers the same final-length prefix, not an earlier sibling's binder.
    Bytes id1{1},id2{2},s1(32,3),s2(48,4);std::array<t::PskOfferView,2> offers{{{id1,s1,c::Hash::sha256,t::PskKind::external,0},{id2,s2,c::Hash::sha384,t::PskKind::external,0}}};
    auto multi=hello();if(!t::prepare_psk_hello(multi,offers))return 4;auto multi_wire=frame(multi);
    if(!t::seal_psk_binders(multi,multi_wire,offers))return 5;
    for(auto const& offer:offers)std::println("{{\"multi\":true,\"hash\":\"{}\",\"kind\":\"external\",\"secret\":\"{}\",\"wire\":\"{}\",\"identity\":\"{}\"}}",t::psk_hash_size(offer.hash)==32 ? "sha256" : "sha384",hex(offer.secret),hex(multi_wire),hex(offer.identity));
    auto binding=t::TicketBinding{"server.example",{'h','2'},{}};binding.authentication_context[0]=1;
    for(auto hash:{c::Hash::sha256,c::Hash::sha384}) {
        Bytes master(t::psk_hash_size(hash),0xa5);auto body=ticket();
        auto material=t::ResumptionTicket::from_message(body,hash,master,binding,1000);if(!material)return 6;
        auto offer=material->offer(1030);if(!offer || offer->obfuscated_age!=14 || material->max_early_data()!=25 || material->usable(1000+604800000ull))return 7;
        std::println("{{\"ticket\":true,\"hash\":\"{}\",\"master\":\"{}\",\"nonce\":\"000102\",\"psk\":\"{}\"}}",master.size()==32 ? "sha256" : "sha384",hex(master),hex(offer->secret));
    }
    auto body=ticket();
    for(std::size_t n=0;n<body.size();++n)if(t::parse_new_session_ticket(View(body).first(n)))return 8;
    auto duplicate=body;duplicate[18]=16;duplicate.insert(duplicate.end(),body.begin()+19,body.end());if(t::parse_new_session_ticket(duplicate))return 9;
    auto zero=body;std::fill_n(zero.begin(),4,0);if(t::ResumptionTicket::from_message(zero,c::Hash::sha256,Bytes(32),binding,0).error()!=t::PskError::expired)return 10;
    t::ResumptionCache<2> cache;
    for(char tag:{'1','2','3'}) {
        auto entry=t::ResumptionTicket::from_message(ticket(tag),c::Hash::sha256,Bytes(32),binding,1000);if(!entry)return 11;cache.insert(std::move(*entry),1000);
    }
    if(cache.size()!=2)return 12;
    auto wrong=binding;wrong.authentication_context[1]^=1;std::array<std::uint16_t,1> suites{0x1301};
    if(cache.take(wrong,suites,1001) || cache.size()!=2)return 13;
    std::array<std::uint16_t,1> wrong_hash{0x1302};if(cache.take(binding,wrong_hash,1001) || cache.size()!=2)return 14;
    auto newest=cache.take(binding,suites,1001);if(!newest || newest->offer(1001)->identity[0]!='3' || cache.size()!=1)return 15;
    if(cache.take(binding,suites,999) || cache.size()!=0)return 16;
    auto bad=multi;bad.extensions.push_back({21,{0}});auto bad_wire=frame(bad);auto before=bad_wire;
    if(t::seal_psk_binders(bad,bad_wire,offers) || bad_wire!=before)return 17;
    std::println("{{\"complete\":true,\"binder_vectors\":10,\"ticket_vectors\":2,\"ordinary_NoPsk_size\":{}}}",sizeof(t::NoPsk));
}
