import std;
import uot;
namespace u=uot;
using Bytes=std::vector<std::uint8_t>;
static auto hex(std::string_view text) -> Bytes {
    auto nibble=[](char c) { return c <= '9' ? c-'0' : c-'a'+10; };
    Bytes b; for (std::size_t i=0;i<text.size();i+=2) b.push_back(static_cast<std::uint8_t>((nibble(text[i])<<4)|nibble(text[i+1]))); return b;
}
int main() {
    // Produced by experiments/uot-vector using SagerNet sing v0.5.1.
    constexpr std::array samples{
        std::pair{"0101c00002010035","00c000020100350004deadbeef"},
        std::pair{"010420010db800000000000000000000000101bb","0120010db800000000000000000000000101bb0004deadbeef"},
        std::pair{"01030b6578616d706c652e636f6d14e9","020b6578616d706c652e636f6d14e90004deadbeef"}
    };
    for (auto const& [request_hex,packet_hex]:samples) {
        auto request=hex(request_hex), packet=hex(packet_hex);
        for (std::size_t n=0;n<request.size();++n) if (u::parse_request(std::span{request}.first(n)).status!=u::Status::incomplete) return 1;
        auto parsed=u::parse_request(request);
        if (parsed.status!=u::Status::accepted || !parsed.request.connected || parsed.consumed!=request.size()) return 2;
        auto joined_request=request; joined_request.insert(joined_request.end(),packet.begin(),packet.end());
        for (std::size_t split=0;split<=request.size();++split) {
            u::RequestDecoder incremental;
            auto first_part=incremental.feed(std::span(joined_request).first(split));
            if (first_part.consumed!=split || first_part.status!=(split==request.size() ? u::Status::accepted : u::Status::incomplete)) return 34;
            auto remaining=incremental.feed(std::span(joined_request).subspan(split));
            if (remaining.status!=u::Status::accepted || remaining.consumed!=request.size()-split ||
                !incremental.request() || incremental.request()->destination!=parsed.request.destination || !incremental.request()->connected) return 35;
            incremental.close(); if (incremental.request() || incremental.feed(packet).status!=u::Status::closed) return 36;
        }
        auto encoded=u::encode_request(parsed.request); if (!encoded || *encoded!=request) return 3;
        for (std::size_t n=0;n<packet.size();++n) if (u::parse_packet(false,{},std::span{packet}.first(n)).status!=u::Status::incomplete) return 4;
        auto decoded=u::parse_packet(false,{},packet);
        if (decoded.status!=u::Status::accepted || decoded.consumed!=packet.size() || decoded.destination!=parsed.request.destination || !std::ranges::equal(decoded.payload,hex("deadbeef"))) return 5;
        auto built=u::encode_packet(false,decoded.destination,decoded.payload); if (!built || *built!=packet) return 6;
        packet.insert(packet.end(),{0,0,0xff});
        decoded=u::parse_packet(false,{},packet); if (decoded.consumed!=packet.size()-3) return 7;
        auto connected=u::encode_packet(true,parsed.request.destination,hex("deadbeef"));
        if (!connected || *connected!=hex("0004deadbeef")) return 8;
        auto implicit=u::parse_packet(true,parsed.request.destination,*connected);
        if (implicit.status!=u::Status::accepted || implicit.destination!=parsed.request.destination || !std::ranges::equal(implicit.payload,hex("deadbeef"))) return 9;
    }
    if (u::parse_request(Bytes{1,99}).status!=u::Status::invalid_address || u::parse_request(Bytes{1,3,0}).status!=u::Status::invalid_address ||
        u::parse_packet(false,{},Bytes{99}).status!=u::Status::invalid_address || u::parse_packet(false,{},Bytes{2,0}).status!=u::Status::invalid_address) return 10;
    u::Address target{}; target.family=u::Family::domain; target.length=255; target.bytes.fill('a'); target.port=65535;
    auto largest_request=u::encode_request({false,target});
    if (!largest_request || largest_request->size()!=260) return 37;
    u::RequestDecoder largest_decoder;
    for (std::size_t i=0;i<largest_request->size();++i) {
        auto fed=largest_decoder.feed(std::span(*largest_request).subspan(i,1));
        if (fed.consumed!=1 || fed.status!=(i+1==largest_request->size() ? u::Status::accepted : u::Status::incomplete)) return 38;
    }
    if (!largest_decoder.request() || largest_decoder.request()->connected || largest_decoder.request()->destination!=target) return 39;
    u::RequestDecoder invalid_request;
    auto bad_request=invalid_request.feed(Bytes{1,3,0,42});
    if (bad_request.status!=u::Status::invalid_address || bad_request.consumed!=3 || invalid_request.feed(Bytes{1}).status!=u::Status::invalid_address) return 40;
    Bytes maximum(65535,0xa5);
    auto wire=u::encode_packet(false,target,maximum); if (!wire) return 11;
    auto parsed=u::parse_packet(false,{},*wire);
    if (parsed.status!=u::Status::accepted || parsed.destination!=target || !std::ranges::equal(parsed.payload,maximum)) return 12;
    maximum.push_back(0); if (u::encode_packet(false,target,maximum).error()!=u::Status::too_large) return 13;
    auto empty=u::encode_packet(true,{},{}); if (!empty || *empty!=Bytes{0,0} || u::parse_packet(true,{},*empty).status!=u::Status::accepted) return 14;
    target.length=0; if (u::encode_request({false,target}) || u::encode_packet(false,target,{})) return 15;
    auto request=hex("0001c00002010035");
    request.insert(request.end(),{0,0});
    auto nonconnected=u::parse_request(request);
    if (nonconnected.status!=u::Status::accepted || nonconnected.request.connected || nonconnected.consumed!=8) return 16;
    auto encoded=u::encode_request(nonconnected.request); if (!encoded || *encoded!=hex("0001c00002010035")) return 17;
    auto first=u::encode_packet(false,nonconnected.request.destination,hex("12"));
    auto second=u::encode_packet(false,nonconnected.request.destination,{});
    if (!first || !second) return 18;
    auto stream=*first; stream.insert(stream.end(),second->begin(),second->end());
    auto one=u::parse_packet(false,{},stream);
    auto two=u::parse_packet(false,{},std::span{stream}.subspan(one.consumed));
    if (one.status!=u::Status::accepted || one.consumed!=first->size() || two.status!=u::Status::accepted || two.consumed!=second->size() || !two.payload.empty()) return 19;
    for (bool connected : {false,true}) {
        auto a=u::encode_packet(connected,nonconnected.request.destination,hex("deadbeef"));
        auto b=u::encode_packet(connected,nonconnected.request.destination,{});
        if (!a || !b) return 20;
        Bytes joined=*a; joined.insert(joined.end(),b->begin(),b->end());
        for (std::size_t split=0;split<=a->size();++split) {
            u::PacketDecoder decoder(connected,nonconnected.request.destination);
            auto f=decoder.feed(std::span(joined).first(split));
            if (f.consumed!=split || f.status!=(split==a->size() ? u::Status::accepted : u::Status::incomplete)) return 21;
            auto rest=decoder.feed(std::span(joined).subspan(split));
            if (rest.status!=u::Status::accepted || rest.consumed!=a->size()-split) return 22;
            auto packet=decoder.packet();
            if (!packet || !std::ranges::equal(packet->payload,hex("deadbeef")) || decoder.at_boundary()) return 23;
            if (decoder.feed(*b).consumed!=0 || !decoder.consume() || !decoder.at_boundary()) return 24;
            auto next=decoder.feed(std::span(joined).subspan(a->size()));
            if (next.status!=u::Status::accepted || next.consumed!=b->size() || !decoder.packet()->payload.empty()) return 25;
            if (!decoder.consume()) return 26;
            decoder.close(); if (decoder.feed(*a).status!=u::Status::closed || decoder.at_boundary()) return 27;
        }
    }
    u::PacketDecoder limited(true,{},3);
    auto oversized=limited.feed(hex("0004deadbeef"));
    if (oversized.status!=u::Status::too_large || oversized.consumed!=2 || limited.feed({}).status!=u::Status::too_large) return 28;
    u::PacketDecoder bad(false);
    auto invalid=bad.feed(hex("0200"));
    if (invalid.status!=u::Status::invalid_address || invalid.consumed!=2 || bad.at_boundary()) return 29;
    u::PacketDecoder maximum_decoder(false,{},65535);
    for (std::size_t i=0;i<wire->size();++i) {
        auto fed=maximum_decoder.feed(std::span(*wire).subspan(i,1));
        if (fed.consumed!=1 || fed.status!=(i+1==wire->size() ? u::Status::accepted : u::Status::incomplete)) return 30;
    }
    if (!maximum_decoder.packet() || maximum_decoder.packet()->payload.size()!=65535 || !maximum_decoder.consume()) return 31;
    u::PacketDecoder partial(true);
    if (partial.feed(hex("0004de")).status!=u::Status::incomplete || partial.at_boundary()) return 32;
    partial.close(); if (partial.packet() || partial.feed(hex("adbeef")).status!=u::Status::closed) return 33;
    return 0;
}
