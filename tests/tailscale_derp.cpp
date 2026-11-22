import std;
import tailscale.derp;
import tailscale.derp_messages;
import tailscale.stun;
namespace d=tailscale::derp;
namespace s=tailscale::stun;
using Bytes=std::vector<std::uint8_t>;
auto require(bool value,std::string_view message) -> void { if (!value) throw std::runtime_error(std::string(message)); }
auto seq(unsigned start,std::size_t count) -> Bytes {
    Bytes result(count); for (std::size_t i=0;i<count;++i) result[i]=static_cast<std::uint8_t>(start+i); return result;
}
template<std::size_t N> auto sequence(unsigned first) -> std::array<std::uint8_t,N> {
    std::array<std::uint8_t,N> result{}; for (std::size_t i=0;i<N;++i) result[i]=static_cast<std::uint8_t>(first+i); return result;
}
auto hex(std::span<std::uint8_t const> bytes) -> std::string {
    constexpr std::string_view digits="0123456789abcdef"; std::string result;
    for (auto byte:bytes) { result.push_back(digits[byte>>4]); result.push_back(digits[byte&15]); } return result;
}
auto vectors() -> std::map<std::string,Bytes> {
    auto key=sequence<32>(0),other=sequence<32>(32); auto nonce=sequence<24>(64); auto sealed=seq(88,32);
    std::map<std::string,Bytes> result;
    auto put=[&](std::string name,auto encoded) {
        require(bool(encoded),"encode failed"); result.emplace(std::move(name),std::move(*encoded));
    };
    put("server-key",d::encode_server_key(key,std::array<std::uint8_t,2>{0xfe,0xff}));
    put("client-info",d::encode_client_info(other,nonce,sealed));
    put("server-info",d::encode_server_info(nonce,sealed));
    put("send-empty",d::encode_packet(d::Type::send_packet,key,{}));
    put("recv-empty",d::encode_packet(d::Type::recv_packet,other,{}));
    put("send-packet",d::encode_packet(d::Type::send_packet,key,seq(100,17)));
    put("recv-packet",d::encode_packet(d::Type::recv_packet,other,seq(101,19)));
    put("forward-packet",d::encode_forwarded_packet(key,other,seq(102,23)));
    put("keep-alive",d::encode_frame(d::Type::keep_alive,{}));
    put("preferred",d::encode_note_preferred(true)); put("not-preferred",d::encode_note_preferred(false));
    put("peer-gone",d::encode_peer_gone(key,1)); put("ping",d::encode_ping(d::Type::ping,sequence<8>(1)));
    put("pong",d::encode_ping(d::Type::pong,sequence<8>(2)));
    constexpr std::string_view health="duplicate";
    put("health",d::encode_frame(d::Type::health,{reinterpret_cast<std::uint8_t const*>(health.data()),health.size()}));
    put("restarting",d::encode_restarting(25,0xffffffff));
    put("watch-connections",d::encode_frame(d::Type::watch_connections,{}));
    put("close-peer",d::encode_frame(d::Type::close_peer,other));
    put("unknown",d::encode_frame(static_cast<d::Type>(0xfe),std::array<std::uint8_t,3>{1,2,3}));
    auto request=s::encode_request(sequence<12>(0)); result["stun-request"]={request.begin(),request.end()};
    auto one=s::encode_response(sequence<12>(0),s::Endpoint{4,{192,0,2,1},3478});
    s::Endpoint v6{6,{0x20,0x01,0x0d,0xb8},9999}; v6.address[14]=0x12; v6.address[15]=0x34;
    auto two=s::encode_response(sequence<12>(0),v6);
    require(one && two,"STUN encode failed");
    result["stun-192.0.2.1:3478"]={one->view().begin(),one->view().end()};
    result["stun-[2001:db8::1234]:9999"]={two->view().begin(),two->view().end()};
    return result;
}
auto fragmentation(Bytes const& wire) -> void {
    auto header=d::parse_header(wire); require(bool(header),"missing header");
    for (std::size_t split=0;split<=wire.size();++split) {
        d::Decoder decoder;
        auto first=decoder.feed(std::span(wire).first(split));
        require(!first.error && first.consumed==split,"split prefix rejected");
        auto second=decoder.feed(std::span(wire).subspan(split));
        require(!second.error && second.consumed==wire.size()-split && second.ready,"split suffix rejected");
        auto frame=decoder.frame();
        require(frame && frame->type==header->type && std::ranges::equal(frame->payload,std::span(wire).subspan(5)),"split payload mismatch");
        require(decoder.feed(wire).consumed==0 && decoder.consume() && decoder.at_boundary(),"retention boundary lost");
    }
    d::Decoder decoder;
    for (std::size_t i=0;i<wire.size();++i) {
        auto fed=decoder.feed(std::span(wire).subspan(i,1));
        require(fed.consumed==1 && !fed.error && fed.ready==(i+1==wire.size()),"single-byte feed failed");
    }
}
auto messages(std::map<std::string,Bytes> const& values) -> void {
    auto frame=[&](std::string const& name) {
        auto const& wire=values.at(name); return d::Frame{static_cast<d::Type>(wire[0]),std::span(wire).subspan(5)};
    };
    auto key=d::parse_server_key(frame("server-key")); require(key && *key==sequence<32>(0),"server key");
    auto client=d::parse_client_info(frame("client-info"));
    require(client && client->node==sequence<32>(32) && client->sealed.nonce==sequence<24>(64) &&
        std::ranges::equal(client->sealed.ciphertext,seq(88,32)),"client encrypted envelope");
    require(d::parse_server_info(frame("server-info")).has_value(),"server encrypted envelope");
    require(!d::parse_sealed_info(std::span(values.at("server-info")).first(39)),"short encrypted info accepted");
    auto sent=d::parse_packet(frame("send-packet"),d::Type::send_packet);
    auto received=d::parse_packet(frame("recv-packet"));
    require(sent && sent->peer==sequence<32>(0) && std::ranges::equal(sent->bytes,seq(100,17)),"send packet");
    require(received && received->peer==sequence<32>(32) && std::ranges::equal(received->bytes,seq(101,19)),"recv packet");
    require(d::parse_packet(frame("recv-empty"))->bytes.empty(),"empty packet not retained");
    auto forwarded=d::parse_forwarded_packet(frame("forward-packet"));
    require(forwarded && forwarded->source==sequence<32>(0) && forwarded->destination==sequence<32>(32) &&
        std::ranges::equal(forwarded->bytes,seq(102,23)),"forward packet");
    require(d::parse_note_preferred(frame("preferred"))==true && d::parse_note_preferred(frame("not-preferred"))==false,"preferred");
    require(d::parse_peer_gone(frame("peer-gone"))->reason==1,"peer gone");
    require(d::parse_ping(frame("ping"))==sequence<8>(1) && d::parse_ping(frame("pong"),d::Type::pong)==sequence<8>(2),"ping/pong");
    auto restarting=d::parse_restarting(frame("restarting"));
    require(restarting && restarting->reconnect_in==std::chrono::milliseconds(25) &&
        restarting->try_for==std::chrono::milliseconds(0xffffffff),"restart unsigned duration");
    require(d::parse_close_peer(frame("close-peer"))==sequence<32>(32),"close peer");
    auto body=seq(0,32);
    auto present=d::parse_peer_present({d::Type::peer_present,body}); require(present && !present->address,"legacy peer present");
    body.insert(body.end(),16,0); body[47]=1; body.insert(body.end(),{0x01,0xbb,1,4,'t','e','s','t'});
    present=d::parse_peer_present({d::Type::peer_present,body});
    require(present && present->address && present->port==443 && present->flags==1 && present->app_name=="test","extended peer present");
    body[51]=32;
    present=d::parse_peer_present({d::Type::peer_present,body});
    require(present && present->app_name.empty(),"truncated optional app name");
    body=seq(0,32);
    require(d::parse_peer_gone({d::Type::peer_gone,body})->reason==0,"legacy peer gone");
    body.push_back(1); body.push_back(2);
    require(d::parse_peer_gone({d::Type::peer_gone,body})->reason==1,"future peer gone suffix");
    require(!d::parse_packet(frame("ping")) && !d::parse_ping(frame("send-empty")) && !d::parse_server_key(frame("server-info")),"type confusion");
}
auto bounds(std::map<std::string,Bytes> const& values) -> void {
    Bytes combined=values.at("ping"); auto const& tail=values.at("unknown"); combined.insert(combined.end(),tail.begin(),tail.end());
    d::Decoder decoder;
    auto fed=decoder.feed(combined); require(fed.ready && fed.consumed==values.at("ping").size(),"consumed following frame");
    require(decoder.consume(),"first consume"); fed=decoder.feed(std::span(combined).subspan(fed.consumed));
    require(fed.ready && fed.consumed==tail.size() && !d::known(decoder.frame()->type),"unknown frame not bounded");
    require(decoder.consume() && decoder.finish().has_value(),"boundary EOF");
    auto large=seq(0,d::max_packet_size);
    auto encoded=d::encode_packet(d::Type::recv_packet,sequence<32>(0),large); require(bool(encoded),"maximum packet rejected");
    d::Decoder full; fed=full.feed(*encoded);
    require(fed.ready && full.retained_bytes()==32+d::max_packet_size && d::parse_packet(*full.frame())->bytes.size()==d::max_packet_size,"maximum packet");
    large.push_back(0); require(!d::encode_packet(d::Type::send_packet,sequence<32>(0),large),"oversized packet encoded");
    auto header=d::encode_header(d::Type::recv_packet,33+d::max_packet_size);
    d::Decoder limited; fed=limited.feed(*header);
    require(fed.error==d::Error::too_large && limited.retained_bytes()==0,"oversized packet allocated");
    std::array<std::uint8_t,5> huge{0xfe,0xff,0xff,0xff,0xff};
    d::Decoder unknown; fed=unknown.feed(huge);
    require(fed.error==d::Error::too_large && fed.consumed==5 && unknown.retained_bytes()==0,"unbounded unknown frame");
    for (std::size_t size=1;size<values.at("client-info").size();++size) {
        d::Decoder truncated; auto part=truncated.feed(std::span(values.at("client-info")).first(size));
        require(!part.error && !truncated.finish() && truncated.finish().error()==d::Error::truncated,"partial EOF accepted");
    }
    full.close(); require(!full.frame() && full.feed(combined).error==d::Error::closed,"closed decoder reused");
}
auto main(int argc,char** argv) -> int {
    try {
        auto values=vectors();
        if (argc==2 && std::string_view(argv[1])=="--vectors") {
            std::cout<<'{'; bool first=true;
            for (auto const& [name,wire]:values) { if (!first) std::cout<<','; first=false; std::cout<<'"'<<name<<"\":\""<<hex(wire)<<'"'; }
            std::cout<<"}\n"; return 0;
        }
        for (auto const& [name,wire]:values) if (!name.starts_with("stun-")) fragmentation(wire);
        messages(values); bounds(values);
        std::println("DERP v2 bounded frames, encrypted envelopes, packet/control views, arbitrary fragments and retained boundaries passed");
    } catch (std::exception const& error) { std::cerr<<error.what()<<'\n'; return 1; }
}

