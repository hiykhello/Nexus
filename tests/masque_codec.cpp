import std;
import masque.datagram;
import masque.capsule;
import masque.ip_control;
import masque.ip_receiver;
import quic.varint;
namespace m=masque;
namespace q=quic;

auto test_datagrams() -> int {
    std::array<std::uint8_t,20> bytes{};
    for(auto stream:std::array<std::uint64_t,7>{0,4,252,256,65532,65536,q::max_varint-3}) {
        auto length=m::write_http3_datagram_prefix(bytes,stream);
        if(!length)return 1;
        bytes[*length]=0;bytes[*length+1]=0xaa;
        auto parsed=m::parse_http3_datagram(std::span(bytes).first(*length+2));
        if(!parsed || parsed->stream_id!=stream || parsed->payload.size()!=2)return 2;
        auto proxy=m::parse_proxy_datagram(parsed->payload,true);
        if(!proxy || proxy->context_id || proxy->payload.size()!=1 || proxy->payload[0]!=0xaa)return 3;
        for(std::size_t n=0;n<*length;++n)if(m::parse_http3_datagram(std::span(bytes).first(n)))return 4;
    }
    if(m::write_http3_datagram_prefix(bytes,1) || m::write_http3_datagram_prefix(bytes,q::max_varint) ||
       m::write_http3_datagram_prefix(std::span(bytes).first(0),0))return 5;
    std::array<std::uint8_t,8> oversized{};q::write_varint(oversized,m::max_quarter_stream_id+1);
    auto invalid=m::parse_http3_datagram(oversized);
    if(invalid || invalid.error()!=m::DatagramError::malformed)return 6;
    // A legal wider prefix is accepted and preserved in the consumed offset.
    std::array<std::uint8_t,4> wider{0x40,0x01,0,0xfe};
    auto parsed=m::parse_http3_datagram(wider);
    if(!parsed || parsed->stream_id!=4 || parsed->payload.size()!=2)return 7;
    if(m::parse_proxy_datagram({},true))return 8;
    std::array<std::uint8_t,1> context{3};
    auto unknown=m::parse_proxy_datagram(context,true);
    if(!unknown || unknown->context_id!=3 || !unknown->payload.empty())return 9;
    std::vector<std::uint8_t> jumbo(m::max_udp_payload+2,0);
    auto over=m::parse_proxy_datagram(jumbo,true);
    if(over || over.error()!=m::DatagramError::payload_too_large || !m::parse_proxy_datagram(jumbo,false))return 10;
    auto prefix=m::write_proxy_datagram_prefix(bytes,0,m::max_udp_payload,true);
    if(!prefix || m::write_proxy_datagram_prefix(bytes,0,m::max_udp_payload+1,true) ||
       !m::write_proxy_datagram_prefix(bytes,1,m::max_udp_payload+1,true))return 11;
    bytes[0]=0;auto empty=m::parse_proxy_datagram(std::span(bytes).first(1),true);
    if(!empty || !empty->payload.empty())return 12;
    // The same CONNECT-UDP payload has a stream prefix only on QUIC
    // DATAGRAM; its DATAGRAM capsule begins directly with Context ID.
    std::array<std::uint8_t,5> h3{1,0,'a','b','c'};
    std::array<std::uint8_t,6> capsule{0,4,0,'a','b','c'};
    auto h3_view=m::parse_http3_datagram(h3);
    auto h3_udp=h3_view ? m::parse_proxy_datagram(h3_view->payload,true) : std::expected<m::ProxyDatagramView,m::DatagramError>{std::unexpected(m::DatagramError::malformed)};
    m::CapsuleDecoder d;auto begin=d.feed(capsule);
    auto body=d.feed(std::span(capsule).subspan(begin.consumed));
    auto capsule_udp=m::parse_proxy_datagram(body.data,true);
    if(!h3_view || h3_view->stream_id!=4 || !h3_udp || begin.event!=m::CapsuleEvent::begin || begin.type!=0 ||
       body.event!=m::CapsuleEvent::data || !capsule_udp || !std::ranges::equal(h3_udp->payload,capsule_udp->payload))return 13;
    return 0;
}

auto test_capsules() -> int {
    // Unknown type with payload, empty DATAGRAM and a type/length split over
    // multiple QUIC varints. The decoder yields borrowed fragments in order.
    std::vector<std::uint8_t> wire{0x40,0x2a,0x03,1,2,3,0,0,0x80,0,0x40,0,0x40,0x04,4,5,6,7};
    for(std::size_t chunk=1;chunk<=wire.size();++chunk) {
        m::CapsuleDecoder decoder(64);std::size_t pos=0,begins=0,ends=0;
        std::vector<std::uint8_t> payload;std::array<std::uint64_t,3> types{},lengths{};
        while(pos<wire.size() || ends<3) {
            auto part=std::span(wire).subspan(pos,std::min(chunk,wire.size()-pos));
            auto result=decoder.feed(part);pos+=result.consumed;
            if(result.event==m::CapsuleEvent::begin) {
                if(begins>=3)return 20;types[begins]=result.type;lengths[begins++]=result.length;
            } else if(result.event==m::CapsuleEvent::data) {
                payload.insert(payload.end(),result.data.begin(),result.data.end());
            } else if(result.event==m::CapsuleEvent::end) ++ends;
            else if(result.event!=m::CapsuleEvent::need_more)return 21;
            if(pos==wire.size() && !result.consumed && result.event==m::CapsuleEvent::need_more)return 22;
        }
        if(types!=std::array<std::uint64_t,3>{42,0,16384} || lengths!=std::array<std::uint64_t,3>{3,0,4} ||
           payload!=std::vector<std::uint8_t>{1,2,3,4,5,6,7} || decoder.finish()!=m::CapsuleEvent::closed ||
           decoder.feed({}).event!=m::CapsuleEvent::closed)return 23;
    }
    std::array<std::uint8_t,16> output;output.fill(0xaa);auto original=output;
    if(m::write_capsule_prefix(std::span(output).first(1),64,4) || output!=original ||
       m::write_capsule_prefix(output,q::max_varint+1,0) || output!=original)return 24;
    auto size=m::write_capsule_prefix(output,64,100);
    if(!size || *size!=4)return 25;
    m::CapsuleDecoder limited(99);auto result=limited.feed(std::span(output).first(*size));
    if(result.event!=m::CapsuleEvent::limit || result.consumed!=*size || limited.finish()!=m::CapsuleEvent::limit)return 26;
    m::CapsuleDecoder exact;std::array<std::uint8_t,3> one{0,1,0x42};
    if(exact.feed(one).event!=m::CapsuleEvent::begin || exact.feed(std::span(one).last(1)).event!=m::CapsuleEvent::data ||
       exact.finish()!=m::CapsuleEvent::end || exact.feed(one).event!=m::CapsuleEvent::closed || exact.finish()!=m::CapsuleEvent::closed)return 28;
    auto huge_size=m::write_capsule_prefix(output,q::max_varint,q::max_varint);
    m::CapsuleDecoder huge;
    if(!huge_size || *huge_size!=16)return 29;
    auto announced=huge.feed(std::span(output).first(*huge_size));
    if(announced.event!=m::CapsuleEvent::begin || announced.type!=q::max_varint || announced.length!=q::max_varint ||
       huge.finish()!=m::CapsuleEvent::truncated)return 46;
    for(std::size_t n=1;n<wire.size();++n) {
        // The first capsule is six bytes; EOF at its exact boundary is legal.
        if(n==6 || n==8)continue;
        m::CapsuleDecoder d;
        auto part=std::span(wire).first(n);std::size_t offset=0;
        while(offset<part.size()) {
            auto event=d.feed(part.subspan(offset));offset+=event.consumed;
            if(event.event==m::CapsuleEvent::need_more && !event.consumed)break;
        }
        if(d.finish()!=m::CapsuleEvent::truncated)return 27;
    }
    return 0;
}
auto test_ip_control() -> int {
    std::array<std::uint8_t,64> output{};
    m::AddressEntry refusal{7,4,32,{}};
    if(!m::address_rejection(refusal))return 83;
    refusal.request_id=0;if(m::address_rejection(refusal))return 84;
    refusal={9,6,128,{}};if(!m::address_rejection(refusal))return 85;
    m::AddressEntry ipv4{64,4,24,{192,0,2,0}};
    auto written=m::write_address_entry(output,ipv4,true);
    if(!written || *written!=8)return 30;
    for(std::size_t i=0;i<*written;++i) {
        auto incomplete=m::read_address_entry(std::span(output).first(i),true);
        if(incomplete || incomplete.error()!=m::IpControlError::incomplete)return 31;
    }
    auto parsed=m::read_address_entry(std::span(output).first(*written),true);
    if(!parsed || parsed->value.request_id!=64 || parsed->value.address[2]!=2 || parsed->value.prefix_length!=24)return 32;
    ipv4.address[3]=1;
    if(m::write_address_entry(output,ipv4,true))return 33;
    ipv4.address[3]=0;ipv4.request_id=0;
    if(m::write_address_entry(output,ipv4,true) || !m::write_address_entry(output,ipv4,false))return 34;
    m::AddressEntry ipv6{q::max_varint,6,65,{0x20,1,0x0d,0xb8,0,0,0,0,0x80}};
    auto six=m::write_address_entry(output,ipv6,true);
    if(!six || *six!=26 || !m::read_address_entry(std::span(output).first(*six),true))return 35;
    ipv6.address[8]=0x81;if(m::write_address_entry(output,ipv6,true))return 36;
    ipv6.address[8]=0x80;ipv6.prefix_length=129;if(m::write_address_entry(output,ipv6,true))return 37;
    output[0]=0;output[1]=5;
    auto invalid=m::read_address_entry(std::span(output).first(2),false);
    if(invalid || invalid.error()!=m::IpControlError::malformed)return 38;

    m::RouteEntry a{4,6,{192,0,2,0},{192,0,2,127}};
    m::RouteEntry b{4,6,{192,0,2,128},{192,0,2,255}};
    m::RouteOrder order;if(!order.accept(a)||!order.accept(b)||order.accept(b))return 39;
    auto size=m::write_route_entry(output,a);if(!size || *size!=10)return 40;
    for(std::size_t i=0;i<*size;++i) {
        auto short_record=m::read_route_entry(std::span(output).first(i));
        if(short_record || short_record.error()!=m::IpControlError::incomplete)return 41;
    }
    auto route=m::read_route_entry(std::span(output).first(*size));
    if(!route || route->value.protocol!=6 || route->value.last[3]!=127)return 42;
    b.first[3]=129;b.last[3]=128;if(m::write_route_entry(output,b))return 43;
    m::RouteOrder protocols;auto higher=a;higher.protocol=17;
    if(!protocols.accept(a) || !protocols.accept(higher) || protocols.accept(a))return 44;
    m::RouteEntry v6{6,0,{0},{0}};if(!protocols.accept(v6) || protocols.accept(a))return 45;
    return 0;
}
auto test_ip_snapshots() -> int {
    m::IpControlState<2,2,3> state;
    std::array<std::uint8_t,128> wire{};
    m::AddressEntry first{1,4,24,{192,0,2,0}},second{2,4,32,{198,51,100,1}};
    auto a=m::write_address_entry(wire,first,true);
    auto b=m::write_address_entry(std::span(wire).subspan(*a),second,true);
    auto both=std::span(wire).first(*a+*b);
    if(!state.assign(both) || state.addresses().size()!=2)return 50;
    if(state.assign(both.first(both.size()-1)) || state.addresses().size()!=2 || state.addresses()[1].request_id!=2)return 51;
    if(!state.assign(std::span(wire).first(*a)) || state.addresses().size()!=1 || !state.assign({}) || !state.addresses().empty())return 52;
    std::array<m::AddressEntry,3> result{};
    if(state.request({},result) || !state.request(both,result) || result[0].request_id!=1 || result[1].request_id!=2)return 53;
    if(state.request(std::span(wire).first(*a),result).error()!=m::IpSnapshotError::reused_request_id)return 54;
    first.request_id=3;auto c=m::write_address_entry(wire,first,true);
    // An invalid tail must not reserve the otherwise valid ID.
    wire[*c]=0xff;
    if(state.request(std::span(wire).first(*c+1),result) || !state.request(std::span(wire).first(*c),result))return 55;
    first.request_id=4;c=m::write_address_entry(wire,first,true);
    if(state.request(std::span(wire).first(*c),result).error()!=m::IpSnapshotError::limit)return 56;
    m::IpControlState<1,2,3> duplicate;
    auto d=m::write_address_entry(std::span(wire).subspan(*c),first,true);
    if(duplicate.request(std::span(wire).first(*c+*d),result).error()!=m::IpSnapshotError::reused_request_id ||
       !duplicate.request(std::span(wire).first(*c),result))return 57;
    m::IpControlState<1,1,2> limits;
    if(!limits.assign(std::span(wire).first(*c)))return 61;
    if(limits.assign(std::span(wire).first(*c+*d)).error()!=m::IpSnapshotError::limit ||
       limits.addresses().size()!=1 || limits.addresses()[0].request_id!=4)return 62;
    result[0].request_id=99;
    if(limits.request(std::span(wire).first(*c+*d),std::span(result).first(1)).error()!=m::IpSnapshotError::limit ||
       result[0].request_id!=99 || !limits.request(std::span(wire).first(*c),result))return 63;
    m::RouteEntry route{4,0,{192,0,2,0},{192,0,2,127}};
    auto r=m::write_route_entry(wire,route);
    if(!state.advertise(std::span(wire).first(*r)))return 58;
    auto specific=route;specific.protocol=6;specific.first[3]=127;specific.last[3]=255;
    auto s=m::write_route_entry(std::span(wire).subspan(*r),specific);
    if(state.advertise(std::span(wire).first(*r+*s)) || state.routes().size()!=1 || state.routes()[0].protocol!=0)return 59;
    specific.first[3]=128;s=m::write_route_entry(std::span(wire).subspan(*r),specific);
    if(!state.advertise(std::span(wire).first(*r+*s)) || state.routes().size()!=2 ||
       state.advertise(std::span(wire).first(*r+*s-1)) || state.routes().size()!=2 ||
       !state.advertise({}) || !state.routes().empty())return 60;
    if(!limits.advertise(std::span(wire).first(*r)) ||
       limits.advertise(std::span(wire).first(*r+*s)).error()!=m::IpSnapshotError::limit ||
       limits.routes().size()!=1)return 64;
    return 0;
}
auto test_ip_capsules() -> int {
    // Unknown capsules are skipped; known empty and nonempty bodies are
    // emitted separately even when all bytes arrive in one feed.
    std::array<std::uint8_t,15> wire{42,3,7,8,9,1,7,0,4,192,0,2,0,24,3};
    std::vector<std::uint8_t> input(wire.begin(),wire.end());input.push_back(0);
    for(std::size_t chunk=1;chunk<=input.size();++chunk) {
        m::IpControlCapsules<7> capsules;std::size_t pos=0,events=0;
        while(pos<input.size() || events<2) {
            auto n=std::min(chunk,input.size()-pos);
            auto result=capsules.feed(std::span(input).subspan(pos,n));pos+=result.consumed;
            if(result.event==m::IpCapsuleEvent::complete) {
                if(events==0 && (result.type!=1 || result.body.size()!=7 || result.body[2]!=192))return 65;
                if(events==1 && (result.type!=3 || !result.body.empty()))return 66;
                if(++events>2)return 67;
            } else if(result.event!=m::IpCapsuleEvent::need_more)return 68;
            if(pos==input.size() && result.event==m::IpCapsuleEvent::need_more)return 69;
        }
        if(capsules.finish().event!=m::IpCapsuleEvent::closed || capsules.feed(input).event!=m::IpCapsuleEvent::closed)return 70;
    }
    m::IpControlCapsules<6> limited;
    auto large=limited.feed(input);
    if(large.event!=m::IpCapsuleEvent::limit || limited.finish().event!=m::IpCapsuleEvent::limit)return 71;
    for(std::size_t n=6;n<14;++n) {
        m::IpControlCapsules<7> truncated;
        auto result=truncated.feed(std::span(input).first(n));
        if(result.event!=m::IpCapsuleEvent::need_more || truncated.finish().event!=m::IpCapsuleEvent::truncated)return 72;
    }
    return 0;
}
struct IpSink {
    unsigned assignments=0,advertisements=0,requests=0,packets=0;
    std::size_t address_count=0,route_count=0;std::uint64_t request_id=0;
    std::uint8_t packet_byte=0;bool reject=false;
    auto assigned(std::span<m::AddressEntry const> entries) noexcept -> bool {
        if(reject)return false;++assignments;address_count=entries.size();return true;
    }
    auto routes(std::span<m::RouteEntry const> entries) noexcept -> bool {
        if(reject)return false;++advertisements;route_count=entries.size();return true;
    }
    auto requested(std::span<m::AddressEntry const> entries) noexcept -> bool {
        if(reject)return false;++requests;request_id=entries.front().request_id;return true;
    }
    auto packet(std::span<std::uint8_t const> data) noexcept -> void {++packets;packet_byte=data.empty() ? 0 : data[0];}
};
struct ReentrantIpSink : IpSink {
    void* owner=nullptr;
    m::IpReceiveStatus (*probe)(void*) noexcept = nullptr;
    m::IpReceiveStatus observed=m::IpReceiveStatus::active;
    auto assigned(std::span<m::AddressEntry const> entries) noexcept -> bool {
        observed=probe(owner);return IpSink::assigned(entries);
    }
};
auto test_ip_receiver() -> int {
    using Status=m::IpReceiveStatus;
    // Control and datagram capsules interleaved on one stream, arriving one
    // byte at a time, plus a QUIC DATAGRAM with the same Context format.
    std::array<std::uint8_t,26> wire{1,7,0,4,192,0,2,0,24,2,7,1,4,192,0,2,0,24,0,2,0,55,0,2,1,99};
    IpSink sink;m::IpReceiver<IpSink,32,2,2,2> receiver(sink);
    for(auto byte:wire)if(auto r=receiver.feed(std::span(&byte,1));r.status!=Status::active || r.consumed!=1)return 73;
    if(sink.assignments!=1 || sink.address_count!=1 || sink.requests!=1 || sink.request_id!=1 || sink.packets!=1 || sink.packet_byte!=55)return 74;
    std::array<std::uint8_t,2> datagram{0,77};
    if(receiver.datagram(datagram)!=Status::active || sink.packets!=2 || sink.packet_byte!=77)return 75;
    std::array<std::uint8_t,12> route{3,10,4,192,0,2,0,192,0,2,255,6};
    if(receiver.feed(route).status!=Status::active || sink.advertisements!=1 || sink.route_count!=1 || receiver.state().routes().size()!=1)return 81;
    // A failed replacement leaves the previous snapshot, and processing
    // stops before the following coalesced datagram.
    sink.reject=true;std::array<std::uint8_t,6> failed{1,0,0,2,0,88};
    auto result=receiver.feed(failed);
    if(result.status!=Status::sink_failure || result.consumed!=2 || receiver.state().addresses().size()!=1 || sink.packets!=2 ||
       receiver.feed(std::span(failed).subspan(2)).consumed!=0 || receiver.datagram(datagram)!=Status::sink_failure)return 76;
    IpSink second;m::IpReceiver<IpSink,32,2,2,2> duplicate(second);
    auto request=std::span(wire).subspan(9,9);
    if(duplicate.feed(request).status!=Status::active || duplicate.feed(request).status!=Status::reused_request_id || second.requests!=1)return 77;
    IpSink third;m::IpReceiver<IpSink,32,2,2,2> truncated(third);
    if(truncated.feed(std::span(wire).first(4)).status!=Status::active || truncated.finish()!=Status::malformed || third.assignments)return 78;
    IpSink fourth;m::IpReceiver<IpSink,3,1,1,1> bounded(fourth);
    // Oversized DATAGRAM is dropped; a later short datagram remains usable.
    std::array<std::uint8_t,11> oversized{0,4,0,1,2,3,0,3,0,9,8};
    if(bounded.feed(oversized).status!=Status::active || fourth.packets!=1 || fourth.packet_byte!=9 || bounded.finish()!=Status::closed)return 79;
    IpSink fifth;m::IpReceiver<IpSink,32,1,1,1> malformed(fifth);
    std::array<std::uint8_t,6> bad{0,0,0,2,0,1};
    auto rejected=malformed.feed(bad);
    if(rejected.status!=Status::malformed || rejected.consumed!=2 || fifth.packets)return 80;
    IpSink sixth;m::IpReceiver<IpSink,3,1,1,1> bad_large(sixth);
    std::array<std::uint8_t,6> incomplete_context{0,4,0xc0,0,0,0};
    if(bad_large.feed(incomplete_context).status!=Status::malformed || sixth.packets)return 82;
    IpSink seventh;m::IpReceiver<IpSink,3,1,1,1> split_context(seventh);
    std::array<std::uint8_t,14> wide{0,8,0xc0,0,0,0,0,0,0,0,0,2,0,7};
    for(auto byte:wide)if(split_context.feed(std::span(&byte,1)).status!=Status::active)return 86;
    if(seventh.packets!=1 || seventh.packet_byte!=7)return 87;
    ReentrantIpSink eighth;m::IpReceiver<ReentrantIpSink,32,1,1,1> guarded(eighth);
    eighth.owner=&guarded;eighth.probe=[](void* owner) noexcept {
        auto* receiver=static_cast<m::IpReceiver<ReentrantIpSink,32,1,1,1>*>(owner);
        std::array<std::uint8_t,2> packet{0,9};return receiver->datagram(packet);
    };
    if(guarded.feed(std::span(wire).first(9)).status!=Status::active || eighth.observed!=Status::reentrant || eighth.packets || guarded.state().addresses().size()!=1)return 88;
    return 0;
}
auto main() -> int {
    if(auto result=test_datagrams())return result;
    if(auto result=test_capsules())return result;
    if(auto result=test_ip_control())return result;
    if(auto result=test_ip_snapshots())return result;
    if(auto result=test_ip_capsules())return result;
    if(auto result=test_ip_receiver())return result;
    std::println("MASQUE HTTP datagram, capsule and IP control boundaries passed");
}
