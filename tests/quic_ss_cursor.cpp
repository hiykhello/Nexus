import std;
import rules;
import shadowsocks.udp_dispatch;
import ss_udp.ordered_route;
import ss_udp.ordered_sniff;
import sniff.udp_quic;
import shadowsocks.udp_packet;

namespace r = ::rules;
namespace s=shadowsocks;
namespace d=shadowsocks::detail;

auto main() -> int {
    auto read=[]() -> std::vector<std::uint8_t> {
        std::array<unsigned char,2> length{};
        if(!std::cin.read(reinterpret_cast<char*>(length.data()),2))return {};
        auto size=(std::size_t(length[0])<<8)|length[1];std::vector<std::uint8_t> bytes(size);
        if(!std::cin.read(reinterpret_cast<char*>(bytes.data()),size))return {};
        return bytes;
    };
    auto first=read(),second=read();if(first.empty() || second.empty())return 1;
    std::vector<r::ProgramRule> rules{
        {r::RuleSet{{},2},{r::ProgramActionKind::resolve}},
        {r::RuleSet{{},2},{r::ProgramActionKind::sniff}},
        {r::RuleSet{{{"domain","example.com"}},2},{r::ProgramActionKind::reject},r::DomainSource::sniffed},
        {r::RuleSet{{},2},{r::ProgramActionKind::route,0}}
    };
    auto program=r::RouteProgram::compile(rules,2);if(!program)return 2;
    s::UdpAccepted packet{};packet.source={4,{127,0,0,1},12345};
    packet.packet.address={3,4,'t','e','s','t',0x01,0xbb};packet.packet.payload=first;
    d::OrderedUdpDecision decision(packet,*program,"edge",true,0);
    packet.packet.address.clear();packet.packet.payload.clear();
    if(decision.next().stop!=d::OrderedUdpStop::resolve)return 3;
    std::array candidates{s::UdpPeer{4,{127,0,0,1},443}};
    if(!decision.supply(candidates) || decision.next(first,true).stop!=d::OrderedUdpStop::sniff_wait)return 4;
    if(decision.supply(candidates) || decision.next().stop!=d::OrderedUdpStop::error)return 5;
    auto result=decision.feed_sniff(second);
    if(result.status!=sniff::QuicProbeStatus::matched || result.domain!="example.com")return 6;
    if(!decision.finish_sniff(std::move(result)) || decision.next().stop!=d::OrderedUdpStop::reject)return 7;
    if(decision.finish_sniff({}))return 8;
    s::UdpAccepted fallback_packet{};fallback_packet.source={4,{127,0,0,1},12345};
    fallback_packet.packet.address={1,127,0,0,1,0x01,0xbb};fallback_packet.packet.payload=first;
    d::OrderedUdpDecision fallback(fallback_packet,*program,"edge",true,0);
    if(fallback.next(first,true).stop!=d::OrderedUdpStop::sniff_wait)return 9;
    auto unrelated=second;unrelated[6]^=1;
    if(fallback.feed_sniff(unrelated).status!=sniff::QuicProbeStatus::unrelated)return 10;
    if(!fallback.finish_sniff({}) || fallback.next().stop!=d::OrderedUdpStop::route)return 11;
    if(fallback.needs_resolution() || fallback.candidates().size()!=1 || fallback.candidates()[0].port!=443)return 12;
    auto policy=r::Matcher::compile({});if(!policy)return 13;
    s::UdpDispatcher dispatcher(std::move(*policy),128,8,128,8*1024*1024);
    using namespace std::chrono_literals;
    using Clock=std::chrono::steady_clock;
    auto now=Clock::time_point{};std::array<std::uint8_t,16> key{};
    s::UdpPacket wire_packet{{1},0,1000,{}, {1,127,0,0,1,0x01,0xbb},{}};
    auto check=[](bool ok,char const* message) {if(!ok)throw std::runtime_error(message);};
    auto start=[&](std::vector<std::uint8_t> const& data,s::UdpPeer source,Clock::duration lifetime=10s) {
        wire_packet.payload=data;auto wire=s::encode_udp_packet(key,s::UdpDirection::client,wire_packet,{});++wire_packet.packet_id;
        check(bool(wire),"encode");auto pending=dispatcher.begin_ordered(key,*wire,source,now,1000,now+lifetime);
        check(bool(pending),"admission");auto accepted=dispatcher.pending_packet(pending->token);
        auto cursor=std::make_shared<d::OrderedUdpDecision>(*accepted,*program,"edge",true,0);
        return d::OrderedUdpSniffOwner::Ready{pending->token,std::move(cursor),now+lifetime};
    };
    auto busy=[](std::uint64_t) {return false;};
    auto submit=[&](auto& owner,auto const& item) {return owner.submit(item.token,item.decision,item.deadline,now);};
    auto take=[&](auto& owner,auto token) {auto item=owner.pop(now,busy);check(item && item->token==token,"FIFO pop");};
    auto advance=[&](auto const& item,auto const& data) {
        auto step=item.decision->next(data,true);
        if(step.stop==d::OrderedUdpStop::resolve) {
            check(item.decision->supply(candidates),"DNS supply");step=item.decision->next(data,true);
        }
        return step.stop;
    };
    auto release=[&](auto& owner,auto const& item) {
        check(owner.complete(item.token) && dispatcher.pending_packet(item.token),"sender transfer canceled token");
        (void)dispatcher.cancel(item.token);
    };
    s::UdpPeer source{4,{127,0,0,1},12345,0};
    {
        // Admission order survives DNS. Opaque and complete Initial packets
        // cannot bypass the head; only a contributing fragment inherits SNI.
        d::OrderedUdpSniffOwner owner(dispatcher,100ms);wire_packet.address={3,4,'t','e','s','t',0x01,0xbb};
        auto a=start(first,source);check(submit(owner,a),"DNS head");take(owner,a.token);
        check(a.decision->next(first,true).stop==d::OrderedUdpStop::resolve,"DNS before sniff");
        std::vector<std::uint8_t> opaque{9,8,7};auto full=first;full.insert(full.end(),second.begin(),second.end());
        auto other=start(opaque,source),b=start(second,source),known=start(full,source);
        check(submit(owner,other) && submit(owner,b) && submit(owner,known) && !owner.pop(now,busy),"DNS held FIFO");
        check(a.decision->supply(candidates) && a.decision->next(first,true).stop==d::OrderedUdpStop::sniff_wait && owner.wait(a.token,now),"DNS sniff resume");
        auto dns_busy=[&](std::uint64_t token){return token==a.token;};check(!owner.pop(now,dns_busy),"DNS callback still active");
        take(owner,a.token);check(a.decision->next().stop==d::OrderedUdpStop::reject,"assembled head");release(owner,a);
        take(owner,other.token);check(advance(other,opaque)==d::OrderedUdpStop::route,"opaque inherited SNI");release(owner,other);
        take(owner,b.token);check(advance(b,second)==d::OrderedUdpStop::reject,"fragment SNI");release(owner,b);
        take(owner,known.token);check(advance(known,full)==d::OrderedUdpStop::reject,"complete Initial rules");release(owner,known);
        check(owner.empty(),"drained FIFO");
    }
    wire_packet.address={1,127,0,0,1,0x01,0xbb};
    {
        d::OrderedUdpSniffOwner owner(dispatcher,100ms);auto a=start(first,source);
        check(submit(owner,a),"isolation head");take(owner,a.token);
        check(advance(a,first)==d::OrderedUdpStop::sniff_wait && owner.wait(a.token,now),"isolation wait");
        auto changed=source;++changed.port;auto other_source=start(second,changed);
        changed=source;++changed.ingress;auto other_ingress=start(second,changed);
        wire_packet.address.back()=0xbc;auto other_target=start(second,source);wire_packet.address.back()=0xbb;
        wire_packet.session_id[0]=2;auto other_session=start(second,source);wire_packet.session_id[0]=1;
        std::array isolated{other_source,other_ingress,other_target,other_session};
        for(auto const& item:isolated) {
            check(submit(owner,item),"isolated submit");take(owner,item.token);
            check(advance(item,second)==d::OrderedUdpStop::sniff_wait && owner.wait(item.token,now),"isolated wait");
        }
        auto b=start(second,source);check(submit(owner,b),"matching submit");take(owner,a.token);
        check(a.decision->next().stop==d::OrderedUdpStop::reject,"matching head");release(owner,a);
        take(owner,b.token);check(advance(b,second)==d::OrderedUdpStop::reject,"matching fragment");release(owner,b);
        now+=100ms;
        for(auto const& item:isolated) {
            take(owner,item.token);check(item.decision->next().stop==d::OrderedUdpStop::route,"isolated timeout");release(owner,item);
        }
    }
    {
        d::OrderedUdpSniffOwner owner(dispatcher,100ms);auto a=start(first,source),b=start(unrelated,source);
        check(submit(owner,a) && submit(owner,b),"CID admission");take(owner,a.token);
        check(advance(a,first)==d::OrderedUdpStop::sniff_wait && owner.wait(a.token,now) && !owner.pop(now,busy),"CID isolation");
        now+=100ms;take(owner,a.token);check(a.decision->next().stop==d::OrderedUdpStop::route,"CID head timeout");release(owner,a);
        // Changing the CID without resealing also invalidates authentication.
        // Its own probe therefore resolves unknown immediately, without waiting.
        take(owner,b.token);check(advance(b,unrelated)==d::OrderedUdpStop::route,"tampered CID unknown fallback");release(owner,b);
    }
    {
        d::OrderedUdpSniffOwner owner(dispatcher,100ms);auto a=start(first,source),b=start(first,source);
        check(submit(owner,a) && submit(owner,b),"cancel admission");take(owner,a.token);
        check(advance(a,first)==d::OrderedUdpStop::sniff_wait && owner.wait(a.token,now),"cancel wait");
        (void)dispatcher.cancel(b.token);take(owner,a.token);
        check(a.decision->next().stop==d::OrderedUdpStop::route,"canceled fragment fallback");release(owner,a);check(owner.empty(),"cancel reclaimed");
    }
    {
        d::OrderedUdpSniffOwner owner(dispatcher,100ms);wire_packet.address={3,4,'t','e','s','t',0x01,0xbb};
        auto a=start(first,source,1ms),b=start(second,source);check(submit(owner,a) && submit(owner,b),"expiry admission");take(owner,a.token);
        check(a.decision->next().stop==d::OrderedUdpStop::resolve,"expiry DNS");now+=2ms;take(owner,b.token);
        check(!dispatcher.pending_packet(a.token) && advance(b,second)==d::OrderedUdpStop::sniff_wait && owner.wait(b.token,now),"promoted head");
        owner.stop();check(owner.empty() && !dispatcher.pending(),"stop drain");wire_packet.address={1,127,0,0,1,0x01,0xbb};
    }
    {
        d::OrderedUdpSniffOwner owner(dispatcher,100ms);auto a=start(first,source);check(submit(owner,a),"capacity head");take(owner,a.token);
        check(advance(a,first)==d::OrderedUdpStop::sniff_wait && owner.wait(a.token,now),"capacity wait");
        for(unsigned i=1;i<8;++i){auto item=start(first,source);check(submit(owner,item),"eight packet capacity");}
        auto excess=start(second,source);check(!submit(owner,excess),"ninth packet rejected");(void)dispatcher.cancel(excess.token);
        take(owner,a.token);check(a.decision->next().stop==d::OrderedUdpStop::route,"full flow unknown");release(owner,a);
        owner.stop();check(!dispatcher.pending(),"full flow cleanup");
    }
    {
        d::OrderedUdpSniffOwner owner(dispatcher,100ms);std::vector<std::uint8_t> large(65000,0xff);
        for(unsigned i=0;i<4;++i){auto item=start(large,source);check(submit(owner,item),"byte budget admission");}
        auto excess=start(large,source);check(!submit(owner,excess),"256 KiB byte budget");(void)dispatcher.cancel(excess.token);
        owner.stop();check(!dispatcher.pending(),"byte budget cleanup");
    }
    for(bool packets:{false,true}) {
        d::OrderedUdpSniffOwner owner(dispatcher,100ms);auto count=packets ? 64u : 32u;
        for(unsigned i=0;i<count;++i){auto peer=source;peer.port=20000+(packets ? i/8 : i);auto item=start(first,peer);check(submit(owner,item),"global admission");}
        auto peer=source;peer.port=21000;auto excess=start(first,peer);check(!submit(owner,excess),"global capacity");(void)dispatcher.cancel(excess.token);
        owner.stop();check(!dispatcher.pending(),"global cleanup");
    }
    {
        std::vector<r::ProgramRule> repeated{
            {r::RuleSet{{},2},{r::ProgramActionKind::resolve}},
            {r::RuleSet{{},2},{r::ProgramActionKind::sniff}},
            {r::RuleSet{{},2},{r::ProgramActionKind::resolve}},
            {r::RuleSet{{},2},{r::ProgramActionKind::sniff}},
            {r::RuleSet{{},2},{r::ProgramActionKind::route,0}}
        };
        auto repeat_program=r::RouteProgram::compile(repeated,2);check(bool(repeat_program),"repeat program");
        d::OrderedUdpSniffOwner owner(dispatcher,0ms);wire_packet.address={3,4,'t','e','s','t',0x01,0xbb};
        auto a=start(first,source);a.decision=std::make_shared<d::OrderedUdpDecision>(*dispatcher.pending_packet(a.token),*repeat_program,"edge",true,0);
        check(submit(owner,a),"repeat submit");take(owner,a.token);
        check(a.decision->next(first,true).stop==d::OrderedUdpStop::resolve && a.decision->supply(candidates),"first resolve");
        check(a.decision->next(first,true).stop==d::OrderedUdpStop::sniff_wait && owner.wait(a.token,now),"synchronous unknown");
        auto dns_busy=[&](std::uint64_t token){return token==a.token;};check(!owner.pop(now,dns_busy),"old DNS owner blocks new resolve");
        take(owner,a.token);
        check(a.decision->next(first,true).stop==d::OrderedUdpStop::resolve && a.decision->supply(candidates),"second resolve");
        check(a.decision->next(first,true).stop==d::OrderedUdpStop::route,"repeat sniff waited after unknown");release(owner,a);
        wire_packet.address={1,127,0,0,1,0x01,0xbb};
    }
    {
        d::OrderedUdpSniffOwner owner(dispatcher,100ms);auto a=start(first,source,100s);check(submit(owner,a),"session expiry admission");now+=63s;
        check(bool(dispatcher.expire(now,1063)),"session expiry");owner.tick(now);check(owner.empty() && !dispatcher.pending(),"stale session cleanup");
    }
    return 0;
}
