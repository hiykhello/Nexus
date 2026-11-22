#include <poll.h>

import std;
import crypto;
import net.udp_socket;
import wireguard.cookie;
import wireguard;
import wireguard.crypto;
import wireguard.endpoint;
import wireguard.registry;
import wireguard.port_types;
import wireguard.port;

namespace {
    using namespace wireguard;
    using namespace std::chrono_literals;
    struct SendCounts {
        static inline std::array<std::array<unsigned,5>,3> counts{};
        static inline bool block_data=false,block_cookie=false;
        static auto before_send(std::optional<PeerHandle> peer,OutboundKind kind,std::span<std::uint8_t const>) noexcept -> std::optional<std::error_code> {
            ++counts[peer ? peer->slot : 2][static_cast<unsigned>(kind)];
            if (block_cookie && kind==OutboundKind::cookie) return std::make_error_code(std::errc::resource_unavailable_try_again);
            if (block_data && kind==OutboundKind::data) return std::make_error_code(std::errc::resource_unavailable_try_again);
            return {};
        }
    };
    using TestPort=UdpPort<2,4,2048,8,SendCounts>;
    auto decode_key(std::string_view text) -> std::optional<Key> {
        if (text.size()!=64) return {};
        auto nibble=[](char c) { return c>='0' && c<='9' ? c-'0' : c>='a' && c<='f' ? c-'a'+10 : -1; };
        Key result;
        for (std::size_t i=0;i<32;++i) {
            auto a=nibble(text[2*i]),b=nibble(text[2*i+1]); if (a<0 || b<0) return {};
            result[i]=static_cast<std::uint8_t>((a<<4)|b);
        }
        return result;
    }
    auto outer(bool ipv6,unsigned port=0) -> EndpointAddress {
        EndpointAddress result{ipv6 ? std::uint8_t{6} : std::uint8_t{4},{},static_cast<std::uint16_t>(port)};
        if (ipv6) result.address[15]=1; else { result.address[0]=127; result.address[3]=1; } return result;
    }
    auto prefixes(unsigned node) -> std::vector<AllowedPrefix> {
        AllowedPrefix v4{4,{10,42,0,static_cast<std::uint8_t>(node)},32},v6{6,{},128};
        v6.address[0]=0xfd; v6.address[1]=0x42; v6.address[15]=static_cast<std::uint8_t>(node); return {v4,v6};
    }
    auto checksum(std::span<std::uint8_t const> bytes) -> std::uint16_t {
        std::uint32_t sum=0;
        for (std::size_t i=0;i<bytes.size();i+=2) sum+=(std::uint16_t(bytes[i])<<8)|(i+1<bytes.size() ? bytes[i+1] : 0);
        while (sum>>16) sum=(sum&65535)+(sum>>16);
        return static_cast<std::uint16_t>(~sum);
    }
    auto packet(unsigned index,unsigned remote,bool core_to_go,bool reply=false,unsigned source=0) -> std::vector<std::uint8_t> {
        constexpr std::array<std::size_t,10> sizes{0,1,15,16,17,63,64,65,512,1024};
        bool ipv6=index%2; auto header=ipv6 ? 40u : 20u; auto udp_size=8+sizes[index];
        auto from=source ? source : core_to_go ? 1u : remote, to=core_to_go ? remote : 1u;
        std::vector<std::uint8_t> result(header+udp_size);
        auto store=[&](std::size_t position,std::size_t value) { result[position]=static_cast<std::uint8_t>(value>>8); result[position+1]=static_cast<std::uint8_t>(value); };
        result[0]=ipv6 ? 0x60 : 0x45;
        if (ipv6) {
            store(4,udp_size); result[6]=17; result[7]=64; result[8]=result[24]=0xfd; result[9]=result[25]=0x42;
            result[23]=static_cast<std::uint8_t>(from); result[39]=static_cast<std::uint8_t>(to);
        } else {
            store(2,result.size()); result[8]=64; result[9]=17; result[12]=result[16]=10; result[13]=result[17]=42;
            result[15]=static_cast<std::uint8_t>(from); result[19]=static_cast<std::uint8_t>(to); store(10,checksum(std::span(result).first(20)));
        }
        store(header,(reply ? 20000 : 10000)+remote); store(header+2,(reply ? 10000 : 20000)+remote); store(header+4,udp_size);
        for (std::size_t i=0;i<sizes[index];++i) result[header+8+i]=static_cast<std::uint8_t>(index+i+remote);
        std::vector<std::uint8_t> pseudo;
        if (ipv6) { pseudo.insert(pseudo.end(),result.begin()+8,result.begin()+40); pseudo.insert(pseudo.end(),{0,0,static_cast<std::uint8_t>(udp_size>>8),static_cast<std::uint8_t>(udp_size),0,0,0,17}); }
        else { pseudo.insert(pseudo.end(),result.begin()+12,result.begin()+20); pseudo.insert(pseudo.end(),{0,17,static_cast<std::uint8_t>(udp_size>>8),static_cast<std::uint8_t>(udp_size)}); }
        pseudo.insert(pseudo.end(),result.begin()+header,result.end()); auto value=checksum(pseudo); store(header+6,value ? value : 65535); return result;
    }
}

auto main(int argc,char** argv) -> int {
    if (argc!=4) return 1;
    auto role=std::string_view(argv[1]),mode=std::string_view(argv[3]);
    bool ipv6=std::string_view(argv[2])=="6",initiate=role=="initiate",deadline=mode=="deadline";
    if ((!initiate && role!="respond") || (std::string_view(argv[2])!="4" && !ipv6) || (mode!="plain" && mode!="cookie" && mode!="auto-cookie" && mode!="backpressure" && mode!="stop-pending" && mode!="cookie-active" && !deadline)) return 1;
    SendCounts::block_data=mode=="stop-pending";
    std::string private_text,btext,ctext,ptext,qtext;
    if (!(std::cin>>private_text>>btext>>ctext>>ptext>>qtext)) return 2;
    auto private_key=decode_key(private_text),bkey=decode_key(btext),ckey=decode_key(ctext),bpsk=decode_key(ptext),cpsk=decode_key(qtext);
    std::fill(private_text.begin(),private_text.end(),'\0'); std::fill(ptext.begin(),ptext.end(),'\0'); std::fill(qtext.begin(),qtext.end(),'\0');
    if (!private_key || !bkey || !ckey || !bpsk || !cpsk) return 3;
    auto secret=::crypto::X25519Private::from_bytes(*private_key); if (!secret) return 23;
    auto public_key=secret->public_key(); if (!public_key) return 23;
    auto foreign_cookie=CookieGenerator::create(*public_key); if (!foreign_cookie) return 23;
    net::UdpSocket foreign;
    if (mode=="cookie-active" && !foreign.bind(outer(ipv6))) return 23;
    PortOptions options; options.require_cookie=mode=="cookie" || mode=="cookie-active";options.auto_cookie=mode=="auto-cookie";
    auto port=TestPort::create(*private_key,options); ::crypto::cleanse(*private_key);
    auto start=Clock::now();
    if (!port || !port->open(outer(ipv6),start,deadline ? start+300ms : start+35s)) return 4;
    auto local=port->local_endpoint(); if (!local) return 7;
    std::println("{{\"port\":{}}}",local->port); std::fflush(nullptr);
    unsigned bport=0,cport=0;
    if (!(std::cin>>bport>>cport) || bport>65535 || cport>65535 || !bport || !cport) return 2;
    auto first=EndpointConfig{.peer_public=*bkey,.allowed_ips={{4,{},0},{6,{},0}},.peer=outer(ipv6,bport)};
    auto second=EndpointConfig{.peer_public=*ckey,.allowed_ips={{4,{},0},{6,{},0}},.peer=outer(ipv6,cport)};
    auto b=port->add_peer(std::move(first),*bpsk),c=port->add_peer(std::move(second),*cpsk);
    ::crypto::cleanse(*bpsk); ::crypto::cleanse(*cpsk);
    if (!b || !c) return 5;
    for (auto const& prefix:prefixes(2)) if (!port->assign_route(*b,prefix)) return 6;
    for (auto const& prefix:prefixes(3)) if (!port->assign_route(*c,prefix)) return 6;
    if(mode=="auto-cookie") {
        net::UdpSocket trigger;if(!trigger.bind(outer(ipv6)))return 23;
        std::array<std::uint8_t,response_size> wire{};wire[0]=2;
        for(unsigned i=0;i<33;++i)if(!trigger.send(*local,wire))return 24;
        for(unsigned i=0;i<100 && !port->status().automatic_cookie_active;++i) {
            if(!port->poll(Clock::now(),std::chrono::system_clock::now()))return 25;
            std::this_thread::sleep_for(1ms);
        }
        if(!port->status().automatic_cookie_active)return 26;
        std::println("auto-cookie-ready");std::fflush(nullptr);
    }
    if (initiate) for (auto node:{2u,3u}) if (!port->enqueue_ip(packet(0,node,true),Clock::now())) return 8;
    std::array<unsigned,2> counts{};
    std::array<std::array<bool,10>,2> seen{};
    auto real_deadline=Clock::now()+30s;
    auto pause_until=start+500ms;
    bool paused=false,waited=mode=="backpressure",injected=false,held=false,readable=false,writable=false;
    std::array<unsigned,2> before_hold{};
    std::array<std::uint8_t,response_size> challenge{}; challenge[0]=2;challenge[4]=0xa5;
    while (Clock::now()<real_deadline && (counts[0]<10 || counts[1]<10)) {
        auto now=Clock::now();
        if (deadline) {
            auto polled=port->poll(now,std::chrono::system_clock::now());
            if (!polled) {
                if (polled.error().code==PortError::timeout && port->drained()) { std::println("deadline stopped and drained both peer queues"); return 0; }
                return 9;
            }
            std::this_thread::sleep_for(1ms); continue;
        }
        auto polled=port->poll(now,std::chrono::system_clock::now());
        if (!polled) {
            if (deadline && polled.error().code==PortError::timeout && port->drained()) { std::println("deadline stopped and drained both peer queues"); return 0; }
            std::println("port failed {}",static_cast<unsigned>(polled.error().code)); return 9;
        }
        if (mode=="stop-pending" && port->status().pending_sends==2) {
            auto before=port->status();
            if (!polled->write_blocked || before.business_packets!=2 || before.business_bytes!=56 || before.registry.indexes!=2 || !port->peer_status(*b)->current || !port->peer_status(*c)->current) return 21;
            port->stop(); if (!port->drained() || port->native_handle()!=-1) return 22;
            std::println("stop drained two confirmed peers with two EAGAIN business packets and 56 charged bytes"); return 0;
        }
        if (mode=="cookie-active" && injected && !held && port->status().pending_sends && polled->write_blocked) {
            held=true; before_hold=counts;
            if (counts[0]>=9 || counts[1]>=9) return 24;
        }
        if (mode=="backpressure" && waited && now<pause_until) { paused|=polled->read_paused; std::this_thread::sleep_for(1ms); continue; }
        while (auto received=port->take_packet()) {
            auto position=received->peer==*b ? 0u : received->peer==*c ? 1u : 2u;
            if (position>1 || !port->valid(received->peer) || counts[position]>=10) return 10;
            auto node=position+2;
            auto index=counts[position];
            if (mode=="backpressure") {
                index=10;
                for (unsigned candidate=0;candidate<10;++candidate) if (!seen[position][candidate] && std::ranges::equal(received->packet(),packet(candidate,node,false,initiate))) { index=candidate; break; }
            }
            auto expected=index<10 ? packet(index,node,false,initiate) : std::vector<std::uint8_t>{};
            if (index>=10 || !std::ranges::equal(received->packet(),expected)) { std::println("peer {} inner {} mismatch: {} bytes",node,counts[position],received->size); return 11; }
            seen[position][index]=true;
            if (!initiate) { if (!port->enqueue_ip(packet(index,node,true,true),now)) return 12; }
            ++counts[position];
            if (initiate && counts[position]<10) { if (!port->enqueue_ip(packet(counts[position],node,true),now)) return 13; }
        }
        if (mode=="cookie-active" && !injected && counts[0]>=1 && counts[1]>=1) {
            if (counts[0]>=9 || counts[1]>=9 || !port->peer_status(*b)->current || !port->peer_status(*c)->current) return 24;
            SendCounts::block_cookie=true;
            if (!foreign_cookie->apply(challenge,now) || !foreign.send(*local,challenge)) return 25;
            injected=true;
        }
        if (mode=="cookie-active" && held) {
            short events=static_cast<short>((polled->read_paused ? 0 : POLLIN)|(polled->write_blocked ? POLLOUT : 0));
            pollfd fd{port->native_handle(),events,0};
            if (::poll(&fd,1,1)<0) return 30;
            readable|=(fd.revents&POLLIN)!=0; writable|=(fd.revents&POLLOUT)!=0;
            if (!readable) { fd.events=POLLIN;fd.revents=0;if (::poll(&fd,1,5)<0)return 30;readable|=(fd.revents&POLLIN)!=0; }
        }
        std::this_thread::sleep_for(1ms);
    }
    if (mode=="cookie-active") {
        if (!injected || !held || !readable || !writable || counts[0]<=before_hold[0] || counts[1]<=before_hold[1] || !port->status().pending_sends) {
            std::println("cookie state injected {} held {} read {} write {} counts {} {} before {} {} pending {}",injected,held,readable,writable,counts[0],counts[1],before_hold[0],before_hold[1],port->status().pending_sends); return 26;
        }
        SendCounts::block_cookie=false;
        bool got=false;std::array<std::uint8_t,256> input{};
        for(unsigned i=0;i<100 && !got;++i) {
            if(!port->poll(Clock::now(),std::chrono::system_clock::now())) return 27;
            auto item=foreign.receive(input);if(!item)return 28;
            if(*item) got=(**item).valid && (**item).size==cookie_size && foreign_cookie->consume(std::span(input).first((**item).size),Clock::now()).has_value();
            std::this_thread::sleep_for(1ms);
        }
        if(!got || port->status().pending_sends) return 29;
        std::println("blocked cookie retained while both authenticated peers sent and received; POLLIN/POLLOUT observed; then recovered");
    }
    if (deadline) return 14;
    if (counts!=std::array<unsigned,2>{10,10} || (mode=="backpressure" && (!waited || !paused))) {
        auto status=port->status();
        std::println("shared-port counts {} {} received {} sent {} drops {} auth {} replay {} source {} keys {} pending {} ingress {} deliveries {}",counts[0],counts[1],status.metrics.received,status.metrics.sent,status.metrics.dropped,status.metrics.authentication_rejects,status.metrics.replay_rejects,status.metrics.source_rejects,status.registry.indexes,status.pending_sends,status.ingress.packets,status.delivery_packets);
        for (std::size_t i=0;i<SendCounts::counts.size();++i) std::println("slot {} init {} response {} data {} keepalive {} cookie {}",i,SendCounts::counts[i][0],SendCounts::counts[i][1],SendCounts::counts[i][2],SendCounts::counts[i][3],SendCounts::counts[i][4]);
        for (auto peer:{*b,*c}) { auto state=port->peer_status(peer); if (state) std::println("peer {} current {} pending {} handshake {} queued {} latest {}",peer.slot,state->current.value_or(0),state->pending.value_or(0),state->handshake.value_or(0),state->queued_packets,state->latest_attempt); }
        return 15;
    }
    // Flush the responder's final staged replies before stopping the port.
    for (unsigned attempt=0;attempt<100 && (port->status().business_packets || port->status().pending_sends);++attempt) {
        if (!port->poll(Clock::now(),std::chrono::system_clock::now())) return 16;
        std::this_thread::sleep_for(1ms);
    }
    auto before=port->status();
    if(mode=="auto-cookie" && !SendCounts::counts[2][static_cast<unsigned>(OutboundKind::cookie)])return 27;
    if (before.metrics.source_rejects<2 || before.registry.peers!=2 || before.registry.indexes!=2 || before.registry.reservations || before.business_packets || before.pending_sends || before.delivery_packets) {
        std::println("status source rejects {} peers {} indexes {} pending {} queued {}",before.metrics.source_rejects,before.registry.peers,before.registry.indexes,before.pending_sends,before.business_packets); return 17;
    }
    if (!port->erase_peer(*b) || port->valid(*b) || port->status().registry.peers!=1 || port->status().routes!=2 || port->status().keys!=1) return 18;
    auto routes_before=port->status().routes;
    auto old=port->assign_route(*b,prefixes(2).front()); if (old || port->status().routes!=routes_before) return 19;
    port->stop();
    if (!port->drained() || port->native_handle()!=-1 || port->status().registry.peers || port->take_packet()) return 20;
    std::println("Nexus WireGuard shared UDP port initial {}, outer IPv{}, mode {}, two peers x10 IPv4/IPv6 packets, global source rejects {}, stop/drain passed; sizeof port={}",role,ipv6 ? 6 : 4,mode,before.metrics.source_rejects,sizeof(TestPort));
}
