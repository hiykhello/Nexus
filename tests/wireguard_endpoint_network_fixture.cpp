import std;
import crypto;
import net.udp_socket;
import wireguard;
import wireguard.admission;
import wireguard.crypto;
import wireguard.endpoint;
import wireguard.identity;
import wireguard.registry;
import wireguard.routing;

namespace {
    using namespace wireguard;
    using namespace std::chrono_literals;
    struct StaticCounts {
        static inline unsigned dh=0,decrypt=0;
        static auto static_dh() noexcept -> void { ++dh; }
        static auto static_decrypt() noexcept -> void { ++decrypt; }
    };
    auto decode_key(std::string_view text) -> std::optional<Key> {
        if (text.size()!=64) return {};
        auto nibble=[](char c) { return c>='0' && c<='9' ? c-'0' : c>='a' && c<='f' ? c-'a'+10 : -1; };
        Key key;
        for (std::size_t i=0;i<32;++i) {
            auto a=nibble(text[2*i]),b=nibble(text[2*i+1]); if (a<0 || b<0) return {};
            key[i]=static_cast<std::uint8_t>((a<<4)|b);
        }
        return key;
    }
    auto checksum(std::span<std::uint8_t const> bytes) -> std::uint16_t {
        std::uint32_t sum=0;
        for (std::size_t i=0;i<bytes.size();i+=2) sum+=(std::uint16_t(bytes[i])<<8)|(i+1<bytes.size() ? bytes[i+1] : 0);
        while (sum>>16) sum=(sum&65535)+(sum>>16);
        return static_cast<std::uint16_t>(~sum);
    }
    auto packet(unsigned index,bool core_to_go,bool reply=false) -> std::vector<std::uint8_t> {
        constexpr std::array<std::size_t,10> sizes{0,1,15,16,17,63,64,65,512,1024};
        bool ipv6=index%2;
        auto header=ipv6 ? 40u : 20u;
        auto udp_size=8+sizes[index%10];
        std::vector<std::uint8_t> out(header+udp_size);
        auto store=[&](std::size_t offset,std::size_t value) { out[offset]=static_cast<std::uint8_t>(value>>8); out[offset+1]=static_cast<std::uint8_t>(value); };
        out[0]=ipv6 ? 0x60 : 0x45;
        if (ipv6) {
            store(4,udp_size); out[6]=17; out[7]=64;
            out[8]=out[24]=0xfd; out[9]=out[25]=0x42; out[23]=core_to_go ? 2 : 1; out[39]=core_to_go ? 1 : 2;
        } else {
            store(2,out.size()); out[8]=64; out[9]=17;
            out[12]=out[16]=10; out[13]=out[17]=42; out[15]=core_to_go ? 2 : 1; out[19]=core_to_go ? 1 : 2;
            store(10,checksum(std::span(out).first(20)));
        }
        auto epoch=index/10;
        store(header,(reply ? 20000 : 10000)+epoch); store(header+2,(reply ? 10000 : 20000)+epoch); store(header+4,udp_size);
        for (std::size_t i=0;i<sizes[index%10];++i) out[header+8+i]=static_cast<std::uint8_t>(index+i);
        std::vector<std::uint8_t> pseudo;
        if (ipv6) {
            pseudo.insert(pseudo.end(),out.begin()+8,out.begin()+40);
            pseudo.insert(pseudo.end(),{0,0,static_cast<std::uint8_t>(udp_size>>8),static_cast<std::uint8_t>(udp_size),0,0,0,17});
        } else {
            pseudo.insert(pseudo.end(),out.begin()+12,out.begin()+20);
            pseudo.insert(pseudo.end(),{0,17,static_cast<std::uint8_t>(udp_size>>8),static_cast<std::uint8_t>(udp_size)});
        }
        pseudo.insert(pseudo.end(),out.begin()+header,out.end()); auto value=checksum(pseudo);
        store(header+6,value ? value : 65535); return out;
    }
    auto prefixes() -> std::vector<AllowedPrefix> {
        AllowedPrefix v4{4,{},32},v6{6,{},128};
        v4.address[0]=10; v4.address[1]=42; v4.address[3]=1;
        v6.address[0]=0xfd; v6.address[1]=0x42; v6.address[15]=1;
        return {v4,v6};
    }
    auto timestamp(std::chrono::seconds offset) -> std::expected<Timestamp,Error> {
        auto wall=std::chrono::system_clock::now().time_since_epoch()+offset;
        auto seconds=std::chrono::duration_cast<std::chrono::seconds>(wall);
        auto nanoseconds=std::chrono::duration_cast<std::chrono::nanoseconds>(wall-seconds);
        if (seconds.count()<0) return std::unexpected(Error::invalid_timestamp);
        return make_timestamp(seconds.count(),nanoseconds.count());
    }
}

auto main(int argc,char** argv) -> int {
    if (argc<4 || argc>6) return 1;
    bool initiator=std::string_view(argv[1])=="initiate",ipv6=std::string_view(argv[2])=="6";
    if ((!initiator && std::string_view(argv[1])!="respond") || (std::string_view(argv[2])!="4" && !ipv6)) return 1;
    auto mode=argc>=5 ? std::string_view(argv[4]) : "plain";
    auto shared=argc==6;
    if (shared && std::string_view(argv[5])!="shared") return 1;
    if (mode!="plain" && mode!="require" && mode!="receive" && mode!="both") return 1;
    auto cookies=mode!="plain",require_cookie=mode=="require" || mode=="both",receive_cookie=mode=="receive" || mode=="both";
    auto target=cookies ? 10u : 30u;
    unsigned port=0; auto parsed=std::from_chars(argv[3],argv[3]+std::char_traits<char>::length(argv[3]),port);
    if (parsed.ec!=std::errc{} || *parsed.ptr || !port || port>65535) return 2;
    std::string private_text,remote_text,psk_text;
    if (!(std::cin>>private_text>>remote_text>>psk_text)) return 3;
    auto private_key=decode_key(private_text),remote=decode_key(remote_text),psk=decode_key(psk_text);
    std::fill(private_text.begin(),private_text.end(),'\0'); std::fill(psk_text.begin(),psk_text.end(),'\0');
    if (!private_key || !remote || !psk) return 4;
    auto local=::crypto::X25519Private::from_bytes(*private_key);
    auto port_identity=::crypto::X25519Private::from_bytes(*private_key); ::crypto::cleanse(*private_key);
    if (!local || !port_identity) return 5;
    net::UdpEndpoint peer{ipv6 ? std::uint8_t{6} : std::uint8_t{4},{},static_cast<std::uint16_t>(port)};
    if (ipv6) peer.address[15]=1; else { peer.address[0]=127; peer.address[3]=1; }
    EndpointConfig config; config.peer_public=*remote; config.peer=peer; config.allowed_ips=prefixes();
    auto endpoint=Endpoint::create(std::move(*local),std::move(config),*psk); ::crypto::cleanse(*psk);
    if (!endpoint) return 6;
    auto ingress=IdentityIngress::create(*port_identity);
    PeerRegistry<1> registry; PeerKeys<1> keys; routing::RouteTable<1,2> routes;
    auto handle=registry.add();
    if (!ingress || !handle || !keys.activate(*handle,*remote) || !routes.activate(*handle)) return 6;
    for (auto const& prefix:prefixes()) if (!routes.assign(*handle,prefix)) return 6;
    if (require_cookie) {
        SecretKey cookie_secret;
        if (!::crypto::random_bytes(cookie_secret.writable())) return 6;
        auto rotated=shared ? ingress->rotate_cookie_secret(std::move(cookie_secret),Clock::now()).has_value() : endpoint->rotate_cookie_secret(std::move(cookie_secret),Clock::now()).has_value();
        if (!rotated) return 6;
    }
    net::UdpSocket socket;
    constexpr std::array<std::uint8_t,14> ready{'N','E','X','U','S','-','W','G','-','R','E','A','D','Y'};
    if (!socket.send(peer,ready)) return 7;
    auto deadline=Clock::now()+(cookies ? 25s : 20s);
    auto offset=0s;
    unsigned incoming=0,outgoing=0,epoch=0,generations=0,initiations=0,responses=0,rekeys=0;
    unsigned cookies_sent=0,cookies_received=0;
    std::optional<std::uint32_t> known;
    std::optional<EndpointDatagram> sending;
    std::optional<admission::Reply> port_sending;
    bool signal_after_generation=false;
    auto signal=[&]() -> bool {
        auto text=std::format("NEXUS-WG-EPOCH-{}",epoch);
        return socket.send(peer,std::span(reinterpret_cast<std::uint8_t const*>(text.data()),text.size())).has_value();
    };
    auto flush=[&](Clock::time_point now) -> bool {
        if (port_sending) {
            if (!ingress->cookie_output_valid(port_sending->request.ticket)) port_sending.reset();
            else {
                auto sent=socket.send(port_sending->destination,port_sending->bytes);
                if (!sent && (sent.error()==std::errc::resource_unavailable_try_again || sent.error()==std::errc::operation_would_block)) return true;
                if (!sent) return false;
                port_sending.reset();
            }
        }
        if (!sending) return true;
        if (!endpoint->output_valid(sending->serial)) { sending.reset(); return true; }
        auto sent=socket.send(sending->destination,sending->bytes);
        if (!sent && (sent.error()==std::errc::resource_unavailable_try_again || sent.error()==std::errc::operation_would_block)) return true;
        if (!endpoint->complete_send(sending->serial,sent.has_value(),now)) return false;
        if (!sent) return false;
        outgoing+=sending->kind==OutboundKind::data;
        sending.reset(); return true;
    };
    auto handshake=[&](HandshakeRequest request,Clock::time_point now) -> bool {
        auto ephemeral=::crypto::X25519Private::generate(); if (!ephemeral) return false;
        std::array<std::uint8_t,4> seed{}; if (!::crypto::random_bytes(seed)) return false;
        auto index=load_le32(seed);
        std::optional<IndexReservation> reserved;
        if (shared) {
            if (!registry.sync(*handle,*endpoint)) return false;
            auto result=registry.reserve(*handle,request.ticket,index); if (!result) return false;
            reserved=*result; index=result->index;
        }
        auto index_mode=shared ? IndexMode::exact : IndexMode::probe;
        if (request.reason==HandshakeReason::response) {
            auto result=endpoint->respond(request,index,std::move(*ephemeral),now,index_mode);
            if (!result) { if (reserved) (void)registry.release(*reserved); return false; }
            sending=std::move(*result); ++responses;
        } else {
            auto stamp=timestamp(offset); if (!stamp) return false;
            auto result=endpoint->initiate(request,index,std::move(*ephemeral),*stamp,0ms,now,index_mode);
            if (!result) { if (reserved) (void)registry.release(*reserved); return false; }
            sending=std::move(*result); ++initiations;
            rekeys+=request.reason==HandshakeReason::rekey;
        }
        if (shared && !registry.sync(*handle,*endpoint)) return false;
        return flush(now);
    };
    auto challenge=[&](CookieRequest request,Clock::time_point now) -> bool {
        std::array<std::uint8_t,24> nonce{}; if (!::crypto::random_bytes(nonce)) return false;
        auto result=endpoint->respond_cookie(request,nonce,now); if (!result) return false;
        sending=std::move(*result); ++cookies_sent; return flush(now);
    };
    auto port_challenge=[&](admission::CookieRequest request,Clock::time_point now) -> bool {
        std::array<std::uint8_t,24> nonce{}; if (!::crypto::random_bytes(nonce)) return false;
        auto result=ingress->respond_cookie(request,nonce,now); if (!result) return false;
        port_sending=*result; ++cookies_sent; return flush(now);
    };
    auto now=Clock::now();
    if (initiator && !endpoint->enqueue(packet(0,true),now)) return 8;
    std::array<std::uint8_t,65535> input{};
    while (Clock::now()<deadline && (incoming<target || outgoing<target)) {
        now=Clock::now()+offset;
        if (!flush(now)) return 9;
        auto status=endpoint->status();
        if (status.current && status.current!=known) {
            if ((generations==0 && status.previous) || (generations && !status.previous)) return 10;
            known=status.current; ++generations;
            if (signal_after_generation) { if (!signal()) return 11; signal_after_generation=false; }
        }
        if (!cookies && epoch<2 && incoming==(epoch+1)*10 && outgoing==incoming && !sending) {
            if (!status.current || status.pending || status.handshake || status.queued_packets || generations!=epoch+1) return 12;
            ++epoch; offset+=121s; now=Clock::now()+offset;
            if (initiator) {
                if (!endpoint->enqueue(packet(incoming,true),now)) return 13;
                signal_after_generation=true;
            } else if (epoch==1) {
                if (!endpoint->request_handshake(now)) return 14;
                signal_after_generation=true;
            } else if (!signal()) return 15;
        }
        // An in-flight initiation is driven by incoming response/retry events;
        // the queued business packet waits so each epoch exercises its new key.
        status=endpoint->status();
        if (!sending && (!status.handshake || cookies)) {
            auto polled=endpoint->poll(now); if (!polled || polled->gave_up) return 16;
            if (polled->cookie) { if (!challenge(*polled->cookie,now)) return 28; }
            else if (polled->handshake) { if (!handshake(*polled->handshake,now)) return 17; }
            else if (polled->datagram) { sending=std::move(*polled->datagram); if (!flush(now)) return 18; }
        }
        auto received=socket.receive(input); if (!received) return 19;
        if (!*received) { std::this_thread::sleep_for(1ms); continue; }
        auto const& datagram=**received;
        if (!datagram.valid || datagram.source!=peer) continue;
        auto wire=std::span(input).first(datagram.size);
        std::expected<EndpointReceived,EndpointFailure> accepted;
        auto type=message_type(wire);
        if (shared && type && *type==MessageType::initiation) {
            auto selected=ingress->receive<StaticCounts>(wire,datagram.source,true,now,keys.view(),require_cookie);
            if (!selected) return 29;
            if (selected->cookie) { if (!port_challenge(*selected->cookie,now)) return 30; continue; }
            accepted=endpoint->receive_selected(std::move(*selected->selected),keys.view(),now,routes.view(*handle));
            if (accepted) ingress->cancel_cookie();
        } else if (shared && type && *type==MessageType::response) {
            auto admitted=ingress->admit_response(wire,datagram.source,true,now,require_cookie); if (!admitted) return 31;
            if (admitted->cookie) { if (!port_challenge(*admitted->cookie,now)) return 30; continue; }
            if (!registry.classify(wire)) return 32;
            accepted=endpoint->receive(wire,datagram.source,true,now,false,routes.view(*handle));
            if (accepted) ingress->cancel_cookie();
        } else {
            if (shared && type && !registry.classify(wire)) continue;
            accepted=endpoint->receive(wire,datagram.source,true,now,shared ? false : require_cookie,shared ? routes.view(*handle) : SourcePolicyView{});
        }
        if (shared && !registry.sync(*handle,*endpoint)) return 33;
        if (!accepted) {
            auto error=accepted.error();
            if (error.code==EndpointError::no_key || error.code==EndpointError::stale_attempt ||
                (error.code==EndpointError::protocol && (error.protocol==Error::authentication || error.protocol==Error::replay))) continue;
            std::println("endpoint receive failed {}",static_cast<unsigned>(error.code)); return 20;
        }
        cookies_received+=accepted->cookie_consumed;
        if (accepted->keepalive || accepted->packet.empty()) continue;
        if (incoming>=target || accepted->packet!=packet(incoming,false,initiator)) {
            std::println("endpoint inner packet {} mismatch",incoming); return 21;
        }
        ++incoming;
        if (!initiator) {
            if (!endpoint->enqueue(packet(incoming-1,true,true),now)) return 22;
        } else if (incoming<target && incoming%10) {
            if (!endpoint->enqueue(packet(incoming,true),now)) return 23;
        }
    }
    auto plain_counts=generations==3 && initiations==(initiator ? 3u : 2u) && responses==(initiator ? 0u : 1u) && rekeys==(initiator ? 2u : 1u);
    auto cookie_counts=generations==1 && cookies_sent==(require_cookie ? 1u : 0u) && cookies_received==(receive_cookie ? 1u : 0u) &&
        initiations==(initiator ? (mode=="both" ? 3u : 2u) : 0u) && responses==(initiator ? 0u : receive_cookie ? 2u : 1u) && !rekeys;
    if (incoming!=target || outgoing!=target || (cookies ? !cookie_counts : !plain_counts)) {
        std::println("endpoint counts: in {} out {} keys {} initiations {} responses {} rekeys {}",incoming,outgoing,generations,initiations,responses,rekeys); return 24;
    }
    if (shared && (StaticCounts::dh!=responses || StaticCounts::decrypt!=responses)) return 34;
    auto overlap=endpoint->status();
    if (!overlap.current || overlap.previous.has_value()!=!cookies || overlap.pending || overlap.indexes!=(cookies ? 1u : 2u) || overlap.queued_packets) return 25;
    auto expired=endpoint->poll(Clock::now()+offset+61s);
    if (!expired || !endpoint->status().current || endpoint->status().previous || endpoint->status().indexes!=1) return 26;
    auto serial=expired->datagram ? expired->datagram->serial : 0;
    endpoint->close();
    if (endpoint->status().indexes || endpoint->status().queued_packets || endpoint->output_valid(serial)) return 27;
    if (shared) {
        ingress->close();
        if (!routes.erase(*handle) || !keys.erase(*handle) || !registry.erase(*handle) || registry.status().indexes || routes.status().prefixes || keys.size()) return 35;
        std::println("shared identity: static DH={} decrypt={} selected responses={} global exact indexes, source routing and stop passed",StaticCounts::dh,StaticCounts::decrypt,responses);
    }
    if (cookies) std::println("Nexus WireGuard Endpoint initial {}, outer IPv{}, cookie mode {}, sent {} received {}, 10 bidirectional IPv4/IPv6 inner packets and stop passed",initiator ? "initiator" : "responder",ipv6 ? 6 : 4,mode,cookies_sent,cookies_received);
    else std::println("Nexus WireGuard Endpoint initial {}, outer IPv{}, three real key generations, 30 bidirectional IPv4/IPv6 inner packets, rekey/previous expiry/stop passed",initiator ? "initiator" : "responder",ipv6 ? 6 : 4);
}
