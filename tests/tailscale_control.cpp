import std;
import tailscale.control;
import crypto;
namespace t=tailscale::control;
using namespace std::chrono_literals;
using Bytes=std::vector<std::uint8_t>;
auto require(bool condition,std::string_view message) -> void {if (!condition) throw std::runtime_error(std::string(message));}
template<class T> auto failed(std::expected<T,t::Error> const& result,t::Error error) -> bool {return !result && result.error()==error;}
template<class Key> auto key(unsigned seed) -> Key {
    t::KeyBytes bytes{};for (unsigned i=0;i<32;++i) bytes[i]=static_cast<std::uint8_t>(i+seed);
    auto result=Key::from_bytes(bytes);::crypto::cleanse(bytes);require(bool(result),"private key");return std::move(*result);
}
auto payload(std::size_t size) -> Bytes {Bytes bytes(size);for (std::size_t i=0;i<size;++i) bytes[i]=static_cast<std::uint8_t>(i*17+size);return bytes;}
inline constexpr auto start=t::Clock::time_point{}+1s;
inline constexpr auto limit=start+5s;
struct Pair {
    t::MachinePrivate machine=key<t::MachinePrivate>(3);
    t::ControlPrivate control=key<t::ControlPrivate>(71);
    t::ClientHandshake client;
    t::ServerHandshake server{control,start,limit};
    std::array<std::uint8_t,t::initiation_size> initiation{};
    std::array<std::uint8_t,t::response_size> response{};
    explicit Pair(std::uint16_t version=148) : client(machine,*control.public_key(),version,start,limit) {
        require(!client.control_peer() && !server.machine_peer() && !client.handshake_hash() && !server.protocol_version(),"early identity publication");
        require(!client.take_transport() && !server.take_transport(),"early transport publication");
        auto ce=key<t::EphemeralPrivate>(141);auto first=client.start(std::move(ce),start+1ms);
        require(first && !ce.public_key() && client.state()==t::HandshakeState::await_response,"client start/ephemeral transfer");
        initiation=*first;
        auto se=key<t::EphemeralPrivate>(211);auto second=server.respond(initiation,std::move(se),start+2ms);
        require(second && !se.public_key(),"server response/ephemeral transfer");response=*second;
        require(bool(client.finish(response,start+3ms)),"client finish");
        require(client.handshake_hash()==server.handshake_hash() && client.protocol_version()==version && server.protocol_version()==version,"binding/version agreement");
        require(client.control_peer()==*control.public_key() && server.machine_peer()==*machine.public_key(),"authenticated typed identities");
    }
    auto install(t::Records& c,t::Records& s) -> void {
        auto ck=client.take_transport();auto sk=server.take_transport();
        require(ck && sk && ck->available() && sk->available(),"take transport");
        require(bool(c.install(std::move(*ck))) && bool(s.install(std::move(*sk))),"install records");
        require(!ck->available() && !sk->available() && !client.take_transport() && !server.take_transport(),"one-shot key material");
    }
};
auto handshakes() -> void {
    static_assert(!std::same_as<t::MachinePublic,t::ControlPublic> && !std::same_as<t::MachinePrivate,t::NodePrivate>);
    static_assert(!std::is_move_constructible_v<t::Records> && !std::is_copy_constructible_v<t::TransportKeys>);
    for (std::uint16_t version:{0,1,148,65535}) {Pair pair(version);t::Records c,s;pair.install(c,s);}
    Pair baseline;
    for (std::size_t byte=0;byte<baseline.initiation.size();++byte) for (unsigned bit=0;bit<8;++bit) {
        auto changed=baseline.initiation;changed[byte]^=static_cast<std::uint8_t>(1u<<bit);
        t::ServerHandshake server(baseline.control,start,limit);auto ephemeral=key<t::EphemeralPrivate>(211);
        require(!server.respond(changed,std::move(ephemeral),start) && server.state()==t::HandshakeState::failed &&
            !server.machine_peer() && !server.take_transport(),"tampered initiation authenticated");
    }
    for (std::size_t byte=0;byte<baseline.response.size();++byte) for (unsigned bit=0;bit<8;++bit) {
        auto changed=baseline.response;changed[byte]^=static_cast<std::uint8_t>(1u<<bit);
        t::ClientHandshake client(baseline.machine,*baseline.control.public_key(),148,start,limit);auto ephemeral=key<t::EphemeralPrivate>(141);
        require(bool(client.start(std::move(ephemeral),start)),"response tamper start");
        require(!client.finish(changed,start) && client.state()==t::HandshakeState::failed && !client.control_peer() && !client.take_transport(),"tampered response authenticated");
    }
    for (std::size_t size=0;size<t::initiation_size;++size) {
        t::ServerHandshake server(baseline.control,start,limit);auto ephemeral=key<t::EphemeralPrivate>(211);
        require(failed(server.respond(std::span(baseline.initiation).first(size),std::move(ephemeral),start),t::Error::framing),"truncated initiation");
    }
    for (std::size_t size=0;size<t::response_size;++size) {
        t::ClientHandshake client(baseline.machine,*baseline.control.public_key(),148,start,limit);auto ephemeral=key<t::EphemeralPrivate>(141);
        require(bool(client.start(std::move(ephemeral),start)),"truncation start");
        require(failed(client.finish(std::span(baseline.response).first(size),start),t::Error::framing),"truncated response");
    }
    for (unsigned point:{0,1}) {
        auto changed=baseline.initiation;std::fill_n(changed.begin()+5,32,0);changed[5]=static_cast<std::uint8_t>(point);
        t::ServerHandshake server(baseline.control,start,limit);auto ephemeral=key<t::EphemeralPrivate>(211);
        require(!server.respond(changed,std::move(ephemeral),start) && !server.machine_peer(),"low-order initiator ephemeral");
        t::KeyBytes bytes{};bytes[0]=static_cast<std::uint8_t>(point);auto pin=t::ControlPublic::from_bytes(bytes);
        t::ClientHandshake client(baseline.machine,*pin,148,start,limit);auto ce=key<t::EphemeralPrivate>(141);
        require(!client.start(std::move(ce),start) && !client.take_transport(),"low-order responder static");
    }
    t::ClientHandshake late(baseline.machine,*baseline.control.public_key(),148,start,limit);auto ce=key<t::EphemeralPrivate>(141);
    require(bool(late.start(std::move(ce),start+1s)) && failed(late.finish(baseline.response,limit),t::Error::timeout) && !late.take_transport(),"original deadline");
    t::ClientHandshake rollback(baseline.machine,*baseline.control.public_key(),148,start,limit);auto re=key<t::EphemeralPrivate>(141);
    require(bool(rollback.start(std::move(re),start+1s)) && failed(rollback.finish(baseline.response,start),t::Error::timeout),"clock rollback");
    t::ServerHandshake expired(baseline.control,start,limit);auto se=key<t::EphemeralPrivate>(211);
    require(failed(expired.respond(baseline.initiation,std::move(se),limit),t::Error::timeout) && !expired.machine_peer(),"server budget");
    auto wrong_control=key<t::ControlPrivate>(72);
    t::ClientHandshake wrong_pin(baseline.machine,*wrong_control.public_key(),148,start,limit);auto we=key<t::EphemeralPrivate>(141);
    auto wrong_initial=wrong_pin.start(std::move(we),start);require(bool(wrong_initial),"wrong pin initiation");
    t::ServerHandshake trusted(baseline.control,start,limit);auto te=key<t::EphemeralPrivate>(211);
    require(!trusted.respond(*wrong_initial,std::move(te),start) && !trusted.machine_peer(),"different control key accepted");
    wrong_pin.cancel();auto canceled_ephemeral=key<t::EphemeralPrivate>(141);
    require(failed(wrong_pin.start(std::move(canceled_ephemeral),start),t::Error::closed) && !wrong_pin.handshake_hash(),"canceled handshake restarted");
    for (unsigned size:{0,17,256,257}) {
        t::ClientHandshake client(baseline.machine,*baseline.control.public_key(),148,start,limit);auto ephemeral=key<t::EphemeralPrivate>(141);
        require(bool(client.start(std::move(ephemeral),start)),"hint start");
        Bytes hint(size+3,'x');hint[0]=3;hint[1]=static_cast<std::uint8_t>(size>>8);hint[2]=static_cast<std::uint8_t>(size);
        require(failed(client.finish(hint,start),size<=256 ? t::Error::peer_hint : t::Error::framing) && !client.control_peer(),"bounded untrusted hint");
    }
    Pair moved;t::Records c,s;auto ck=moved.client.take_transport();auto sk=moved.server.take_transport();
    t::TransportKeys transferred(std::move(*ck));
    require(!ck->available() && !c.install(std::move(*ck)) && bool(c.install(std::move(transferred))) && !transferred.available(),"moved material reused");
    require(!c.install(std::move(*sk)) && sk->available(),"records key reset allowed");
    s.cancel();require(!s.install(std::move(*sk)),"canceled record owner resurrected");
    moved.server.cancel();require(!moved.server.handshake_hash() && !moved.server.take_transport(),"closed handshake metadata");
}
auto records() -> void {
    Pair pair;t::Records c,s;pair.install(c,s);
    for (std::size_t size:{0,1,17,4077}) {
        auto plain=payload(size);std::array<std::uint8_t,t::max_record_wire> wire{};wire.fill(0xa5);
        require(!c.seal_to(std::span(wire).first(size+18),plain) && !c.send_pending() && std::ranges::all_of(wire,[](auto x){return x==0xa5;}),"capacity wrote or consumed nonce");
        auto sealed=c.seal_to(wire,plain);require(sealed && *sealed==size+19 && c.send_pending(),"seal frame size");
        require(!c.seal_to(wire,plain),"concurrent pending seal");
        Bytes opened(size,0xa5);
        if (size) require(failed(s.open_to(std::span(opened).first(size-1),std::span(wire).first(*sealed)),t::Error::capacity) && s.receive_alive(),"receive capacity poisoned or consumed nonce");
        auto received=s.open_to(opened,std::span(wire).first(*sealed));require(received && *received==size && opened==plain,"open record/empty frame");
        require(bool(c.sent()) && !c.sent(),"send completion not one-shot");
    }
    std::array<std::uint8_t,t::max_record_wire+1> too_large{};
    require(failed(c.seal_to(too_large,std::span(too_large).first(t::max_record_plaintext+1)),t::Error::capacity),"oversize plaintext");
    std::array<std::uint8_t,64> overlap{};overlap.fill(0x71);auto before=overlap;
    require(failed(c.seal_to(overlap,std::span(overlap).subspan(1,17)),t::Error::overlap) && overlap==before,"partial seal overlap");
    auto plain=payload(17);std::ranges::copy(plain,overlap.begin()+3);
    auto sealed=c.seal_to(overlap,std::span(overlap).subspan(3,17));require(bool(sealed),"exact cipher-start seal");
    auto unchanged=overlap;
    require(failed(s.open_to(std::span(overlap).subspan(1,17),std::span(overlap).first(*sealed)),t::Error::overlap) && overlap==unchanged && s.receive_alive(),"partial open overlap");
    auto received=s.open_to(std::span(overlap).subspan(3,17),std::span(overlap).first(*sealed));
    require(received && std::ranges::equal(std::span(overlap).subspan(3,17),plain) && bool(c.sent()),"exact cipher-start open");
    Pair corrupt;t::Records a,b;corrupt.install(a,b);std::array<std::uint8_t,64> wire{};auto encrypted=a.seal_to(wire,plain);require(bool(encrypted),"tamper seal");
    wire[*encrypted-1]^=1;std::array<std::uint8_t,17> output{};output.fill(0xa5);
    require(failed(b.open_to(output,std::span(wire).first(*encrypted)),t::Error::authentication) && !b.receive_alive() &&
        std::ranges::all_of(output,[](auto x){return x==0;}) && b.send_alive(),"authentication failure not terminal/clean");
    require(failed(b.open_to(output,std::span(wire).first(*encrypted)),t::Error::closed),"retry after bad tag");
    auto reverse=b.seal_to(wire,plain);require(reverse && bool(a.open_to(output,std::span(wire).first(*reverse))) && bool(b.sent()),"directions coupled");
    a.fail_send();require(!a.send_alive() && a.receive_alive() && !a.sent() && failed(a.seal_to(wire,plain),t::Error::closed),"abandoned/partial send reused nonce");
    Pair replay;t::Records x,y;replay.install(x,y);auto frame=x.seal_to(wire,plain);require(frame && bool(y.open_to(output,std::span(wire).first(*frame))),"replay first frame");
    require(failed(y.open_to(output,std::span(wire).first(*frame)),t::Error::authentication) && !y.receive_alive(),"replayed record accepted");
    for (unsigned mode:{0,1,2}) {
        Pair invalid;t::Records i,j;invalid.install(i,j);auto n=i.seal_to(wire,plain);require(bool(n),"invalid seal");
        if (mode==0) wire[0]=5;else if (mode==1) --wire[2];else wire[1]=0xff;
        require(failed(j.open_to(output,std::span(wire).first(*n)),t::Error::framing) && !j.receive_alive(),"malformed record resynchronized");
    }
}
auto decoders() -> void {
    Pair pair;t::Records c,s;pair.install(c,s);std::array<std::uint8_t,64> buffer{};
    auto sealed=c.seal_to(buffer,{});require(sealed && *sealed==19,"empty wire");auto wire=std::span(buffer).first(*sealed);
    Bytes coalesced;coalesced.insert(coalesced.end(),wire.begin(),wire.end());coalesced.insert(coalesced.end(),wire.begin(),wire.end());
    for (std::size_t chunk:{1,2,3,7,19,64}) {
        t::RecordDecoder decoder;std::size_t used=0;
        while (!decoder.ready()) {auto n=decoder.feed(std::span(coalesced).subspan(used,std::min(chunk,coalesced.size()-used)));require(bool(n),"fragmented decode");used+=*n;}
        require(used==wire.size() && std::ranges::equal(decoder.wire(),wire) && decoder.feed(std::span(coalesced).subspan(used))==0,"decoder overconsumed");
        require(bool(decoder.consume()),"consume frame");auto n=decoder.feed(std::span(coalesced).subspan(used));
        require(n && *n==wire.size() && decoder.ready() && bool(decoder.consume()) && bool(decoder.eof()) && failed(decoder.feed(wire),t::Error::closed),"coalesced frame/terminal EOF");
    }
    for (std::size_t size=1;size<wire.size();++size) {
        t::RecordDecoder decoder;require(bool(decoder.feed(wire.first(size))) && !decoder.eof() && !decoder.feed(wire),"truncated frame EOF");
    }
    for (auto header:{std::array<std::uint8_t,3>{5,0,16},std::array<std::uint8_t,3>{4,0,15},std::array<std::uint8_t,3>{4,0x0f,0xfe},std::array<std::uint8_t,3>{4,0x10,0}}) {
        t::RecordDecoder decoder;require(failed(decoder.feed(header),t::Error::framing) && failed(decoder.feed(wire),t::Error::closed),"bad frame header");
    }
    for (std::uint64_t first:std::array<std::uint64_t,5>{0,1,255,256,std::numeric_limits<std::uint64_t>::max()-1}) {
        t::NonceCounter counter(first);auto nonce=counter.take();require(bool(nonce),"nonce value");
        require(std::ranges::all_of(std::span(*nonce).first(4),[](auto x){return x==0;}),"nonce fixed prefix");
        std::uint64_t recovered=0;for (auto byte:std::span(*nonce).subspan(4)) recovered=(recovered<<8)|byte;
        require(recovered==first,"nonce must be big endian");
        if (first==std::numeric_limits<std::uint64_t>::max()-1) require(!counter.take() && !counter.take(),"nonce exhaustion reused all-ones");
        counter.clear();require(!counter.take(),"cleared nonce counter");
    }
}
auto hex(std::span<std::uint8_t const> bytes) -> std::string {std::string result;for (auto byte:bytes) {result+="0123456789abcdef"[byte>>4];result+="0123456789abcdef"[byte&15];}return result;}
auto vector(std::string const& label,std::span<std::uint8_t const> bytes) -> void {
    if (bytes.size()>256) {auto hash=::crypto::digest(::crypto::Hash::sha256,bytes);require(bool(hash),"vector hash");std::println("{}=sha256:{}",label,hex(*hash));}
    else std::println("{}={}",label,hex(bytes));
}
auto vectors() -> void {
    for (std::uint16_t version:{1,148,65535}) {
        Pair pair(version);auto suffix=std::to_string(version);
        vector("init-"+suffix,pair.initiation);vector("response-"+suffix,pair.response);vector("hash-"+suffix,*pair.client.handshake_hash());
        t::Records c,s;pair.install(c,s);
        for (std::size_t size:{0,1,17,33,4077}) {
            auto plain=payload(size);std::array<std::uint8_t,t::max_record_wire> wire{};auto first=c.seal_to(wire,plain);
            require(bool(first),"vector client record");vector("c2s-"+suffix+"-"+std::to_string(size),std::span(wire).first(*first));require(bool(c.sent()),"vector c sent");
            auto second=s.seal_to(wire,plain);require(bool(second),"vector server record");vector("s2c-"+suffix+"-"+std::to_string(size),std::span(wire).first(*second));require(bool(s.sent()),"vector s sent");
        }
    }
}
auto main(int argc,char** argv) -> int {
    try {
        if (argc==2 && std::string_view(argv[1])=="--vectors") {vectors();return 0;}
        handshakes();records();decoders();
        std::println("Control Noise IK typed identities, binding, deadlines, bit tampering, one-shot keys, record bounds/counters and terminal failure passed");
        std::println("sizeof(ClientHandshake)={} ServerHandshake={} Records={} RecordDecoder={} TransportKeys={}",sizeof(t::ClientHandshake),sizeof(t::ServerHandshake),sizeof(t::Records),sizeof(t::RecordDecoder),sizeof(t::TransportKeys));
    } catch (std::exception const& error) {std::cerr<<error.what()<<'\n';return 1;}
}
