import std;
import tailscale.derp;
import tailscale.derp_messages;
import tailscale.derp_handshake;
import tailscale.derp_info;
import net.socket_stream;
import crypto;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;
namespace d=tailscale::derp;
namespace c = ::crypto;
namespace capy=nex::capy;
namespace io=nex::corosio;
using namespace std::chrono_literals;
using Lower=net::SocketByteStream<io::tcp_socket>;
struct Fixture {
    io::io_context context;
    io::tcp_socket socket{context};
    bool done=false,passed=false;
    std::string_view stage="connect";
    explicit Fixture(bool uring) : context(io::make_io_context(uring)) {}
};
struct Cancel { Lower& stream; ~Cancel() {stream.cancel();} };
struct Frames {
    Lower& lower;
    d::Decoder decoder;
    std::array<std::uint8_t,4096> input{};
    std::size_t begin=0,end=0;
    auto next(d::HandshakeClock::time_point deadline) -> capy::task<std::optional<d::Frame>> {
        if (decoder.frame() && !decoder.consume()) co_return std::nullopt;
        for (;;) {
            if (begin==end) {
                auto read=co_await lower.read(input,deadline);
                if (!read || !*read || *read>input.size()) co_return std::nullopt;
                begin=0;end=*read;
            }
            auto fed=decoder.feed(std::span(input).subspan(begin,end-begin));begin+=fed.consumed;
            if (fed.error) co_return std::nullopt;
            if (fed.ready) co_return decoder.frame();
        }
    }
};
auto send(Lower& lower,std::span<std::uint8_t const> wire,d::HandshakeClock::time_point deadline) -> capy::task<bool> {
    std::size_t fragmented=std::min(std::size_t{97},wire.size());
    while (fragmented) {
        auto size=std::min(std::size_t{3},fragmented);
        if (!co_await lower.send(wire.first(size),deadline)) co_return false;
        wire=wire.subspan(size);fragmented-=size;
    }
    co_return wire.empty() || co_await lower.send(wire,deadline);
}
auto run(Fixture& fixture,std::uint16_t port,d::Key pin,d::Key peer) -> capy::task<> {
    auto start=d::HandshakeClock::now(),deadline=start+8s;
    auto [error]=co_await io::timeout(fixture.socket.connect(io::endpoint(io::ipv4_address::loopback(),port)),deadline);
    if (error) co_return;
    Lower stream(fixture.socket);Cancel cancel{stream};Frames frames{stream};
    std::array<std::uint8_t,32> bytes{};for (unsigned i=0;i<32;++i) bytes[i]=static_cast<std::uint8_t>(i);
    auto local=c::X25519Private::from_bytes(bytes);c::cleanse(bytes);if (!local) co_return;
    d::PinnedClientHandshake handshake(*local,pin,start,deadline);
    fixture.stage="DERP key";
    auto frame=co_await frames.next(deadline);if (!frame) co_return;
    d::Nonce nonce{};if (!c::random_bytes(nonce)) co_return;
    auto login=handshake.start(*frame,nonce,d::HandshakeClock::now());if (!login) co_return;
    fixture.stage="client NaCl login";
    if (!co_await send(stream,*login,deadline)) co_return;
    frame=co_await frames.next(deadline);if (!frame) co_return;
    fixture.stage="server NaCl info";
    if (!handshake.finish(*frame,d::HandshakeClock::now()) || handshake.state()!=d::HandshakeState::ready) co_return;
    auto preferred=d::encode_note_preferred(true);if (!preferred || !co_await send(stream,*preferred,deadline)) co_return;
    for (unsigned size:{0,17,65536}) {
        fixture.stage="DERP packets";
        std::vector<std::uint8_t> payload(size);for (std::size_t i=0;i<size;++i) payload[i]=static_cast<std::uint8_t>(i+size);
        auto wire=d::encode_packet(d::Type::send_packet,peer,payload);
        if (!wire || !co_await send(stream,*wire,deadline)) co_return;
        bool received=false;
        for (unsigned count=0;count<64 && !received;++count) {
            frame=co_await frames.next(deadline);if (!frame) co_return;
            if (frame->type==d::Type::ping) {
                auto token=d::parse_ping(*frame);if (!token) co_return;
                auto pong=d::encode_ping(d::Type::pong,*token);if (!pong || !co_await send(stream,*pong,deadline)) co_return;
            } else if (frame->type==d::Type::recv_packet) {
                auto packet=d::parse_packet(*frame);
                if (!packet || packet->peer!=peer || packet->bytes.size()!=size) co_return;
                for (std::size_t i=0;i<size;++i) if (packet->bytes[i]!=(payload[i]^0x5a)) co_return;
                received=true;
            } else if (frame->type==d::Type::peer_gone) {
                auto gone=d::parse_peer_gone(*frame);if (!gone || gone->peer!=peer) co_return;
            } else if (frame->type!=d::Type::keep_alive && frame->type!=d::Type::health) co_return;
        }
        if (!received) co_return;
    }
    auto unknown=d::encode_frame(static_cast<d::Type>(0xfe),std::array<std::uint8_t,3>{1,2,3});
    if (!unknown || !co_await send(stream,*unknown,deadline)) co_return;
    std::array<std::uint8_t,8> token{1,2,3,4,5,6,7,8};
    auto ping=d::encode_ping(d::Type::ping,token);if (!ping || !co_await send(stream,*ping,deadline)) co_return;
    fixture.stage="DERP pong";
    for (unsigned count=0;count<64;++count) {
        frame=co_await frames.next(deadline);if (!frame) co_return;
        if (frame->type==d::Type::pong) {
            auto parsed=d::parse_ping(*frame,d::Type::pong);
            if (!parsed || *parsed!=token) co_return;
            fixture.passed=true;co_return;
        }
        if (frame->type==d::Type::peer_gone) {
            auto gone=d::parse_peer_gone(*frame);if (!gone || gone->peer!=peer) co_return;
        } else if (frame->type!=d::Type::keep_alive && frame->type!=d::Type::health) co_return;
    }
}
auto root(Fixture& fixture,std::uint16_t port,d::Key pin,d::Key peer) -> capy::task<> {
    try {co_await run(fixture,port,pin,peer);} catch (...) {fixture.passed=false;}
    fixture.socket.close();fixture.done=true;
}
auto decode(std::string_view text,d::Key& key) -> bool {
    if (text.size()!=64) return false;
    auto digit=[](char c)->int {if (c>='0' && c<='9') return c-'0';if (c>='a' && c<='f') return c-'a'+10;return -1;};
    for (std::size_t i=0;i<32;++i) {auto one=digit(text[i*2]),two=digit(text[i*2+1]);if (one<0 || two<0) return false;key[i]=static_cast<std::uint8_t>(one*16+two);}
    return true;
}
auto main(int argc,char** argv) -> int {
    if (argc!=5) return 64;
    unsigned port=0,backend=0;auto one=std::string_view(argv[1]),two=std::string_view(argv[4]);
    auto a=std::from_chars(one.data(),one.data()+one.size(),port),b=std::from_chars(two.data(),two.data()+two.size(),backend);
    d::Key pin{},peer{};
    if (a.ec!=std::errc{} || a.ptr!=one.data()+one.size() || !port || port>65535 || b.ec!=std::errc{} || b.ptr!=two.data()+two.size() ||
        backend>1 || !decode(argv[2],pin) || !decode(argv[3],peer)) return 64;
    if (backend && !io::has_uring) return 77;
    Fixture fixture(backend!=0);
    capy::run_async(fixture.context.get_executor())(root(fixture,static_cast<std::uint16_t>(port),pin,peer));
    fixture.context.run_for(10s);
    if (!fixture.done) {fixture.socket.close();fixture.context.restart();fixture.context.run_for(1s);}
    if (!fixture.done || !fixture.context.stopped()) std::_Exit(65);
    if (!fixture.passed) {std::cerr<<"DERP authenticated fixture failed at "<<fixture.stage<<'\n';return 1;}
    std::println("derp-network-passed");
}

