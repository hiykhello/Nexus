import std;
import net.packet_stream_socket;
import net.datagram_frame;
import xudp;
import uot;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;
namespace capy=nex::capy;namespace io=nex::corosio;namespace x=xudp;
using namespace std::chrono_literals;
using Clock=std::chrono::steady_clock;
struct Stream {
    std::vector<std::uint8_t> input,output;
    std::size_t offset=0,chunk=3;
    capy::async_event changed,writable;
    bool canceled=false,hold=false,writing=false;
    auto send(std::span<std::uint8_t const> bytes) -> capy::task<bool> {
        writing=true;
        if(hold) {auto [error]=co_await writable.wait();if(error){writing=false;co_return false;}}
        writing=false;if(canceled)co_return false;
        output.insert(output.end(),bytes.begin(),bytes.end());co_return true;
    }
    auto read(std::span<std::uint8_t> bytes) -> capy::task<std::expected<std::size_t,std::string>> {
        while(offset==input.size() && !canceled) {changed.clear();auto [error]=co_await changed.wait();if(error)co_return std::unexpected("canceled");}
        if(canceled)co_return std::unexpected("closed");
        auto n=std::min({bytes.size(),chunk,input.size()-offset});std::copy_n(input.begin()+offset,n,bytes.begin());offset+=n;co_return n;
    }
    auto push(std::span<std::uint8_t const> bytes) -> void {input.insert(input.end(),bytes.begin(),bytes.end());changed.set();}
    auto cancel() noexcept -> void {canceled=true;changed.set();writable.set();}
};
using Socket=net::PacketStreamSocket<Stream>;
auto peer_address(io::endpoint peer) -> net::ProxyAddress {
    net::ProxyAddress result;result.port=peer.port();
    if(peer.is_v6()){result.family=net::ProxyAddressFamily::ipv6;result.length=16;auto bytes=peer.address().to_v6().to_bytes();std::ranges::copy(bytes,result.bytes.begin());}
    else{result.family=net::ProxyAddressFamily::ipv4;result.length=4;auto bytes=peer.address().to_v4().to_bytes();std::ranges::copy(bytes,result.bytes.begin());}
    return result;
}
auto exercise(io::io_context& context,bool ipv6,unsigned mode,bool& ok) -> capy::task<> {
    Stream stream;Socket socket(context);
    io::endpoint peer=ipv6 ? io::endpoint(io::ipv6_address::loopback(),443) : io::endpoint(io::ipv4_address::loopback(),443);
    auto target=peer_address(peer);
    net::DatagramFraming framing{net::AddressWire::uot,mode==1,mode==2};
    net::PacketTransport transport{mode==3 ? net::PacketTransportKind::xudp : net::PacketTransportKind::framed,framing,mode==0};
    if(!socket.attach(stream,transport,peer) || !co_await socket.prepare(Clock::now()+1s))co_return;
    if(mode==0) {
        auto request=uot::parse_request(stream.output);
        if(request.status!=net::DatagramStatus::accepted || request.request.connected || request.request.destination!=target)co_return;
        stream.output.clear();
    }
    std::array<std::uint8_t,4> payload{0,1,2,255};
    auto [error,sent]=co_await socket.send_to(capy::const_buffer(payload.data(),payload.size()),peer);
    if(error || sent!=payload.size())co_return;
    if(mode==3) {
        auto opened=x::parse(stream.output);if(opened.status!=x::Status::ready || opened.frame.kind!=x::Kind::open || opened.frame.session!=1 || opened.frame.payload.size()!=payload.size())co_return;
        auto reply=x::encode(x::Frame{1,x::Kind::data,true,false,{}, {},payload});if(!reply)co_return;
        auto empty=x::encode(x::Frame{1,x::Kind::data,true,false,{}, {},{}});if(!empty)co_return;
        stream.push(*reply);stream.push(*empty);
    } else {
        auto wire=net::parse_datagram(framing,target,stream.output);if(wire.status!=net::DatagramStatus::accepted || wire.payload.size()!=payload.size())co_return;
        auto wrong=target;wrong.port++;
        if(!framing.connected){auto unauthorized=net::encode_datagram(framing,wrong,payload);if(!unauthorized)co_return;stream.push(*unauthorized);}
        auto reply=net::encode_datagram(framing,target,payload),empty=net::encode_datagram(framing,target,{});
        if(!reply || !empty)co_return;stream.push(*reply);stream.push(*empty);
    }
    std::array<std::uint8_t,20> output{};io::endpoint source;
    auto [first,n]=co_await socket.recv_from(capy::mutable_buffer(output.data(),output.size()),source);
    if(first || n!=payload.size() || source!=peer || !std::ranges::equal(std::span(output).first(n),payload))co_return;
    auto [second,empty]=co_await socket.recv_from(capy::mutable_buffer(output.data(),output.size()),source);
    if(second || empty || source!=peer)co_return;
    auto [wrong,written]=co_await socket.send_to(capy::const_buffer(payload.data(),payload.size()),io::endpoint(io::ipv4_address::loopback(),999));
    if(!wrong || written)co_return;
    bool pending=false,closed=false;
    auto reader=[&]() -> capy::task<capy::results<>> {pending=true;auto [failure,size]=co_await socket.recv_from(capy::mutable_buffer(output.data(),output.size()),source);(void)size;closed=bool(failure);co_return capy::results<>{};};
    auto cancel=[&]() -> capy::task<capy::results<>> {while(!pending){auto [e]=co_await io::delay(1ms);if(e)co_return capy::results<>{e};}socket.close();co_return capy::results<>{};};
    auto [join,a,b]=co_await capy::when_all(reader(),cancel());(void)a;(void)b;
    ok=!join && closed && stream.canceled;
}

auto concurrent(io::io_context& context,bool& ok) -> capy::task<> {
    Stream stream;stream.hold=true;Socket socket(context);io::endpoint peer(io::ipv4_address::loopback(),443);
    if(!socket.attach(stream,{net::PacketTransportKind::xudp},peer) || !co_await socket.prepare(Clock::now()+1s))co_return;
    std::array<std::uint8_t,4> payload{8,7,6,5},output{};io::endpoint source;
    auto reply=x::encode(x::Frame{1,x::Kind::data,true,false,{}, {},payload});if(!reply)co_return;stream.push(*reply);
    bool sent=false,received=false,blocked=false;
    auto writer=[&]() -> capy::task<capy::results<>> {auto [error,n]=co_await socket.send_to(capy::const_buffer(payload.data(),payload.size()),peer);sent=!error && n==payload.size();co_return capy::results<>{};};
    auto reader=[&]() -> capy::task<capy::results<>> {auto [error,n]=co_await socket.recv_from(capy::mutable_buffer(output.data(),output.size()),source);received=!error && n==payload.size() && output==payload && source==peer;co_return capy::results<>{};};
    auto release=[&]() -> capy::task<capy::results<>> {
        while(!stream.writing){auto [error]=co_await io::delay(1ms);if(error)co_return capy::results<>{error};}
        auto [error]=co_await io::delay(5ms);if(error)co_return capy::results<>{error};
        blocked=!sent && !received;stream.hold=false;stream.writable.set();co_return capy::results<>{};
    };
    auto [error,a,b,c]=co_await capy::when_all(writer(),reader(),release());(void)a;(void)b;(void)c;
    ok=!error && blocked && sent && received;
}

auto deadline(io::io_context& context,bool& ok) -> capy::task<> {
    Stream stream;stream.hold=true;Socket socket(context);io::endpoint peer(io::ipv4_address::loopback(),443);
    if(!socket.attach(stream,{net::PacketTransportKind::framed,{},true},peer))co_return;
    auto started=Clock::now();auto result=co_await socket.prepare(started+60ms);auto elapsed=Clock::now()-started;
    ok=!result && stream.canceled && elapsed>=45ms && elapsed<500ms;
}
auto cancel_backpressure(io::io_context& context,bool xudp,bool& ok) -> capy::task<> {
    Stream stream;stream.hold=true;Socket socket(context);io::endpoint peer(io::ipv4_address::loopback(),443);
    auto kind=xudp ? net::PacketTransportKind::xudp : net::PacketTransportKind::framed;
    if(!socket.attach(stream,{kind},peer) || !co_await socket.prepare(Clock::now()+1s))co_return;
    std::array<std::uint8_t,4> payload{1,2,3,4},output{};io::endpoint source;
    bool writer_failed=false,reader_failed=false,blocked=false;
    auto writer=[&]() -> capy::task<capy::results<>> {
        auto [error,size]=co_await socket.send_to(capy::const_buffer(payload.data(),payload.size()),peer);
        writer_failed=bool(error) && !size;co_return capy::results<>{};
    };
    auto reader=[&]() -> capy::task<capy::results<>> {
        auto [error,size]=co_await socket.recv_from(capy::mutable_buffer(output.data(),output.size()),source);
        reader_failed=bool(error) && !size;co_return capy::results<>{};
    };
    auto cancel=[&]() -> capy::task<capy::results<>> {
        while(!stream.writing){auto [error]=co_await io::delay(1ms);if(error)co_return capy::results<>{error};}
        auto [error]=co_await io::delay(5ms);if(error)co_return capy::results<>{error};
        blocked=!writer_failed && !reader_failed;socket.close();co_return capy::results<>{};
    };
    auto [error,a,b,c]=co_await capy::when_all(writer(),reader(),cancel());(void)a;(void)b;(void)c;
    ok=!error && blocked && writer_failed && reader_failed && stream.canceled;
}
auto main() -> int {
    for(bool uring:{false,true})for(bool ipv6:{false,true})for(unsigned mode=0;mode<4;++mode) {
        io::io_context context=io::make_io_context(uring);bool ok=false,done=false;
        capy::run_async(context.get_executor(),[&]() noexcept {done=true;},[&](std::exception_ptr) noexcept {done=true;})(exercise(context,ipv6,mode,ok));
        context.run_for(2s);
        if(!done || !ok){std::println("packet socket failed backend={} v6={} mode={} done={} ok={}",uring,ipv6,mode,done,ok);return 1;}
    }
    for(bool uring:{false,true}) {
        io::io_context context=io::make_io_context(uring);bool done=false,ok=false;
        capy::run_async(context.get_executor(),[&]() noexcept {done=true;},[&](std::exception_ptr) noexcept {done=true;})(deadline(context,ok));
        context.run_for(1s);if(!done || !ok){std::println("packet socket deadline backend={} failed",uring);return 2;}
        context.restart();done=ok=false;
        capy::run_async(context.get_executor(),[&]() noexcept {done=true;},[&](std::exception_ptr) noexcept {done=true;})(concurrent(context,ok));
        context.run_for(1s);if(!done || !ok){std::println("packet socket concurrent backend={} failed",uring);return 3;}
        for(bool xudp:{false,true}) {
            context.restart();done=ok=false;
            capy::run_async(context.get_executor(),[&]() noexcept {done=true;},[&](std::exception_ptr) noexcept {done=true;})(cancel_backpressure(context,xudp,ok));
            context.run_for(1s);if(!done || !ok){std::println("packet socket backpressure cancellation backend={} xudp={} failed",uring,xudp);return 4;}
        }
    }
    std::println("packet socket: framed, connected, CRLF and XUDP; dual backend/family, fragmented input, unauthorized source, empty packet, pending and backpressure cancellation, concurrent XUDP and UoT deadline passed");
}
