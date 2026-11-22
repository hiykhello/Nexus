import std;
import net.buffered_input;
import net.framed_stream;
import net.socket_stream;
import tailscale.control;
import tailscale.control_record_codec;
import tailscale.control_http;
import crypto;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;
namespace t=tailscale::control;
namespace h=tailscale::control_http;
namespace net=net;
namespace capy=nex::capy;
namespace io=nex::corosio;
using namespace std::chrono_literals;
using Deadline=net::StreamDeadline;
struct Memory {
    std::vector<std::uint8_t> input,output;
    std::size_t position=0,chunk=4096,reads=0,writes=0,cancels=0;
    std::optional<Deadline> observed;
    std::chrono::milliseconds delay{0};
    bool mismatch=false,read_error=false,read_throw=false,write_error=false,write_throw=false,late=false;
    auto cancel() noexcept -> void {++cancels;}
    auto record(Deadline deadline) -> void {if (!observed) observed=deadline;else if (*observed!=deadline) mismatch=true;}
    auto read(std::span<std::uint8_t> bytes,Deadline deadline) -> capy::task<std::expected<std::size_t,int>> {
        record(deadline);++reads;
        {auto [error]=co_await io::delay(1ns);if (error) co_return std::unexpected(1);}
        if (delay.count()) {auto [error]=co_await io::delay(delay);if (error) co_return std::unexpected(1);}
        if (read_throw) throw std::bad_alloc();if (read_error) co_return std::unexpected(1);
        auto size=std::min({bytes.size(),chunk,input.size()-position});std::copy_n(input.begin()+position,size,bytes.begin());position+=size;co_return size;
    }
    auto send(std::span<std::uint8_t const> bytes,Deadline deadline) -> capy::task<bool> {
        record(deadline);++writes;
        if (write_throw) throw std::bad_alloc();
        if (delay.count()) {auto [error]=co_await io::delay(delay);if (error) co_return false;}
        auto size=write_error ? std::min(std::size_t{2},bytes.size()) : bytes.size();output.insert(output.end(),bytes.begin(),bytes.begin()+size);
        co_return !write_error;
    }
    auto close_output(Deadline deadline) -> capy::task<bool> {record(deadline);co_return !write_error;}
};
using Frame=net::FramedByteStream<Memory,t::RecordCodec>;
template<class Key> auto key(unsigned seed) -> Key {
    t::KeyBytes bytes{};for (unsigned i=0;i<32;++i) bytes[i]=static_cast<std::uint8_t>(i+seed);
    auto result=Key::from_bytes(bytes);::crypto::cleanse(bytes);if (!result) throw std::runtime_error("key");return std::move(*result);
}
struct Keys {t::TransportKeys client,server;};
auto keys() -> Keys {
    auto client=key<t::MachinePrivate>(3);auto server=key<t::ControlPrivate>(71);
    auto now=t::Clock::now();t::ClientHandshake initiator(client,*server.public_key(),148,now,now+5s);t::ServerHandshake responder(server,now,now+5s);
    auto first=initiator.start(key<t::EphemeralPrivate>(141),now);if (!first) throw std::runtime_error("start");
    auto reply=responder.respond(*first,key<t::EphemeralPrivate>(211),now);if (!reply || !initiator.finish(*reply,now)) throw std::runtime_error("finish");
    auto c=initiator.take_transport(),s=responder.take_transport();if (!c || !s) throw std::runtime_error("keys");return {std::move(*c),std::move(*s)};
}
auto install(Frame& frame,t::RecordCodec& peer) -> void {auto pair=keys();if (!frame.codec().install(std::move(pair.client)) || !peer.install(std::move(pair.server))) throw std::runtime_error("install");}
auto append(std::vector<std::uint8_t>& out,t::RecordCodec& peer,std::span<std::uint8_t const> input) -> void {
    std::array<std::uint8_t,t::max_record_wire> bytes{};
    do {auto size=std::min(input.size(),t::max_record_plaintext);auto result=peer.seal(bytes,input.first(size));if (!result || !peer.sent()) throw std::runtime_error("seal");
        out.insert(out.end(),bytes.begin(),bytes.begin()+*result);input=input.subspan(size);} while (!input.empty());
}
auto payload(std::size_t size) -> std::vector<std::uint8_t> {std::vector<std::uint8_t> out(size);for (std::size_t i=0;i<size;++i) out[i]=static_cast<std::uint8_t>(i*17+size);return out;}
auto read_all(Frame& frame,std::span<std::uint8_t> out,Deadline deadline,std::size_t chunk=1) -> capy::task<bool> {
    while (!out.empty()) {auto result=co_await frame.read(out.first(std::min(out.size(),chunk)),deadline);if (!result || !*result || *result>out.size()) co_return false;out=out.subspan(*result);}co_return true;
}
struct Result {bool done=false,passed=false,exception=false;};
auto transfer(Frame& frame,Memory& memory,t::RecordCodec& peer,std::size_t read_chunk,Result& result) -> capy::task<> {
    auto deadline=t::Clock::now()+2s;
    auto expected=payload(16385);std::vector<std::uint8_t> actual(expected.size());
    if (!co_await read_all(frame,actual,deadline,read_chunk) || actual!=expected) co_return;
    auto ended=co_await frame.read(actual,deadline);if (!ended || *ended || frame.failure() || !frame.input_eof() || frame.codec().receive_alive()) co_return;
    ended=co_await frame.read(actual,deadline);if (!ended || *ended) co_return;
    if (!co_await frame.send({},deadline) || memory.writes || !co_await frame.send(expected,deadline)) co_return;
    std::vector<std::uint8_t> opened;
    auto bytes=std::span(memory.output);
    while (!bytes.empty()) {
        auto size=peer.inspect(bytes.first(3));if (!size || *size>bytes.size()) co_return;
        auto plain=peer.open(bytes.first(*size));if (!plain) co_return;
        opened.insert(opened.end(),bytes.begin()+plain->offset,bytes.begin()+plain->offset+plain->size);bytes=bytes.subspan(*size);
    }
    if (opened!=expected || frame.codec().send_pending()) co_return;
    if (!co_await frame.close_output(deadline) || frame.codec().send_alive()) co_return;
    result.passed=!memory.mismatch;result.done=true;
}
auto fragments(bool uring) -> bool {
    for (std::size_t wire_chunk:{1,3,19,4096}) for (std::size_t read_chunk:{1,17,4097}) {
        auto context=io::make_io_context(uring);Memory memory;memory.chunk=wire_chunk;Frame frame(memory);t::RecordCodec peer;install(frame,peer);
        append(memory.input,peer,{});append(memory.input,peer,payload(16385));Result result;
        capy::run_async(context.get_executor())(transfer(frame,memory,peer,read_chunk,result));context.run_for(3s);
        if (!result.done || !result.passed) {std::cerr<<"fragment "<<uring<<' '<<wire_chunk<<' '<<read_chunk<<'\n';return false;}
    }return true;
}
auto failure_task(Frame& frame,Memory& memory,int mode,Result& result) -> capy::task<> {
    auto deadline=t::Clock::now()+(mode==7 ? -1ms : mode==8 || mode==9 ? 5ms : 1s);
    auto data=payload(9000);
    try {
        if (mode==4 || mode==5 || mode==9) result.passed=!co_await frame.send(data,deadline);
        else {auto read=co_await frame.read(data,deadline);result.passed=!read;}
    } catch (std::bad_alloc const&) {result.exception=true;result.passed=mode==3 || mode==5;}
    if (!frame.failure() || !memory.cancels || frame.codec().send_alive() || frame.codec().receive_alive() || frame.codec().send_pending()) result.passed=false;
    if ((mode==7 || mode==8 || mode==9) && frame.failure()->error!=net::RecordStreamError::timeout) result.passed=false;
    if (mode==7 && (memory.reads || memory.writes)) result.passed=false;
    if (co_await frame.send(data,deadline)) result.passed=false;
    result.done=true;
}
auto failures(bool uring) -> bool {
    for (int mode=0;mode<10;++mode) {
        auto context=io::make_io_context(uring);Memory memory;Frame frame(memory);t::RecordCodec peer;install(frame,peer);append(memory.input,peer,payload(10));
        if (mode==0) memory.input.pop_back();
        if (mode==1) memory.input.back()^=1;
        memory.read_error=mode==2;memory.read_throw=mode==3;memory.write_error=mode==4;memory.write_throw=mode==5;
        if (mode==6) memory.input[0]=1;
        if (mode==8 || mode==9) memory.delay=10ms;
        Result result;capy::run_async(context.get_executor())(failure_task(frame,memory,mode,result));context.run_for(2s);
        if (!result.done || !result.passed || memory.mismatch) {std::cerr<<"failure "<<uring<<' '<<mode<<' '<<result.done<<' '<<result.passed<<'\n';return false;}
    }return true;
}
struct UpgradeState {
    using Result=std::expected<void,h::Error>;
    Frame& frame;h::UpgradeResponseDecoder decoder;
    UpgradeState(Frame& owner,t::Clock::time_point start,t::Clock::time_point deadline) : frame(owner),decoder(start,deadline) {}
    auto input() noexcept -> Frame::Window& {return frame.startup_input();}
    auto abort() noexcept -> void {decoder.close();}
    auto feed(std::span<std::uint8_t> bytes) noexcept -> net::InputStep {
        auto fed=decoder.feed(bytes,t::Clock::now());return {fed.consumed,1,fed.error ? net::InputAction::fail : fed.ready ? net::InputAction::complete : net::InputAction::more};
    }
    auto finish(net::InputStatus status) noexcept -> Result {if (status==net::InputStatus::ready) return {};return std::unexpected(h::Error::truncated);}
};
struct ResponseState {
    using Result=std::expected<void,t::Error>;
    Frame& frame;t::ClientHandshake& handshake;
    auto input() noexcept -> Frame::Window& {return frame.startup_input();}
    auto abort() noexcept -> void {handshake.cancel();}
    auto feed(std::span<std::uint8_t> bytes) noexcept -> net::InputStep {
        if (bytes.size()<t::response_size) return {0,t::response_size};
        auto done=handshake.finish(bytes.first(t::response_size),t::Clock::now());
        if (done) {auto keys=handshake.take_transport();done=keys ? frame.codec().install(std::move(*keys)) : std::unexpected(keys.error());}
        return {t::response_size,0,done ? net::InputAction::complete : net::InputAction::fail};
    }
    auto finish(net::InputStatus status) noexcept -> Result {if (status==net::InputStatus::ready) return {};return std::unexpected(t::Error::authentication);}
};
auto startup_task(Memory& memory,Frame& frame,t::ClientHandshake& handshake,Result& result,t::Clock::time_point start,t::Clock::time_point deadline) -> capy::task<> {
    auto header=co_await Frame::Window::drive(memory,[&] {return UpgradeState(frame,start,deadline);},deadline);if (!header) co_return;
    auto response=co_await Frame::Window::drive(memory,[&] {return ResponseState{frame,handshake};},deadline);if (!response) co_return;
    auto expected=payload(5000);std::vector<std::uint8_t> actual(expected.size());
    if (!co_await read_all(frame,actual,deadline,7) || actual!=expected || memory.mismatch) co_return;
    result.done=result.passed=true;
}
auto startup(bool uring) -> bool {
    for (std::size_t chunk:{1,3,4096}) {
        auto client=key<t::MachinePrivate>(3);auto server=key<t::ControlPrivate>(71);auto now=t::Clock::now(),deadline=now+2s;
        t::ClientHandshake initiator(client,*server.public_key(),148,now,deadline);t::ServerHandshake responder(server,now,deadline);
        auto first=initiator.start(key<t::EphemeralPrivate>(141),now);if (!first) return false;
        auto reply=responder.respond(*first,key<t::EphemeralPrivate>(211),now);if (!reply) return false;
        Memory memory;memory.chunk=chunk;Frame frame(memory);t::RecordCodec peer;auto transport=responder.take_transport();if (!transport || !peer.install(std::move(*transport))) return false;
        std::string_view http="HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: tailscale-control-protocol\r\n\r\n";
        memory.input.assign(http.begin(),http.end());memory.input.insert(memory.input.end(),reply->begin(),reply->end());append(memory.input,peer,{});append(memory.input,peer,payload(5000));
        auto context=io::make_io_context(uring);Result result;capy::run_async(context.get_executor())(startup_task(memory,frame,initiator,result,now,deadline));context.run_for(3s);
        if (!result.done || !result.passed) {std::cerr<<"startup "<<uring<<' '<<chunk<<'\n';return false;}
    }return true;
}
struct Tracked {
    net::SocketByteStream<io::local_stream_socket> lower;
    std::size_t& cancels;
    auto read(std::span<std::uint8_t> out,Deadline deadline) {return lower.read(out,deadline);}
    auto send(std::span<std::uint8_t const> in,Deadline deadline) {return lower.send(in,deadline);}
    auto close_output(Deadline deadline) {return lower.close_output(deadline);}
    auto cancel() noexcept -> void {++cancels;lower.cancel();}
};
using SocketFrame=net::FramedByteStream<Tracked,t::RecordCodec>;
struct Life {bool entered=false,done=false,passed=false,destroyed=false;std::size_t cancels=0;};
auto life_task(io::io_context& context,bool writer,Deadline deadline,Life& state) -> capy::task<> {
    io::local_stream_socket socket(context),peer_socket(context);if (io::connect_pair(socket,peer_socket)) co_return;
    Tracked lower{net::SocketByteStream(socket),state.cancels};SocketFrame frame(lower);t::RecordCodec peer;auto pair=keys();
    if (!frame.codec().install(std::move(pair.client)) || !peer.install(std::move(pair.server))) co_return;
    struct Mark {Life& state;~Mark() {state.destroyed=true;}} mark{state};
    state.entered=true;
    if (writer) {auto data=payload(4<<20);state.passed=!co_await frame.send(data,deadline);}
    else {std::array<std::uint8_t,10> out{};auto result=co_await frame.read(out,deadline);state.passed=!result;}
    if (frame.codec().send_alive() || frame.codec().receive_alive() || frame.codec().send_pending()) state.passed=false;
    state.done=true;
}
auto lifecycle(bool uring) -> bool {
    for (bool writer:{false,true}) for (bool abandon:{false,true}) {
        Life state;
        {
            auto context=io::make_io_context(uring);auto deadline=t::Clock::now()+(abandon ? 5s : 20ms);
            capy::run_async(context.get_executor())(life_task(context,writer,deadline,state));context.run_for(abandon ? 10ms : 200ms);
            if (!state.entered || (abandon && (state.done || state.destroyed))) return false;
            if (!abandon && (!state.done || !state.passed || !context.stopped())) return false;
        }
        if (!state.destroyed || !state.cancels || (abandon && state.done)) return false;
    }return true;
}
auto cleanup_task(Frame& frame,Memory& memory,int mode,Result& result) -> capy::task<> {
    auto expected=payload(77);std::array<std::uint8_t,1> first{};auto deadline=t::Clock::now()+1s;
    auto read=co_await frame.read(first,deadline);if (!read || *read!=1 || first[0]!=expected[0]) co_return;
    auto borrowed=frame.startup_input().pending();if (borrowed.size()!=96 || !std::ranges::equal(borrowed.subspan(3,77),expected)) co_return;
    if (mode==1) frame.cancel();else if (mode==2) {memory.write_error=true;if (co_await frame.send(expected,deadline)) co_return;}else {std::array<std::uint8_t,76> rest{};if (!co_await read_all(frame,rest,deadline,7)) co_return;}
    if (!std::ranges::all_of(borrowed,[](auto byte) {return byte==0;})) co_return;
    result.done=result.passed=true;
}
auto cleanup(bool uring) -> bool {
    for (int mode:{0,1,2}) {auto context=io::make_io_context(uring);Memory memory;Frame frame(memory);t::RecordCodec peer;install(frame,peer);append(memory.input,peer,payload(77));
        Result result;capy::run_async(context.get_executor())(cleanup_task(frame,memory,mode,result));context.run_for(2s);
        if (!result.done || !result.passed) return false;
    }return true;
}
auto main() -> int {
    for (bool uring:{false,true}) {if (uring && !io::has_uring) continue;
        if (!fragments(uring)) return 1;if (!failures(uring)) return 2;if (!startup(uring)) return 3;if (!lifecycle(uring)) return 4;if (!cleanup(uring)) return 5;
    }
    std::println("framed-unit passed: fragments/partial plaintext/nonce/empty/EOF/send/error/deadline/same-window startup/abandon/plaintext erase on both backends");
    std::println("sizeof window={} codec={} frame={} upgrade-state={} response-state={}",sizeof(Frame::Window),sizeof(t::RecordCodec),sizeof(Frame),sizeof(UpgradeState),sizeof(ResponseState));
}
