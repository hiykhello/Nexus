import std;
import net.buffered_input;
import net.framed_stream;
import net.socket_stream;
import tailscale.control;
import tailscale.control_record_codec;
import tailscale.control_http;
import tailscale.control_stream;
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
namespace startup=tailscale::control_stream;
constexpr std::array<std::uint8_t,9> h2header{0,0,0,4,0,0,0,0,0};
auto early_wire(std::span<std::uint8_t const> body) -> std::vector<std::uint8_t> {
    std::vector<std::uint8_t> wire{0xff,0xff,0xff,'T','S',0,0,0,0};
    for (unsigned i=0;i<4;++i) wire[8-i]=static_cast<std::uint8_t>(body.size()>>(i*8));wire.insert(wire.end(),body.begin(),body.end());return wire;
}
auto exercise(Frame& frame,Memory& memory,std::span<std::uint8_t> storage,std::span<std::uint8_t const> body,
    int mode,bool after_partial,Result& result) -> capy::task<> {
    auto now=t::Clock::now(),deadline=now+1s;
    if (after_partial) {std::array<std::uint8_t,1> prefix{};auto first=co_await frame.read(prefix,deadline);if (!first || *first!=1 || prefix[0]!=42) co_return;}
    auto early=co_await frame.drive_plain([&] {return startup::detail::EarlyConsumer(storage,now,deadline);},deadline);
    if (mode>=3) {
        result.passed=!early && frame.failure().has_value() && !frame.codec().send_alive() && !frame.codec().receive_alive() && memory.cancels;
        if (mode==3 || mode==4 || mode==7 || mode==8) result.passed=result.passed && early.error().error==startup::Error::early;
        if (mode==5 || mode==6) result.passed=result.passed && early.error().error==startup::Error::truncated;
        if (mode==9 || mode==10) result.passed=result.passed && early.error().error==startup::Error::noise && early.error().noise==(mode==9 ? t::Error::authentication : t::Error::framing);
        result.done=true;co_return;
    }
    if (!early || bool(early->early)!=(mode==1)) co_return;
    if (mode==1) {if (!early->http2_prefix().empty() || !std::ranges::equal(*early->early,body)) co_return;}
    else {auto expected=h2header;if (mode==2) expected[0]=0xfe;if (!std::ranges::equal(early->http2_prefix(),expected)) co_return;}
    auto expected=payload(5000);if (mode==1) expected.insert(expected.begin(),h2header.begin(),h2header.end());
    std::vector<std::uint8_t> actual(expected.size());if (!co_await read_all(frame,actual,deadline,7) || actual!=expected || memory.mismatch) co_return;
    result.done=result.passed=true;
}
auto memory(bool uring) -> bool {
    for (int mode:{0,1,2,3,4,5,6,7,8,9,10}) for (std::size_t chunk:{1,3,4096}) for (bool after_partial:{false,true}) {
        auto context=io::make_io_context(uring);Memory memory;memory.chunk=chunk;Frame frame(memory);t::RecordCodec peer;install(frame,peer);
        std::vector<std::uint8_t> body(mode==3 ? h::max_early_payload+1 : mode==4 ? 33 : mode==7 ? 1 : 101,'x');
        std::vector<std::uint8_t> plain;
        if (mode==1 || mode==3 || mode==4 || mode==5 || mode==7 || mode==8) plain=early_wire(body);
        else {plain.assign(h2header.begin(),h2header.end());if (mode==2) plain[0]=0xfe;}
        if (mode==8) {plain[5]=0xff;plain[6]=0xff;plain[7]=0xff;plain[8]=0xff;}
        if (mode==5) plain.resize(15);else if (mode==6) plain.resize(8);else {if (mode==1) plain.insert(plain.end(),h2header.begin(),h2header.end());auto tail=payload(5000);plain.insert(plain.end(),tail.begin(),tail.end());}
        if (after_partial && mode!=9 && mode!=10) plain.insert(plain.begin(),42);
        append(memory.input,peer,{});
        if (after_partial && (mode==9 || mode==10)) {std::array<std::uint8_t,1> first{42};append(memory.input,peer,first);}
        auto bad_record=memory.input.size();append(memory.input,peer,plain);
        if (mode==9) memory.input[bad_record+4095]^=1;
        if (mode==10) memory.input[bad_record]=1;
        std::vector<std::uint8_t> storage(mode==4 ? 32 : mode==7 ? 0 : h::max_early_payload);
        Result result;capy::run_async(context.get_executor())(exercise(frame,memory,storage,body,mode,after_partial,result));context.run_for(2s);
        if (!result.done || !result.passed) {std::cerr<<"early mode="<<mode<<" chunk="<<chunk<<" partial="<<after_partial<<" backend="<<uring<<'\n';return false;}
    }
    // Exactly the local 64KiB payload boundary across many records.
    {auto context=io::make_io_context(uring);Memory memory;Frame frame(memory);t::RecordCodec peer;install(frame,peer);
        std::vector<std::uint8_t> body(h::max_early_payload,'x'),storage(body.size());auto plain=early_wire(body);plain.insert(plain.end(),h2header.begin(),h2header.end());auto tail=payload(5000);plain.insert(plain.end(),tail.begin(),tail.end());append(memory.input,peer,plain);
        Result result;capy::run_async(context.get_executor())(exercise(frame,memory,storage,body,1,false,result));context.run_for(2s);if (!result.done || !result.passed) return false;
    }return true;
}
struct Life {bool entered=false,done=false,destroyed=false,passed=false;std::size_t cancels=0;};
struct Tracked {
    net::SocketByteStream<io::local_stream_socket> lower;Life& state;
    auto read(std::span<std::uint8_t> out,Deadline deadline) {return lower.read(out,deadline);}
    auto send(std::span<std::uint8_t const> in,Deadline deadline) {return lower.send(in,deadline);}
    auto close_output(Deadline deadline) {return lower.close_output(deadline);}
    auto cancel() noexcept -> void {++state.cancels;lower.cancel();}
};
auto pending(io::io_context& context,Life& state,bool abandon) -> capy::task<> {
    io::local_stream_socket socket(context),peer(context);if (io::connect_pair(socket,peer)) co_return;
    Tracked lower{net::SocketByteStream(socket),state};net::FramedByteStream<Tracked,t::RecordCodec> frame(lower);auto pair=keys();if (!frame.codec().install(std::move(pair.client))) co_return;
    struct Mark {Life& state;~Mark() {state.destroyed=true;}} mark{state};std::array<std::uint8_t,1> storage{};
    auto now=t::Clock::now(),deadline=now+(abandon ? 5s : 10ms);state.entered=true;
    auto ready=co_await frame.drive_plain([&] {return startup::detail::EarlyConsumer(storage,now,deadline);},deadline);
    state.passed=!ready && !frame.codec().send_alive() && !frame.codec().receive_alive();state.done=true;
}
auto lifecycle(bool uring) -> bool {
    for (bool abandon:{false,true}) {Life state;{auto context=io::make_io_context(uring);capy::run_async(context.get_executor())(pending(context,state,abandon));context.run_for(abandon ? 5ms : 100ms);
        if (!state.entered || (abandon && (state.done || state.destroyed)) || (!abandon && (!state.done || !state.passed || !context.stopped()))) return false;
    }if (!state.destroyed || !state.cancels || (abandon && state.done)) return false;}
    return true;
}
auto main() -> int {
    for (bool uring:{false,true}) {if (uring && !io::has_uring) continue;if (!memory(uring)) return 1;if (!lifecycle(uring)) return 2;}
    std::println("plain consumer early absent/present/bad magic/bounds/truncation/same-record tail/partial read/deadline/abandon passed on both backends");
    std::println("sizeof early-ready={} early-consumer={} startup={}",sizeof(startup::Ready),sizeof(startup::detail::EarlyConsumer),sizeof(startup::Stream<Memory>));
}
