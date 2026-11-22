#include <boost/capy/buffers.hpp>
#include <boost/capy/task.hpp>
#include <boost/capy/cond.hpp>
#include <boost/capy/ex/run_async.hpp>
#include <boost/corosio/backend.hpp>
#include <boost/corosio/io_context.hpp>
#include <boost/corosio/local_stream_socket.hpp>
#include <boost/corosio/local_connect_pair.hpp>
import std;
import shadowsocks.corosio_server;
import shadowsocks.chunk;
import shadowsocks.request;
import shadowsocks.response;
import shadowsocks.replay;
import shadowsocks.frame;
namespace capy=boost::capy; namespace io=boost::corosio; namespace s=shadowsocks;
using namespace std::chrono_literals;
using Socket=io::local_stream_socket;
struct Reader {
    Socket& socket; unsigned cancels=0;
    auto read_some(capy::mutable_buffer bytes) { return socket.read_some(bytes); }
    auto cancel() noexcept -> void { ++cancels; socket.cancel(); }
};
struct Writer {
    Socket& socket; unsigned cancels=0; bool limit=false;
    auto write_some(capy::const_buffer bytes) {
        return socket.write_some(capy::const_buffer(bytes.data(),limit ? std::min(bytes.size(),std::size_t{3}) : bytes.size()));
    }
    auto cancel() noexcept -> void { ++cancels; socket.cancel(); }
};
struct Result {
    std::optional<std::expected<s::detail::AcceptedRequest,s::detail::ServerReadError>> request;
    std::optional<std::expected<s::ChunkCipher,s::detail::ServerWriteError>> response;
    std::array<std::uint8_t,1024> bytes{}; std::size_t n=0; bool sent=false;
};
auto write(Socket& socket,std::span<std::uint8_t const> data,Result& result) -> capy::task<> {
    auto [error,n]=co_await socket.write_some(capy::const_buffer(data.data(),data.size())); result.sent=!error && n==data.size();
}
auto receive(Reader& socket,std::span<std::uint8_t const> key,s::ReplayTable& replay,Result& result) -> capy::task<> {
    result.request=co_await s::detail::receive_request(socket,key,replay,std::chrono::steady_clock::now()+1s);
}
auto respond(Writer& socket,std::span<std::uint8_t const> key,std::span<std::uint8_t const> salt,Result& result) -> capy::task<> {
    std::array<std::uint8_t,5> data{'w','o','r','l','d'};
    result.response=co_await s::detail::send_response(socket,key,salt,data,std::chrono::steady_clock::now()+1s);
}
auto read(Socket& socket,Result& result) -> capy::task<> {
    auto [error,n]=co_await socket.read_some(capy::mutable_buffer(result.bytes.data(),result.bytes.size())); if (!error) result.n=n;
}
auto main() -> int {
#if BOOST_COROSIO_HAVE_LIBURING
    io::io_context context(io::uring);
#else
    io::io_context context;
#endif
    auto ex=context.get_executor(); std::array<std::uint8_t,16> key{},salt{}; salt[0]=1;
    std::array<std::uint8_t,7> address{1,127,0,0,1,0,80}; std::array<std::uint8_t,1> pad{0};
    std::array<std::uint8_t,5> payload{'h','e','l','l','o'};
    auto wall=std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    auto request=s::encode_request(key,salt,wall,address,pad,payload); if (!request) return 1;
    s::FrameEncoder encoder(std::move(request->cipher)); auto frame=encoder.encode(payload); if (!frame) return 2;
    auto wire=request->wire; wire.insert(wire.end(),frame->begin(),frame->end()); s::ReplayTable replay(8);
    Socket a(context),b(context); if (io::connect_pair(a,b)) return 3;
    Result sent; context.restart(); capy::run_async(ex)(write(b,wire,sent)); context.run_for(1s); if (!sent.sent) return 4;
    Reader reader{a}; Result accepted; context.restart(); capy::run_async(ex)(receive(reader,key,replay,accepted)); context.run_for(2s);
    if (!accepted.request || !*accepted.request || reader.cancels || (*accepted.request)->salt!=std::vector<std::uint8_t>(salt.begin(),salt.end()) ||
        !std::ranges::equal((*accepted.request)->header.address,address) || !std::ranges::equal((*accepted.request)->header.payload,payload) ||
        (*accepted.request)->unread!=*frame) return 5;
    s::FrameDecoder decoder(std::move((*accepted.request)->cipher)); auto decoded=decoder.feed((*accepted.request)->unread);
    if (!decoded || !decoded->payload || !std::ranges::equal(*decoded->payload,payload)) return 6;
    Writer writer{a}; Result response,received; context.restart();
    capy::run_async(ex)(respond(writer,key,salt,response)); capy::run_async(ex)(read(b,received)); context.run_for(2s);
    if (!response.response || !*response.response || writer.cancels || !received.n) return 7;
    auto prefix=s::decode_response_prefix(key,salt,std::span{received.bytes}.first(received.n),wall);
    if (!prefix) return 8;
    auto offset=prefix->consumed; auto length=prefix->payload_length+16;
    auto result=s::decode_response_payload(std::move(*prefix),std::span{received.bytes}.subspan(offset,length));
    if (!result || std::string(result->payload.begin(),result->payload.end())!="world") return 9;
    a.close(); b.close(); context.restart(); context.run_for(1s);
    Socket c(context),d(context); if (io::connect_pair(c,d)) return 10;
    Result replay_sent; context.restart(); capy::run_async(ex)(write(d,wire,replay_sent)); context.run_for(1s);
    Reader replay_reader{c}; Result rejected; context.restart(); capy::run_async(ex)(receive(replay_reader,key,replay,rejected)); context.run_for(2s);
    if (!replay_sent.sent || !rejected.request || *rejected.request || rejected.request->error()!=s::detail::ServerReadError::invalid_request || replay_reader.cancels!=1) return 11;
    c.close(); d.close(); context.restart(); context.run_for(1s);
    Socket e(context),f(context); if (io::connect_pair(e,f)) return 12;
    Writer short_writer{e,0,true}; Result short_response; context.restart(); capy::run_async(ex)(respond(short_writer,key,salt,short_response)); context.run_for(2s);
    if (!short_response.response || *short_response.response || short_response.response->error()!=s::detail::ServerWriteError::partial_write || short_writer.cancels!=1) return 13;
    e.close(); f.close(); context.restart(); context.run_for(1s);
    salt[0]=2; auto split=s::encode_request(key,salt,wall,address,pad,payload); if (!split) return 14;
    Socket g(context),h(context); if (io::connect_pair(g,h)) return 15;
    constexpr std::size_t cut=46; Result first;
    context.restart(); capy::run_async(ex)(write(h,std::span{split->wire}.first(cut),first)); context.run_for(1s);
    Reader split_reader{g}; Result split_result; context.restart();
    capy::run_async(ex)(receive(split_reader,key,replay,split_result)); context.run_for(30ms);
    if (!first.sent || split_result.request) return 16;
    Result rest; context.restart(); capy::run_async(ex)(write(h,std::span{split->wire}.subspan(cut),rest)); context.run_for(2s);
    if (!rest.sent || !split_result.request || !*split_result.request || split_reader.cancels ||
        !std::ranges::equal((*split_result.request)->header.payload,payload)) return 17;
    g.close(); h.close(); context.restart(); context.run_for(1s);
    Socket i(context),j(context); if (io::connect_pair(i,j)) return 18;
    Result too_short; context.restart(); capy::run_async(ex)(write(j,std::span{split->wire}.first(12),too_short)); context.run_for(1s);
    Reader short_reader{i}; Result short_request; context.restart(); capy::run_async(ex)(receive(short_reader,key,replay,short_request)); context.run_for(2s);
    if (!too_short.sent || !short_request.request || *short_request.request ||
        short_request.request->error()!=s::detail::ServerReadError::invalid_request || short_reader.cancels!=1) return 19;
    i.close(); j.close(); context.restart(); context.run_for(1s);
    std::cout << "Shadowsocks 2022 Corosio server handshake passed\n";
}
