#include <boost/capy/buffers.hpp>
#include <boost/capy/task.hpp>
#include <boost/capy/cond.hpp>
#include <boost/capy/ex/async_mutex.hpp>
#include <boost/capy/ex/run_async.hpp>
#include <boost/corosio/backend.hpp>
#include <boost/corosio/io_context.hpp>
#include <boost/corosio/local_stream_socket.hpp>
#include <boost/corosio/local_connect_pair.hpp>
#include <boost/corosio/shutdown_type.hpp>
import std;
import shadowsocks.chunk;
import shadowsocks.frame;
import shadowsocks.request;
import shadowsocks.replay;
import shadowsocks.corosio_server;
import shadowsocks.corosio_client;
import shadowsocks.corosio_inbound;
namespace capy=boost::capy; namespace io=boost::corosio; namespace s=shadowsocks;
using namespace std::chrono_literals;
using Socket=io::local_stream_socket;
struct State {
    bool done=false,ok=false; std::vector<std::uint8_t> data;
    std::optional<std::expected<s::detail::AcceptedRequest,s::detail::ServerReadError>> request;
    std::optional<std::expected<s::detail::StartedResponse,s::detail::ReceiveError>> response;
};
auto send_request(Socket& socket,std::span<std::uint8_t const> bytes,State& state) -> capy::task<> {
    auto [error,n]=co_await socket.write_some(capy::const_buffer(bytes.data(),bytes.size()));
    state.ok=!error && n==bytes.size() && !socket.shutdown(io::shutdown_send); state.done=true;
}
auto accept(Socket& socket,std::span<std::uint8_t const> key,s::ReplayTable& replay,State& state) -> capy::task<> {
    state.request=co_await s::detail::receive_request(socket,key,replay,std::chrono::steady_clock::now()+2s); state.done=true;
}
auto read_inbound(s::detail::InboundStream<Socket>& stream,State& state) -> capy::task<> {
    std::array<std::uint8_t,2> bytes{};
    for (;;) {
        auto result=co_await stream.read(bytes,std::chrono::steady_clock::now()+2s);
        if (!result) break;
        if (!*result) { state.ok=true; break; }
        state.data.insert(state.data.end(),bytes.begin(),bytes.begin()+*result);
    }
    state.done=true;
}
auto send_inbound(s::detail::InboundStream<Socket>& stream,State& state) -> capy::task<> {
    std::array<std::uint8_t,5> a{'w','o','r','l','d'},b{'a','g','a','i','n'};
    state.ok=co_await stream.send(a,std::chrono::steady_clock::now()+2s);
    if (state.ok) state.ok=co_await stream.send(b,std::chrono::steady_clock::now()+2s);
    if (state.ok) state.ok=co_await stream.close_output();
    state.done=true;
}
auto receive_response(Socket& socket,std::span<std::uint8_t const> key,std::span<std::uint8_t const> salt,State& state) -> capy::task<> {
    state.response=co_await s::detail::receive_response(socket,key,salt,std::chrono::steady_clock::now()+2s); state.done=true;
}
auto read_response(s::detail::FrameReader<Socket>& reader,State& state) -> capy::task<> {
    std::array<std::uint8_t,2> bytes{};
    for (;;) {
        auto result=co_await reader.read(bytes,std::chrono::steady_clock::now()+2s);
        if (!result) break;
        if (!*result) { state.ok=true; break; }
        state.data.insert(state.data.end(),bytes.begin(),bytes.begin()+*result);
    }
    state.done=true;
}
auto main() -> int {
#if BOOST_COROSIO_HAVE_LIBURING
    io::io_context context(io::uring);
#else
    io::io_context context;
#endif
    Socket client(context),server(context); if (io::connect_pair(client,server)) return 1;
    std::array<std::uint8_t,16> key{},salt{}; salt[0]=1;
    std::array<std::uint8_t,7> address{1,127,0,0,1,0,80}; std::array<std::uint8_t,1> padding{0};
    std::array<std::uint8_t,5> payload{'h','e','l','l','o'};
    auto wall=std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    auto request=s::encode_request(key,salt,wall,address,padding,payload); if (!request) return 2;
    s::FrameEncoder encoder(std::move(request->cipher)); auto frame=encoder.encode(payload); if (!frame) return 3;
    auto wire=request->wire; wire.insert(wire.end(),frame->begin(),frame->end());
    State sent,accepted; s::ReplayTable replay(4); auto ex=context.get_executor();
    capy::run_async(ex)(send_request(client,wire,sent)); capy::run_async(ex)(accept(server,key,replay,accepted)); context.run_for(2s);
    if (!sent.done || !sent.ok || !accepted.request || !*accepted.request) return 4;
    s::detail::InboundStream stream(server,key,std::move(**accepted.request));
    if (!std::ranges::equal(stream.address(),address)) return 5;
    State upload; context.restart(); capy::run_async(ex)(read_inbound(stream,upload)); context.run_for(2s);
    if (!upload.done || !upload.ok || std::string(upload.data.begin(),upload.data.end())!="hellohello") return 6;
    State download; context.restart(); capy::run_async(ex)(send_inbound(stream,download)); context.run_for(2s);
    if (!download.done || !download.ok) return 7;
    State response; context.restart(); capy::run_async(ex)(receive_response(client,key,salt,response)); context.run_for(2s);
    if (!response.response || !*response.response) return 8;
    s::detail::FrameReader reader(client,std::move(**response.response)); State output;
    context.restart(); capy::run_async(ex)(read_response(reader,output)); context.run_for(2s);
    if (!output.done || !output.ok || std::string(output.data.begin(),output.data.end())!="worldagain") return 9;
    client.close(); server.close(); context.restart(); context.run_for(1s);
    Socket client2(context),server2(context); if (io::connect_pair(client2,server2)) return 10;
    salt[0]=2; auto second=s::encode_request(key,salt,wall,address,padding,{}); if (!second) return 11;
    State sent2,accepted2;
    // Keep the sending half open so the server's frame read remains pending.
    auto write_only=[&]() -> capy::task<> {
        auto [error,n]=co_await client2.write_some(capy::const_buffer(second->wire.data(),second->wire.size()));
        sent2.ok=!error && n==second->wire.size(); sent2.done=true;
    };
    context.restart(); capy::run_async(ex)(write_only()); capy::run_async(ex)(accept(server2,key,replay,accepted2)); context.run_for(1s);
    if (!sent2.done || !sent2.ok || !accepted2.request || !*accepted2.request) return 12;
    s::detail::InboundStream stream2(server2,key,std::move(**accepted2.request)); State pending;
    context.restart(); capy::run_async(ex)(read_inbound(stream2,pending)); context.run_for(30ms);
    if (pending.done) return 13;
    stream2.cancel(); context.restart(); context.run_for(1s);
    if (!pending.done || pending.ok || !context.stopped()) return 14;
    State after_cancel; context.restart(); capy::run_async(ex)(send_inbound(stream2,after_cancel)); context.run_for(1s);
    if (!after_cancel.done || after_cancel.ok) return 15;
    client2.close(); server2.close(); context.restart(); context.run_for(1s);
    std::cout << "Shadowsocks 2022 Corosio inbound stream passed\n";
}
