#include <boost/capy/buffers.hpp>
#include <boost/capy/task.hpp>
#include <boost/capy/cond.hpp>
#include <boost/capy/error.hpp>
#include <boost/capy/ex/async_mutex.hpp>
#include <boost/capy/ex/run_async.hpp>
#include <boost/corosio/backend.hpp>
#include <boost/corosio/io_context.hpp>
#include <boost/corosio/local_stream_socket.hpp>
#include <boost/corosio/local_connect_pair.hpp>
#include <boost/corosio/shutdown_type.hpp>
import std;
import nexus.shadowsocks.key;
import nexus.shadowsocks.chunk;
import nexus.shadowsocks.frame;
import nexus.shadowsocks.response;
import nexus.shadowsocks.corosio_client;
import nexus.shadowsocks.corosio_relay;
namespace capy=boost::capy; namespace io=boost::corosio; namespace s=nexus::shadowsocks;
using namespace std::chrono_literals;
using Socket=io::local_stream_socket;
using Relay=s::detail::DuplexRelay<Socket,Socket>;
struct Result { bool done=false,ok=false; std::vector<std::uint8_t> bytes; };
auto write_close(Socket& socket,std::span<std::uint8_t const> bytes,Result& result) -> capy::task<> {
    while (!bytes.empty()) {
        auto [error,n]=co_await socket.write_some(capy::const_buffer(bytes.data(),bytes.size()));
        if (error || !n) { result.done=true; co_return; } bytes=bytes.subspan(n);
    }
    result.ok=!socket.shutdown(io::shutdown_send); result.done=true;
}
auto read_all(Socket& socket,Result& result) -> capy::task<> {
    std::array<std::uint8_t,512> bytes{};
    for (;;) {
        auto [error,n]=co_await socket.read_some(capy::mutable_buffer(bytes.data(),bytes.size()));
        if (error == capy::cond::eof || (!error && !n)) { result.ok=true; break; }
        if (error || !n) break;
        result.bytes.insert(result.bytes.end(),bytes.begin(),bytes.begin()+n);
    }
    result.done=true;
}
auto upload(Relay& relay,Result& result) -> capy::task<> { result.ok=co_await relay.upload(); result.done=true; }
auto download(Relay& relay,Result& result) -> capy::task<> { result.ok=co_await relay.download(); result.done=true; }
auto main() -> int {
#if BOOST_COROSIO_HAVE_LIBURING
    io::io_context context(io::uring);
#else
    io::io_context context;
#endif
    Socket client(context),local(context),remote(context),peer(context);
    if (io::connect_pair(client,local) || io::connect_pair(remote,peer)) return 1;
    std::array<std::uint8_t,16> psk{},request_salt{},response_salt{}; request_salt[0]=1; response_salt[0]=2;
    auto key=s::SessionKey::derive(psk,request_salt); auto send_cipher=s::ChunkCipher::create(std::move(*key),true);
    auto receive_key=s::SessionKey::derive(psk,request_salt); auto receive_cipher=s::ChunkCipher::create(std::move(*receive_key),false);
    auto wall=std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    std::array<std::uint8_t,5> hello{'h','e','l','l','o'},world{'w','o','r','l','d'};
    auto response=s::encode_response(psk,response_salt,request_salt,wall,world); if (!response) return 2;
    s::detail::StartedRequest started{std::vector<std::uint8_t>(request_salt.begin(),request_salt.end()),std::move(*send_cipher)};
    Relay relay(local,remote,psk,std::move(started));
    Result local_send,peer_send,local_read,peer_read,up,down; auto ex=context.get_executor();
    capy::run_async(ex)(write_close(client,hello,local_send)); capy::run_async(ex)(write_close(peer,response->wire,peer_send));
    capy::run_async(ex)(upload(relay,up)); capy::run_async(ex)(download(relay,down));
    capy::run_async(ex)(read_all(client,local_read)); capy::run_async(ex)(read_all(peer,peer_read));
    context.run_for(3s);
    if (!local_send.done || !peer_send.done || !local_read.done || !peer_read.done || !up.done || !down.done ||
        !local_send.ok || !peer_send.ok || !local_read.ok || !peer_read.ok || !up.ok || !down.ok) return 3;
    if (!std::ranges::equal(local_read.bytes,world)) return 4;
    s::FrameDecoder decoder(std::move(*receive_cipher)); auto step=decoder.feed(peer_read.bytes);
    if (!step || !step->payload || !std::ranges::equal(*step->payload,hello) || !decoder.finish()) return 5;
    client.close(); local.close(); remote.close(); peer.close(); context.restart(); context.run_for(1s);
    Socket client2(context),local2(context),remote2(context),peer2(context);
    if (io::connect_pair(client2,local2) || io::connect_pair(remote2,peer2)) return 6;
    auto key2=s::SessionKey::derive(psk,request_salt); auto cipher2=s::ChunkCipher::create(std::move(*key2),true);
    s::detail::StartedRequest started2{std::vector<std::uint8_t>(request_salt.begin(),request_salt.end()),std::move(*cipher2)};
    Relay relay2(local2,remote2,psk,std::move(started2)); Result pending_up,pending_down;
    context.restart(); capy::run_async(ex)(upload(relay2,pending_up)); capy::run_async(ex)(download(relay2,pending_down)); context.run_for(30ms);
    if (pending_up.done || pending_down.done) return 7;
    relay2.cancel(); context.restart(); context.run_for(1s);
    if (!pending_up.done || !pending_down.done || pending_up.ok || pending_down.ok || !context.stopped()) return 8;
    client2.close(); local2.close(); remote2.close(); peer2.close(); context.restart(); context.run_for(1s);
    std::cout << "Shadowsocks 2022 Corosio duplex relay passed\n";
}
