#include <boost/corosio/backend.hpp>
#include <sys/socket.h>
#include <cerrno>
import std;
import xudp;
import xudp.client_sessions;
import xudp.client_io;
import capy;
import corosio;
namespace x=xudp; namespace io = ::corosio;
using Bytes=std::vector<std::uint8_t>; using namespace std::chrono_literals;
struct Stream {
    Bytes input,output; std::size_t offset=0,chunk=1; bool canceled=false,fail_write=false;
    auto write(std::span<std::uint8_t const> data) -> capy::task<bool> {
        if (fail_write || canceled) co_return false;
        output.insert(output.end(),data.begin(),data.end()); co_return true;
    }
    auto read(std::span<std::uint8_t> buffer) -> capy::task<std::expected<std::size_t,int>> {
        if (canceled) co_return std::unexpected(1);
        auto n=std::min({chunk,buffer.size(),input.size()-offset});
        std::copy_n(input.begin()+offset,n,buffer.begin()); offset+=n; co_return n;
    }
    auto cancel() noexcept -> void { canceled=true; }
};
using Client=x::ClientIo<Stream>;
auto execute(Client& client,Stream& stream,x::Address a,bool& ok) -> capy::task<> {
    Bytes payload{9,8}; auto first=co_await client.open(a,payload); if (!first || *first!=1) co_return;
    auto second=co_await client.open(a,payload); if (!second || *second!=2) co_return;
    if (!co_await client.send(2,{},payload)) co_return;
    auto one=co_await client.read(); if (!one || one->action!=x::Incoming::datagram || one->session!=1 || one->source!=a || one->payload!=Bytes({1,2,3})) co_return;
    auto two=co_await client.read(); if (!two || two->action!=x::Incoming::ended || two->session!=2 || !two->error) co_return;
    auto invalid=co_await client.send(2,{},payload); if (invalid || invalid.error()!=x::ClientIoError::session) co_return;
    if (!co_await client.end(1)) co_return;
    std::array<x::Kind,5> kinds{x::Kind::open,x::Kind::open,x::Kind::data,x::Kind::end,x::Kind::end};
    std::size_t pos=0;
    for (auto kind:kinds) {
        auto frame=x::parse(std::span(stream.output).subspan(pos)); if (frame.status!=x::Status::ready || frame.frame.kind!=kind) co_return;
        if (kind==x::Kind::end && pos<stream.output.size() && frame.frame.session!=99 && frame.frame.session!=1) co_return;
        pos+=frame.consumed;
    }
    ok=pos==stream.output.size();
}
auto failure(Client& client,Stream& stream,x::Address a,bool& ok) -> capy::task<> {
    stream.fail_write=true; auto result=co_await client.open(a,{}); if (result || result.error()!=x::ClientIoError::transport || !stream.canceled) co_return;
    auto again=co_await client.open(a,{}); ok=!again && again.error()==x::ClientIoError::closed;
}
auto exhaustion(Client& client,x::Address address,bool& ok) -> capy::task<> {
    for (std::uint32_t id=1;id<=65535;++id) {
        auto opened=co_await client.open(address,{});
        if (!opened || *opened!=id || !co_await client.end(*opened)) co_return;
        if (id%100==0) { auto [error]=co_await io::delay(1ms); if (error) co_return; }
    }
    auto opened=co_await client.open(address,{});
    ok=!opened && opened.error()==x::ClientIoError::exhausted;
}
struct DelayedStream {
    capy::async_event gate; Bytes input; bool canceled=false,write_entered=false;
    auto write(std::span<std::uint8_t const>) -> capy::task<bool> {
        write_entered=true; (void)co_await gate.wait(); co_return !canceled;
    }
    auto read(std::span<std::uint8_t> buffer) -> capy::task<std::expected<std::size_t,int>> {
        if (input.empty()) co_return std::unexpected(1);
        auto n=std::min(buffer.size(),input.size()); std::copy_n(input.begin(),n,buffer.begin()); input.erase(input.begin(),input.begin()+n); co_return n;
    }
    auto cancel() noexcept -> void { canceled=true; gate.set(); }
};
using DelayedClient=x::ClientIo<DelayedStream>;
auto delayed_open(DelayedClient& client,x::Address address,bool& done,bool& ok) -> capy::task<> { auto result=co_await client.open(address,{}); ok=result && *result==1; done=true; }
auto delayed_read(DelayedClient& client,bool& done,bool& ok) -> capy::task<> { auto result=co_await client.read(); ok=result && result->session==1 && result->action==x::Incoming::datagram && result->payload==Bytes({7}); done=true; }
struct SocketStream {
    io::local_stream_socket& socket;
    auto write(std::span<std::uint8_t const> data) -> capy::task<bool> {
        while (!data.empty()) { auto [error,n]=co_await socket.write_some(capy::const_buffer(data.data(),data.size())); if (error || !n) co_return false; data=data.subspan(n); } co_return true;
    }
    auto read(std::span<std::uint8_t> data) -> capy::task<std::expected<std::size_t,int>> {
        auto [error,n]=co_await socket.read_some(capy::mutable_buffer(data.data(),data.size())); if (error) co_return std::unexpected(1); co_return n;
    }
    auto cancel() noexcept -> void { socket.cancel(); }
};
using SocketClient=x::ClientIo<SocketStream>;
auto wait_read(SocketClient& client,bool& done,bool& failed) -> capy::task<> { auto result=co_await client.read(); failed=!result; done=true; }
auto socket_open(SocketClient& client,x::Address address,bool& done,bool& ok) -> capy::task<> {
    auto result=co_await client.open(address,{}); ok=result && *result==1; done=true;
}
auto socket_reply(SocketClient& client,bool& done,bool& ok) -> capy::task<> {
    auto result=co_await client.read(); ok=result && result->session==1 && result->payload==Bytes({7}); done=true;
}
auto fill_socket(int fd) -> std::optional<std::size_t> {
    std::array<std::uint8_t,4096> data{}; std::size_t total=0;
    for (;;) {
        auto n=::send(fd,data.data(),data.size(),MSG_DONTWAIT|MSG_NOSIGNAL);
        if (n>0) { total+=n; continue; }
        if (n<0 && errno==EINTR) continue;
        if (n<0 && (errno==EAGAIN || errno==EWOULDBLOCK)) return total;
        return {};
    }
}
auto drain_socket(int fd,std::size_t count) -> bool {
    std::array<std::uint8_t,4096> data{};
    while (count) {
        auto n=::recv(fd,data.data(),std::min(count,data.size()),MSG_DONTWAIT);
        if (n>0) { count-=n; continue; }
        if (n<0 && errno==EINTR) continue;
        return false;
    }
    return true;
}
template<class Backend> auto run(Backend backend) -> bool {
    io::io_context context(backend); x::Address a; a.length=4; a.port=53; a.bytes[0]=127; a.bytes[3]=1;
    Bytes payload{1,2,3}; Bytes input;
    auto unauthorized=a; unauthorized.port=54;
    for (auto frame:{x::Frame{99,x::Kind::data,true,false,{}, {},payload},x::Frame{1,x::Kind::data,true,false,unauthorized, {},payload},x::Frame{1,x::Kind::data,true,false,{}, {},payload},x::Frame{2,x::Kind::end,false,true}}) {
        auto encoded=x::encode(frame); if (!encoded) return false; input.insert(input.end(),encoded->begin(),encoded->end());
    }
    for (auto chunk:{std::size_t{1},std::size_t{65535}}) {
        Stream stream; stream.input=input; stream.chunk=chunk; Client client(stream,2); bool ok=false;
        capy::run_async(context.get_executor())(execute(client,stream,a,ok)); context.restart(); (void)context.run_for(2s);
        if (!context.stopped() || !ok) return false;
    }
    Stream broken; Client client(broken,1); bool ok=false;
    capy::run_async(context.get_executor())(failure(client,broken,a,ok)); context.restart(); (void)context.run_for(2s);
    if (!context.stopped() || !ok) return false;
    Stream bounded; Client finite(bounded,1); bool exhausted=false;
    capy::run_async(context.get_executor())(exhaustion(finite,a,exhausted)); context.restart(); (void)context.run_for(10s);
    if (!context.stopped() || !exhausted) return false;
    DelayedStream delayed; auto frame=x::encode(x::Frame{1,x::Kind::data,true,false,{}, {},Bytes{7}}); if (!frame) return false; delayed.input=*frame;
    DelayedClient delayed_client(delayed,1); bool open_done=false,open_ok=false,read_done=false,read_ok=false;
    capy::run_async(context.get_executor())(delayed_open(delayed_client,a,open_done,open_ok));
    capy::run_async(context.get_executor())(delayed_read(delayed_client,read_done,read_ok));
    context.restart(); (void)context.run_for(30ms);
    if (!delayed.write_entered || open_done || read_done) { delayed_client.cancel(); return false; }
    delayed.gate.set(); context.restart(); (void)context.run_for(1s);
    if (!context.stopped() || !open_done || !open_ok || !read_done || !read_ok) { delayed_client.cancel(); return false; }
    DelayedStream interrupted; interrupted.input=*frame; DelayedClient interrupted_client(interrupted,1);
    open_done=open_ok=read_done=read_ok=false;
    capy::run_async(context.get_executor())(delayed_open(interrupted_client,a,open_done,open_ok));
    capy::run_async(context.get_executor())(delayed_read(interrupted_client,read_done,read_ok));
    context.restart(); (void)context.run_for(30ms);
    if (!interrupted.write_entered || open_done || read_done) { interrupted_client.cancel(); return false; }
    interrupted_client.cancel(); context.restart(); (void)context.run_for(1s);
    if (!context.stopped() || !open_done || open_ok || !read_done || read_ok) return false;
    // A full real socket holds the write mutex while the peer's reply is
    // already readable. Exercise both recovery and cancellation in that state.
    for (bool cancel:{false,true}) {
        io::local_stream_socket writer(context),peer(context); if (io::connect_pair(writer,peer)) return false;
        auto filled=fill_socket(writer.native_handle()); if (!filled || !*filled) return false;
        auto encoded=x::encode(x::Frame{1,x::Kind::data,true,false,{}, {},Bytes{7}}); if (!encoded) return false;
        if (::send(peer.native_handle(),encoded->data(),encoded->size(),MSG_NOSIGNAL)!=static_cast<ssize_t>(encoded->size())) return false;
        SocketStream blocked_stream{writer}; SocketClient blocked(blocked_stream,1);
        bool open_done=false,open_ok=false,reply_done=false,reply_ok=false;
        capy::run_async(context.get_executor())(socket_open(blocked,a,open_done,open_ok));
        capy::run_async(context.get_executor())(socket_reply(blocked,reply_done,reply_ok));
        context.restart(); (void)context.run_for(30ms);
        if (open_done || reply_done) { blocked.cancel(); return false; }
        if (cancel) blocked.cancel();
        else if (!drain_socket(peer.native_handle(),*filled)) { blocked.cancel(); return false; }
        context.restart(); (void)context.run_for(1s);
        if (!context.stopped() || !open_done || !reply_done || open_ok==cancel || reply_ok==cancel) { blocked.cancel(); return false; }
        if (cancel) {
            if (!drain_socket(peer.native_handle(),*filled)) return false;
            std::array<std::uint8_t,128> output{};
            auto n=::recv(peer.native_handle(),output.data(),output.size(),MSG_DONTWAIT);
            if (n>0 || (n<0 && errno!=EAGAIN && errno!=EWOULDBLOCK)) return false;
        } else {
            std::array<std::uint8_t,128> output{};
            auto n=::recv(peer.native_handle(),output.data(),output.size(),MSG_DONTWAIT);
            if (n<=0) return false;
            auto parsed=x::parse(std::span(output).first(static_cast<std::size_t>(n)));
            if (parsed.status!=x::Status::ready || parsed.frame.session!=1 || parsed.frame.kind!=x::Kind::open) return false;
        }
    }
    io::local_stream_socket left(context),right(context); if (io::connect_pair(left,right)) return false;
    SocketStream stream{left}; SocketClient pending(stream,1); bool done=false,failed=false;
    capy::run_async(context.get_executor())(wait_read(pending,done,failed)); context.restart(); (void)context.run_for(30ms);
    if (done) return false; pending.cancel(); context.restart(); (void)context.run_for(1s);
    return context.stopped() && done && failed;
}
int main() {
    if (!run(io::epoll)) return 1;
#if BOOST_COROSIO_HAVE_LIBURING
    if (!run(io::uring)) return 2;
#endif
    std::cout << "XUDP stream splits, coalescing, unknown sessions, write races, failure and cancellation passed\n";
}
