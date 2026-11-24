#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cerrno>
#include <boost/corosio/backend.hpp>
import std;
import xudp;
import xudp.server_io;
import xudp.server_direct;
import xudp.server_sessions;
import net.udp_socket;
import rules;
import capy;
import corosio;
namespace x=xudp; namespace io = ::corosio;
using Bytes=std::vector<std::uint8_t>; using namespace std::chrono_literals;
struct Stream {
    Bytes input,output; std::size_t offset=0,chunk=1; bool canceled=false,wait_write=false,write_entered=false; capy::async_event write_gate;
    auto read(std::span<std::uint8_t> buffer) -> capy::task<std::expected<std::size_t,int>> {
        if (canceled) co_return std::unexpected(1);
        auto n=std::min({chunk,buffer.size(),input.size()-offset});
        std::copy_n(input.begin()+offset,n,buffer.begin()); offset+=n; co_return n;
    }
    auto write(std::span<std::uint8_t const> data) -> capy::task<bool> {
        if (wait_write) { write_entered=true; (void)co_await write_gate.wait(); }
        if (canceled) co_return false; output.insert(output.end(),data.begin(),data.end()); co_return true;
    }
    auto cancel() noexcept -> void { canceled=true; write_gate.set(); }
};
struct Resolver {
    bool canceled=false; int calls=0; std::optional<net::UdpEndpoint> candidate;
    auto resolve(x::Address const&) -> capy::task<std::expected<std::vector<net::UdpEndpoint>,int>> { ++calls; if (!candidate) co_return std::unexpected(1); co_return std::vector{*candidate}; }
    auto cancel() noexcept -> void { canceled=true; }
};
using Server=x::ServerIo<Stream,Resolver>;
auto execute(Server& server,Stream& stream,int fd,bool& ok) -> capy::task<> {
    if (!co_await server.read_one()) co_return;
    std::array<std::uint8_t,32> data{}; sockaddr_storage source{}; socklen_t length=sizeof(source);
    auto n=::recvfrom(fd,data.data(),data.size(),0,reinterpret_cast<sockaddr*>(&source),&length);
    if (n!=2 || data[0]!=7 || data[1]!=8) co_return;
    if (::sendto(fd,"reply",5,0,reinterpret_cast<sockaddr*>(&source),length)!=5) co_return;
    bool received=false;
    for (int i=0;i<100 && !received;++i) {
        auto result=co_await server.poll_one(); if (!result) co_return; received=*result;
        if (!received) { auto [error]=co_await io::delay(1ms); if (error) co_return; }
    }
    auto parsed=x::parse(stream.output);
    if (!received || parsed.status!=x::Status::ready || parsed.frame.session!=1 || parsed.frame.kind!=x::Kind::data || !std::ranges::equal(parsed.frame.payload,std::string_view("reply"))) co_return;
    if (!co_await server.read_one()) co_return;
    if (!co_await server.read_one()) co_return;
    auto tail=x::parse(std::span(stream.output).subspan(parsed.consumed));
    ok=tail.status==x::Status::ready && tail.frame.session==99 && tail.frame.kind==x::Kind::end;
}
auto run(int family,std::size_t chunk,bool domain) -> bool {
    int fd=::socket(family,SOCK_DGRAM|SOCK_CLOEXEC,0); if (fd<0) return false;
    struct Guard { int fd; ~Guard(){::close(fd);} } guard{fd};
    sockaddr_storage addr{}; socklen_t len;
    x::Address target; target.family=family==AF_INET?x::Family::ipv4:x::Family::ipv6; target.length=family==AF_INET?4:16;
    if (family==AF_INET) { auto& a=*reinterpret_cast<sockaddr_in*>(&addr); a.sin_family=AF_INET; a.sin_addr.s_addr=htonl(INADDR_LOOPBACK); target.bytes[0]=127; target.bytes[3]=1; len=sizeof(a); }
    else { auto& a=*reinterpret_cast<sockaddr_in6*>(&addr); a.sin6_family=AF_INET6; a.sin6_addr=in6addr_loopback; target.bytes[15]=1; len=sizeof(a); }
    if (::bind(fd,reinterpret_cast<sockaddr*>(&addr),len) || ::getsockname(fd,reinterpret_cast<sockaddr*>(&addr),&len)) return false;
    target.port=ntohs(family==AF_INET?reinterpret_cast<sockaddr_in*>(&addr)->sin_port:reinterpret_cast<sockaddr_in6*>(&addr)->sin6_port);
    timeval timeout{2,0}; ::setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout));
    net::UdpEndpoint candidate; candidate.family=family==AF_INET?4:6; std::copy_n(target.bytes.begin(),target.length,candidate.address.begin()); candidate.port=target.port;
    if (domain) { target.family=x::Family::domain; target.length=11; std::ranges::copy(std::string_view("example.org"),target.bytes.begin()); }
    Stream stream; stream.chunk=chunk; Bytes data{7,8};
    for (auto frame:{x::Frame{1,x::Kind::open,true,false,target,{},data},x::Frame{1,x::Kind::end},x::Frame{99,x::Kind::data,true,false,{}, {},data}}) {
        auto wire=x::encode(frame); if (!wire) return false; stream.input.insert(stream.input.end(),wire->begin(),wire->end());
    }
    auto policy=::rules::RouteMatcher::compile(std::span<::rules::RouteRule const>{},0,3); if (!policy) return false;
    Resolver resolver; resolver.candidate=candidate; Server server(stream,resolver,*policy,2); io::io_context context(io::epoll); bool ok=false;
    capy::run_async(context.get_executor())(execute(server,stream,fd,ok)); (void)context.run_for(2s); return context.stopped() && ok && resolver.calls==int(domain);
}
auto read_step(Server& server,bool& done,bool& ok) -> capy::task<> { auto result=co_await server.read_one(); ok=bool(result); done=true; }
auto poll_step(Server& server,bool& done,bool& ok) -> capy::task<> { auto result=co_await server.poll_one(); ok=result && *result; done=true; }
auto blocked_write(bool cancel) -> bool {
    int fd=::socket(AF_INET,SOCK_DGRAM|SOCK_CLOEXEC,0); if (fd<0) return false;
    struct Guard { int fd; ~Guard(){::close(fd);} } guard{fd};
    sockaddr_in addr{}; addr.sin_family=AF_INET; addr.sin_addr.s_addr=htonl(INADDR_LOOPBACK); socklen_t len=sizeof(addr);
    if (::bind(fd,reinterpret_cast<sockaddr*>(&addr),len) || ::getsockname(fd,reinterpret_cast<sockaddr*>(&addr),&len)) return false;
    x::Address target; target.length=4; target.bytes[0]=127; target.bytes[3]=1; target.port=ntohs(addr.sin_port);
    Bytes data{1}; Stream stream;
    for (auto frame:{x::Frame{1,x::Kind::open,true,false,target,{},data},x::Frame{1,x::Kind::end}}) {
        auto wire=x::encode(frame); if (!wire) return false; stream.input.insert(stream.input.end(),wire->begin(),wire->end());
    }
    auto policy=::rules::RouteMatcher::compile(std::span<::rules::RouteRule const>{},0,3); if (!policy) return false;
    Resolver resolver; Server server(stream,resolver,*policy,2); io::io_context context(io::epoll);
    bool done=false,ok=false; capy::run_async(context.get_executor())(read_step(server,done,ok)); (void)context.run_for(1s);
    if (!done || !ok) return false;
    sockaddr_storage source{}; socklen_t source_len=sizeof(source); std::array<char,2> buffer{};
    if (::recvfrom(fd,buffer.data(),buffer.size(),MSG_DONTWAIT,reinterpret_cast<sockaddr*>(&source),&source_len)!=1 ||
        ::sendto(fd,"r",1,0,reinterpret_cast<sockaddr*>(&source),source_len)!=1) return false;
    stream.wait_write=true; bool poll_done=false,poll_ok=false,read_done=false,read_ok=false;
    capy::run_async(context.get_executor())(poll_step(server,poll_done,poll_ok));
    capy::run_async(context.get_executor())(read_step(server,read_done,read_ok));
    context.restart(); (void)context.run_for(30ms);
    if (!stream.write_entered || poll_done || read_done) { server.cancel(); return false; }
    if (cancel) server.cancel(); else stream.write_gate.set();
    context.restart(); (void)context.run_for(1s);
    return context.stopped() && poll_done && read_done && poll_ok!=cancel && read_ok!=cancel;
}
auto resolve_failure_step(Server& server,Stream& stream,bool& ok) -> capy::task<> {
    if (!co_await server.read_one()) co_return;
    auto response=x::parse(stream.output);
    ok=response.status==x::Status::ready && response.frame.kind==x::Kind::end && response.frame.session==1 && response.frame.error;
}
auto resolve_failure() -> bool {
    x::Address domain; domain.family=x::Family::domain; domain.length=11; domain.port=53;
    std::ranges::copy(std::string_view("example.org"),domain.bytes.begin());
    Bytes payload{1}; auto wire=x::encode(x::Frame{1,x::Kind::open,true,false,domain,{},payload}); if (!wire) return false;
    Stream stream; stream.input=*wire; Resolver resolver;
    auto policy=::rules::RouteMatcher::compile(std::span<::rules::RouteRule const>{},0,3); if (!policy) return false;
    Server server(stream,resolver,*policy,2); io::io_context context(io::epoll); bool ok=false;
    capy::run_async(context.get_executor())(resolve_failure_step(server,stream,ok)); (void)context.run_for(1s);
    return context.stopped() && ok && resolver.calls==1 && !stream.canceled;
}
auto reject_then_new_step(Server& server,Stream& stream,int target,bool& ok) -> capy::task<> {
    if (!co_await server.read_one()) co_return;
    auto end=x::parse(stream.output);
    if (end.status!=x::Status::ready || end.frame.session!=1 || end.frame.kind!=x::Kind::end || !end.frame.error) co_return;
    if (!co_await server.read_one()) co_return;
    std::array<std::uint8_t,8> buffer{};
    auto n=::recv(target,buffer.data(),buffer.size(),MSG_DONTWAIT);
    ok=n==1 && buffer[0]==42 && stream.output.size()==end.consumed;
}
auto reject_then_new() -> bool {
    int fd=::socket(AF_INET,SOCK_DGRAM|SOCK_CLOEXEC,0); if (fd<0) return false;
    struct Guard { int fd; ~Guard(){::close(fd);} } guard{fd};
    sockaddr_in addr{}; addr.sin_family=AF_INET; addr.sin_addr.s_addr=htonl(INADDR_LOOPBACK); socklen_t length=sizeof(addr);
    if (::bind(fd,reinterpret_cast<sockaddr*>(&addr),length) || ::getsockname(fd,reinterpret_cast<sockaddr*>(&addr),&length)) return false;
    x::Address blocked; blocked.length=4; blocked.bytes[0]=127; blocked.bytes[3]=2; blocked.port=ntohs(addr.sin_port);
    auto allowed=blocked; allowed.bytes[3]=1;
    Bytes payload{42}; Stream stream;
    for (auto frame:{x::Frame{1,x::Kind::open,true,false,blocked,{},payload},x::Frame{2,x::Kind::open,true,false,allowed,{},payload}}) {
        auto wire=x::encode(frame); if (!wire) return false; stream.input.insert(stream.input.end(),wire->begin(),wire->end());
    }
    ::rules::RuleSet rules{{{"ip-cidr","127.0.0.2/32",{}}}};
    auto policy=::rules::RouteMatcher::compile(std::array{::rules::RouteRule{rules,1}},0,2); if (!policy) return false;
    Resolver resolver; Server server(stream,resolver,*policy,2); io::io_context context(io::epoll); bool ok=false;
    capy::run_async(context.get_executor())(reject_then_new_step(server,stream,fd,ok)); (void)context.run_for(1s);
    return context.stopped() && ok;
}
struct WaitingResolver {
    capy::async_event gate; bool entered=false,canceled=false;
    std::optional<net::UdpEndpoint> candidate;
    auto resolve(x::Address const&) -> capy::task<std::expected<std::vector<net::UdpEndpoint>,int>> {
        entered=true; (void)co_await gate.wait();
        if (candidate && !canceled) co_return std::vector{*candidate};
        co_return std::unexpected(1);
    }
    auto cancel() noexcept -> void { canceled=true; gate.set(); }
};
using WaitingServer=x::ServerIo<Stream,WaitingResolver>;
auto waiting_read(WaitingServer& server,bool& done,bool& failed) -> capy::task<> {
    auto result=co_await server.read_one(); failed=!result; done=true;
}
auto cancel_resolve() -> bool {
    x::Address domain; domain.family=x::Family::domain; domain.length=11; domain.port=53;
    std::ranges::copy(std::string_view("example.org"),domain.bytes.begin());
    Bytes payload{1}; auto wire=x::encode(x::Frame{1,x::Kind::open,true,false,domain,{},payload}); if (!wire) return false;
    Stream stream; stream.input=*wire; WaitingResolver resolver;
    net::UdpEndpoint candidate{4,{},53}; candidate.address[0]=127; candidate.address[3]=1; resolver.candidate=candidate;
    auto policy=::rules::RouteMatcher::compile(std::span<::rules::RouteRule const>{},0,3); if (!policy) return false;
    WaitingServer server(stream,resolver,*policy,2); io::io_context context(io::epoll); bool done=false,failed=false;
    capy::run_async(context.get_executor())(waiting_read(server,done,failed)); (void)context.run_for(30ms);
    if (!resolver.entered || done) { server.cancel(); return false; }
    server.cancel(); context.restart(); (void)context.run_for(1s);
    return context.stopped() && done && failed && resolver.canceled && stream.canceled && stream.output.empty();
}
auto expire_resolve_step(WaitingServer& server,bool& done,bool& ok) -> capy::task<> {
    auto result=co_await server.expire_one(std::chrono::steady_clock::now()+20s,10s);
    ok=result && *result; done=true;
}
auto expire_during_resolve() -> bool {
    x::Address domain; domain.family=x::Family::domain; domain.length=11; domain.port=53;
    std::ranges::copy(std::string_view("example.org"),domain.bytes.begin());
    Bytes payload{1}; auto wire=x::encode(x::Frame{1,x::Kind::open,true,false,domain,{},payload}); if (!wire) return false;
    Stream stream; stream.input=*wire; WaitingResolver resolver;
    net::UdpEndpoint candidate{4,{},53}; candidate.address[0]=127; candidate.address[3]=1; resolver.candidate=candidate;
    auto policy=::rules::RouteMatcher::compile(std::span<::rules::RouteRule const>{},0,3); if (!policy) return false;
    WaitingServer server(stream,resolver,*policy,2); io::io_context context(io::epoll); bool done=false,failed=false,expired=false,ok=false;
    capy::run_async(context.get_executor())(waiting_read(server,done,failed)); (void)context.run_for(30ms);
    if (!resolver.entered || done) { server.cancel(); return false; }
    capy::run_async(context.get_executor())(expire_resolve_step(server,expired,ok)); context.restart(); (void)context.run_for(30ms);
    if (!expired || !ok || done) { server.cancel(); return false; }
    resolver.gate.set(); context.restart(); (void)context.run_for(1s);
    auto end=x::parse(stream.output);
    return context.stopped() && done && !failed && end.status==x::Status::ready && end.frame.kind==x::Kind::end && !end.frame.error && end.consumed==stream.output.size();
}
struct BackpressuredDirect : x::ServerDirect {
    using ServerDirect::ServerDirect;
    static inline int attempts=0, failures=0;
    auto send(x::ServerToken token,x::Address const& target,net::UdpEndpoint candidate,std::span<std::uint8_t const> payload)
        -> std::expected<void,x::ServerDirectFailure> {
        ++attempts;
        if (attempts<=failures) return std::unexpected(x::ServerDirectFailure{std::make_error_code(std::errc::resource_unavailable_try_again)});
        return ServerDirect::send(token,target,candidate,payload);
    }
};
using BackpressureServer=x::ServerIo<Stream,Resolver,BackpressuredDirect>;
auto backpressure_read(BackpressureServer& server,bool& done,bool& ok) -> capy::task<> {
    auto result=co_await server.read_one(); ok=bool(result); done=true;
}
auto backpressure(int mode) -> bool {
    int fd=::socket(AF_INET,SOCK_DGRAM|SOCK_CLOEXEC,0); if (fd<0) return false;
    struct Guard { int fd; ~Guard(){::close(fd);} } guard{fd};
    sockaddr_in addr{}; addr.sin_family=AF_INET; addr.sin_addr.s_addr=htonl(INADDR_LOOPBACK); socklen_t len=sizeof(addr);
    if (::bind(fd,reinterpret_cast<sockaddr*>(&addr),len) || ::getsockname(fd,reinterpret_cast<sockaddr*>(&addr),&len)) return false;
    x::Address target; target.length=4; target.bytes[0]=127; target.bytes[3]=1; target.port=ntohs(addr.sin_port);
    Bytes data{1,2}; auto wire=x::encode(x::Frame{1,x::Kind::open,true,false,target,{},data}); if (!wire) return false;
    Stream stream; stream.input=*wire; Resolver resolver;
    auto policy=::rules::RouteMatcher::compile(std::span<::rules::RouteRule const>{},0,3); if (!policy) return false;
    BackpressureServer server(stream,resolver,*policy,2); io::io_context context(io::epoll); bool done=false,ok=false;
    BackpressuredDirect::attempts=0; BackpressuredDirect::failures=mode?1000:2;
    capy::run_async(context.get_executor())(backpressure_read(server,done,ok)); (void)context.run_for(mode==1?2ms:2s);
    if (mode==1) { if (done || !BackpressuredDirect::attempts) return false; server.cancel(); context.restart(); (void)context.run_for(1s); }
    std::array<std::uint8_t,8> received{}; auto n=::recv(fd,received.data(),received.size(),MSG_DONTWAIT);
    if (!context.stopped() || !done) return false;
    if (mode==1) return !ok && n<0;
    if (mode==2) { auto end=x::parse(stream.output); return ok && n<0 && BackpressuredDirect::attempts==101 && end.status==x::Status::ready && end.frame.kind==x::Kind::end && end.frame.error; }
    return ok && BackpressuredDirect::attempts==3 && n==2 && received[0]==1 && received[1]==2;
}
struct SocketStream {
    io::local_stream_socket& socket;
    auto read(std::span<std::uint8_t> data) -> capy::task<std::expected<std::size_t,int>> {
        auto [error,n]=co_await socket.read_some(capy::mutable_buffer(data.data(),data.size()));
        if (error) co_return std::unexpected(1); co_return n;
    }
    auto write(std::span<std::uint8_t const> data) -> capy::task<bool> {
        while (!data.empty()) {
            auto [error,n]=co_await socket.write_some(capy::const_buffer(data.data(),data.size()));
            if (error || !n) co_return false; data=data.subspan(n);
        }
        co_return true;
    }
    auto cancel() noexcept -> void { socket.cancel(); }
};
using SocketServer=x::ServerIo<SocketStream,Resolver>;
auto socket_read(SocketServer& server,bool& done,bool& ok) -> capy::task<> { auto result=co_await server.read_one(); ok=bool(result); done=true; }
auto socket_poll(SocketServer& server,bool& done,bool& ok) -> capy::task<> { auto result=co_await server.poll_one(); ok=result && !*result; done=true; }
auto fill(int fd) -> std::optional<std::size_t> {
    std::array<std::uint8_t,4096> bytes{}; std::size_t total=0;
    for (;;) {
        auto n=::send(fd,bytes.data(),bytes.size(),MSG_DONTWAIT|MSG_NOSIGNAL);
        if (n>0) { total+=n; continue; }
        if (n<0 && errno==EINTR) continue;
        if (n<0 && (errno==EAGAIN || errno==EWOULDBLOCK)) return total;
        return {};
    }
}
auto drain(int fd,std::size_t count) -> bool {
    std::array<std::uint8_t,4096> bytes{};
    while (count) {
        auto n=::recv(fd,bytes.data(),std::min(count,bytes.size()),MSG_DONTWAIT);
        if (n>0) { count-=n; continue; }
        if (n<0 && errno==EINTR) continue;
        return false;
    }
    return true;
}
template<class Backend> auto socket_backpressure(Backend backend,bool cancel) -> bool {
    io::io_context context(backend); io::local_stream_socket server_socket(context),peer(context);
    if (io::connect_pair(server_socket,peer)) return false;
    auto filled=fill(server_socket.native_handle()); if (!filled || !*filled) return false;
    Bytes payload{1}; auto frame=x::encode(x::Frame{99,x::Kind::data,true,false,{}, {},payload}); if (!frame) return false;
    if (::send(peer.native_handle(),frame->data(),frame->size(),MSG_NOSIGNAL)!=static_cast<ssize_t>(frame->size())) return false;
    auto policy=::rules::RouteMatcher::compile(std::span<::rules::RouteRule const>{},0,3); if (!policy) return false;
    SocketStream stream{server_socket}; Resolver resolver; SocketServer server(stream,resolver,*policy,2);
    bool read_done=false,read_ok=false,poll_done=false,poll_ok=false;
    capy::run_async(context.get_executor())(socket_read(server,read_done,read_ok));
    (void)context.run_for(30ms);
    if (read_done) { server.cancel(); return false; }
    capy::run_async(context.get_executor())(socket_poll(server,poll_done,poll_ok));
    context.restart(); (void)context.run_for(30ms);
    if (read_done || poll_done) { server.cancel(); return false; }
    if (cancel) server.cancel(); else if (!drain(peer.native_handle(),*filled)) { server.cancel(); return false; }
    context.restart(); (void)context.run_for(1s);
    if (!context.stopped() || !read_done || !poll_done || read_ok==cancel || poll_ok==cancel) { server.cancel(); return false; }
    if (cancel && !drain(peer.native_handle(),*filled)) return false;
    std::array<std::uint8_t,128> output{}; auto n=::recv(peer.native_handle(),output.data(),output.size(),MSG_DONTWAIT);
    if (cancel) return n<0 && (errno==EAGAIN || errno==EWOULDBLOCK);
    if (n<=0) return false;
    auto response=x::parse(std::span(output).first(static_cast<std::size_t>(n)));
    return response.status==x::Status::ready && response.frame.session==99 && response.frame.kind==x::Kind::end;
}
int main() {
    for (bool cancel:{false,true}) if (!socket_backpressure(io::epoll,cancel)) return 3;
#if BOOST_COROSIO_HAVE_LIBURING
    for (bool cancel:{false,true}) if (!socket_backpressure(io::uring,cancel)) return 4;
#endif
    if (!backpressure(0) || !backpressure(1) || !backpressure(2) || !resolve_failure() || !reject_then_new() || !cancel_resolve() || !expire_during_resolve() || !blocked_write(false) || !blocked_write(true)) return 2;
    for (auto family:{AF_INET,AF_INET6}) for (auto chunk:{std::size_t{1},std::size_t{65535}}) for (bool domain:{false,true}) if (!run(family,chunk,domain)) return 1;
    std::cout<<"XUDP server stream and UDP round trips passed\n";
}
