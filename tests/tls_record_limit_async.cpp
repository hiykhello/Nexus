#include <boost/corosio/backend.hpp>
#include <sys/socket.h>
#include <errno.h>
import std;
import tls.corosio_application;
import tls.application_io;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;
namespace t=tls;namespace c = ::crypto;namespace io=nex::corosio;namespace capy=nex::capy;
using Bytes=c::Bytes;using namespace std::chrono_literals;
auto secret(int n) -> t::Secret { return t::Secret(Bytes(32,static_cast<std::uint8_t>(n))); }
auto layer(t::RecordDirection direction,int n) -> t::RecordLayer {
    auto s=secret(n);auto k=t::expand_label(c::Hash::sha256,s.view(),"key",{},16),iv=t::expand_label(c::Hash::sha256,s.view(),"iv",{},12);
    if (!k || !iv) std::abort();auto value=t::RecordLayer::create(direction,c::Aead::aes_128_gcm,k->view(),iv->view());
    if (!value) std::abort();return std::move(*value);
}
using Conn=t::detail::ApplicationConnection<io::local_stream_socket>;
struct Result { bool reader=false,writer=false,read_failed=false,write_failed=false; };
auto read_task(Conn& connection,Result& r) -> capy::task<> { auto value=co_await connection.read(std::chrono::steady_clock::now()+3s);r.read_failed=!value;r.reader=true; }
auto write_task(Conn& connection,Result& r,bool closing) -> capy::task<> {
    Bytes payload(1024,42);auto deadline=std::chrono::steady_clock::now()+3s;
    auto value=closing ? co_await connection.close_notify(deadline) : co_await connection.send(payload,deadline);
    r.write_failed=!value;r.writer=true;
}
template<class Backend> auto exercise(Backend backend,bool closing) -> bool {
    io::io_context context(backend);io::local_stream_socket local(context),remote(context);if (io::connect_pair(local,remote)) return false;
    t::ApplicationRecords owner(layer(t::RecordDirection::send,1),layer(t::RecordDirection::receive,2),16385,64,c::Hash::sha256,c::Aead::aes_128_gcm,16,secret(1),secret(2),t::ApplicationRole::client);
    Conn connection(local,std::move(owner),{});Result state;
    struct Guard { Conn& connection;io::local_stream_socket& local;io::local_stream_socket& remote;io::io_context& context;
        ~Guard() {connection.cancel();local.close();remote.close();context.restart();(void)context.run_for(1s);if (!connection.idle()) std::_Exit(90);} } guard{connection,local,remote,context};
    std::array<char,4096> fill{};std::size_t total=0;
    for (;;) { auto n=::send(local.native_handle(),fill.data(),fill.size(),MSG_DONTWAIT|MSG_NOSIGNAL);if (n>0) {total+=n;continue;} if (n<0 && errno==EINTR) continue;if (n<0 && (errno==EAGAIN || errno==EWOULDBLOCK)) break;return false; }
    auto executor=context.get_executor();capy::run_async(executor)(write_task(connection,state,closing));capy::run_async(executor)(read_task(connection,state));
    context.restart();(void)context.run_for(30ms);if (state.reader || state.writer) return false;
    auto send=layer(t::RecordDirection::send,2),receive=layer(t::RecordDirection::receive,1);
    auto violation=send.seal(t::ContentType::application_data,Bytes(64,1));if (!violation) return false;
    if (::send(remote.native_handle(),violation->data(),violation->size(),MSG_NOSIGNAL)!=static_cast<ssize_t>(violation->size())) return false;
    context.restart();(void)context.run_for(30ms);if (state.reader || state.writer) return false;
    std::array<char,4096> buffer{};while (total) {auto n=::recv(remote.native_handle(),buffer.data(),std::min(total,buffer.size()),0);if (n<=0) return false;total-=n;}
    context.restart();(void)context.run_for(2s);
    if (!state.reader || !state.writer || !state.read_failed || !state.write_failed || !connection.idle() || connection.active()) return false;
    Bytes received;for (;;) {auto n=::recv(remote.native_handle(),buffer.data(),buffer.size(),MSG_DONTWAIT);if(n>0){received.insert(received.end(),buffer.data(),buffer.data()+n);continue;}if(n<0&&errno==EINTR)continue;break;}
    auto take=[&](std::size_t& offset) -> std::optional<t::PlaintextRecord> {
        if (received.size()-offset<5) return {};auto size=5+(std::size_t{received[offset+3]}<<8)+received[offset+4];
        if (size>received.size()-offset) return {};auto result=receive.open(std::span(received).subspan(offset,size));offset+=size;
        if (!result) return {};return std::move(*result);
    };
    std::size_t pos=0;auto first=take(pos);
    if (closing) return first && first->type==t::ContentType::alert && first->content==Bytes({1,0}) && pos==received.size();
    auto alert=take(pos);
    return first && first->type==t::ContentType::application_data && first->content==Bytes(1024,42) &&
        alert && alert->type==t::ContentType::alert && alert->content==Bytes({2,22}) && pos==received.size();
}
auto main() -> int {
    if (!exercise(io::epoll,false) || !exercise(io::epoll,true)) return 1;
#if BOOST_COROSIO_HAVE_LIBURING
    if (!exercise(io::uring,false) || !exercise(io::uring,true)) return 2;
#endif
    std::println("TLS overflow waits for in-flight writer, then sends encrypted alert on both backends");
}
