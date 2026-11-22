#include <boost/corosio/backend.hpp>
#include <sys/socket.h>
#include <cerrno>
import std;
import vision;
import vision.corosio_writer;
import vision.corosio_reader;
import tls.application_io;
import tls.corosio_application;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;
namespace v=vision; namespace t=tls; namespace c = ::crypto; namespace capy=nex::capy; namespace io=nex::corosio;
using Bytes=c::Bytes; using namespace std::chrono_literals;
auto secret(int n) -> t::Secret { return t::Secret(Bytes(32,static_cast<std::uint8_t>(n))); }
auto layer(t::RecordDirection direction,int n) -> t::RecordLayer {
    auto s=secret(n); auto key=t::expand_label(c::Hash::sha256,s.view(),"key",{},16), iv=t::expand_label(c::Hash::sha256,s.view(),"iv",{},12);
    if (!key || !iv) std::abort(); auto value=t::RecordLayer::create(direction,c::Aead::aes_128_gcm,key->view(),iv->view());
    if (!value) std::abort(); return std::move(*value);
}
auto records() -> t::ApplicationRecords { return {layer(t::RecordDirection::send,1),layer(t::RecordDirection::receive,2),16385,16385,c::Hash::sha256,c::Aead::aes_128_gcm,16,secret(1),secret(2),t::ApplicationRole::client}; }
using Connection=t::detail::ApplicationConnection<io::local_stream_socket>;
using Reader=v::detail::Reader<io::local_stream_socket>;
auto small_reads(io::local_stream_socket& socket,Connection& connection,v::UserId user,Bytes frame,Bytes expected,bool& success) -> capy::task<> {
    v::TrafficFilter filter; v::detail::Writer writer(socket,connection,filter,user);
    t::detail::ApplicationStreamReader stream(connection); Reader reader(socket,stream,writer,filter,user,frame);
    Bytes got; std::array<std::uint8_t,1> output{};
    while (got.size()<expected.size()) {
        auto result=co_await reader.read(output); if (!result || *result!=1) co_return;
        got.push_back(output[0]);
    }
    success=got==expected && filter.is_tls() && filter.direct_eligible() && filter.cipher()==0x1301 && filter.remaining()==0;
}
template<class Backend> auto filter_test(Backend backend) -> bool {
    io::io_context context(backend); io::local_stream_socket a(context),b(context); if (io::connect_pair(a,b)) return false;
    Connection connection(a,records(),{}); v::UserId user{}; std::iota(user.begin(),user.end(),std::uint8_t{0});
    Bytes hello(85); hello[0]=0x16; hello[1]=hello[2]=3; hello[4]=80; hello[5]=2; hello[43]=32; hello[76]=0x13; hello[77]=1;
    std::array<std::uint8_t,6> extension{0,0x2b,0,2,3,4}; std::ranges::copy(extension,hello.begin()+79);
    auto frame=v::encode_block(user,v::Command::end,hello,{}); if (!frame) return false;
    bool success=false; capy::run_async(context.get_executor())(small_reads(a,connection,user,std::move(*frame),std::move(hello),success));
    context.restart(); (void)context.run_for(2s); if (!context.stopped()) { connection.cancel(); context.restart(); (void)context.run_for(1s); return false; }
    return success;
}
auto blocked_read(Reader& reader,bool& done,bool& failed) -> capy::task<> {
    std::array<std::uint8_t,32> output{}; auto result=co_await reader.read(output); failed=!result; done=true;
}
template<class Backend> auto cancel_test(Backend backend) -> bool {
    io::io_context context(backend); io::local_stream_socket a(context),b(context); if (io::connect_pair(a,b)) return false;
    Connection connection(a,records(),{}); v::UserId user{}; v::TrafficFilter filter;
    v::detail::Writer writer(a,connection,filter,user); t::detail::ApplicationStreamReader stream(connection); Reader reader(a,stream,writer,filter,user);
    bool done=false,failed=false; capy::run_async(context.get_executor())(blocked_read(reader,done,failed));
    context.restart(); (void)context.run_for(30ms); if (done || connection.idle()) { reader.cancel(); return false; }
    reader.cancel(); context.restart(); (void)context.run_for(1s);
    return context.stopped() && done && failed && connection.idle() && !connection.active();
}
auto consume(io::local_stream_socket& socket,Connection& connection,v::UserId user,Bytes expected,bool& success) -> capy::task<> {
    v::TrafficFilter filter; v::detail::Writer writer(socket,connection,filter,user);
    t::detail::ApplicationStreamReader stream(connection); std::array<std::uint8_t,7> pre{};
    auto head=co_await stream.read_some(pre);
    if (!head || head->kind!=t::detail::AsyncStreamReadKind::data || head->size!=pre.size()) co_return;
    v::detail::Reader reader(socket,stream,writer,filter,user,pre);
    Bytes got; std::array<std::uint8_t,73> out{};
    for (;;) {
        auto read=co_await reader.read(out); if (!read) co_return;
        if (!*read) break;
        got.insert(got.end(),out.begin(),out.begin()+*read);
        if (got.size()>expected.size()) co_return;
    }
    success=(got==expected && connection.idle());
}
auto consume_eof(io::local_stream_socket& socket,Connection& connection,v::UserId user,bool truncated,bool& success) -> capy::task<> {
    v::TrafficFilter filter; v::detail::Writer writer(socket,connection,filter,user);
    t::detail::ApplicationStreamReader stream(connection); v::detail::Reader reader(socket,stream,writer,filter,user);
    Bytes got; std::array<std::uint8_t,1> output{};
    for (;;) {
        auto result=co_await reader.read(output);
        if (!result) { success=truncated && result.error()==v::detail::ReadError::protocol; co_return; }
        if (!*result) { success=!truncated && got==Bytes({0,1,2}); co_return; }
        got.push_back(output[0]); if (got.size()>3) co_return;
    }
}
template<class Backend> auto eof_test(Backend backend,bool truncated) -> bool {
    io::io_context context(backend); io::local_stream_socket a(context),b(context); if (io::connect_pair(a,b)) return false;
    v::UserId user{}; std::iota(user.begin(),user.end(),std::uint8_t{0});
    t::ApplicationIo peer(t::ApplicationRecords(layer(t::RecordDirection::send,2),layer(t::RecordDirection::receive,1),16385,16385,c::Hash::sha256,c::Aead::aes_128_gcm,16,secret(2),secret(1),t::ApplicationRole::client));
    Bytes data=truncated ? Bytes(user.begin(),user.end()) : Bytes{0,1,2};
    if (!peer.send(data)) return false; Bytes wire(peer.pending_output().begin(),peer.pending_output().end());
    if (!peer.written(peer.pending_output().size()) || !peer.close_notify()) return false;
    wire.insert(wire.end(),peer.pending_output().begin(),peer.pending_output().end());
    if (::send(b.native_handle(),wire.data(),wire.size(),MSG_NOSIGNAL)!=static_cast<ssize_t>(wire.size())) return false;
    Connection connection(a,records(),{}); bool success=false;
    capy::run_async(context.get_executor())(consume_eof(a,connection,user,truncated,success));
    context.restart(); (void)context.run_for(2s); if (!context.stopped()) { connection.cancel(); context.restart(); (void)context.run_for(1s); return false; }
    return success;
}
auto concurrent_write(v::detail::Writer<io::local_stream_socket>& writer,Bytes data,bool& done,bool& ok) -> capy::task<> {
    ok=co_await writer.write(data); done=true;
}
auto concurrent_close(v::detail::Writer<io::local_stream_socket>& writer,bool& done,bool& ok) -> capy::task<> {
    ok=co_await writer.close_output(); done=true;
}
auto concurrent_read(Reader& reader,bool& done,bool& ok) -> capy::task<> {
    std::array<std::uint8_t,8> output{}; auto result=co_await reader.read(output);
    ok=result && *result==2 && output[0]==7 && output[1]==8; done=true;
}
template<class Backend> auto key_update_race(Backend backend,bool direct,bool close) -> bool {
    io::io_context context(backend); io::local_stream_socket a(context),b(context); if (io::connect_pair(a,b)) return false;
    std::array<char,4096> filler{}; std::size_t filled=0;
    for (;;) {
        auto n=::send(a.native_handle(),filler.data(),filler.size(),MSG_DONTWAIT|MSG_NOSIGNAL);
        if (n>0) { filled+=n; continue; }
        if (n<0 && errno==EINTR) continue;
        if (n<0 && (errno==EAGAIN || errno==EWOULDBLOCK)) break;
        return false;
    }
    Connection connection(a,records(),{}); v::UserId user{}; v::TrafficFilter filter;
    v::detail::Writer writer(a,connection,filter,user); t::detail::ApplicationStreamReader stream(connection); Reader reader(a,stream,writer,filter,user);
    Bytes data(8192,42);
    if (direct) {
        Bytes hello(85); hello[0]=0x16; hello[1]=hello[2]=3; hello[4]=80; hello[5]=2; hello[43]=32; hello[76]=0x13; hello[77]=1;
        std::array<std::uint8_t,6> extension{0,0x2b,0,2,3,4}; std::ranges::copy(extension,hello.begin()+79); filter.observe(hello);
        data[0]=0x17; data[1]=data[2]=3; data[3]=0x1f; data[4]=0xfb;
    }
    bool write_done=false,write_ok=false,read_done=false,read_ok=false,close_done=false,close_ok=false;
    capy::run_async(context.get_executor())(concurrent_write(writer,data,write_done,write_ok));
    context.restart(); (void)context.run_for(30ms);
    if (write_done || connection.idle()) { writer.cancel(); return false; }
    if (close) {
        capy::run_async(context.get_executor())(concurrent_close(writer,close_done,close_ok));
        context.restart(); (void)context.run_for(30ms);
        if (close_done) { writer.cancel(); return false; }
    }
    t::ApplicationIo peer(t::ApplicationRecords(layer(t::RecordDirection::send,2),layer(t::RecordDirection::receive,1),16385,16385,c::Hash::sha256,c::Aead::aes_128_gcm,16,secret(2),secret(1),t::ApplicationRole::client));
    if (!peer.request_key_update(true)) return false;
    Bytes incoming(peer.pending_output().begin(),peer.pending_output().end());
    if (!peer.written(peer.pending_output().size()) || !peer.send(Bytes{7,8})) return false;
    incoming.insert(incoming.end(),peer.pending_output().begin(),peer.pending_output().end());
    if (::send(b.native_handle(),incoming.data(),incoming.size(),MSG_NOSIGNAL)!=static_cast<ssize_t>(incoming.size())) return false;
    capy::run_async(context.get_executor())(concurrent_read(reader,read_done,read_ok));
    context.restart(); (void)context.run_for(30ms);
    if (write_done || read_done) { writer.cancel(); return false; }
    while (filled) {
        auto n=::recv(b.native_handle(),filler.data(),std::min(filled,filler.size()),0);
        if (n<0 && errno==EINTR) continue;
        if (n<=0) { writer.cancel(); return false; }
        filled-=n;
    }
    context.restart(); (void)context.run_for(2s);
    if (!context.stopped() || !write_done || !write_ok || !read_done || !read_ok || (close && (!close_done || !close_ok)) || !connection.idle()) { writer.cancel(); return false; }
    Bytes wire; std::array<std::uint8_t,16384> buffer{};
    for (;;) {
        auto n=::recv(b.native_handle(),buffer.data(),buffer.size(),MSG_DONTWAIT);
        if (n>0) { wire.insert(wire.end(),buffer.begin(),buffer.begin()+n); continue; }
        if (n<0 && errno==EINTR) continue;
        if ((n<0 && (errno==EAGAIN || errno==EWOULDBLOCK)) || (n==0 && close && direct)) break;
        return false;
    }
    bool received_data=false,update=false,notify=false; std::size_t offset=0;
    while (offset<wire.size()) {
        auto result=peer.feed(std::span(wire).subspan(offset)); if (!result || !result->consumed) return false;
        offset+=result->consumed;
        if (result->event && result->event->kind==t::ApplicationEventKind::data) {
            v::Receiver receiver(user); Bytes decoded(8192); auto step=receiver.feed(result->event->data,decoded);
            received_data=step.written==decoded.size() && decoded==data && (!direct || step.status==v::ReceiveStatus::direct);
        }
        if (result->event && result->event->kind==t::ApplicationEventKind::key_update) { if (!received_data || notify) return false; update=true; }
        if (result->event && result->event->kind==t::ApplicationEventKind::close_notify) { if (!update) return false; notify=true; }
    }
    return received_data && update && (notify==(close && !direct)) && (!direct || writer.status()==v::SendStatus::direct);
}
template<class Backend> auto run(Backend backend) -> bool {
    io::io_context context(backend); io::local_stream_socket a(context),b(context); if (io::connect_pair(a,b)) return false;
    v::UserId user{}; std::iota(user.begin(),user.end(),std::uint8_t{0}); Bytes data(8192,42);
    auto frame=v::encode_block(user,v::Command::direct,data,Bytes{1,2,3}); if (!frame) return false;
    frame->insert(frame->end(),{'T','L','S'});
    auto peer=layer(t::RecordDirection::send,2); auto encrypted=peer.seal(t::ContentType::application_data,*frame); if (!encrypted) return false;
    encrypted->insert(encrypted->end(),{'R','A','W'});
    if (::send(b.native_handle(),encrypted->data(),encrypted->size(),MSG_NOSIGNAL)!=static_cast<ssize_t>(encrypted->size())) return false;
    if (b.shutdown(io::shutdown_send)) return false;
    Connection connection(a,records(),{}); Bytes expected=data; expected.insert(expected.end(),{'T','L','S','R','A','W'});
    bool success=false; capy::run_async(context.get_executor())(consume(a,connection,user,std::move(expected),success));
    context.restart(); (void)context.run_for(3s); if (!context.stopped()) { connection.cancel(); context.restart(); (void)context.run_for(1s); return false; }
    return success;
}
int main() {
    if (!run(io::epoll) || !eof_test(io::epoll,false) || !eof_test(io::epoll,true) || !cancel_test(io::epoll) || !filter_test(io::epoll) || !key_update_race(io::epoll,false,false) || !key_update_race(io::epoll,true,false) || !key_update_race(io::epoll,false,true) || !key_update_race(io::epoll,true,true)) return 1;
#if BOOST_COROSIO_HAVE_LIBURING
    if (!run(io::uring) || !eof_test(io::uring,false) || !eof_test(io::uring,true) || !cancel_test(io::uring) || !filter_test(io::uring) || !key_update_race(io::uring,false,false) || !key_update_race(io::uring,true,false) || !key_update_race(io::uring,false,true) || !key_update_race(io::uring,true,true)) return 2;
#endif
    std::cout << "Vision reader preserves VLESS, TLS and raw suffix order\n";
}
