#include <boost/corosio/backend.hpp>
#include <errno.h>
#include <sys/socket.h>
import std;
import tls.application_io;
import capy;
import corosio;
import tls.corosio_application;
namespace io = ::corosio; namespace t=tls; namespace c = ::crypto;
using Bytes=c::Bytes; using namespace std::chrono_literals;
auto secret(int n) -> t::Secret { return t::Secret(Bytes(32,static_cast<std::uint8_t>(n))); }
auto layer(t::RecordDirection direction,int n,std::uint64_t limit=1u << 24) -> t::RecordLayer {
    auto s=secret(n); auto key=t::expand_label(c::Hash::sha256,s.view(),"key",{},16), iv=t::expand_label(c::Hash::sha256,s.view(),"iv",{},12);
    if (!key || !iv) std::abort(); auto value=t::RecordLayer::create(direction,c::Aead::aes_128_gcm,key->view(),iv->view(),limit);
    if (!value) std::abort(); return std::move(*value);
}
auto records(std::uint64_t limit,std::size_t write_limit=16385) -> t::ApplicationRecords {
    return {layer(t::RecordDirection::send,1,limit),layer(t::RecordDirection::receive,2),write_limit,16385,c::Hash::sha256,c::Aead::aes_128_gcm,16,secret(1),secret(2),t::ApplicationRole::client};
}
using Connection=t::detail::ApplicationConnection<io::local_stream_socket>;
struct Fixture {
    io::io_context context; io::local_stream_socket a{context}, b{context}; Connection connection;
    bool read_done=false, write_done=false, duplicate_read=false, duplicate_write=false; bool read_failed=false, write_failed=false, fatal=false;
    std::optional<t::detail::AsyncApplicationError> read_error, write_error;
    template<class Backend> explicit Fixture(Backend backend,std::uint64_t limit=1u << 24,std::size_t write_limit=16385,Bytes unread={}) : context(backend), connection(a,records(limit,write_limit),std::move(unread)) {}
    ~Fixture() { connection.cancel(); a.close(); b.close(); context.restart(); (void)context.run_for(1s); if (!context.stopped() || !connection.idle()) std::_Exit(90); }
};
struct FailingSocket {
    io::local_stream_socket& socket; bool fail_read;
    auto read_some(capy::mutable_buffer b) { if (fail_read) throw std::bad_alloc{}; return socket.read_some(b); }
    auto write_some(capy::const_buffer b) { if (!fail_read) throw std::bad_alloc{}; return socket.write_some(b); }
    void cancel() { socket.cancel(); }
};
using FailingConnection=t::detail::ApplicationConnection<FailingSocket>;
auto exception_operation(FailingConnection& connection,int mode,bool& caught) -> capy::task<> {
    try {
        Bytes data{1,2,3};
        if (mode==0) (void)co_await connection.read();
        else if (mode==1) (void)co_await connection.send(data);
        else if (mode==2) (void)co_await connection.send_all(data);
        else if (mode==3) (void)co_await connection.key_update(false);
        else (void)co_await connection.close_notify();
    } catch (std::bad_alloc const&) { caught=true; }
}
template<class Backend> auto exception_test(Backend backend,int mode) -> bool {
    io::io_context context(backend); io::local_stream_socket a(context),b(context); if (io::connect_pair(a,b)) return false;
    FailingSocket socket{a,mode==0}; FailingConnection connection(socket,records(1u << 24),{}); bool caught=false;
    capy::run_async(context.get_executor())(exception_operation(connection,mode,caught)); context.restart(); (void)context.run_for(1s);
    return context.stopped() && caught && !connection.active() && connection.idle() && !connection.pending_output();
}
auto pending_operation(FailingConnection& connection,bool reading,bool& done,bool& failed) -> capy::task<> {
    Bytes data(1024,42);
    if (reading) { auto result=co_await connection.read(); failed=!result; }
    else { auto result=co_await connection.send(data); failed=!result; }
    done=true;
}
template<class Backend> auto exception_overlap(Backend backend,bool fail_read) -> bool {
    io::io_context context(backend); io::local_stream_socket a(context),b(context); if (io::connect_pair(a,b)) return false;
    FailingSocket socket{a,fail_read}; FailingConnection connection(socket,records(1u << 24),{});
    if (fail_read) {
        std::array<char,4096> filler{};
        for (;;) { auto n=::send(a.native_handle(),filler.data(),filler.size(),MSG_DONTWAIT|MSG_NOSIGNAL);
            if (n>0 || (n<0 && errno==EINTR)) continue;
            if (n<0 && (errno==EAGAIN || errno==EWOULDBLOCK)) break; return false; }
    }
    bool done=false,failed=false,caught=false;
    capy::run_async(context.get_executor())(pending_operation(connection,!fail_read,done,failed));
    context.restart(); (void)context.run_for(20ms);
    if (done || connection.idle()) return false;
    capy::run_async(context.get_executor())(exception_operation(connection,fail_read ? 0 : 1,caught));
    context.restart(); (void)context.run_for(1s);
    return context.stopped() && caught && done && failed && !connection.active() && connection.idle() && !connection.pending_output();
}
auto reader(Fixture& f) -> capy::task<> { auto result=co_await f.connection.read(); f.read_failed=!result; if (!result) f.read_error=result.error(); f.fatal=result && result->event && result->event->kind==t::ApplicationEventKind::fatal_alert; f.read_done=true; }
auto boundary_reader(Fixture& f) -> capy::task<> {
    auto result=co_await f.connection.read();
    f.fatal=result && result->event && result->event->kind==t::ApplicationEventKind::data && result->event->data==Bytes(4074,42);
    f.read_done=true;
}
template<class Backend> auto unread_boundary_test(Backend backend) -> bool {
    auto peer=layer(t::RecordDirection::send,2); auto wire=peer.seal(t::ContentType::application_data,Bytes(4074,42));
    if (!wire || wire->size()!=4096) return false;
    wire->reserve(1u << 20);
    io::io_context context(backend); io::local_stream_socket socket(context);
    Connection connection(socket,records(1u << 24),std::move(*wire));
    if (!connection.active() || wire->capacity()!=0) return false;
    auto peer2=layer(t::RecordDirection::send,2); auto data=peer2.seal(t::ContentType::application_data,Bytes(4074,42));
    if (!data) return false;
    Fixture full(backend,1u << 24,16385,std::move(*data));
    capy::run_async(full.context.get_executor())(boundary_reader(full)); full.context.restart(); (void)full.context.run_for(1s);
    if (!full.context.stopped() || !full.read_done || !full.fatal) return false;
    Bytes oversized(4097,0); oversized.reserve(1u << 20);
    Connection rejected(socket,records(1u << 24),std::move(oversized));
    return !rejected.active() && rejected.idle() && oversized.capacity()==0;
}
auto writer(Fixture& f) -> capy::task<> { Bytes data(1024,42); auto result=co_await f.connection.send(data); f.write_failed=!result; if (!result) f.write_error=result.error(); f.write_done=true; }
auto stream_read(Fixture& f) -> capy::task<> {
    t::detail::ApplicationStreamReader reader(f.connection); std::array<std::uint8_t,2> buffer{}; Bytes received;
    for (auto expected:{2u,1u,2u,1u}) {
        auto result=co_await reader.read_some(buffer);
        if (!result || result->kind!=t::detail::AsyncStreamReadKind::data || result->size!=expected) { f.read_done=true; co_return; }
        received.insert(received.end(),buffer.begin(),buffer.begin()+static_cast<std::ptrdiff_t>(result->size));
    }
    auto close=co_await reader.read_some(buffer); auto eof=co_await reader.read_some(buffer);
    f.fatal=received==Bytes({1,2,3,4,5,6}) && close && close->kind==t::detail::AsyncStreamReadKind::event && close->event && close->event->kind==t::ApplicationEventKind::close_notify && eof && eof->kind==t::detail::AsyncStreamReadKind::eof;
    f.read_done=true;
}
template<class Backend> auto stream_read_test(Backend backend) -> bool {
    t::ApplicationIo peer(t::ApplicationRecords(layer(t::RecordDirection::send,2),layer(t::RecordDirection::receive,1),16385,16385,c::Hash::sha256,c::Aead::aes_128_gcm,16,secret(2),secret(1),t::ApplicationRole::client));
    Bytes wire;
    for (auto data:{Bytes{1,2,3},Bytes{4,5,6}}) {
        if (!peer.send(data)) return false; auto pending=peer.pending_output(); wire.insert(wire.end(),pending.begin(),pending.end()); if (!peer.written(pending.size())) return false;
    }
    if (!peer.close_notify()) return false; auto pending=peer.pending_output(); wire.insert(wire.end(),pending.begin(),pending.end());
    Fixture f(backend,1u << 24,16385,std::move(wire)); if (io::connect_pair(f.a,f.b)) return false;
    capy::run_async(f.context.get_executor())(stream_read(f)); f.context.restart(); (void)f.context.run_for(1s);
    return f.context.stopped() && f.connection.idle() && f.read_done && f.fatal;
}
auto detach_reader(Fixture& f) -> capy::task<> {
    t::detail::ApplicationStreamReader reader(f.connection); std::array<std::uint8_t,2> output{};
    auto first=co_await reader.read_some(output);
    if (!first || first->kind!=t::detail::AsyncStreamReadKind::data || first->size!=2 || output!=std::array<std::uint8_t,2>{1,2}) { f.read_done=true; co_return; }
    auto detached=reader.detach_input();
    if (!detached || detached->plaintext!=Bytes({3,4,5}) || detached->transport!=Bytes({9,8,7}) || reader.detach_input()) { f.read_done=true; co_return; }
    auto again=co_await reader.read_some(output);
    auto direct_read=co_await f.connection.read();
    auto sent=co_await f.connection.send(Bytes{42});
    f.fatal=!again && again.error()==t::detail::AsyncApplicationError::state && !direct_read && direct_read.error()==t::detail::AsyncApplicationError::state && sent.has_value();
    f.read_done=true;
}
template<class Backend> auto detach_test(Backend backend) -> bool {
    auto peer=layer(t::RecordDirection::send,2); auto wire=peer.seal(t::ContentType::application_data,Bytes{1,2,3,4,5});
    if (!wire) return false; wire->insert(wire->end(),{9,8,7});
    Fixture f(backend,1u << 24,16385,std::move(*wire)); if (io::connect_pair(f.a,f.b)) return false;
    capy::run_async(f.context.get_executor())(detach_reader(f)); f.context.restart(); (void)f.context.run_for(1s);
    if (!f.context.stopped() || !f.read_done || !f.fatal || !f.connection.active()) return false;
    std::array<std::uint8_t,128> data{}; auto n=::recv(f.b.native_handle(),data.data(),data.size(),MSG_DONTWAIT);
    auto receiver=layer(t::RecordDirection::receive,1);
    if (n<=0) return false;
    auto opened=receiver.open(std::span(data).first(static_cast<std::size_t>(n)));
    return opened && opened->content==Bytes{42};
}
auto detach_writer(Fixture& f) -> capy::task<> {
    if (!co_await f.connection.send(Bytes{1,2}) || !f.connection.detach_output() || f.connection.detach_output()) { f.write_done=true; co_return; }
    auto no_send=co_await f.connection.send(Bytes{3});
    auto no_empty=co_await f.connection.send_all({});
    auto no_update=co_await f.connection.key_update(false);
    auto no_close=co_await f.connection.close_notify();
    auto no_flush=co_await f.connection.flush();
    std::array<std::uint8_t,3> raw{7,8,9};
    auto n=::send(f.a.native_handle(),raw.data(),raw.size(),MSG_NOSIGNAL);
    auto read=co_await f.connection.read();
    f.fatal=!no_send && !no_empty && !no_update && !no_close && !no_flush && n==3 && read && read->event && read->event->data==Bytes({4,5});
    f.write_done=true;
}
template<class Backend> auto detach_writer_test(Backend backend) -> bool {
    auto peer=layer(t::RecordDirection::send,2); auto incoming=peer.seal(t::ContentType::application_data,Bytes{4,5});
    if (!incoming) return false;
    Fixture f(backend,1u << 24,16385,std::move(*incoming)); if (io::connect_pair(f.a,f.b)) return false;
    capy::run_async(f.context.get_executor())(detach_writer(f)); f.context.restart(); (void)f.context.run_for(1s);
    if (!f.context.stopped() || !f.write_done || !f.fatal || !f.connection.active()) return false;
    std::array<std::uint8_t,128> data{}; auto n=::recv(f.b.native_handle(),data.data(),data.size(),MSG_DONTWAIT);
    if (n<8) return false;
    auto count=static_cast<std::size_t>(n)-3;
    if (!std::ranges::equal(std::span(data).subspan(count,3),std::array<std::uint8_t,3>{7,8,9})) return false;
    auto receiver=layer(t::RecordDirection::receive,1); auto opened=receiver.open(std::span(data).first(count));
    return opened && opened->content==Bytes({1,2});
}
auto stream_writer(Fixture& f) -> capy::task<> { Bytes data(200,42); auto result=co_await f.connection.send_all(data); f.write_failed=!result; if (!result) f.write_error=result.error(); f.write_done=true; }
template<class Backend> auto stream_test(Backend backend) -> bool {
    Fixture f(backend,3,65); if (io::connect_pair(f.a,f.b)) return false;
    capy::run_async(f.context.get_executor())(stream_writer(f)); f.context.restart(); (void)f.context.run_for(1s);
    if (!f.context.stopped() || !f.connection.idle() || !f.write_done || f.write_failed) return false;
    std::array<std::uint8_t,1024> wire{}; auto n=::recv(f.b.native_handle(),wire.data(),wire.size(),MSG_DONTWAIT);
    if (n<=0) return false;
    t::ApplicationIo peer(t::ApplicationRecords(layer(t::RecordDirection::send,2),layer(t::RecordDirection::receive,1),16385,16385,c::Hash::sha256,c::Aead::aes_128_gcm,16,secret(2),secret(1),t::ApplicationRole::client));
    Bytes data; std::vector<std::size_t> sizes; int updates=0; std::size_t offset=0;
    while (offset<static_cast<std::size_t>(n)) {
        auto result=peer.feed(std::span{wire}.subspan(offset,static_cast<std::size_t>(n)-offset));
        if (!result || !result->consumed || !result->event) return false;
        offset+=result->consumed;
        if (result->event->kind==t::ApplicationEventKind::data) { sizes.push_back(result->event->data.size()); data.insert(data.end(),result->event->data.begin(),result->event->data.end()); }
        else if (result->event->kind==t::ApplicationEventKind::key_update) ++updates;
        else return false;
    }
    return data==Bytes(200,42) && sizes==std::vector<std::size_t>{64,64,64,8} && updates==1;
}
auto duplicates(Fixture& f) -> capy::task<> {
    auto read=co_await f.connection.read(); f.duplicate_read=!read && read.error()==t::detail::AsyncApplicationError::state;
    auto write=co_await f.connection.send(Bytes{1}); f.duplicate_write=!write && write.error()==t::detail::AsyncApplicationError::state;
}
auto budget_writer(Fixture& f) -> capy::task<> {
    Bytes data{42};
    for (int i=0;i<4;++i) if (!co_await f.connection.send(data)) { f.write_done=true; co_return; }
    f.fatal=true; f.write_done=true;
}
template<class Backend> auto budget_test(Backend backend) -> bool {
    Fixture f(backend,3); if (io::connect_pair(f.a,f.b)) return false;
    capy::run_async(f.context.get_executor())(budget_writer(f)); f.context.restart(); (void)f.context.run_for(1s);
    if (!f.context.stopped() || !f.connection.idle() || !f.write_done || !f.fatal) return false;
    std::array<std::uint8_t,1024> wire{}; auto n=::recv(f.b.native_handle(),wire.data(),wire.size(),MSG_DONTWAIT);
    if (n<=0) return false;
    t::ApplicationIo peer(t::ApplicationRecords(layer(t::RecordDirection::send,2),layer(t::RecordDirection::receive,1),16385,16385,c::Hash::sha256,c::Aead::aes_128_gcm,16,secret(2),secret(1),t::ApplicationRole::client));
    std::vector<t::ApplicationEventKind> events; std::size_t offset=0;
    while (offset<static_cast<std::size_t>(n)) {
        auto result=peer.feed(std::span{wire}.subspan(offset,static_cast<std::size_t>(n)-offset));
        if (!result || !result->consumed || !result->event) return false;
        offset+=result->consumed; events.push_back(result->event->kind);
        if (result->event->kind==t::ApplicationEventKind::data && result->event->data!=Bytes{42}) return false;
    }
    return events==std::vector<t::ApplicationEventKind>{t::ApplicationEventKind::data,t::ApplicationEventKind::data,t::ApplicationEventKind::key_update,t::ApplicationEventKind::data,t::ApplicationEventKind::data};
}
auto prime_budget(Fixture& f) -> capy::task<> {
    Bytes data{42}; f.fatal=(co_await f.connection.send(data)) && (co_await f.connection.send(data)); f.write_done=true;
}
auto competing_writer(Fixture& f) -> capy::task<> {
    auto result=co_await f.connection.send(Bytes{1}); f.duplicate_write=!result && result.error()==t::detail::AsyncApplicationError::state;
}
template<class Backend> auto blocked_update_test(Backend backend) -> bool {
    Fixture f(backend,3); if (io::connect_pair(f.a,f.b)) return false;
    auto ex=f.context.get_executor(); capy::run_async(ex)(prime_budget(f)); f.context.restart(); (void)f.context.run_for(1s);
    if (!f.write_done || !f.fatal) return false;
    std::array<char,4096> filler{};
    for (;;) { auto n=::send(f.a.native_handle(),filler.data(),filler.size(),MSG_DONTWAIT|MSG_NOSIGNAL); if (n>0 || (n<0 && errno==EINTR)) continue; if (n<0 && (errno==EAGAIN || errno==EWOULDBLOCK)) break; return false; }
    f.write_done=false; capy::run_async(ex)(stream_writer(f)); f.context.restart(); (void)f.context.run_for(20ms);
    if (f.write_done || f.connection.idle() || !f.connection.pending_output()) return false;
    capy::run_async(ex)(competing_writer(f)); f.context.restart(); (void)f.context.run_for(20ms);
    if (!f.duplicate_write || f.write_done) return false;
    f.connection.cancel(); f.context.restart(); (void)f.context.run_for(1s);
    return f.context.stopped() && f.connection.idle() && f.write_done && f.write_failed && !f.connection.pending_output();
}
auto timed_reader(Fixture& f) -> capy::task<> {
    auto result=co_await f.connection.read(std::chrono::steady_clock::now()+80ms);
    if (!result) f.read_error=result.error(); f.read_done=true;
}
auto timed_writer(Fixture& f) -> capy::task<> {
    Bytes data(1024,42); auto result=co_await f.connection.send(data,std::chrono::steady_clock::now()+80ms);
    if (!result) f.write_error=result.error(); f.write_done=true;
}
auto expired_reader(Fixture& f) -> capy::task<> {
    auto result=co_await f.connection.read(std::chrono::steady_clock::now()-1ms);
    if (!result) f.read_error=result.error(); f.read_done=true;
}
auto preserve_reader(Fixture& f) -> capy::task<> {
    auto result=co_await f.connection.read(std::chrono::steady_clock::now()+50ms,t::detail::ReadTimeoutPolicy::preserve_connection);
    if(!result)f.read_error=result.error();f.read_done=true;
}
auto preserve_verify(Fixture& f) -> capy::task<> {
    auto result=co_await f.connection.read();
    f.fatal=result && result->event && result->event->kind==t::ApplicationEventKind::data && result->event->data==Bytes{1,2,3};
    f.read_done=true;
}
template<class Backend> auto preserve_timeout_test(Backend backend) -> bool {
    Fixture f(backend);if(io::connect_pair(f.a,f.b))return false;
    auto peer=layer(t::RecordDirection::send,2);auto wire=peer.seal(t::ContentType::application_data,Bytes{1,2,3});
    if(!wire || ::send(f.b.native_handle(),wire->data(),6,MSG_NOSIGNAL)!=6)return false;
    capy::run_async(f.context.get_executor())(preserve_reader(f));f.context.restart();(void)f.context.run_for(1s);
    if(!f.read_done || f.read_error!=t::detail::AsyncApplicationError::timeout || !f.connection.active() || !f.connection.idle())return false;
    if(::send(f.b.native_handle(),wire->data()+6,wire->size()-6,MSG_NOSIGNAL)!=static_cast<ssize_t>(wire->size()-6))return false;
    f.read_done=false;capy::run_async(f.context.get_executor())(preserve_verify(f));
    f.context.restart();(void)f.context.run_for(1s);
    return f.read_done && f.fatal && f.connection.active() && f.connection.idle();
}
template<class Backend> auto expired_test(Backend backend) -> bool {
    Fixture f(backend); if (io::connect_pair(f.a,f.b)) return false;
    capy::run_async(f.context.get_executor())(expired_reader(f)); f.context.restart(); (void)f.context.run_for(1s);
    return f.context.stopped() && f.connection.idle() && f.read_done && f.read_error==t::detail::AsyncApplicationError::timeout;
}
template<class Backend> auto deadline_test(Backend backend, bool read_timeout) -> bool {
    Fixture f(backend); if (io::connect_pair(f.a,f.b)) return false;
    std::array<char,4096> filler{};
    for (;;) { auto n=::send(f.a.native_handle(),filler.data(),filler.size(),MSG_DONTWAIT|MSG_NOSIGNAL); if (n>0 || (n<0 && errno==EINTR)) continue; if (n<0 && (errno==EAGAIN || errno==EWOULDBLOCK)) break; return false; }
    auto ex=f.context.get_executor();
    if (read_timeout) { capy::run_async(ex)(timed_reader(f)); capy::run_async(ex)(writer(f)); }
    else { capy::run_async(ex)(reader(f)); capy::run_async(ex)(timed_writer(f)); }
    f.context.restart(); (void)f.context.run_for(20ms);
    if (f.read_done || f.write_done) return false;
    f.context.restart(); (void)f.context.run_for(1s);
    return f.context.stopped() && f.connection.idle() && f.read_done && f.write_done && f.read_error && f.write_error &&
        (read_timeout ? *f.read_error : *f.write_error)==t::detail::AsyncApplicationError::timeout && !f.connection.pending_output();
}
template<class Backend> auto exercise(Backend backend) -> bool {
    Fixture f(backend); if (io::connect_pair(f.a,f.b)) return false;
    std::array<char,4096> filler{};
    for (;;) { auto n=::send(f.a.native_handle(),filler.data(),filler.size(),MSG_DONTWAIT|MSG_NOSIGNAL); if (n>0 || (n<0 && errno==EINTR)) continue; if (n<0 && (errno==EAGAIN || errno==EWOULDBLOCK)) break; return false; }
    // Leave an incomplete encrypted record in the reader while the writer is parked.
    auto peer=layer(t::RecordDirection::send,2); auto wire=peer.seal(t::ContentType::application_data,Bytes(4096,42));
    if (!wire || ::send(f.b.native_handle(),wire->data(),1024,MSG_NOSIGNAL)!=1024) return false;
    auto ex=f.context.get_executor(); capy::run_async(ex)(reader(f)); capy::run_async(ex)(writer(f));
    f.context.restart(); (void)f.context.run_for(20ms);
    if (f.read_done || f.write_done || f.connection.idle() || !f.connection.pending_output()) return false;
    if (f.connection.detach_input()) return false;
    if (f.connection.detach_output()) return false;
    capy::run_async(ex)(duplicates(f)); f.context.restart(); (void)f.context.run_for(20ms);
    if (!f.duplicate_read || !f.duplicate_write || f.read_done || f.write_done) return false;
    f.connection.cancel(); f.connection.cancel(); f.context.restart(); (void)f.context.run_for(1s);
    return f.context.stopped() && f.connection.idle() && f.read_done && f.write_done && f.read_failed && f.write_failed && !f.connection.pending_output();
}
template<class Backend> auto protocol_failure(Backend backend, bool fatal=false) -> bool {
    Fixture f(backend); if (io::connect_pair(f.a,f.b)) return false;
    std::array<char,4096> filler{};
    for (;;) { auto n=::send(f.a.native_handle(),filler.data(),filler.size(),MSG_DONTWAIT|MSG_NOSIGNAL); if (n>0 || (n<0 && errno==EINTR)) continue; if (n<0 && (errno==EAGAIN || errno==EWOULDBLOCK)) break; return false; }
    auto ex=f.context.get_executor(); capy::run_async(ex)(reader(f)); capy::run_async(ex)(writer(f));
    f.context.restart(); (void)f.context.run_for(20ms);
    if (f.read_done || f.write_done) return false;
    Bytes wire{23,3,3,0,1,0};
    if (fatal) { auto peer=layer(t::RecordDirection::send,2); auto alert=peer.seal(t::ContentType::alert,Bytes{2,40}); if (!alert) return false; wire=std::move(*alert); }
    auto n=::send(f.b.native_handle(),wire.data(),wire.size(),MSG_NOSIGNAL);
    if (n!=static_cast<ssize_t>(wire.size())) return false;
    f.context.restart(); (void)f.context.run_for(1s);
    return f.context.stopped() && f.connection.idle() && f.read_done && f.write_done && (fatal ? f.fatal : f.read_failed) && f.write_failed && !f.connection.pending_output();
}
auto send_wire(io::local_stream_socket& s, Bytes wire, bool shutdown_wr) -> capy::task<> {
    std::size_t off = 0;
    while (off < wire.size()) {
        auto [ec, n] = co_await s.write_some(capy::const_buffer(wire.data() + off, wire.size() - off));
        if (ec || !n) co_return;
        off += n;
    }
    if (shutdown_wr) (void)s.shutdown(io::shutdown_send);
}
template<class Backend> auto bulk_padded_and_alert_test(Backend backend) -> bool {
    // Subcase 1: max-padded record + multi-record bulk read_into (65536 B & 16624 B)
    auto peer = layer(t::RecordDirection::send, 2);
    Bytes p1(100, 0x11), p2(16384, 0x22), p3(100, 0x33), wire;
    for (auto const& part : {peer.seal(t::ContentType::application_data, p1, 16284),
            peer.seal(t::ContentType::application_data, p2),
            peer.seal(t::ContentType::application_data, p3),
            peer.seal(t::ContentType::alert, Bytes{1, 0})}) {
        if (!part) return false;
        wire.insert(wire.end(), part->begin(), part->end());
    }
    Fixture f(backend); if (io::connect_pair(f.a, f.b)) return false;
    bool ok = false;
    auto run_bulk = [&]() -> capy::task<> {
        t::detail::ApplicationStreamReader reader(f.connection);
        Bytes buf(65536, 0), got;
        while (true) {
            auto r = co_await reader.read_some(buf);
            if (!r) co_return;
            if (r->kind == t::detail::AsyncStreamReadKind::data) got.insert(got.end(), buf.begin(), buf.begin() + static_cast<std::ptrdiff_t>(r->size));
            else if (r->kind == t::detail::AsyncStreamReadKind::event && r->event && r->event->kind == t::ApplicationEventKind::close_notify) break;
            else co_return;
        }
        auto eof = co_await reader.read_some(std::span{buf}.first(t::detail::ApplicationInput::kMinDirectReadBuffer));
        Bytes expected = p1; expected.insert(expected.end(), p2.begin(), p2.end()); expected.insert(expected.end(), p3.begin(), p3.end());
        ok = got == expected && eof && eof->kind == t::detail::AsyncStreamReadKind::eof;
    };
    capy::run_async(f.context.get_executor())(send_wire(f.b, std::move(wire), true));
    capy::run_async(f.context.get_executor())(run_bulk());
    f.context.restart(); (void)f.context.run_for(2s);
    if (!ok || !f.context.stopped()) return false;

    // Subcase 2: coalesced data + fatal_alert delivers data then fatal_alert
    auto p_alert = layer(t::RecordDirection::send, 2);
    auto d = p_alert.seal(t::ContentType::application_data, Bytes(64, 0x44));
    auto a = p_alert.seal(t::ContentType::alert, Bytes{2, 40});
    if (!d || !a) return false;
    d->insert(d->end(), a->begin(), a->end());
    Fixture f2(backend); if (io::connect_pair(f2.a, f2.b)) return false;
    bool ok2 = false;
    auto run_alert = [&]() -> capy::task<> {
        t::detail::ApplicationStreamReader reader(f2.connection);
        Bytes buf(65536, 0);
        auto r1 = co_await reader.read_some(buf);
        if (!r1 || r1->kind != t::detail::AsyncStreamReadKind::data || r1->size != 64 || !std::ranges::equal(std::span{buf}.first(64), Bytes(64, 0x44))) co_return;
        auto r2 = co_await reader.read_some(buf);
        if (!r2 || r2->kind != t::detail::AsyncStreamReadKind::event || !r2->event || r2->event->kind != t::ApplicationEventKind::fatal_alert) co_return;
        auto r3 = co_await reader.read_some(buf);
        ok2 = !r3 && r3.error() == t::detail::AsyncApplicationError::state;
    };
    capy::run_async(f2.context.get_executor())(send_wire(f2.b, std::move(*d), false));
    capy::run_async(f2.context.get_executor())(run_alert());
    f2.context.restart(); (void)f2.context.run_for(2s);
    if (!ok2 || !f2.context.stopped()) return false;

    // Subcase 3: trailing garbage bytes after close_notify fail with truncated on read_into EOF
    auto p_eof = layer(t::RecordDirection::send, 2);
    auto cn = p_eof.seal(t::ContentType::alert, Bytes{1, 0});
    if (!cn) return false;
    cn->insert(cn->end(), {1, 2, 3});
    Fixture f3(backend); if (io::connect_pair(f3.a, f3.b)) return false;
    bool ok3 = false;
    auto run_trunc = [&]() -> capy::task<> {
        Bytes buf(65536, 0);
        auto r1 = co_await f3.connection.read_into(buf);
        if (!r1 || !r1->event || r1->event->kind != t::ApplicationEventKind::close_notify) co_return;
        auto r2 = co_await f3.connection.read_into(buf);
        ok3 = !r2 && r2.error() == t::detail::AsyncApplicationError::truncated;
    };
    capy::run_async(f3.context.get_executor())(send_wire(f3.b, std::move(*cn), true));
    capy::run_async(f3.context.get_executor())(run_trunc());
    f3.context.restart(); (void)f3.context.run_for(2s);
    return ok3 && f3.context.stopped() && f3.connection.idle();
}
int main() {
    if (!exception_overlap(io::epoll,false) || !exception_overlap(io::epoll,true)) return 7;
    for (int mode=0;mode<5;++mode) if (!exception_test(io::epoll,mode)) return 5;
    if (!unread_boundary_test(io::epoll) || !detach_test(io::epoll) || !detach_writer_test(io::epoll)) return 3;
    if (!bulk_padded_and_alert_test(io::epoll)) return 9;
#if BOOST_COROSIO_HAVE_LIBURING
    if (!exception_overlap(io::uring,false) || !exception_overlap(io::uring,true)) return 8;
    for (int mode=0;mode<5;++mode) if (!exception_test(io::uring,mode)) return 6;
    if (!unread_boundary_test(io::uring) || !detach_test(io::uring) || !detach_writer_test(io::uring)) return 4;
    if (!bulk_padded_and_alert_test(io::uring)) return 10;
#endif
    for (int i=0;i<10;++i) {
        if (!preserve_timeout_test(io::epoll) || !stream_read_test(io::epoll) || !stream_test(io::epoll) || !blocked_update_test(io::epoll) || !budget_test(io::epoll) || !expired_test(io::epoll) || !deadline_test(io::epoll,true) || !deadline_test(io::epoll,false) || !exercise(io::epoll) || !protocol_failure(io::epoll) || !protocol_failure(io::epoll,true)) { std::cerr << "epoll connection cancellation failed at " << i << '\n'; return 1; }
#if BOOST_COROSIO_HAVE_LIBURING
        if (!preserve_timeout_test(io::uring) || !stream_read_test(io::uring) || !stream_test(io::uring) || !blocked_update_test(io::uring) || !budget_test(io::uring) || !expired_test(io::uring) || !deadline_test(io::uring,true) || !deadline_test(io::uring,false) || !exercise(io::uring) || !protocol_failure(io::uring) || !protocol_failure(io::uring,true)) { std::cerr << "io_uring connection cancellation failed at " << i << '\n'; return 2; }
#endif
    }
    std::cout << "TLS application owner deadlines, overlapping operations and cancellation passed\n";
}
