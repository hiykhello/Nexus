#include <boost/corosio/backend.hpp>
#include <errno.h>
#include <sys/socket.h>
import std;
import nexus.tls.application_io;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;
import nexus.tls.corosio_application;
namespace capy=nex::capy; namespace io=nex::corosio; namespace t=nexus::tls; namespace c=nexus::crypto;
using Bytes=c::Bytes; using namespace std::chrono_literals;
auto secret(int n) -> t::Secret { return t::Secret(Bytes(32,static_cast<std::uint8_t>(n))); }
auto layer(t::RecordDirection direction,int n,std::uint64_t limit=1u << 24) -> t::RecordLayer {
    auto s=secret(n); auto key=t::expand_label(c::Hash::sha256,s.view(),"key",{},16), iv=t::expand_label(c::Hash::sha256,s.view(),"iv",{},12);
    if (!key || !iv) std::abort(); auto value=t::RecordLayer::create(direction,c::Aead::aes_128_gcm,key->view(),iv->view(),limit);
    if (!value) std::abort(); return std::move(*value);
}
auto records(std::uint64_t limit,std::size_t write_limit=16385) -> t::ApplicationRecords {
    return {layer(t::RecordDirection::send,1,limit),layer(t::RecordDirection::receive,2),write_limit,16385,c::Hash::sha256,c::Aead::aes_128_gcm,16,secret(1),secret(2)};
}
using Connection=t::detail::ApplicationConnection<io::local_stream_socket>;
struct Fixture {
    io::io_context context; io::local_stream_socket a{context}, b{context}; Connection connection;
    bool read_done=false, write_done=false, duplicate_read=false, duplicate_write=false; bool read_failed=false, write_failed=false, fatal=false;
    std::optional<t::detail::AsyncApplicationError> read_error, write_error;
    template<class Backend> explicit Fixture(Backend backend,std::uint64_t limit=1u << 24,std::size_t write_limit=16385,Bytes unread={}) : context(backend), connection(a,records(limit,write_limit),std::move(unread)) {}
    ~Fixture() { connection.cancel(); a.close(); b.close(); context.restart(); (void)context.run_for(1s); if (!context.stopped() || !connection.idle()) std::_Exit(90); }
};
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
    t::ApplicationIo peer(t::ApplicationRecords(layer(t::RecordDirection::send,2),layer(t::RecordDirection::receive,1),16385,16385,c::Hash::sha256,c::Aead::aes_128_gcm,16,secret(2),secret(1)));
    Bytes wire;
    for (auto data:{Bytes{1,2,3},Bytes{4,5,6}}) {
        if (!peer.send(data)) return false; auto pending=peer.pending_output(); wire.insert(wire.end(),pending.begin(),pending.end()); if (!peer.written(pending.size())) return false;
    }
    if (!peer.close_notify()) return false; auto pending=peer.pending_output(); wire.insert(wire.end(),pending.begin(),pending.end());
    Fixture f(backend,1u << 24,16385,std::move(wire)); if (io::connect_pair(f.a,f.b)) return false;
    capy::run_async(f.context.get_executor())(stream_read(f)); f.context.restart(); (void)f.context.run_for(1s);
    return f.context.stopped() && f.connection.idle() && f.read_done && f.fatal;
}
auto stream_writer(Fixture& f) -> capy::task<> { Bytes data(200,42); auto result=co_await f.connection.send_all(data); f.write_failed=!result; if (!result) f.write_error=result.error(); f.write_done=true; }
template<class Backend> auto stream_test(Backend backend) -> bool {
    Fixture f(backend,3,65); if (io::connect_pair(f.a,f.b)) return false;
    capy::run_async(f.context.get_executor())(stream_writer(f)); f.context.restart(); (void)f.context.run_for(1s);
    if (!f.context.stopped() || !f.connection.idle() || !f.write_done || f.write_failed) return false;
    std::array<std::uint8_t,1024> wire{}; auto n=::recv(f.b.native_handle(),wire.data(),wire.size(),MSG_DONTWAIT);
    if (n<=0) return false;
    t::ApplicationIo peer(t::ApplicationRecords(layer(t::RecordDirection::send,2),layer(t::RecordDirection::receive,1),16385,16385,c::Hash::sha256,c::Aead::aes_128_gcm,16,secret(2),secret(1)));
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
    t::ApplicationIo peer(t::ApplicationRecords(layer(t::RecordDirection::send,2),layer(t::RecordDirection::receive,1),16385,16385,c::Hash::sha256,c::Aead::aes_128_gcm,16,secret(2),secret(1)));
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
    auto ex=f.context.get_executor(); capy::run_async(ex)(reader(f)); capy::run_async(ex)(writer(f));
    f.context.restart(); (void)f.context.run_for(20ms);
    if (f.read_done || f.write_done || f.connection.idle() || !f.connection.pending_output()) return false;
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
int main() {
    if (!unread_boundary_test(io::epoll)) return 3;
#if BOOST_COROSIO_HAVE_LIBURING
    if (!unread_boundary_test(io::uring)) return 4;
#endif
    for (int i=0;i<10;++i) {
        if (!stream_read_test(io::epoll) || !stream_test(io::epoll) || !blocked_update_test(io::epoll) || !budget_test(io::epoll) || !expired_test(io::epoll) || !deadline_test(io::epoll,true) || !deadline_test(io::epoll,false) || !exercise(io::epoll) || !protocol_failure(io::epoll) || !protocol_failure(io::epoll,true)) { std::cerr << "epoll connection cancellation failed at " << i << '\n'; return 1; }
#if BOOST_COROSIO_HAVE_LIBURING
        if (!stream_read_test(io::uring) || !stream_test(io::uring) || !blocked_update_test(io::uring) || !budget_test(io::uring) || !expired_test(io::uring) || !deadline_test(io::uring,true) || !deadline_test(io::uring,false) || !exercise(io::uring) || !protocol_failure(io::uring) || !protocol_failure(io::uring,true)) { std::cerr << "io_uring connection cancellation failed at " << i << '\n'; return 2; }
#endif
    }
    std::cout << "TLS application owner deadlines, overlapping operations and cancellation passed\n";
}
