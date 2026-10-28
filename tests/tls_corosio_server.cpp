#include <boost/corosio/backend.hpp>
#include <sys/socket.h>
#include <unistd.h>
import std;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;
import nexus.tls.corosio_server_handshake;
import nexus.tls.server_handshake_io;
import nexus.tls.application_io;
import nexus.tls.client_handshake_io;
namespace t=nexus::tls; namespace io=nex::corosio; namespace capy=nex::capy;
using namespace std::chrono_literals;
auto file(char const* path) -> nexus::crypto::Bytes { std::ifstream in(path,std::ios::binary); return {std::istreambuf_iterator<char>(in),{}}; }
auto now() -> std::uint64_t { return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count(); }
struct Fixture {
#if BOOST_COROSIO_HAVE_LIBURING
    io::io_context context{io::uring};
#else
    io::io_context context;
#endif
    io::local_stream_socket incoming{context}, peer{context};
    std::optional<t::ServerHandshakeIo> handshake;
    bool done=false, success=false; std::optional<t::detail::ServerAsyncError> error;
};
auto pending(Fixture& f) -> capy::task<> {
    auto result=co_await t::detail::server_handshake(f.incoming,*f.handshake); if (!result) f.error=result.error(); f.done=true;
}
struct FailingSocket {
    io::local_stream_socket& socket; bool fail_read;
    auto read_some(capy::mutable_buffer b) { if (fail_read) throw std::bad_alloc{}; return socket.read_some(b); }
    auto write_some(capy::const_buffer b) { if (!fail_read) throw std::bad_alloc{}; return socket.write_some(b); }
};
auto exception_handshake(FailingSocket& socket,t::ServerHandshakeIo& handshake,bool& caught) -> capy::task<> {
    try { (void)co_await t::detail::server_handshake(socket,handshake); }
    catch (std::bad_alloc const&) { caught=true; }
}
auto exception_test(char const* cert,char const* key,bool reading) -> bool {
    Fixture f; auto credential=t::ServerCredential::create(file(cert),file(key)); if (!credential || io::connect_pair(f.incoming,f.peer)) return false;
    auto start=now(); auto handshake=t::ServerHandshakeIo::create(std::move(*credential),start,start+1000); if (!handshake) return false;
    if (!reading) {
        std::array<std::uint16_t,1> groups{29}; auto hello=t::make_client_hello({},std::span<std::string_view const>{},groups); if (!hello) return false;
        std::array<std::uint8_t,1> root{1},name{'a'}; std::array<std::span<std::uint8_t const>,1> anchors{root};
        auto session=t::ClientSessionHandshake::create(std::move(*hello),29,anchors,t::PeerNameKind::dns,name,0); if (!session) return false;
        auto record=session->initial_record(); if (!record || !handshake->feed(*record,start) || handshake->pending_output().empty()) return false;
    }
    FailingSocket socket{f.incoming,reading}; bool caught=false;
    capy::run_async(f.context.get_executor())(exception_handshake(socket,*handshake,caught));
    f.context.restart(); (void)f.context.run_for(1s);
    return f.context.stopped() && caught && !handshake->tick(start) && handshake->pending_output().empty();
}
auto failure(char const* cert,char const* key,bool cancel) -> bool {
    Fixture f; auto credential=t::ServerCredential::create(file(cert),file(key)); if (!credential || io::connect_pair(f.incoming,f.peer)) return false;
    auto start=now(); auto handshake=t::ServerHandshakeIo::create(std::move(*credential),start,start+(cancel ? 1000 : 50)); if (!handshake) return false;
    f.handshake.emplace(std::move(*handshake)); capy::run_async(f.context.get_executor())(pending(f));
    (void)f.context.run_for(cancel ? 20ms : 1s);
    if (cancel) { if (f.done) return false; f.incoming.cancel(); f.context.restart(); (void)f.context.run_for(1s); }
    if (!f.done) std::_Exit(90);
    return f.error && *f.error==(cancel ? t::detail::ServerAsyncError::transport : t::detail::ServerAsyncError::timeout);
}
auto peer_close(char const* cert,char const* key) -> bool {
    Fixture f; auto credential=t::ServerCredential::create(file(cert),file(key)); if (!credential || io::connect_pair(f.incoming,f.peer)) return false;
    auto start=now(); auto handshake=t::ServerHandshakeIo::create(std::move(*credential),start,start+1000); if (!handshake) return false;
    f.handshake.emplace(std::move(*handshake)); capy::run_async(f.context.get_executor())(pending(f));
    (void)f.context.run_for(20ms); if (f.done) return false;
    f.peer.close(); f.context.restart(); (void)f.context.run_for(1s);
    return f.context.stopped() && f.done && f.error==t::detail::ServerAsyncError::transport && !f.handshake->tick(now());
}
struct Network {
#if BOOST_COROSIO_HAVE_LIBURING
    io::io_context context{io::uring};
#else
    io::io_context context;
#endif
    io::tcp_socket socket{context}; std::optional<t::ServerHandshakeIo> handshake;
    bool done=false,success=false;
};
auto serve(Network& f) -> capy::task<> {
    auto result=co_await t::detail::server_handshake(f.socket,*f.handshake);
    if (!result || (f.handshake->negotiated_alpn().size() &&
        !std::ranges::equal(f.handshake->negotiated_alpn(),nexus::crypto::Bytes{'h','2'}))) { f.done=true; co_return; }
    t::ApplicationIo app(std::move(result->records)); auto bytes=std::move(result->unread);
    for (;;) {
        if (bytes.empty()) {
            std::array<std::uint8_t,4096> buffer{};
            auto [error,n]=co_await f.socket.read_some(capy::mutable_buffer(buffer.data(),buffer.size()));
            if (error || !n) { f.done=true; co_return; }
            bytes.assign(buffer.begin(),buffer.begin()+n);
        }
        auto feed=app.feed(bytes); if (!feed || !feed->consumed) { f.done=true; co_return; }
        bytes.erase(bytes.begin(),bytes.begin()+static_cast<std::ptrdiff_t>(feed->consumed));
        if (!feed->event) continue;
        if (feed->event->kind!=t::ApplicationEventKind::data || feed->event->data!=nexus::crypto::Bytes({'h','e','l','l','o'}) || !app.send(feed->event->data)) { f.done=true; co_return; }
        while (!app.pending_output().empty()) {
            auto output=app.pending_output(); auto [error,n]=co_await f.socket.write_some(capy::const_buffer(output.data(),output.size()));
            if (error || !n || !app.written(n)) { f.done=true; co_return; }
        }
        if (!app.close_notify()) { f.done=true; co_return; }
        while (!app.pending_output().empty()) {
            auto output=app.pending_output(); auto [error,n]=co_await f.socket.write_some(capy::const_buffer(output.data(),output.size()));
            if (error || !n || !app.written(n)) { f.done=true; co_return; }
        }
        f.success=true; f.done=true; co_return;
    }
}
int main(int argc,char** argv) {
    if (argc!=4 && (argc!=5 || std::string_view(argv[4])!="h2")) return 1;
    if (std::string_view(argv[3])=="failures") return failure(argv[1],argv[2],false) && failure(argv[1],argv[2],true) && peer_close(argv[1],argv[2]) && exception_test(argv[1],argv[2],false) && exception_test(argv[1],argv[2],true) ? 0 : 2;
    auto fd=::accept(std::atoi(argv[3]),nullptr,nullptr); if (fd<0) return 3;
    Network f; if (f.socket.assign(fd)) { ::close(fd); return 4; }
    auto cred=t::ServerCredential::create(file(argv[1]),file(argv[2])); if (!cred) return 5;
    auto start=now(); auto handshake=t::ServerHandshakeIo::create(std::move(*cred),start,start+5000,argc==5 ? "h2" : ""); if (!handshake) return 6;
    f.handshake.emplace(std::move(*handshake)); capy::run_async(f.context.get_executor())(serve(f)); (void)f.context.run_for(6s);
    if (!f.done) { f.socket.cancel(); f.context.restart(); (void)f.context.run_for(1s); if (!f.done) std::_Exit(90); }
    return f.success ? 0 : 7;
}
