#include <boost/corosio/backend.hpp>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <errno.h>
import std;
import nexus.tls.client_handshake_io;
import nexus.tls.application_io;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;
import nexus.tls.corosio_client;
namespace capy=nex::capy; namespace io=nex::corosio; namespace t=nexus::tls;
using namespace std::chrono_literals;
struct Fixture {
    #if BOOST_COROSIO_HAVE_LIBURING
    io::io_context context{io::uring};
#else
    io::io_context context;
#endif
 io::local_stream_socket client{context}, peer{context};
    std::optional<t::ClientHandshakeIo> handshake; bool done=false; std::optional<t::detail::AsyncHandshakeError> error;
    ~Fixture() { client.close(); peer.close(); context.restart(); (void)context.run_for(1s); if (!context.stopped()) std::_Exit(1); }
};
auto run(Fixture& f) -> capy::task<> {
    auto result=co_await t::detail::corosio_handshake(f.client,*f.handshake);
    if (!result) f.error=result.error(); f.done=true;
}
auto make(Fixture& f, std::chrono::milliseconds duration) -> bool {
    t::ClientHello h; h.cipher_suites={0x1301}; h.compression_methods={0}; h.extensions={{43,{2,3,4}},{10,{0,2,0,0x1d}},{51,{0,0}}};
    std::array<std::uint8_t,1> root{1}, name{'a'}; std::array<std::span<std::uint8_t const>,1> anchors{root};
    auto session=t::ClientSessionHandshake::create(std::move(h),0,anchors,t::PeerNameKind::dns,name,0); if (!session) return false;
    auto now=std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch());
    auto handshake=t::ClientHandshakeIo::create(std::move(*session),now.count(),(now+duration).count()); if (!handshake) return false; f.handshake=std::move(*handshake);
    return !io::connect_pair(f.client,f.peer);
}
struct FailingSocket {
    io::local_stream_socket& socket; bool fail_read;
    auto read_some(capy::mutable_buffer b) { if (fail_read) throw std::bad_alloc{}; return socket.read_some(b); }
    auto write_some(capy::const_buffer b) { if (!fail_read) throw std::bad_alloc{}; return socket.write_some(b); }
    void cancel() { socket.cancel(); }
};
using FailingClient=t::detail::ClientConnection<FailingSocket>;
auto exception_handshake(FailingSocket& socket,t::ClientHandshakeIo& handshake,bool& caught) -> capy::task<> {
    try { (void)co_await t::detail::corosio_handshake(socket,handshake); }
    catch (std::bad_alloc const&) { caught=true; }
}
auto exception_owner(FailingClient& client,bool& caught) -> capy::task<> {
    try { (void)co_await client.start(); }
    catch (std::bad_alloc const&) { caught=true; }
}
auto exception_test(bool reading,bool owner) -> bool {
    Fixture f; if (!make(f,1s)) return false;
    FailingSocket socket{f.client,reading}; bool caught=false;
    if (owner) {
        FailingClient client(socket,std::move(*f.handshake)); f.handshake.reset();
        capy::run_async(f.context.get_executor())(exception_owner(client,caught));
        f.context.restart(); (void)f.context.run_for(1s);
        return f.context.stopped() && caught && client.idle() && !client.application() && !client.negotiated();
    }
    capy::run_async(f.context.get_executor())(exception_handshake(socket,*f.handshake,caught));
    f.context.restart(); (void)f.context.run_for(1s);
    return f.context.stopped() && caught && !f.handshake->tick(0) && f.handshake->pending_output().empty();
}
using Client=t::detail::ClientConnection<io::local_stream_socket>;
struct OwnerResult { bool done=false, failed=false, duplicate=false; std::optional<t::detail::AsyncHandshakeError> error; };
auto owner_start(Client& client,OwnerResult& state) -> capy::task<> {
    auto result=co_await client.start(); state.failed=!result; state.done=true;
}
auto owner_duplicate(Client& client,OwnerResult& state) -> capy::task<> {
    auto result=co_await client.start(); state.duplicate=!result && result.error()==t::detail::AsyncHandshakeError::protocol;
}
auto owner_test(bool cancel_before) -> bool {
    Fixture f; if (!make(f,1s)) return false;
    Client client(f.client,std::move(*f.handshake)); f.handshake.reset(); OwnerResult state;
    if (client.application() || client.negotiated() || !client.idle()) return false;
    if (cancel_before) client.cancel();
    capy::run_async(f.context.get_executor())(owner_start(client,state));
    f.context.restart(); (void)f.context.run_for(20ms);
    if (!cancel_before) {
        bool valid = !state.done && !client.idle() && !client.application() && !client.negotiated();
        capy::run_async(f.context.get_executor())(owner_duplicate(client,state));
        f.context.restart(); (void)f.context.run_for(20ms);
        valid = valid && state.duplicate && !state.done;
        client.cancel(); client.cancel(); f.context.restart(); (void)f.context.run_for(1s);
        if (!client.idle()) std::_Exit(1);
        if (!valid) return false;
    }
    return state.done && state.failed && client.idle() && !client.application() && !client.negotiated() && f.context.stopped();
}
auto owned_start(t::detail::OwnedClient& client,io::endpoint endpoint,OwnerResult& state) -> capy::task<> {
    auto result=co_await client.start(endpoint); state.failed=!result; if (!result) state.error=result.error(); state.done=true;
}
auto owned_duplicate(t::detail::OwnedClient& client,io::endpoint endpoint,OwnerResult& state) -> capy::task<> {
    auto result=co_await client.start(endpoint); state.duplicate=!result && result.error()==t::detail::AsyncHandshakeError::protocol;
}
auto owned_test(bool cancel_before) -> bool {
    Fixture f; if (!make(f,1s)) return false;
    int listener=::socket(AF_INET,SOCK_STREAM|SOCK_CLOEXEC,0); if (listener<0) return false;
    struct Guard { int fd; ~Guard() { ::close(fd); } } guard{listener};
    sockaddr_in address{}; address.sin_family=AF_INET; address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    if (::bind(listener,reinterpret_cast<sockaddr*>(&address),sizeof(address)) || ::listen(listener,1)) return false;
    socklen_t length=sizeof(address); if (::getsockname(listener,reinterpret_cast<sockaddr*>(&address),&length)) return false;
    io::endpoint endpoint(io::ipv4_address::loopback(),ntohs(address.sin_port));
    t::detail::OwnedClient client(f.context,std::move(*f.handshake)); f.handshake.reset(); OwnerResult state;
    if (cancel_before) client.cancel();
    capy::run_async(f.context.get_executor())(owned_start(client,endpoint,state)); f.context.restart(); (void)f.context.run_for(20ms);
    if (!cancel_before) {
        if (state.done || client.idle() || client.client()) return false;
        capy::run_async(f.context.get_executor())(owned_duplicate(client,endpoint,state)); f.context.restart(); (void)f.context.run_for(20ms);
        if (!state.duplicate || state.done) return false;
        client.cancel(); client.cancel(); f.context.restart(); (void)f.context.run_for(1s);
        if (!client.idle()) std::_Exit(1);
    }
    return state.done && state.failed && client.idle() && !client.client() && f.context.stopped();
}
auto owned_failure(bool expired) -> bool {
    Fixture f; if (!make(f,expired ? 20ms : 1s)) return false;
    t::detail::OwnedClient client(f.context,std::move(*f.handshake)); f.handshake.reset(); OwnerResult state;
    if (expired) std::this_thread::sleep_for(30ms);
    capy::run_async(f.context.get_executor())(owned_start(client,io::endpoint(io::ipv4_address::loopback(),0),state));
    f.context.restart(); (void)f.context.run_for(1s);
    return state.done && state.failed && state.error==(expired ? t::detail::AsyncHandshakeError::timeout : t::detail::AsyncHandshakeError::transport) && client.idle() && !client.client() && f.context.stopped();
}
int main() {
    for (bool read:{false,true}) for (bool owner:{false,true}) if (!exception_test(read,owner)) return 10;
    if (!owned_test(true) || !owned_test(false) || !owned_failure(true) || !owned_failure(false)) return 9;
    if (!owner_test(true) || !owner_test(false)) return 8;
    for (bool timeout:{false,true}) {
        Fixture f; if (!make(f,timeout ? 80ms : 1s)) return 1;
        capy::run_async(f.context.get_executor())(run(f));
        f.context.restart(); (void)f.context.run_for(20ms);
        if (f.done || f.context.stopped() || !f.handshake->pending_output().empty()) return 2;
        if (!timeout) f.client.cancel(); f.context.restart(); (void)f.context.run_for(1s);
        if (!f.done || !f.error || *f.error!=(timeout ? t::detail::AsyncHandshakeError::timeout : t::detail::AsyncHandshakeError::transport) || !f.handshake->pending_output().empty()) return 3;
    }
    {
        Fixture f; if (!make(f,1s)) return 11;
        capy::run_async(f.context.get_executor())(run(f)); f.context.restart(); (void)f.context.run_for(20ms);
        if (f.done || !f.handshake->pending_output().empty()) return 12;
        f.peer.close(); f.context.restart(); (void)f.context.run_for(1s);
        if (!f.context.stopped() || !f.done || f.error!=t::detail::AsyncHandshakeError::transport || !f.handshake->pending_output().empty()) return 13;
    }
    for (bool timeout:{false,true}) {
        Fixture f; if (!make(f,timeout ? 80ms : 1s)) return 4;
        std::array<char,4096> bytes{};
        while (true) { auto n=::send(f.client.native_handle(),bytes.data(),bytes.size(),MSG_DONTWAIT | MSG_NOSIGNAL);
            if (n>0) continue; if (n<0 && errno==EINTR) continue; if (n<0 && (errno==EAGAIN || errno==EWOULDBLOCK)) break; return 5; }
        capy::run_async(f.context.get_executor())(run(f));
        f.context.restart(); (void)f.context.run_for(20ms);
        if (f.done || f.context.stopped() || f.handshake->pending_output().empty()) return 6;
        if (!timeout) f.client.cancel(); f.context.restart(); (void)f.context.run_for(1s);
        if (!f.done || !f.error || *f.error!=(timeout ? t::detail::AsyncHandshakeError::timeout : t::detail::AsyncHandshakeError::transport) || !f.handshake->pending_output().empty()) return 7;
    }
    std::cout << "Corosio TLS handshake parked read, cancellation and timeout passed\n";
}
