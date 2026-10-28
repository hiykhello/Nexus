#include <boost/corosio/backend.hpp>
#include <errno.h>
#include <sys/socket.h>
import std;
import nexus.http2.tls_server;
import nexus.tls.application_io;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;
namespace h=nexus::http2; namespace t=nexus::tls; namespace c=nexus::crypto;
namespace io=nex::corosio; namespace capy=nex::capy;
using namespace std::chrono_literals;
auto secret(int n) -> t::Secret { return t::Secret(c::Bytes(32,static_cast<std::uint8_t>(n))); }
auto layer(t::RecordDirection direction,int n) -> t::RecordLayer {
    auto s=secret(n); auto key=t::expand_label(c::Hash::sha256,s.view(),"key",{},16), iv=t::expand_label(c::Hash::sha256,s.view(),"iv",{},12);
    if (!key || !iv) std::abort(); auto result=t::RecordLayer::create(direction,c::Aead::aes_128_gcm,key->view(),iv->view());
    if (!result) std::abort(); return std::move(*result);
}
auto records() -> t::ApplicationRecords {
    return {layer(t::RecordDirection::send,1),layer(t::RecordDirection::receive,2),16385,16385,
            c::Hash::sha256,c::Aead::aes_128_gcm,16,secret(1),secret(2),t::ApplicationRole::server};
}
auto headers(void*,std::int32_t,std::span<h::Header const>,bool,bool) noexcept -> bool { return true; }
auto data(void*,std::int32_t,std::span<std::byte const>) noexcept -> h::DataDisposition { return h::DataDisposition::accepted; }
auto end(void*,std::int32_t) noexcept -> bool { return true; }
void closed(void*,std::int32_t,std::uint32_t) noexcept {}
using Connection=h::TlsServerConnection<io::local_stream_socket>;
struct Fixture {
    io::io_context context; io::local_stream_socket socket{context},peer{context};
    std::unique_ptr<h::ServerSession> session; std::optional<Connection> connection;
    bool done=false, duplicate=false; std::optional<h::TlsServerError> error;
    template<class Backend> explicit Fixture(Backend backend) : context(backend) {
        auto created=h::ServerSession::create({8,16,4096,1024,4096},{nullptr,headers,data,end,closed});
        if (!created || io::connect_pair(socket,peer)) std::abort(); session=std::move(*created);
        connection.emplace(socket,*session,records(),c::Bytes{});
    }
    ~Fixture() { connection->cancel(); socket.close(); peer.close(); context.restart(); (void)context.run_for(1s); if (!context.stopped()) std::_Exit(90); }
};
auto step(Fixture& f,bool timeout) -> capy::task<> {
    auto deadline=timeout ? std::optional{std::chrono::steady_clock::now()+100ms} : std::nullopt;
    auto result=co_await f.connection->step(deadline); if (!result) f.error=result.error(); f.done=true;
}
auto duplicate(Fixture& f) -> capy::task<> {
    auto result=co_await f.connection->step(); f.duplicate=!result && result.error()==h::TlsServerError::invalid_state;
}
template<class Backend> auto exercise(Backend backend,bool timeout) -> bool {
    Fixture f(backend); std::array<char,4096> filler{};
    for (;;) {
        auto n=::send(f.socket.native_handle(),filler.data(),filler.size(),MSG_DONTWAIT|MSG_NOSIGNAL);
        if (n>0 || (n<0 && errno==EINTR)) continue;
        if (n<0 && (errno==EAGAIN || errno==EWOULDBLOCK)) break;
        return false;
    }
    auto ex=f.context.get_executor(); capy::run_async(ex)(step(f,timeout));
    f.context.restart(); (void)f.context.run_for(20ms);
    if (f.done) return false;
    capy::run_async(ex)(duplicate(f)); f.context.restart(); (void)f.context.run_for(20ms);
    if (f.done || !f.duplicate) return false;
    if (!timeout) f.connection->cancel();
    f.context.restart(); (void)f.context.run_for(1s);
    if (!f.context.stopped() || !f.done || !f.error ||
        *f.error!=(timeout ? h::TlsServerError::timeout : h::TlsServerError::tls)) return false;
    f.duplicate=false; capy::run_async(ex)(duplicate(f)); f.context.restart(); (void)f.context.run_for(1s);
    return f.context.stopped() && f.duplicate;
}
int main() {
    for (int i=0;i<5;++i) {
        if (!exercise(io::epoll,false) || !exercise(io::epoll,true)) return 1;
#if BOOST_COROSIO_HAVE_LIBURING
        if (!exercise(io::uring,false) || !exercise(io::uring,true)) return 2;
#endif
    }
    std::cout << "HTTP/2 TLS blocked output cancellation and deadline passed\n";
}
