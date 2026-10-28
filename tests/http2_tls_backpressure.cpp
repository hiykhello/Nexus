#include <boost/corosio/backend.hpp>
#include <errno.h>
#include <sys/socket.h>
import std;
import nexus.http2.tls_server;
import nexus.tls.application_io;
import nexus.thirdparty.nghttp2;
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
        constexpr std::string_view preface="PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
        constexpr std::array<std::byte,9> settings{std::byte{0},std::byte{0},std::byte{0},std::byte{4}};
        constexpr std::array<std::byte,15> request{
            std::byte{0},std::byte{0},std::byte{6},std::byte{1},std::byte{5},std::byte{0},std::byte{0},std::byte{0},std::byte{1},
            std::byte{0x82},std::byte{0x87},std::byte{0x01},std::byte{0x01},std::byte{'x'},std::byte{0x84}};
        if (!session->receive(std::as_bytes(std::span{preface})) || !session->receive(settings)) std::abort();
        std::array<std::byte,4096> sink{};
        for (;;) { auto n=session->output(sink); if (!n) std::abort(); if (!*n) break; }
        std::array<std::byte,512> body{};
        if (!session->receive(request) || !session->respond_body(1,200,body) || session->response_memory_used()!=body.size()) std::abort();
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
    if (f.done || f.session->response_memory_used()!=512) return false;
    capy::run_async(ex)(duplicate(f)); f.context.restart(); (void)f.context.run_for(20ms);
    if (f.done || !f.duplicate) return false;
    if (!timeout) f.connection->cancel();
    f.context.restart(); (void)f.context.run_for(1s);
    if (!f.context.stopped() || !f.done || !f.error ||
        *f.error!=(timeout ? h::TlsServerError::timeout : h::TlsServerError::tls)) return false;
    if (f.session->response_memory_used()!=512) return false;
    f.duplicate=false; capy::run_async(ex)(duplicate(f)); f.context.restart(); (void)f.context.run_for(1s);
    if (!f.context.stopped() || !f.duplicate || !f.session->reset_stream(1,8)) return false;
    std::array<std::byte,4096> sink{};
    for (;;) { auto n=f.session->output(sink); if (!n) return false; if (!*n) break; }
    return f.session->response_memory_used()==0 && f.session->stream_memory_charge()==0;
}
auto read_step(Connection& connection,bool& done,std::optional<h::TlsServerError>& error) -> capy::task<> {
    auto result=co_await connection.step(); if (!result) error=result.error(); done=true;
}
template<class Backend> auto input_budget(Backend backend,bool enough) -> bool {
    h::ServerEvents events{nullptr,headers,data,end,closed}; h::ServerLimits limits{8,16,4096,1024,4096};
    auto reference=h::ServerSession::create(limits,events); if (!reference) return false;
    std::array<std::byte,4096> sink{};
    for (;;) { auto n=(**reference).output(sink); if (!n) return false; if (!*n) break; }
    auto baseline=(**reference).shared_memory_used(); reference->reset();
    limits.shared_memory_bytes=baseline+(enough ? 16384 : 16383);
    auto session=h::ServerSession::create(limits,events); if (!session) return false;
    for (;;) { auto n=(**session).output(sink); if (!n) return false; if (!*n) break; }
    io::io_context context(backend); io::local_stream_socket a(context),b(context); if (io::connect_pair(a,b)) return false;
    Connection connection(a,**session,records(),c::Bytes{}); bool done=false; std::optional<h::TlsServerError> error;
    capy::run_async(context.get_executor())(read_step(connection,done,error)); context.restart(); (void)context.run_for(20ms);
    if (enough) {
        if (done || (**session).shared_memory_used()!=baseline+16384) return false;
        connection.cancel(); context.restart(); (void)context.run_for(1s);
        return done && error==h::TlsServerError::tls && context.stopped() && (**session).shared_memory_used()==baseline;
    }
    return done && error==h::TlsServerError::budget_exceeded && context.stopped() && (**session).shared_memory_used()==baseline;
}
auto pause_data(void*,std::int32_t,std::span<std::byte const>) noexcept -> h::DataDisposition { return h::DataDisposition::pause; }
auto until_paused(Connection& connection,bool& paused) -> capy::task<> {
    for (int i=0;i<20;++i) {
        auto result=co_await connection.step();
        if (!result) co_return;
        if (*result==h::TlsServerStep::paused) { paused=true; co_return; }
    }
}
auto until_released(Connection& connection,h::ServerSession& session,bool& released) -> capy::task<> {
    for (int i=0;i<20;++i) {
        auto result=co_await connection.step(); if (!result) co_return;
        if (!session.input_memory_charge()) { released=true; co_return; }
    }
}
template<class Backend> auto abandon_paused(Backend backend,int mode) -> bool {
    io::io_context context(backend); io::local_stream_socket a(context),b(context); if (io::connect_pair(a,b)) return false;
    h::ServerLimits limits{8,16,4096,262144,262144}; limits.shared_memory_bytes=262144;
    auto session=h::ServerSession::create(limits,{nullptr,headers,pause_data,end,closed}); if (!session) return false;
    constexpr std::string_view preface="PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    c::Bytes input(preface.begin(),preface.end());
    constexpr std::array<std::uint8_t,49> frames{0,0,0,4,0,0,0,0,0,
        0,0,6,1,5,0,0,0,1,0x82,0x87,0x01,0x01,'x',0x84,
        0,0,6,1,4,0,0,0,3,0x82,0x87,0x01,0x01,'x',0x84,
        0,0,1,0,1,0,0,0,3,'x'};
    input.insert(input.end(),frames.begin(),frames.end());
    auto peer=layer(t::RecordDirection::send,2); auto wire=peer.seal(t::ContentType::application_data,input); if (!wire) return false;
    auto connection=std::make_unique<Connection>(a,**session,records(),std::move(*wire)); bool paused=false;
    capy::run_async(context.get_executor())(until_paused(*connection,paused)); context.restart(); (void)context.run_for(1s);
    if (!context.stopped() || !paused || (**session).paused_stream()!=3 || (**session).input_memory_charge()!=16384) return false;
    if (mode==1) {
        auto available=limits.shared_memory_bytes-(**session).shared_memory_used();
        if (available<sizeof(nex::nghttp2::nghttp2_nv)) return false;
        std::vector<std::byte> body(available);
        auto blocked=(**session).respond_body(1,200,body);
        if (blocked || blocked.error().kind!=h::ServerErrorKind::budget_exceeded || (**session).response_memory_used() ||
            (**session).input_memory_charge()!=16384 || (**session).shared_memory_used()>limits.shared_memory_bytes) return false;
        if (!(**session).resume_input(3)) return false;
        bool released=false; capy::run_async(context.get_executor())(until_released(*connection,**session,released));
        context.restart(); (void)context.run_for(1s);
        if (!context.stopped() || !released || (**session).input_memory_charge() || !(**session).respond_body(1,200,body)) return false;
        return (**session).response_memory_used()==body.size() && (**session).shared_memory_used()<=limits.shared_memory_bytes;
    }
    if (mode==3) {
        if (!(**session).respond_empty(1,204)) return false;
        std::array<char,4096> filler{};
        for (;;) { auto n=::send(a.native_handle(),filler.data(),filler.size(),MSG_DONTWAIT|MSG_NOSIGNAL);
            if (n>0 || (n<0 && errno==EINTR)) continue;
            if (n<0 && (errno==EAGAIN || errno==EWOULDBLOCK)) break; return false; }
        bool done=false; std::optional<h::TlsServerError> error;
        capy::run_async(context.get_executor())(read_step(*connection,done,error)); context.restart(); (void)context.run_for(20ms);
        if (done) return false;
        connection->cancel();
        if ((**session).input_memory_charge()!=16384) return false;
        context.restart(); (void)context.run_for(1s);
        if (!done || error!=h::TlsServerError::tls || !context.stopped()) return false;
    } else if (mode==2) connection->cancel(); else connection.reset();
    auto resumed=(**session).resume_input(3); auto output=(**session).output(std::span<std::byte>{});
    return !resumed && resumed.error().kind==h::ServerErrorKind::failed && !output &&
        output.error().kind==h::ServerErrorKind::failed && (**session).input_memory_charge()==0;
}
int main() {
    for (int i=0;i<5;++i) {
        if (!exercise(io::epoll,false) || !exercise(io::epoll,true) || !input_budget(io::epoll,true) || !input_budget(io::epoll,false) || !abandon_paused(io::epoll,0) || !abandon_paused(io::epoll,1) || !abandon_paused(io::epoll,2) || !abandon_paused(io::epoll,3)) return 1;
#if BOOST_COROSIO_HAVE_LIBURING
        if (!exercise(io::uring,false) || !exercise(io::uring,true) || !input_budget(io::uring,true) || !input_budget(io::uring,false) || !abandon_paused(io::uring,0) || !abandon_paused(io::uring,1) || !abandon_paused(io::uring,2) || !abandon_paused(io::uring,3)) return 2;
#endif
    }
    std::cout << "HTTP/2 TLS blocked output cancellation and deadline passed\n";
}
