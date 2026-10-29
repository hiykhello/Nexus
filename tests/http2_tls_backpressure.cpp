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
static thread_local std::size_t watched_size=0;
static thread_local void* watched_allocation=nullptr;
static thread_local h::ServerSession* watched_session=nullptr;
static thread_local bool released_with_input_charge=false;
static thread_local bool watch_output=false, released_with_output_charge=false;
void* operator new(std::size_t size) {
    if (auto p=std::malloc(size ? size : 1)) {
        if (watched_size && size==watched_size) { watched_allocation=p; if (!watch_output) watched_size=0; }
        return p;
    }
    throw std::bad_alloc{};
}
void operator delete(void* p) noexcept {
    if (p && p==watched_allocation) {
        if (watch_output) released_with_output_charge=watched_session && watched_session->output_memory_charge()==183;
        else released_with_input_charge=watched_session && watched_session->input_memory_charge()==16640;
        watched_allocation=nullptr;
    }
    std::free(p);
}
void operator delete(void* p,std::size_t) noexcept { ::operator delete(p); }
using namespace std::chrono_literals;
auto secret(int n) -> t::Secret { return t::Secret(c::Bytes(32,static_cast<std::uint8_t>(n))); }
auto layer(t::RecordDirection direction,int n,std::uint64_t limit=1u << 24) -> t::RecordLayer {
    auto s=secret(n); auto key=t::expand_label(c::Hash::sha256,s.view(),"key",{},16), iv=t::expand_label(c::Hash::sha256,s.view(),"iv",{},12);
    if (!key || !iv) std::abort(); auto result=t::RecordLayer::create(direction,c::Aead::aes_128_gcm,key->view(),iv->view(),limit);
    if (!result) std::abort(); return std::move(*result);
}
auto records(t::ApplicationRole role=t::ApplicationRole::server) -> t::ApplicationRecords {
    return {layer(t::RecordDirection::send,1),layer(t::RecordDirection::receive,2),16385,16385,
            c::Hash::sha256,c::Aead::aes_128_gcm,16,secret(1),secret(2),role};
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
    template<class Backend> explicit Fixture(Backend backend,bool bind=true, std::size_t budget=std::numeric_limits<std::size_t>::max()) : context(backend) {
        h::ServerLimits limits{8,16,4096,1024,4096}; limits.shared_memory_bytes=budget;
        auto created=h::ServerSession::create(limits,{nullptr,headers,data,end,closed});
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
        if (bind) connection.emplace(socket,*session,records(),c::Bytes{});
    }
    ~Fixture() { if (connection) connection->cancel(); socket.close(); peer.close(); context.restart(); (void)context.run_for(1s); if (!context.stopped()) std::_Exit(90); }
};
auto step(Fixture& f,bool timeout) -> capy::task<> {
    auto deadline=timeout ? std::optional{std::chrono::steady_clock::now()+100ms} : std::nullopt;
    auto result=co_await f.connection->step(deadline); if (!result) f.error=result.error(); f.done=true;
}
auto duplicate(Fixture& f) -> capy::task<> {
    auto result=co_await f.connection->step(); f.duplicate=!result && result.error()==h::TlsServerError::invalid_state;
}
struct PartialSocket {
    io::local_stream_socket& socket; io::local_stream_socket& peer;
    unsigned writes=0; std::array<std::uint8_t,5> observed{}; ssize_t observed_size=-1;
    auto read_some(capy::mutable_buffer buffer) { return socket.read_some(buffer); }
    auto write_some(capy::const_buffer buffer) {
        if (++writes==1) return socket.write_some(capy::const_buffer(buffer.data(),std::min(buffer.size(),observed.size())));
        observed_size=::recv(peer.native_handle(),observed.data(),observed.size(),MSG_PEEK|MSG_DONTWAIT);
        peer.close(); return socket.write_some(buffer);
    }
    void cancel() { socket.cancel(); }
};
struct ChargeSocket {
    io::local_stream_socket& socket; h::ServerSession& session;
    std::size_t size=0, charge=0;
    auto read_some(capy::mutable_buffer buffer) { return socket.read_some(buffer); }
    auto write_some(capy::const_buffer buffer) {
        size=buffer.size(); charge=session.output_memory_charge(); return socket.write_some(buffer);
    }
    void cancel() { socket.cancel(); }
};
template<class Socket> auto partial_step(h::TlsServerConnection<Socket>& connection,bool& done,std::optional<h::TlsServerError>& error) -> capy::task<> {
    auto result=co_await connection.step(); if (!result) error=result.error(); done=true;
}
template<class Backend> auto partial_failure(Backend backend) -> bool {
    Fixture f(backend,false); PartialSocket socket{f.socket,f.peer};
    h::TlsServerConnection connection(socket,*f.session,records(),c::Bytes{});
    bool done=false; std::optional<h::TlsServerError> error;
    capy::run_async(f.context.get_executor())(partial_step(connection,done,error)); f.context.restart(); (void)f.context.run_for(1s);
    std::array<std::byte,64> sink{}; auto output=f.session->output(sink);
    return f.context.stopped() && done && error==h::TlsServerError::tls && socket.writes==2 &&
        f.session->output_memory_charge()==0 && socket.observed_size==5 && socket.observed[0]==23 && socket.observed[1]==3 && socket.observed[2]==3 &&
        (socket.observed[3]!=0 || socket.observed[4]>16) &&
        !output && output.error().kind==h::ServerErrorKind::failed;
}
template<class Backend> auto sealing_charge(Backend backend) -> bool {
    Fixture f(backend,false); ChargeSocket socket{f.socket,*f.session};
    h::TlsServerConnection connection(socket,*f.session,records(),c::Bytes{});
    bool done=false; std::optional<h::TlsServerError> error;
    capy::run_async(f.context.get_executor())(partial_step(connection,done,error)); f.context.restart(); (void)f.context.run_for(1s);
    if (!f.context.stopped() || !done || error || socket.size<=27) return false;
    auto plaintext=socket.size-22;
    return socket.charge==std::max({3*plaintext+40,2*socket.size,std::size_t{55}})+128 && !f.session->output_memory_charge();
}
struct ThrowSocket {
    io::local_stream_socket& socket; bool throw_read; bool enabled=true;
    auto read_some(capy::mutable_buffer buffer) { if (enabled && throw_read) throw std::bad_alloc{}; return socket.read_some(buffer); }
    auto write_some(capy::const_buffer buffer) { if (enabled && !throw_read) throw std::bad_alloc{}; return socket.write_some(buffer); }
    void cancel() { socket.cancel(); }
};
template<class Backend> auto allocation_failure(Backend backend,bool reading) -> bool {
    Fixture f(backend,false);
    if (reading) {
        std::array<std::byte,4096> sink{};
        for (;;) { auto n=f.session->output(sink); if (!n) return false; if (!*n) break; }
    }
    ThrowSocket socket{f.socket,reading}; h::TlsServerConnection connection(socket,*f.session,records(),c::Bytes{});
    bool done=false; std::optional<h::TlsServerError> error;
    capy::run_async(f.context.get_executor())(partial_step(connection,done,error)); f.context.restart(); (void)f.context.run_for(1s);
    std::array<std::byte,64> sink{}; auto output=f.session->output(sink);
    return f.context.stopped() && done && error==h::TlsServerError::allocation &&
        !f.session->input_memory_charge() && !f.session->output_memory_charge() &&
        !f.session->ciphertext_memory_charge() && !f.session->scratch_memory_charge() &&
        f.session->transport_memory_charge()==4096 && !output && output.error().kind==h::ServerErrorKind::failed;
}
template<class Backend> auto output_budget(Backend backend) -> bool {
    Fixture reference(backend,false);
    auto baseline=reference.session->shared_memory_used();
    // nghttp2 can allocate while producing output; find a cap that permits
    // serialization but cannot accommodate the transport reservation.
    for (std::size_t extra=0;extra<4096;extra+=16) {
        Fixture f(backend,true,baseline+32768);
        auto available=baseline+32768-f.session->shared_memory_used();
        if (16384+extra>=available || !f.session->reserve_input(available-16384-extra)) return false;
        capy::run_async(f.context.get_executor())(step(f,false));
        f.context.restart(); (void)f.context.run_for(1s);
        if (!f.done || f.error!=h::TlsServerError::budget_exceeded) continue;
        std::uint8_t byte{}; auto n=::recv(f.peer.native_handle(),&byte,1,MSG_DONTWAIT); auto read_error=errno;
        std::array<std::byte,64> sink{}; auto result=f.session->output(sink);
        return f.context.stopped() && n<0 && (read_error==EAGAIN || read_error==EWOULDBLOCK) &&
            f.session->output_memory_charge()==0 && !result && result.error().kind==h::ServerErrorKind::failed;
    }
    return false;
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
    if (f.done || f.session->response_memory_used()!=512 || f.session->output_memory_charge()<54 || f.session->scratch_memory_charge()!=16384) return false;
    capy::run_async(ex)(duplicate(f)); f.context.restart(); (void)f.context.run_for(20ms);
    if (f.done || !f.duplicate) return false;
    if (!timeout) f.connection->cancel();
    f.context.restart(); (void)f.context.run_for(1s);
    if (!f.context.stopped() || !f.done || !f.error ||
        *f.error!=(timeout ? h::TlsServerError::timeout : h::TlsServerError::tls)) return false;
    if (f.session->response_memory_used()!=512 || f.session->output_memory_charge()!=0 || f.session->scratch_memory_charge()!=0) return false;
    f.duplicate=false; capy::run_async(ex)(duplicate(f)); f.context.restart(); (void)f.context.run_for(1s);
    if (!f.context.stopped() || !f.duplicate) return false;
    auto reset=f.session->reset_stream(1,8);
    std::array<std::byte,4096> sink{};
    auto output=f.session->output(sink);
    return !reset && reset.error().kind==h::ServerErrorKind::failed &&
        !output && output.error().kind==h::ServerErrorKind::failed && f.session->response_memory_used()==512;
}
auto read_step(Connection& connection,bool& done,std::optional<h::TlsServerError>& error) -> capy::task<> {
    auto result=co_await connection.step(); if (!result) error=result.error(); done=true;
}
auto progress_step(Connection& connection,bool& done,bool& progress) -> capy::task<> {
    auto result=co_await connection.step(); progress=result && *result==h::TlsServerStep::progress; done=true;
}
template<class Backend> auto duplicate_owner(Backend backend) -> bool {
    io::io_context context(backend); io::local_stream_socket a(context),b(context); if (io::connect_pair(a,b)) return false;
    auto session=h::ServerSession::create({8,16,4096,1024,4096},{nullptr,headers,data,end,closed}); if (!session) return false;
    Connection owner(a,**session,records(),c::Bytes{});
    {
        Connection duplicate(a,**session,records(t::ApplicationRole::client),c::Bytes{}); bool done=false; std::optional<h::TlsServerError> error;
        capy::run_async(context.get_executor())(read_step(duplicate,done,error)); context.restart(); (void)context.run_for(1s);
        if (!context.stopped() || !done || error!=h::TlsServerError::invalid_state) return false;
        duplicate.cancel();
    }
    bool done=false, progress=false; capy::run_async(context.get_executor())(progress_step(owner,done,progress));
    context.restart(); (void)context.run_for(1s);
    return context.stopped() && done && progress;
}
template<class Backend> auto drop_idle_driver(Backend backend) -> bool {
    io::io_context context(backend); io::local_stream_socket a(context),b(context); if (io::connect_pair(a,b)) return false;
    auto session=h::ServerSession::create({8,16,4096,1024,4096},{nullptr,headers,data,end,closed}); if (!session) return false;
    { Connection connection(a,**session,records(),c::Bytes{}); }
    std::array<std::byte,64> sink{}; auto output=(**session).output(sink);
    return !output && output.error().kind==h::ServerErrorKind::failed && !(**session).input_memory_charge();
}
template<class Backend> auto oversized_unread(Backend backend) -> bool {
    io::io_context context(backend); io::local_stream_socket a(context),b(context); if (io::connect_pair(a,b)) return false;
    auto session=h::ServerSession::create({8,16,4096,1024,4096},{nullptr,headers,data,end,closed}); if (!session) return false;
    c::Bytes unread(4097,42); unread.reserve(1u<<20);
    Connection connection(a,**session,records(),std::move(unread));
    std::array<std::byte,64> sink{}; auto output=(**session).output(sink);
    bool done=false; std::optional<h::TlsServerError> error;
    capy::run_async(context.get_executor())(read_step(connection,done,error)); context.restart(); (void)context.run_for(1s);
    std::uint8_t byte{}; auto n=::recv(b.native_handle(),&byte,1,MSG_DONTWAIT);
    return unread.capacity()==0 && !output && output.error().kind==h::ServerErrorKind::failed &&
        context.stopped() && done && error==h::TlsServerError::invalid_state && n<0 && (errno==EAGAIN || errno==EWOULDBLOCK);
}
template<class Backend> auto transport_budget(Backend backend,bool enough) -> bool {
    h::ServerEvents events{nullptr,headers,data,end,closed}; h::ServerLimits limits{8,16,4096,1024,4096};
    auto reference=h::ServerSession::create(limits,events); if (!reference) return false;
    auto baseline=(**reference).shared_memory_used(); reference->reset();
    limits.shared_memory_bytes=baseline+(enough ? 4096 : 4095);
    auto session=h::ServerSession::create(limits,events); if (!session) return false;
    io::io_context context(backend); io::local_stream_socket a(context),b(context); if (io::connect_pair(a,b)) return false;
    {
        Connection connection(a,**session,records(),c::Bytes{});
        if ((**session).transport_memory_charge()!=(enough ? 4096u : 0u)) return false;
        if (!enough) {
            bool done=false; std::optional<h::TlsServerError> error;
            capy::run_async(context.get_executor())(read_step(connection,done,error)); context.restart(); (void)context.run_for(1s);
            std::uint8_t byte{}; auto n=::recv(b.native_handle(),&byte,1,MSG_DONTWAIT);
            if (!done || error!=h::TlsServerError::invalid_state || n>=0 || (errno!=EAGAIN && errno!=EWOULDBLOCK)) return false;
        }
    }
    std::array<std::byte,32> output{}; auto result=(**session).output(output);
    return !(**session).transport_memory_charge() && (**session).shared_memory_used()==baseline &&
        !result && result.error().kind==h::ServerErrorKind::failed;
}
template<class Backend> auto wrong_role(Backend backend) -> bool {
    io::io_context context(backend); io::local_stream_socket a(context),b(context); if (io::connect_pair(a,b)) return false;
    auto session=h::ServerSession::create({8,16,4096,1024,4096},{nullptr,headers,data,end,closed}); if (!session) return false;
    Connection connection(a,**session,records(t::ApplicationRole::client),c::Bytes{});
    bool done=false; std::optional<h::TlsServerError> error;
    capy::run_async(context.get_executor())(read_step(connection,done,error)); context.restart(); (void)context.run_for(1s);
    std::array<std::byte,64> sink{}; auto output=(**session).output(sink);
    std::uint8_t byte{}; auto n=::recv(b.native_handle(),&byte,1,MSG_DONTWAIT);
    return context.stopped() && done && error==h::TlsServerError::invalid_state &&
        !output && output.error().kind==h::ServerErrorKind::failed && n<0 && (errno==EAGAIN || errno==EWOULDBLOCK);
}
template<class Backend> auto unready_records(Backend backend,int mode) -> bool {
    io::io_context context(backend); io::local_stream_socket a(context),b(context); if (io::connect_pair(a,b)) return false;
    auto session=h::ServerSession::create({8,16,4096,1024,4096},{nullptr,headers,data,end,closed}); if (!session) return false;
    auto state=records(); std::optional<t::ApplicationRecords> moved;
    if (mode>=6) {
        auto send=layer(t::RecordDirection::send,1,2);
        if (!send.seal(t::ContentType::application_data,c::Bytes{1})) return false;
        if (mode==7 && !send.seal(t::ContentType::application_data,c::Bytes{2})) return false;
        state=t::ApplicationRecords(std::move(send),layer(t::RecordDirection::receive,2),16385,16385,t::ApplicationRole::server);
    }
    else if (mode==5) state=t::ApplicationRecords(layer(t::RecordDirection::receive,1),layer(t::RecordDirection::send,2),16385,16385,t::ApplicationRole::server);
    else if (mode==0) moved.emplace(std::move(state));
    else if (mode==1) { if (!state.close_notify()) return false; }
    else {
        auto peer=layer(t::RecordDirection::send,2);
        auto message=mode==2 ? c::Bytes{1,0} : mode==3 ? c::Bytes{24,0} : c::Bytes{24,0,0,1,1};
        auto wire=peer.seal(mode==2 ? t::ContentType::alert : t::ContentType::handshake,message);
        if (!wire || !state.open_event(*wire)) return false;
    }
    Connection connection(a,**session,std::move(state),c::Bytes{});
    bool done=false; std::optional<h::TlsServerError> error;
    capy::run_async(context.get_executor())(read_step(connection,done,error)); context.restart(); (void)context.run_for(1s);
    std::array<std::byte,64> sink{}; auto output=(**session).output(sink);
    std::uint8_t byte{}; auto n=::recv(b.native_handle(),&byte,1,MSG_DONTWAIT);
    return context.stopped() && done && error==h::TlsServerError::invalid_state &&
        !output && output.error().kind==h::ServerErrorKind::failed && n<0 && (errno==EAGAIN || errno==EWOULDBLOCK);
}
template<class Backend> auto input_budget(Backend backend,bool enough) -> bool {
    h::ServerEvents events{nullptr,headers,data,end,closed}; h::ServerLimits limits{8,16,4096,1024,4096};
    auto reference=h::ServerSession::create(limits,events); if (!reference) return false;
    std::array<std::byte,4096> sink{};
    for (;;) { auto n=(**reference).output(sink); if (!n) return false; if (!*n) break; }
    auto baseline=(**reference).shared_memory_used(); reference->reset();
    limits.shared_memory_bytes=baseline+(enough ? 53953 : 53952);
    auto session=h::ServerSession::create(limits,events); if (!session) return false;
    for (;;) { auto n=(**session).output(sink); if (!n) return false; if (!*n) break; }
    io::io_context context(backend); io::local_stream_socket a(context),b(context); if (io::connect_pair(a,b)) return false;
    Connection connection(a,**session,records(),c::Bytes{}); bool done=false; std::optional<h::TlsServerError> error;
    if (enough) {
        constexpr std::array<std::uint8_t,8> partial{23,3,3,0,30,1,2,3};
        if (::send(b.native_handle(),partial.data(),partial.size(),MSG_NOSIGNAL)!=static_cast<ssize_t>(partial.size())) return false;
    }
    capy::run_async(context.get_executor())(read_step(connection,done,error)); context.restart(); (void)context.run_for(20ms);
    if (enough) {
        if (done || (**session).shared_memory_used()!=baseline+53953 || (**session).ciphertext_memory_charge()!=16650 || (**session).scratch_memory_charge()!=16384) return false;
        connection.cancel(); context.restart(); (void)context.run_for(1s);
        auto output=(**session).output(sink);
        return done && error==h::TlsServerError::tls && context.stopped() && (**session).shared_memory_used()==baseline+4096 && (**session).transport_memory_charge()==4096 && !(**session).ciphertext_memory_charge() && !(**session).scratch_memory_charge() &&
            !output && output.error().kind==h::ServerErrorKind::failed;
    }
    auto output=(**session).output(sink);
    return done && error==h::TlsServerError::budget_exceeded && context.stopped() && (**session).shared_memory_used()==baseline+4096 && (**session).transport_memory_charge()==4096 &&
        !output && output.error().kind==h::ServerErrorKind::failed;
}
template<class Backend> auto invalid_max_record(Backend backend) -> bool {
    io::io_context context(backend); io::local_stream_socket a(context),b(context); if (io::connect_pair(a,b)) return false;
    h::ServerLimits limits{8,16,4096,262144,262144}; limits.shared_memory_bytes=262144;
    auto session=h::ServerSession::create(limits,{nullptr,headers,data,end,closed}); if (!session) return false;
    std::array<std::byte,4096> sink{};
    for (;;) { auto n=(**session).output(sink); if (!n) return false; if (!*n) break; }
    Connection connection(a,**session,records(),c::Bytes{});
    c::Bytes wire(16645,0); wire[0]=23; wire[1]=3; wire[2]=3; wire[3]=65; wire[4]=0;
    if (::send(b.native_handle(),wire.data(),wire.size(),MSG_NOSIGNAL)!=static_cast<ssize_t>(wire.size())) return false;
    bool done=false; std::optional<h::TlsServerError> error;
    capy::run_async(context.get_executor())(read_step(connection,done,error)); context.restart(); (void)context.run_for(1s);
    return context.stopped() && done && error==h::TlsServerError::tls && !(**session).input_memory_charge() &&
        !(**session).ciphertext_memory_charge() && !(**session).scratch_memory_charge();
}
template<class Backend> auto control_budget(Backend backend,int mode) -> bool {
    io::io_context context(backend); io::local_stream_socket a(context),b(context); if (io::connect_pair(a,b)) return false;
    auto session=h::ServerSession::create({8,16,4096,1024,4096},{nullptr,headers,data,end,closed}); if (!session) return false;
    std::array<std::byte,4096> sink{};
    for (;;) { auto n=(**session).output(sink); if (!n) return false; if (!*n) break; }
    auto peer=layer(t::RecordDirection::send,2); c::Bytes update{24,0,0,1,1};
    auto wire=peer.seal(t::ContentType::handshake,update); if (!wire) return false;
    auto connection=std::make_unique<Connection>(a,**session,records(),std::move(*wire));
    bool done=false,progress=false;
    if (mode==1 || mode==3) { watched_session=session->get(); watched_size=27; watch_output=true; released_with_output_charge=false; }
    capy::run_async(context.get_executor())(progress_step(*connection,done,progress)); context.restart(); (void)context.run_for(1s);
    watched_size=0;
    if (!context.stopped() || !done || !progress || (**session).output_memory_charge()!=183 || (**session).input_memory_charge()) return false;
    if (mode==1 || mode==3) {
        if (!watched_allocation) return false;
        if (mode==1) connection->cancel(); else connection.reset();
        auto ok=!watched_allocation && released_with_output_charge && (**session).output_memory_charge()==0;
        watched_session=nullptr; watch_output=false; return ok;
    }
    if (mode==2) {
        std::array<char,4096> filler{};
        for (;;) { auto n=::send(a.native_handle(),filler.data(),filler.size(),MSG_DONTWAIT|MSG_NOSIGNAL);
            if (n>0 || (n<0 && errno==EINTR)) continue; if (n<0 && (errno==EAGAIN || errno==EWOULDBLOCK)) break; return false; }
    }
    done=false; std::optional<h::TlsServerError> error;
    capy::run_async(context.get_executor())(read_step(*connection,done,error)); context.restart(); (void)context.run_for(20ms);
    if (mode==2) {
        if (done || (**session).output_memory_charge()!=183) return false;
        connection->cancel(); if ((**session).output_memory_charge()!=183) return false;
        context.restart(); (void)context.run_for(1s);
        return context.stopped() && done && error==h::TlsServerError::tls && !(**session).output_memory_charge();
    }
    std::array<std::uint8_t,27> response{}; auto n=::recv(b.native_handle(),response.data(),response.size(),MSG_DONTWAIT);
    return context.stopped() && done && !error && !(**session).output_memory_charge() && n==27 && response[0]==23;
}
template<class Socket> auto close_step(h::TlsServerConnection<Socket>& connection,bool& done,std::optional<h::TlsServerError>& error) -> capy::task<> {
    auto result=co_await connection.close_notify(); if (!result) error=result.error(); done=true;
}
template<class Backend> auto control_allocation_failure(Backend backend,bool closing) -> bool {
    io::io_context context(backend); io::local_stream_socket a(context),b(context); if (io::connect_pair(a,b)) return false;
    auto session=h::ServerSession::create({8,16,4096,1024,4096},{nullptr,headers,data,end,closed}); if (!session) return false;
    std::array<std::byte,4096> sink{};
    for (;;) { auto n=(**session).output(sink); if (!n) return false; if (!*n) break; }
    auto peer=layer(t::RecordDirection::send,2); auto message=closing ? c::Bytes{1,0} : c::Bytes{24,0,0,1,1};
    auto wire=peer.seal(closing ? t::ContentType::alert : t::ContentType::handshake,message); if (!wire) return false;
    ThrowSocket socket{a,false,false}; h::TlsServerConnection connection(socket,**session,records(),std::move(*wire));
    bool done=false; std::optional<h::TlsServerError> error;
    capy::run_async(context.get_executor())(partial_step(connection,done,error)); context.restart(); (void)context.run_for(1s);
    if (!done || error || (**session).output_memory_charge()!=(closing ? 0u : 183u)) return false;
    if (closing) {
        done=false; capy::run_async(context.get_executor())(partial_step(connection,done,error)); context.restart(); (void)context.run_for(1s);
        if (!done || error) return false;
    }
    socket.enabled=true; done=false;
    if (closing) capy::run_async(context.get_executor())(close_step(connection,done,error));
    else capy::run_async(context.get_executor())(partial_step(connection,done,error));
    context.restart(); (void)context.run_for(1s);
    auto output=(**session).output(sink); std::uint8_t byte{}; auto n=::recv(b.native_handle(),&byte,1,MSG_DONTWAIT);
    return context.stopped() && done && error==h::TlsServerError::allocation && n<0 && (errno==EAGAIN || errno==EWOULDBLOCK) &&
        !(**session).input_memory_charge() && !(**session).output_memory_charge() && !(**session).ciphertext_memory_charge() &&
        !(**session).scratch_memory_charge() && (**session).transport_memory_charge()==4096 && !output && output.error().kind==h::ServerErrorKind::failed;
}
template<class Backend> auto close_budget(Backend backend,bool blocked) -> bool {
    io::io_context context(backend); io::local_stream_socket a(context),b(context); if (io::connect_pair(a,b)) return false;
    h::ServerLimits limits{8,16,4096,1024,4096}; limits.shared_memory_bytes=131072;
    auto session=h::ServerSession::create(limits,{nullptr,headers,data,end,closed}); if (!session) return false;
    std::array<std::byte,4096> sink{};
    for (;;) { auto n=(**session).output(sink); if (!n) return false; if (!*n) break; }
    auto peer=layer(t::RecordDirection::send,2); auto wire=peer.seal(t::ContentType::alert,c::Bytes{1,0}); if (!wire) return false;
    Connection connection(a,**session,records(),std::move(*wire)); bool done=false,progress=false;
    capy::run_async(context.get_executor())(progress_step(connection,done,progress)); context.restart(); (void)context.run_for(1s);
    if (!done || !progress || (**session).output_memory_charge()) return false;
    done=false; std::optional<h::TlsServerError> error;
    capy::run_async(context.get_executor())(read_step(connection,done,error)); context.restart(); (void)context.run_for(1s);
    if (!done || error) return false;
    if (blocked) {
        auto available=limits.shared_memory_bytes-(**session).shared_memory_used();
        if (available<48 || !(**session).reserve_input(available-47)) return false;
    }
    done=false; capy::run_async(context.get_executor())(close_step(connection,done,error)); context.restart(); (void)context.run_for(1s);
    std::array<std::uint8_t,32> response{}; auto n=::recv(b.native_handle(),response.data(),response.size(),MSG_DONTWAIT); auto read_error=errno;
    if (blocked) return context.stopped() && done && error==h::TlsServerError::budget_exceeded &&
        !(**session).output_memory_charge() && n<0 && (read_error==EAGAIN || read_error==EWOULDBLOCK);
    return context.stopped() && done && !error && !(**session).output_memory_charge() && n==24 && response[0]==23;
}
template<class Backend> auto truncated_input(Backend backend) -> bool {
    io::io_context context(backend); io::local_stream_socket a(context),b(context); if (io::connect_pair(a,b)) return false;
    auto session=h::ServerSession::create({8,16,4096,1024,4096},{nullptr,headers,data,end,closed}); if (!session) return false;
    std::array<std::byte,4096> sink{};
    for (;;) { auto n=(**session).output(sink); if (!n) return false; if (!*n) break; }
    constexpr std::array<std::uint8_t,8> partial{23,3,3,0,30,1,2,3};
    if (::send(b.native_handle(),partial.data(),partial.size(),MSG_NOSIGNAL)!=static_cast<ssize_t>(partial.size())) return false;
    b.close(); Connection connection(a,**session,records(),c::Bytes{}); bool done=false; std::optional<h::TlsServerError> error;
    capy::run_async(context.get_executor())(read_step(connection,done,error)); context.restart(); (void)context.run_for(1s);
    auto output=(**session).output(sink);
    return context.stopped() && done && error==h::TlsServerError::tls && (**session).input_memory_charge()==0 &&
        !output && output.error().kind==h::ServerErrorKind::failed;
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
    if (mode==0 || mode==2) { watched_session=session->get(); watched_size=input.size()+17; released_with_input_charge=false; }
    capy::run_async(context.get_executor())(until_paused(*connection,paused)); context.restart(); (void)context.run_for(1s);
    watched_size=0;
    if (!context.stopped() || !paused || (**session).paused_stream()!=3 || (**session).input_memory_charge()!=16640) return false;
    if (mode==1) {
        auto available=limits.shared_memory_bytes-(**session).shared_memory_used();
        if (available<sizeof(nex::nghttp2::nghttp2_nv)) return false;
        std::vector<std::byte> body(available);
        auto blocked=(**session).respond_body(1,200,body);
        if (blocked || blocked.error().kind!=h::ServerErrorKind::budget_exceeded || (**session).response_memory_used() ||
            (**session).input_memory_charge()!=16640 || (**session).shared_memory_used()>limits.shared_memory_bytes) return false;
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
        if ((**session).input_memory_charge()!=16640) return false;
        context.restart(); (void)context.run_for(1s);
        if (!done || error!=h::TlsServerError::tls || !context.stopped()) return false;
    } else if (mode==2) {
        if (!watched_allocation) return false;
        connection->cancel();
        if (watched_allocation || !released_with_input_charge) return false;
        watched_session=nullptr;
    } else {
        if (!watched_allocation) return false;
        connection.reset();
        if (watched_allocation || !released_with_input_charge) return false;
        watched_session=nullptr;
    }
    auto resumed=(**session).resume_input(3); auto output=(**session).output(std::span<std::byte>{});
    return !resumed && resumed.error().kind==h::ServerErrorKind::failed && !output &&
        output.error().kind==h::ServerErrorKind::failed && (**session).input_memory_charge()==0;
}
int main() {
    for (int i=0;i<5;++i) {
        if (!transport_budget(io::epoll,true) || !transport_budget(io::epoll,false)) return 1;
        for (int mode=0;mode<8;++mode) if (!unready_records(io::epoll,mode)) return 1;
        if (!allocation_failure(io::epoll,false) || !allocation_failure(io::epoll,true)) return 1;
        if (!control_allocation_failure(io::epoll,false) || !control_allocation_failure(io::epoll,true)) return 1;
        if (!wrong_role(io::epoll)) return 1;
        if (!oversized_unread(io::epoll)) { std::cerr << "oversized_unread(io::epoll) failed\n"; return 1; }
        if (!duplicate_owner(io::epoll)) { std::cerr << "duplicate_owner(io::epoll) failed\n"; return 1; }
        if (!drop_idle_driver(io::epoll)) { std::cerr << "drop_idle_driver(io::epoll) failed\n"; return 1; }
        if (!sealing_charge(io::epoll)) { std::cerr << "sealing_charge(io::epoll) failed\n"; return 1; }
        if (!partial_failure(io::epoll)) { std::cerr << "partial_failure(io::epoll) failed\n"; return 1; }
        if (!output_budget(io::epoll)) { std::cerr << "output_budget(io::epoll) failed\n"; return 1; }
        if (!control_budget(io::epoll,0)) { std::cerr << "control_budget(io::epoll,0) failed\n"; return 1; }
        if (!control_budget(io::epoll,1)) { std::cerr << "control_budget(io::epoll,1) failed\n"; return 1; }
        if (!control_budget(io::epoll,3)) { std::cerr << "control_budget(io::epoll,3) failed\n"; return 1; }
        if (!control_budget(io::epoll,2)) { std::cerr << "control_budget(io::epoll,2) failed\n"; return 1; }
        if (!close_budget(io::epoll,false)) { std::cerr << "close_budget(io::epoll,false) failed\n"; return 1; }
        if (!close_budget(io::epoll,true)) { std::cerr << "close_budget(io::epoll,true) failed\n"; return 1; }
        if (!truncated_input(io::epoll)) { std::cerr << "truncated_input(io::epoll) failed\n"; return 1; }
        if (!exercise(io::epoll,false)) { std::cerr << "exercise(io::epoll,false) failed\n"; return 1; }
        if (!exercise(io::epoll,true)) { std::cerr << "exercise(io::epoll,true) failed\n"; return 1; }
        if (!invalid_max_record(io::epoll)) { std::cerr << "invalid_max_record(io::epoll) failed\n"; return 1; }
        if (!input_budget(io::epoll,true)) { std::cerr << "input_budget(io::epoll,true) failed\n"; return 1; }
        if (!input_budget(io::epoll,false)) { std::cerr << "input_budget(io::epoll,false) failed\n"; return 1; }
        if (!abandon_paused(io::epoll,0)) { std::cerr << "abandon_paused(io::epoll,0) failed\n"; return 1; }
        if (!abandon_paused(io::epoll,1)) { std::cerr << "abandon_paused(io::epoll,1) failed\n"; return 1; }
        if (!abandon_paused(io::epoll,2)) { std::cerr << "abandon_paused(io::epoll,2) failed\n"; return 1; }
        if (!abandon_paused(io::epoll,3)) { std::cerr << "abandon_paused(io::epoll,3) failed\n"; return 1; }
#if BOOST_COROSIO_HAVE_LIBURING
        if (!transport_budget(io::uring,true) || !transport_budget(io::uring,false)) return 2;
        for (int mode=0;mode<8;++mode) if (!unready_records(io::uring,mode)) return 2;
        if (!allocation_failure(io::uring,false) || !allocation_failure(io::uring,true)) return 2;
        if (!control_allocation_failure(io::uring,false) || !control_allocation_failure(io::uring,true)) return 2;
        if (!wrong_role(io::uring)) return 2;
        if (!oversized_unread(io::uring)) { std::cerr << "oversized_unread(io::uring) failed\n"; return 2; }
        if (!duplicate_owner(io::uring)) { std::cerr << "duplicate_owner(io::uring) failed\n"; return 2; }
        if (!drop_idle_driver(io::uring)) { std::cerr << "drop_idle_driver(io::uring) failed\n"; return 2; }
        if (!sealing_charge(io::uring)) { std::cerr << "sealing_charge(io::uring) failed\n"; return 2; }
        if (!partial_failure(io::uring)) { std::cerr << "partial_failure(io::uring) failed\n"; return 2; }
        if (!output_budget(io::uring)) { std::cerr << "output_budget(io::uring) failed\n"; return 2; }
        if (!control_budget(io::uring,0)) { std::cerr << "control_budget(io::uring,0) failed\n"; return 2; }
        if (!control_budget(io::uring,1)) { std::cerr << "control_budget(io::uring,1) failed\n"; return 2; }
        if (!control_budget(io::uring,3)) { std::cerr << "control_budget(io::uring,3) failed\n"; return 2; }
        if (!control_budget(io::uring,2)) { std::cerr << "control_budget(io::uring,2) failed\n"; return 2; }
        if (!close_budget(io::uring,false)) { std::cerr << "close_budget(io::uring,false) failed\n"; return 2; }
        if (!close_budget(io::uring,true)) { std::cerr << "close_budget(io::uring,true) failed\n"; return 2; }
        if (!truncated_input(io::uring)) { std::cerr << "truncated_input(io::uring) failed\n"; return 2; }
        if (!exercise(io::uring,false)) { std::cerr << "exercise(io::uring,false) failed\n"; return 2; }
        if (!exercise(io::uring,true)) { std::cerr << "exercise(io::uring,true) failed\n"; return 2; }
        if (!invalid_max_record(io::uring)) { std::cerr << "invalid_max_record(io::uring) failed\n"; return 2; }
        if (!input_budget(io::uring,true)) { std::cerr << "input_budget(io::uring,true) failed\n"; return 2; }
        if (!input_budget(io::uring,false)) { std::cerr << "input_budget(io::uring,false) failed\n"; return 2; }
        if (!abandon_paused(io::uring,0)) { std::cerr << "abandon_paused(io::uring,0) failed\n"; return 2; }
        if (!abandon_paused(io::uring,1)) { std::cerr << "abandon_paused(io::uring,1) failed\n"; return 2; }
        if (!abandon_paused(io::uring,2)) { std::cerr << "abandon_paused(io::uring,2) failed\n"; return 2; }
        if (!abandon_paused(io::uring,3)) { std::cerr << "abandon_paused(io::uring,3) failed\n"; return 2; }
#endif
    }
    std::cout << "HTTP/2 TLS output and input budgets, cancellation and deadlines passed\n";
}
