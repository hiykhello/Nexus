#include <boost/corosio/backend.hpp>
#include <cerrno>
#include <cstdlib>
#include <sys/socket.h>
#include <unistd.h>
import std;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;
import tls.corosio_server_handshake;
import tls.server_handshake_io;
import tls.application_io;
import tls.client_handshake_io;
import tls.corosio_client;
import tls.handshake;
namespace t=tls; namespace io=nex::corosio; namespace capy=nex::capy;
using namespace std::chrono_literals;
static void* watched_unread=nullptr;
static ::memory::Budget* watched_budget=nullptr;
static bool released_while_reserved=false;
static void* watched_key_secret=nullptr;
static bool key_released_while_reserved=false;
void operator delete(void* p) noexcept {
    if (p && p==watched_unread) { released_while_reserved=watched_budget->reserved()==8; watched_unread=nullptr; }
    if (p && p==watched_key_secret) { key_released_while_reserved=watched_budget->reserved()==2*t::ApplicationRecords::key_charge; watched_key_secret=nullptr; }
    std::free(p);
}
void operator delete(void* p,std::size_t) noexcept { ::operator delete(p); }
auto move_assignment_test() -> bool {
    std::array<std::uint8_t,16> key{}; std::array<std::uint8_t,12> iv{};
    auto make_records=[&]() {
        auto write=t::RecordLayer::create(t::RecordDirection::send,::crypto::Aead::aes_128_gcm,key,iv);
        auto read=t::RecordLayer::create(t::RecordDirection::receive,::crypto::Aead::aes_128_gcm,key,iv);
        return t::ApplicationRecords(std::move(*write),std::move(*read),16385,16385,t::ApplicationRole::server);
    };
    auto budget=std::make_shared<::memory::Budget>(8);
    t::detail::ServerAsyncResult old(make_records(),::memory::Budget::reserve(budget,3),::crypto::Bytes(3,1));
    t::detail::ServerAsyncResult next(make_records(),::memory::Budget::reserve(budget,5),::crypto::Bytes(5,2));
    watched_unread=old.unread.data(); watched_budget=budget.get(); released_while_reserved=false;
    old=std::move(next);
    auto valid=released_while_reserved && !watched_unread && budget->reserved()==5 && old.unread==::crypto::Bytes(5,2);
    old=std::move(old);
    valid=valid && budget->reserved()==5 && old.unread.size()==5;
    ::crypto::Bytes{}.swap(old.unread);
    if (!valid || !old.release_unread_reservation() || budget->reserved()) return false;
    auto keys_budget=std::make_shared<::memory::Budget>(2*t::ApplicationRecords::key_charge);
    auto make_keyed=[&]() {
        auto write=t::RecordLayer::create(t::RecordDirection::send,::crypto::Aead::aes_128_gcm,key,iv);
        auto read=t::RecordLayer::create(t::RecordDirection::receive,::crypto::Aead::aes_128_gcm,key,iv);
        ::crypto::Bytes first(32,1),second(32,2);
        auto pointer=first.data();
        t::ApplicationRecords records(std::move(*write),std::move(*read),16385,16385,::crypto::Hash::sha256,::crypto::Aead::aes_128_gcm,16,t::Secret(std::move(first)),t::Secret(std::move(second)),t::ApplicationRole::server);
        auto reservation=::memory::Budget::reserve(keys_budget,t::ApplicationRecords::key_charge);
        if (!reservation || !records.retain_key_reservation(std::move(*reservation))) std::abort();
        return std::pair{std::move(records),pointer};
    };
    {
        auto first=make_keyed(),second=make_keyed();
        watched_key_secret=first.second; watched_budget=keys_budget.get(); key_released_while_reserved=false;
        auto other_budget=std::make_shared<::memory::Budget>(t::ApplicationRecords::key_charge);
        auto duplicate=::memory::Budget::reserve(other_budget,t::ApplicationRecords::key_charge);
        if (!duplicate || first.first.retain_key_reservation(std::move(*duplicate)) || duplicate->size()!=t::ApplicationRecords::key_charge) return false;
        first.first=std::move(second.first);
        if (watched_key_secret || !key_released_while_reserved || keys_budget->reserved()!=t::ApplicationRecords::key_charge) return false;
        first.first=std::move(first.first);
        if (keys_budget->reserved()!=t::ApplicationRecords::key_charge) return false;
    }
    return keys_budget->reserved()==0;
}
auto file(char const* path) -> ::crypto::Bytes { std::ifstream in(path,std::ios::binary); return {std::istreambuf_iterator<char>(in),{}}; }
auto now() -> std::uint64_t { return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count(); }
struct Fixture {
#if BOOST_COROSIO_HAVE_LIBURING
    io::io_context context{io::uring};
#else
    io::io_context context;
#endif
    io::local_stream_socket incoming{context}, peer{context};
    std::optional<t::ServerHandshakeIo> handshake;
    std::shared_ptr<::memory::Budget> budget;
    bool done=false, success=false; std::optional<t::detail::ServerAsyncError> error;
};
auto pending(Fixture& f) -> capy::task<> {
    auto result=co_await t::detail::server_handshake(f.incoming,*f.handshake,f.budget); if (!result) f.error=result.error(); f.done=true;
}
struct FailingSocket {
    io::local_stream_socket& socket; bool fail_read;
    auto read_some(capy::mutable_buffer b) { if (fail_read) throw std::bad_alloc{}; return socket.read_some(b); }
    auto write_some(capy::const_buffer b) { if (!fail_read) throw std::bad_alloc{}; return socket.write_some(b); }
};
auto exception_handshake(FailingSocket& socket,t::ServerHandshakeIo& handshake,std::shared_ptr<::memory::Budget> budget,bool& caught) -> capy::task<> {
    try { (void)co_await t::detail::server_handshake(socket,handshake,std::move(budget)); }
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
    FailingSocket socket{f.incoming,reading}; bool caught=false; auto budget=std::make_shared<::memory::Budget>(8192);
    capy::run_async(f.context.get_executor())(exception_handshake(socket,*handshake,budget,caught));
    f.context.restart(); (void)f.context.run_for(1s);
    return f.context.stopped() && caught && !budget->reserved() && !handshake->tick(start) && handshake->pending_output().empty();
}
struct HandoverResult { bool done=false, valid=false; };
auto handover(Fixture& f,::crypto::Bytes expected,HandoverResult& state,bool reject,std::span<std::uint8_t const> initial={}) -> capy::task<> {
    auto result=co_await t::detail::server_handshake(f.incoming,*f.handshake,f.budget,initial);
    if (reject) { state.valid=!result && result.error()==t::detail::ServerAsyncError::budget_exceeded && !f.budget->reserved(); state.done=true; co_return; }
    if (result && result->unread==expected) {
        if (f.budget && (f.budget->reserved()!=expected.size() || result->release_unread_reservation())) { state.done=true; co_return; }
        auto data=result->records.open(result->unread);
        state.valid=data && *data==::crypto::Bytes({'h','e','l','l','o'});
        ::crypto::Bytes{}.swap(result->unread);
        if (!result->release_unread_reservation() || (f.budget && f.budget->reserved())) state.valid=false;
    }
    state.done=true;
}
auto coalesced_handover(char const* cert,char const* key,bool close_peer,bool reject=false,bool pre_read=false) -> bool {
    Fixture f; auto certificate=file(cert); auto credential=t::ServerCredential::create(certificate,file(key));
    if (!credential || io::connect_pair(f.incoming,f.peer)) return false;
    auto start=now(); auto server=t::ServerHandshakeIo::create(std::move(*credential),start,start+1000); if (!server) return false;
    std::array<std::uint16_t,1> groups{29}; auto hello=t::make_client_hello("localhost",std::span<std::string_view const>{},groups); if (!hello) return false;
    std::array<std::span<std::uint8_t const>,1> anchors{certificate}; std::string_view host="localhost";
    auto identity=std::span{reinterpret_cast<std::uint8_t const*>(host.data()),host.size()};
    auto seconds=std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    auto client=t::ClientSessionHandshake::create(std::move(*hello),29,anchors,t::PeerNameKind::dns,identity,seconds); if (!client) return false;
    auto initial=client->initial_record(); if (!initial || !client->sent() || !server->feed(*initial,start)) return false;
    std::optional<::crypto::Bytes> finished;
    while (!server->pending_output().empty()) {
        auto output=server->pending_output(); auto result=client->feed(output);
        if (!result || result->consumed!=output.size()) return false;
        if (result->outbound) finished=std::move(*result->outbound);
        if (!server->written(output.size(),start)) return false;
    }
    if (!finished || !client->sent()) return false;
    auto app=client->take_application_records(); if (!app) return false;
    ::crypto::Bytes plain{'h','e','l','l','o'}; auto encrypted=app->seal(plain); if (!encrypted) return false;
    auto input=*finished; input.insert(input.end(),encrypted->begin(),encrypted->end());
    if (!pre_read && ::send(f.peer.native_handle(),input.data(),input.size(),MSG_NOSIGNAL)!=static_cast<ssize_t>(input.size())) return false;
    if (close_peer) f.peer.close();
    f.handshake.emplace(std::move(*server)); f.budget=std::make_shared<::memory::Budget>(reject ? 4096+encrypted->size()-1 : 8192); HandoverResult state;
    capy::run_async(f.context.get_executor())(handover(f,*encrypted,state,reject,pre_read ? std::span<std::uint8_t const>{input} : std::span<std::uint8_t const>{})); f.context.restart(); (void)f.context.run_for(1s);
    return f.context.stopped() && state.done && state.valid;
}
struct CountingSocket {
    io::local_stream_socket& socket; unsigned reads=0;
    auto read_some(capy::mutable_buffer b) { ++reads; return socket.read_some(b); }
    auto write_some(capy::const_buffer b) { return socket.write_some(b); }
    void cancel() { socket.cancel(); }
};
using Client=t::detail::ClientConnection<CountingSocket>;
auto client_handover(Client& client,HandoverResult& state) -> capy::task<> {
    auto started=co_await client.start();
    if (started && client.application()) {
        auto data=co_await client.application()->read();
        state.valid=data && data->event && data->event->kind==t::ApplicationEventKind::data && data->event->data==::crypto::Bytes({'h','e','l','l','o'});
    }
    state.done=true;
}
auto client_coalesced_handover(char const* cert,char const* key) -> bool {
    Fixture f; auto certificate=file(cert); auto credential=t::ServerCredential::create(certificate,file(key));
    if (!credential || io::connect_pair(f.incoming,f.peer)) return false;
    std::array<std::uint16_t,1> groups{29}; auto hello=t::make_client_hello("localhost",std::span<std::string_view const>{},groups); if (!hello) return false;
    hello->cipher_suites={0x1301}; std::array<std::span<std::uint8_t const>,1> anchors{certificate}; std::string_view host="localhost";
    auto identity=std::span{reinterpret_cast<std::uint8_t const*>(host.data()),host.size()};
    auto seconds=std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    auto session=t::ClientSessionHandshake::create(std::move(*hello),29,anchors,t::PeerNameKind::dns,identity,seconds); if (!session) return false;
    auto initial=session->initial_record(); if (!initial) return false;
    auto scheme=*credential->scheme(); auto keys=t::server_handshake_keys(std::span{*initial}.subspan(5),std::span{&scheme,1}); if (!keys) return false;
    auto server_hello=keys->server_hello; auto hash=keys->hash;
    auto master=t::master_secret(hash,keys->handshake_secret.view());
    auto hk=t::expand_label(hash,keys->server_traffic.view(),"key",{},16), hi=t::expand_label(hash,keys->server_traffic.view(),"iv",{},12);
    if (!master || !hk || !hi) return false;
    auto reader=t::RecordLayer::create(t::RecordDirection::receive,::crypto::Aead::aes_128_gcm,hk->view(),hi->view());
    auto transcript=t::Transcript::create(hash); auto decoder=t::HandshakeDecoder::create(1048584);
    if (!reader || !transcript || !decoder || !transcript->append(std::span{*initial}.subspan(5)) || !transcript->append(server_hello)) return false;
    auto flight=t::ServerFlight::create(std::move(*keys),*credential); if (!flight) return false;
    ::crypto::Bytes output{22,3,3,static_cast<std::uint8_t>(server_hello.size()>>8),static_cast<std::uint8_t>(server_hello.size())};
    output.insert(output.end(),server_hello.begin(),server_hello.end());
    for (auto const& record:flight->records()) {
        auto plain=reader->open(record); if (!plain) return false;
        auto messages=decoder->feed(plain->content); if (!messages) return false;
        for (auto const& message:*messages) {
            auto encoded=t::HandshakeDecoder::encode(message.type,message.body,1048584); if (!encoded || !transcript->append(*encoded)) return false;
        }
        output.insert(output.end(),record.begin(),record.end());
    }
    auto digest=transcript->snapshot(); if (!digest || decoder->pending_bytes()) return false;
    auto traffic=t::derive_secret(hash,master->view(),"s ap traffic",*digest); if (!traffic) return false;
    auto ak=t::expand_label(hash,traffic->view(),"key",{},16), ai=t::expand_label(hash,traffic->view(),"iv",{},12); if (!ak || !ai) return false;
    auto writer=t::RecordLayer::create(t::RecordDirection::send,::crypto::Aead::aes_128_gcm,ak->view(),ai->view()); if (!writer) return false;
    ::crypto::Bytes plain{'h','e','l','l','o'}; auto encrypted=writer->seal(t::ContentType::application_data,plain); if (!encrypted) return false;
    output.insert(output.end(),encrypted->begin(),encrypted->end()); if (output.size()>4096) return false;
    if (::send(f.incoming.native_handle(),output.data(),output.size(),MSG_NOSIGNAL)!=static_cast<ssize_t>(output.size())) return false;
    auto start=now(); auto handshake=t::ClientHandshakeIo::create(std::move(*session),start,start+1000); if (!handshake) return false;
    CountingSocket socket{f.peer}; Client client(socket,std::move(*handshake)); HandoverResult state;
    capy::run_async(f.context.get_executor())(client_handover(client,state)); f.context.restart(); (void)f.context.run_for(1s);
    return f.context.stopped() && state.done && state.valid && client.idle() && socket.reads==1;
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
auto budget_failure(char const* cert,char const* key,int mode) -> bool {
    Fixture f; auto credential=t::ServerCredential::create(file(cert),file(key));
    if (!credential || io::connect_pair(f.incoming,f.peer)) return false;
    auto start=now(); auto handshake=t::ServerHandshakeIo::create(std::move(*credential),start,start+1000); if (!handshake) return false;
    std::size_t limit=mode==0 ? 4095 : 4096;
    if (mode>=2) {
        std::array<std::uint16_t,1> groups{29}; auto hello=t::make_client_hello({},std::span<std::string_view const>{},groups); if (!hello) return false;
        std::array<std::uint8_t,1> root{1},name{'a'}; std::array<std::span<std::uint8_t const>,1> anchors{root};
        auto client=t::ClientSessionHandshake::create(std::move(*hello),29,anchors,t::PeerNameKind::dns,name,0); if (!client) return false;
        auto record=client->initial_record(); if (!record || !handshake->feed(*record,start) || handshake->pending_output().empty()) return false;
        limit+=handshake->pending_output().size()-(mode==2 ? 1 : 0);
        if (mode==3) {
            std::array<std::byte,4096> filler{}; bool full=false;
            for (int i=0;i<10000;++i) {
                auto n=::send(f.incoming.native_handle(),filler.data(),filler.size(),MSG_DONTWAIT|MSG_NOSIGNAL);
                if (n<0 && (errno==EAGAIN || errno==EWOULDBLOCK)) { full=true; break; }
                if (n<=0) return false;
            }
            if (!full) return false;
        }
    }
    f.budget=std::make_shared<::memory::Budget>(limit); f.handshake.emplace(std::move(*handshake));
    capy::run_async(f.context.get_executor())(pending(f));
    (void)f.context.run_for(mode==1 || mode==3 ? 20ms : 1s);
    if (mode==1 || mode==3) {
        if (f.done || f.budget->reserved()!=limit) return false;
        f.incoming.cancel(); f.context.restart(); (void)f.context.run_for(1s);
    }
    return f.done && f.error==((mode==1 || mode==3) ? t::detail::ServerAsyncError::transport : t::detail::ServerAsyncError::budget_exceeded) &&
        f.budget->reserved()==0 && !f.handshake->tick(now());
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
        !std::ranges::equal(f.handshake->negotiated_alpn(),::crypto::Bytes{'h','2'}))) { f.done=true; co_return; }
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
        if (feed->event->kind!=t::ApplicationEventKind::data || feed->event->data!=::crypto::Bytes({'h','e','l','l','o'}) || !app.send(feed->event->data)) { f.done=true; co_return; }
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
    if (std::string_view(argv[3])=="failures") return move_assignment_test() && failure(argv[1],argv[2],false) && failure(argv[1],argv[2],true) && budget_failure(argv[1],argv[2],0) && budget_failure(argv[1],argv[2],1) && budget_failure(argv[1],argv[2],2) && budget_failure(argv[1],argv[2],3) && peer_close(argv[1],argv[2]) && exception_test(argv[1],argv[2],false) && exception_test(argv[1],argv[2],true) && coalesced_handover(argv[1],argv[2],false) && coalesced_handover(argv[1],argv[2],true) && coalesced_handover(argv[1],argv[2],false,true) && coalesced_handover(argv[1],argv[2],false,false,true) && coalesced_handover(argv[1],argv[2],false,true,true) && client_coalesced_handover(argv[1],argv[2]) ? 0 : 2;
    auto fd=::accept(std::atoi(argv[3]),nullptr,nullptr); if (fd<0) return 3;
    Network f; if (f.socket.assign(fd)) { ::close(fd); return 4; }
    auto cred=t::ServerCredential::create(file(argv[1]),file(argv[2])); if (!cred) return 5;
    auto start=now(); auto handshake=t::ServerHandshakeIo::create(std::move(*cred),start,start+5000,argc==5 ? "h2" : ""); if (!handshake) return 6;
    f.handshake.emplace(std::move(*handshake)); capy::run_async(f.context.get_executor())(serve(f)); (void)f.context.run_for(6s);
    if (!f.done) { f.socket.cancel(); f.context.restart(); (void)f.context.run_for(1s); if (!f.done) std::_Exit(90); }
    return f.success ? 0 : 7;
}
