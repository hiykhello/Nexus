#include <boost/corosio/backend.hpp>
#include <sys/socket.h>
#include <fcntl.h>
#include <unistd.h>
import std;
import nexus.http2.tls_server;
import nexus.tls.corosio_server_handshake;
import nexus.tls.server_handshake_io;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;
namespace h=nexus::http2; namespace t=nexus::tls; namespace io=nex::corosio; namespace capy=nex::capy;
using namespace std::chrono_literals;
auto file(char const* path) -> nexus::crypto::Bytes { std::ifstream in(path,std::ios::binary); return {std::istreambuf_iterator<char>(in),{}}; }
auto make_context() -> io::io_context {
#if BOOST_COROSIO_HAVE_LIBURING
    if (std::getenv("NEXUS_TEST_URING")) return io::io_context(io::uring);
#else
    if (std::getenv("NEXUS_TEST_URING")) std::_Exit(8);
#endif
    return io::io_context(io::epoll);
}
struct Fixture {
    io::io_context context{make_context()};
    io::tcp_socket socket{context};
    std::optional<t::ServerHandshakeIo> handshake;
    std::unique_ptr<h::ServerSession> session;
    std::int32_t request=0;
    std::vector<std::int32_t> requests;
    unsigned closed_count=0;
    bool response=false, closed=false, done=false, success=false, pause=false, paused=false, ended=false, multi=false, peer_close=false, truncated=false, stale=false, timeout=false, curl=false, head=false, cancel=false, canceled=false, pause_output=false, output_during_pause=false, pause_multi=false, second_response=false;
    std::string body;
};
auto headers(void* p,std::int32_t id,std::span<h::Header const>,bool trailers,bool end) noexcept -> bool {
    auto& f=*static_cast<Fixture*>(p); if (trailers || (!f.multi && !f.pause_multi && f.request) || (f.multi && !end) ||
        (f.pause_multi && (f.requests.size()>=2 || (f.requests.empty() && !end)))) return false;
    try { f.requests.push_back(id); } catch (...) { return false; }
    f.request=id; f.ended=end; return true;
}
auto data(void* p,std::int32_t,std::span<std::byte const> bytes) noexcept -> h::DataDisposition {
    auto& f=*static_cast<Fixture*>(p);
    try { f.body.append(reinterpret_cast<char const*>(bytes.data()),bytes.size()); } catch (...) { return h::DataDisposition::failure; }
    if (f.pause && !f.paused) { f.paused=true; return h::DataDisposition::pause; }
    return h::DataDisposition::accepted;
}
auto end(void* p,std::int32_t) noexcept -> bool { static_cast<Fixture*>(p)->ended=true; return true; }
void closed(void* p,std::int32_t,std::uint32_t code) noexcept {
    auto& f=*static_cast<Fixture*>(p); f.closed=code==0; if (code==0) ++f.closed_count;
}
auto cancel_later(h::TlsServerConnection<io::tcp_socket>& connection, bool& canceled) -> capy::task<> {
    auto [error]=co_await io::delay(100ms);
    if (!error) { canceled=true; connection.cancel(); }
}
auto serve(Fixture& f) -> capy::task<> {
    auto handshake=co_await t::detail::server_handshake(f.socket,*f.handshake);
    if (!handshake || !std::ranges::equal(f.handshake->negotiated_alpn(),nexus::crypto::Bytes{'h','2'})) { f.done=true; co_return; }
    h::TlsServerConnection connection(f.socket,*f.session,std::move(handshake->records),std::move(handshake->unread));
    auto deadline=std::chrono::steady_clock::now()+(f.timeout ? 150ms : 5000ms);
    if (f.cancel) capy::run_async(f.context.get_executor())(cancel_later(connection,f.canceled));
    auto premature=co_await connection.close_notify(deadline);
    if (premature || premature.error()!=h::TlsServerError::invalid_state) { f.done=true; co_return; }
    int shutdown_phase=0;
    for (int i=0;i<100;++i) {
        if (f.multi && f.requests.size()==2 && shutdown_phase==0) {
            if (!f.session->start_shutdown()) break;
            auto notice=co_await connection.step(deadline);
            if (!notice || *notice!=h::TlsServerStep::progress || !f.session->finish_shutdown()) break;
            for (auto id:f.requests) {
                constexpr std::string_view body="hello h2";
                if (!f.session->respond_body(id,200,{reinterpret_cast<std::byte const*>(body.data()),body.size()})) { f.done=true; co_return; }
            }
            f.response=true; shutdown_phase=1;
        }
        if (!f.multi && !f.pause_multi && f.request && f.ended && !f.response) {
            constexpr std::string_view body="hello h2";
            std::array<h::Header,2> fields{{{"content-type","text/plain"},{"content-length","8"}}};
            auto response=f.head ? f.session->respond_empty(f.request,200,fields) :
                f.session->respond_body(f.request,200,{reinterpret_cast<std::byte const*>(body.data()),body.size()},
                                        f.curl ? std::span<h::Header const>{fields} : std::span<h::Header const>{});
            if (!response) break;
            f.response=true;
        }
        if (f.pause_multi && f.ended && f.response && !f.second_response) {
            constexpr std::string_view body="hello h2";
            if (!f.session->respond_body(f.request,200,{reinterpret_cast<std::byte const*>(body.data()),body.size()})) break;
            f.second_response=true;
        }
        auto result=co_await connection.step(deadline);
        if (!result) {
            auto after=co_await connection.step(deadline);
            f.success=!after && ((f.truncated && result.error()==h::TlsServerError::tls && f.closed_count==1) ||
                                 (f.timeout && result.error()==h::TlsServerError::timeout && !f.request) ||
                                 (f.curl && result.error()==h::TlsServerError::tls && f.closed_count==1) ||
                                 (f.cancel && f.canceled && !f.request));
            break;
        }
        if (*result==h::TlsServerStep::paused) {
            if (f.session->input_memory_charge()!=16384) break;
            if ((f.pause_output || f.pause_multi) && !f.response) {
                constexpr std::string_view body="hello h2";
                if (f.pause_multi && (f.requests.size()!=2 || f.session->paused_stream()!=f.requests[1])) break;
                auto response_id=f.pause_multi ? f.requests[0] : f.request;
                if (!f.session->respond_body(response_id,200,{reinterpret_cast<std::byte const*>(body.data()),body.size()})) break;
                f.response=true;
                auto output=co_await connection.step(deadline);
                if (!output || *output!=h::TlsServerStep::progress || !f.session->paused_stream()) break;
                f.output_during_pause=true;
                continue;
            }
            if (f.pause_multi && (f.closed_count!=1 || f.session->paused_stream()!=f.requests[1])) break;
            if (!f.session->resume_input(f.session->paused_stream())) break;
            continue;
        }
        if (*result==h::TlsServerStep::peer_closed && f.stale) {
            if (!f.session->start_shutdown()) break;
            auto rejected=co_await connection.close_notify(deadline);
            f.success=!rejected && rejected.error()==h::TlsServerError::invalid_state;
            connection.cancel();
            break;
        }
        if (*result==h::TlsServerStep::peer_closed && (f.peer_close || f.curl)) {
            auto close=co_await connection.close_notify(deadline);
            auto duplicate=co_await connection.close_notify(deadline);
            auto after=co_await connection.step(deadline);
            f.success=close.has_value() && !duplicate && !after && f.closed_count==1;
            break;
        }
        if (*result==h::TlsServerStep::drained && f.multi) {
            auto close=co_await connection.close_notify(deadline);
            auto duplicate=co_await connection.close_notify(deadline);
            auto after=co_await connection.step(deadline);
            f.success=close.has_value() && !duplicate && !after && f.closed_count==2;
            break;
        }
        if (*result!=h::TlsServerStep::progress) break;
        if (f.pause_multi && f.closed_count==2) {
            f.success=f.output_during_pause && f.second_response && f.body=="upload" && !f.session->input_memory_charge(); break;
        }
        if (!f.multi && !f.pause_multi && !f.peer_close && !f.truncated && !f.stale && !f.curl && f.closed) { f.success=!f.pause || (f.paused && f.body=="upload" && !f.session->input_memory_charge() && (!f.pause_output || f.output_during_pause)); break; }
    }
    f.done=true;
}
int main(int argc,char** argv) {
    if (argc!=4 && (argc!=5 || (std::string_view(argv[4])!="pause" && std::string_view(argv[4])!="pause_output" && std::string_view(argv[4])!="pause_multi" && std::string_view(argv[4])!="multi" && std::string_view(argv[4])!="peer" && std::string_view(argv[4])!="truncated" && std::string_view(argv[4])!="stale" && std::string_view(argv[4])!="timeout" && std::string_view(argv[4])!="curl" && std::string_view(argv[4])!="cancel" && std::string_view(argv[4])!="head"))) return 1;
    auto fd=::accept4(std::atoi(argv[3]),nullptr,nullptr,SOCK_NONBLOCK | SOCK_CLOEXEC); if (fd<0) return 2;
    Fixture f; f.pause_multi=argc==5 && std::string_view(argv[4])=="pause_multi"; f.pause_output=argc==5 && std::string_view(argv[4])=="pause_output"; f.pause=argc==5 && (std::string_view(argv[4])=="pause" || f.pause_output || f.pause_multi); f.multi=argc==5 && std::string_view(argv[4])=="multi"; f.peer_close=argc==5 && std::string_view(argv[4])=="peer"; f.truncated=argc==5 && std::string_view(argv[4])=="truncated"; f.stale=argc==5 && std::string_view(argv[4])=="stale"; f.timeout=argc==5 && std::string_view(argv[4])=="timeout"; f.head=argc==5 && std::string_view(argv[4])=="head"; f.curl=argc==5 && (std::string_view(argv[4])=="curl" || f.head); f.cancel=argc==5 && std::string_view(argv[4])=="cancel"; if (f.socket.assign(fd)) { ::close(fd); return 3; }
    auto credential=t::ServerCredential::create(file(argv[1]),file(argv[2])); if (!credential) return 4;
    auto now=static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count());
    auto handshake=t::ServerHandshakeIo::create(std::move(*credential),now,now+5000,"h2"); if (!handshake) return 5;
    f.handshake.emplace(std::move(*handshake));
    auto session=h::ServerSession::create({8,16,4096,1024,4096},h::ServerEvents{&f,headers,data,end,closed});
    if (!session) return 6; f.session=std::move(*session);
    capy::run_async(f.context.get_executor())(serve(f)); (void)f.context.run_for(6s);
    if (!f.done) { f.socket.cancel(); f.context.restart(); (void)f.context.run_for(1s); if (!f.done) std::_Exit(90); }
    return f.success ? 0 : 7;
}
