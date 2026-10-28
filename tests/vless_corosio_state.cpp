#include <sys/socket.h>
#include <boost/corosio/backend.hpp>

import std;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;
import nexus.vless;
import nexus.vless.corosio_server;

namespace io=nex::corosio;
namespace capy=nex::capy;
namespace v=nexus::vless;
using namespace std::chrono_literals;
struct Fixture {
#if BOOST_COROSIO_HAVE_LIBURING
    io::io_context context{io::uring};
#else
    io::io_context context;
#endif
    io::local_stream_socket incoming{context}, peer{context};
    std::optional<v::detail::TcpServer<io::local_stream_socket>> server;
    bool done=false, success=false;
};
auto run(Fixture& f, int mode) -> capy::task<> {
    auto request=co_await f.server->read_request();
    if (mode==1 || mode==3) {
        f.success=!request && request.error()==(mode==1 ? v::detail::ServerError::rejected : v::detail::ServerError::io);
        f.done=true; co_return;
    }
    if (!request || request->port!=443) { f.done=true; co_return; }
    auto response=co_await f.server->complete_dial(mode!=2);
    if (mode==2) {
        f.success=!response && response.error()==v::detail::ServerError::rejected;
        f.done=true; co_return;
    }
    if (!response) { f.done=true; co_return; }
    std::array<std::uint8_t,5> payload{};
    auto first=co_await f.server->read(std::span(payload).first(2));
    auto second=co_await f.server->read(std::span(payload).subspan(2));
    f.success=first && *first==2 && second && *second==3 && payload==std::array<std::uint8_t,5>{'h','e','l','l','o'};
    f.done=true;
}
auto scenario(int mode) -> bool {
    Fixture f;
    if (io::connect_pair(f.incoming,f.peer)) return false;
    auto user=v::parse_user_id("00010203-0405-0607-0809-0a0b0c0d0e0f");
    std::array<v::UserId,1> users{*user};
    auto state=v::ServerHandshake::create(users);
    f.server.emplace(f.incoming,std::move(*state));
    if (mode!=3) {
        v::TcpRequest request{*user,v::AddressKind::ipv4,443,{127,0,0,1}};
        if (mode==1) request.user[0]^=1;
        auto input=v::encode_tcp_request(request);
        input->insert(input->end(),{'h','e','l','l','o'});
        if (::send(f.peer.native_handle(),input->data(),input->size(),MSG_NOSIGNAL)!=static_cast<ssize_t>(input->size())) return false;
    }
    capy::run_async(f.context.get_executor())(run(f,mode));
    (void)f.context.run_for(mode==3 ? 30ms : 2s);
    if (!f.done) {
        f.server->cancel(); f.context.restart(); (void)f.context.run_for(2s);
        if (!f.done) std::_Exit(90);
        if (mode!=3) return false;
    }
    std::array<unsigned char,2> response{};
    auto read=::recv(f.peer.native_handle(),response.data(),response.size(),MSG_DONTWAIT);
    if (mode==0 && (read!=2 || response!=std::array<unsigned char,2>{0,0})) return false;
    if (mode!=0 && read>0) return false;
    return f.done && f.success;
}
int main() {
    for (int mode=0;mode<4;++mode) if (!scenario(mode)) return 1+mode;
    std::cout << "VLESS async inbound buffering, denial and cancellation passed\n";
}
