import std;
import tls.client_handshake_io;
import tls.server_handshake_io;
import tls.corosio_client;
import tls.corosio_server_handshake;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;
namespace t=tls;namespace c=nex::capy;namespace io=nex::corosio;
auto client_adapter(io::local_stream_socket& socket,t::ClientHandshakeIo& handshake)
 -> c::task<std::expected<t::detail::AsyncHandshakeResult,t::detail::AsyncHandshakeError>> {
 co_return co_await t::detail::corosio_handshake(socket,handshake);
}
auto server_adapter(io::local_stream_socket& socket,t::ServerHandshakeIo& handshake)
 -> c::task<std::expected<t::detail::ServerAsyncResult,t::detail::ServerAsyncError>> {
 co_return co_await t::detail::server_handshake(socket,handshake);
}
int main() {
 static_assert(t::detail::AsyncHandshakeError::crypto!=t::detail::AsyncHandshakeError::authentication);
 static_assert(t::detail::ServerAsyncError::crypto!=t::detail::ServerAsyncError::protocol);
 std::println("typed asynchronous adapters compiled and linked");
}
