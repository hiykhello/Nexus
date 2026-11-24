import std;
import tls.corosio_application;
import tls.client_handshake_io;
import tls.application_io;
import http.connect;
import capy;
import corosio;
import tls.corosio_client;
import tls.connector;
import platform.socket_options;
import http.corosio_https;
import net.stream_relay;
namespace io = ::corosio; namespace t=tls;
using Bytes=std::vector<std::uint8_t>; using namespace std::chrono_literals;
struct Fixture {
    io::io_context context=io::make_io_context(io::has_uring && !std::getenv("NEXUS_TEST_EPOLL"));
 std::optional<t::ClientHandshakeIo> handshake; std::uint16_t port; bool done=false, success=false, authentication_failed=false, require_alpn=true, reject_output=false;
    std::optional<http::detail::HttpsError> exchange_error;
    std::string_view response_case;
    ~Fixture() { context.restart(); (void)context.run_for(1s); if (!context.stopped()) std::_Exit(1); }
};
auto now_ms() -> std::uint64_t { return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count()); }
template<class Client>
auto exchange(Fixture& f,Client& client) -> capy::task<> {
    if (!client.application() || !client.negotiated()) { f.done=true; co_return; }
    auto& connection=*client.application();
    auto deadline=std::chrono::steady_clock::now()+10s;
    if (!co_await connection.key_update(true,deadline)) { f.done=true; co_return; }
    std::string request="GET / HTTP/1.0\r\nHost: server.example\r\nX-Padding: "+std::string(20000,'a')+"\r\n\r\n";
    bool final_header=false; std::size_t bytes=0; std::string body;
    auto output=[&](http::ResponseStep const& step) {
        if (step.event==http::ResponseEvent::header && !step.informational) final_header=step.wire.starts_with(f.response_case.empty() ? "HTTP/1.0 200 ok" : f.response_case=="empty" ? "HTTP/1.1 204 No Content" : "HTTP/1.1 200 OK");
        if (step.event==http::ResponseEvent::data || step.event==http::ResponseEvent::complete) { bytes+=step.wire.size(); if (!f.response_case.empty()) body+=step.wire; }
        return !f.reject_output && bytes<=1048576;
    };
    auto result=co_await http::detail::https_exchange(client,request,false,output,deadline,!f.require_alpn);
    if (!result && connection.idle() && !connection.active()) f.exchange_error=result.error();
    auto expected=f.response_case=="fixed" ? "hello" : f.response_case=="chunked" ? "3\r\nabc\r\n0\r\n\r\n" : "";
    f.success=result && connection.idle() && final_header && (bytes>0 || f.response_case=="empty") && (f.response_case.empty() || body==expected);
    if (!f.success) std::cerr << "HTTPS exchange failed, error=" << (result ? -1 : static_cast<int>(result.error())) << " bytes=" << bytes << "\n"; f.done=true;
}
struct FramedTransport {
    io::tcp_socket& socket;
    unsigned reads=0,writes=0;
    auto read(std::span<std::uint8_t> bytes) -> capy::task<std::expected<std::size_t,std::string>> {
        ++reads;
        auto [error,n]=co_await socket.read_some(capy::mutable_buffer(bytes.data(),std::min(bytes.size(),std::size_t{113})));
        if (capy::is_eof(error)) co_return 0;
        if (error) co_return std::unexpected(error.message());
        co_return n;
    }
    auto send(std::span<std::uint8_t const> bytes) -> capy::task<bool> {
        ++writes;
        while (!bytes.empty()) {
            auto [error,n]=co_await socket.write_some(capy::const_buffer(bytes.data(),std::min(bytes.size(),std::size_t{127})));
            if (error || !n || n>bytes.size()) co_return false;
            bytes=bytes.subspan(n);
        }
        co_return true;
    }
    auto close_output() -> capy::task<bool> { co_return !socket.shutdown(io::shutdown_send); }
    auto cancel() noexcept -> void { socket.cancel(); }
};
struct FastOpenResolver {
    io::endpoint endpoint;
    auto cancel() noexcept -> void {}
    auto operator()(std::chrono::steady_clock::time_point) -> capy::task<std::optional<std::vector<io::endpoint>>> {
        std::vector<io::endpoint> endpoints{endpoint};
        if (auto second=std::getenv("NEXUS_TEST_FAST_OPEN_SECOND_PORT"))
            endpoints.emplace_back(io::ipv4_address::loopback(),static_cast<std::uint16_t>(std::strtoul(second,nullptr,10)));
        co_return endpoints;
    }
};
struct FastOpenProfile {
    mutable std::optional<t::ClientHandshakeIo> pending;
    auto handshake(std::uint64_t,std::uint64_t,std::int64_t) const -> std::optional<t::ClientHandshakeIo> {
        return std::move(pending);
    }
};
auto run(Fixture& f) -> capy::task<> {
    auto endpoint=io::endpoint(io::ipv4_address::loopback(),f.port);
    if (std::getenv("NEXUS_TEST_FAST_OPEN")) {
        auto deadline=std::chrono::steady_clock::time_point(std::chrono::milliseconds(f.handshake->deadline()));
        FastOpenProfile profile{std::move(f.handshake)};
        ::platform::TcpSocketOptions options;
        t::detail::FastOpenPhysicalConnector client(f.context,FastOpenResolver{endpoint},profile,options);
        t::detail::ConnectResult started;
        if (std::getenv("NEXUS_TEST_FAST_OPEN_CANCEL")) {
            auto start=[&]() -> capy::task<capy::results<t::detail::ConnectResult>> {
                co_return capy::results<t::detail::ConnectResult>{std::error_code{},co_await client.start(deadline)};
            };
            auto cancel=[&]() -> capy::task<capy::results<>> {
                io::steady_timer timer(f.context);timer.expires_at(std::chrono::steady_clock::now()+100ms);
                auto [error]=co_await timer.wait();if (!error) client.cancel();co_return capy::results<>{error};
            };
            auto [error,result,ignored]=co_await capy::when_all(start(),cancel());(void)error;(void)ignored;started=result;
        } else started=co_await client.start(deadline);
        if (std::getenv("NEXUS_TEST_FAST_OPEN_EXPECT_FAILURE")) {
            f.done=true;f.success=started==t::detail::ConnectResult::failed;co_return;
        }
        if (std::getenv("NEXUS_TEST_FAST_OPEN_EXPECT_TIMEOUT")) {
            f.done=true;f.success=started==t::detail::ConnectResult::timeout;co_return;
        }
        if (started!=t::detail::ConnectResult::connected) { f.done=true; co_return; }
        co_await exchange(f,*client.client());
    } else if (std::getenv("NEXUS_TEST_BYTE_STREAM_ADAPTER")) {
        io::tcp_socket socket(f.context);
        auto [error]=co_await socket.connect(endpoint);
        if (error) { f.done=true; co_return; }
        FramedTransport transport{socket}; net::ByteStreamAdapter stream(transport);
        t::detail::ClientConnection client(stream,std::move(*f.handshake)); f.handshake.reset();
        auto started=co_await client.start();
        if (!started) { f.authentication_failed=started.error()==t::detail::AsyncHandshakeError::authentication; f.done=true; co_return; }
        co_await exchange(f,client);
        if (!transport.reads || !transport.writes) f.success=false;
    } else {
        t::detail::OwnedClient owner(f.context,std::move(*f.handshake)); f.handshake.reset();
        auto started=co_await owner.start(endpoint);
        if (!started) { f.authentication_failed=started.error()==t::detail::AsyncHandshakeError::authentication; std::cerr << "TLS handshake error=" << static_cast<int>(started.error()) << '\n'; f.done=true; co_return; }
        co_await exchange(f,*owner.client());
    }
}
int main(int argc,char** argv) {
    if (argc<4 || argc>6 || (argc==6 && std::string_view(argv[5])!="sni-test" && std::string_view(argv[5])!="alpn-required" && std::string_view(argv[5])!="reject-output" && std::string_view(argv[5])!="fixed" && std::string_view(argv[5])!="chunked" && std::string_view(argv[5])!="empty" && std::string_view(argv[5])!="truncated" && std::string_view(argv[5])!="malformed")) return 1; auto port=std::strtoul(argv[1],nullptr,10); if (!port || port>65535) return 2;
    auto roots=t::load_trust_bundle(argv[2]); if (!roots) return 3;
    bool hybrid=std::string_view(argv[3])=="hybrid"; auto group=hybrid ? t::x25519_mlkem768_group : std::uint16_t{0x001d};
    std::array<std::string_view,1> protocols{"http/1.1"}; std::array<std::uint16_t,1> groups{group};
    std::string_view host=argc>=5 ? argv[4] : "server.example";
    bool ip=host=="127.0.0.1" || host=="127.0.0.2";
    auto hello=t::make_client_hello(ip ? std::optional<std::string_view>{} : std::optional<std::string_view>{"server.example"},protocols,groups); if (!hello) return 4;
    std::array<std::uint8_t,4> address{127,0,0,static_cast<std::uint8_t>(host=="127.0.0.2" ? 2 : 1)};
    auto name=ip ? std::span<std::uint8_t const>{address} : std::span{reinterpret_cast<std::uint8_t const*>(host.data()),host.size()};
    auto seconds=std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    t::ClientTlsConfig config{std::move(*hello),{},Bytes(name.begin(),name.end()),ip ? t::PeerNameKind::ip : t::PeerNameKind::dns,seconds,0};
    for (auto const& anchor:*roots) config.trust_anchors.emplace_back(anchor);
    auto session=t::ClientSessionHandshake::create(std::move(config)); if (!session) return 5;
    auto now=now_ms(); auto handshake=t::ClientHandshakeIo::create(std::move(*session),now,now+(std::getenv("NEXUS_TEST_FAST_OPEN_EXPECT_TIMEOUT") ? 500 : 10000)); if (!handshake) return 6;
    Fixture f; f.port=static_cast<std::uint16_t>(port); f.require_alpn=argc!=6 || std::string_view(argv[5])!="sni-test"; f.reject_output=argc==6 && std::string_view(argv[5])=="reject-output";
    if (argc==6 && (std::string_view(argv[5])=="fixed" || std::string_view(argv[5])=="chunked" || std::string_view(argv[5])=="empty" || std::string_view(argv[5])=="truncated" || std::string_view(argv[5])=="malformed")) f.response_case=argv[5];
    f.handshake=std::move(*handshake); capy::run_async(f.context.get_executor())(run(f));
    (void)f.context.run_for(10s); if (f.authentication_failed) return 8;
    if (f.exchange_error==http::detail::HttpsError::output_rejected) return 9;
    if (f.exchange_error==http::detail::HttpsError::alpn) return 10;
    if (f.exchange_error==http::detail::HttpsError::truncated) return 11;
    if (f.exchange_error==http::detail::HttpsError::malformed) return 12;
    if (!f.done || !f.success) return 7;
    std::cout << "Corosio TLS 1.3 " << argv[3] << " forced retry and HTTP passed\n";
}
