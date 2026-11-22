import std;
import net.stream_relay;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;
import tls.client_handshake_io;
import tls.corosio_client;

namespace capy=nex::capy;
namespace io=nex::corosio;
using namespace std::chrono_literals;

struct Transport {
    io::local_stream_socket& socket;
    unsigned reads=0,writes=0,closes=0,cancels=0;
    bool fail_read=false,fail_write=false;
    auto read(std::span<std::uint8_t> bytes) -> capy::task<std::expected<std::size_t,std::string>> {
        ++reads; if (fail_read) co_return std::unexpected("read failure");
        auto [error,n]=co_await socket.read_some(capy::mutable_buffer(bytes.data(),bytes.size()));
        if (capy::is_eof(error)) co_return 0;
        if (error) co_return std::unexpected(error.message());
        co_return n;
    }
    auto send(std::span<std::uint8_t const> bytes) -> capy::task<bool> {
        ++writes;
        if (fail_write) co_return false;
        while (!bytes.empty()) {
            auto [error,n]=co_await socket.write_some(capy::const_buffer(bytes.data(),bytes.size()));
            if (error || !n || n>bytes.size()) co_return false;
            bytes=bytes.subspan(n);
        }
        co_return true;
    }
    auto close_output() -> capy::task<bool> { ++closes; co_return !socket.shutdown(io::shutdown_send); }
    auto cancel() noexcept -> void { ++cancels; socket.cancel(); }
};

struct Fixture {
    io::io_context context;
    io::local_stream_socket client{context}, peer{context};
    Transport transport{client}; net::ByteStreamAdapter<Transport> stream{transport};
    bool done=false,ok=false;
    explicit Fixture(bool uring) : context(io::make_io_context(uring)) {}
    ~Fixture() { client.close(); peer.close(); context.restart(); (void)context.run_for(1s); }
};

auto exchange(Fixture& f) -> capy::task<> {
    std::array<std::uint8_t,8> buffer{};
    auto [empty_error,empty_count]=co_await f.stream.write_some(capy::const_buffer(nullptr,0));
    auto [empty_read_error,empty_read_count]=co_await f.stream.read_some(capy::mutable_buffer(nullptr,0));
    if (empty_error || empty_count || empty_read_error || empty_read_count || f.transport.writes || f.transport.reads) { f.done=true; co_return; }
    std::array<std::uint8_t,3> outgoing{1,2,3};
    auto [write_error,written]=co_await f.stream.write_some(capy::const_buffer(outgoing.data(),outgoing.size()));
    auto [read_error,received]=co_await f.peer.read_some(capy::mutable_buffer(buffer.data(),buffer.size()));
    if (write_error || written!=3 || read_error || received!=3 || !std::equal(outgoing.begin(),outgoing.end(),buffer.begin())) { f.done=true; co_return; }
    if (!co_await f.stream.close_output()) { f.done=true; co_return; }
    auto [end_error,end_count]=co_await f.peer.read_some(capy::mutable_buffer(buffer.data(),buffer.size()));
    if (!capy::is_eof(end_error) && (end_error || end_count)) { f.done=true; co_return; }
    auto [peer_error,peer_count]=co_await f.peer.write_some(capy::const_buffer(outgoing.data(),outgoing.size()));
    auto [reply_error,reply_count]=co_await f.stream.read_some(capy::mutable_buffer(buffer.data(),buffer.size()));
    if (peer_error || peer_count!=3 || reply_error || reply_count!=3 || !std::equal(outgoing.begin(),outgoing.end(),buffer.begin())) { f.done=true; co_return; }
    auto [timeout,count]=co_await io::timeout(f.stream.read_some(capy::mutable_buffer(buffer.data(),buffer.size())),std::chrono::steady_clock::now()+50ms);
    f.ok=capy::is_timeout(timeout) && count==0 && f.transport.closes==1 && f.transport.writes==1;
    if (!f.ok) std::cerr << "timeout=" << timeout.message() << " count=" << count << " closes=" << f.transport.closes << " writes=" << f.transport.writes << '\n';
    f.done=true;
}

auto failures(Fixture& f) -> capy::task<> {
    std::array<std::uint8_t,1> bytes{1};
    f.transport.fail_read=true; f.transport.fail_write=true;
    auto [read_error,read_count]=co_await f.stream.read_some(capy::mutable_buffer(bytes.data(),bytes.size()));
    auto [write_error,write_count]=co_await f.stream.write_some(capy::const_buffer(bytes.data(),bytes.size()));
    f.ok=read_error==std::errc::io_error && write_error==std::errc::io_error && !read_count && !write_count;
    f.done=true;
}

auto handshake(Fixture& f,tls::ClientHandshakeIo&& handshake) -> capy::task<> {
    tls::detail::ClientConnection<net::ByteStreamAdapter<Transport>> client(f.stream,std::move(handshake));
    auto result=co_await client.start();
    f.ok=!result && result.error()==tls::detail::AsyncHandshakeError::timeout && client.idle();
    f.done=true;
}

auto run(bool uring) -> int {
    {
        Fixture f(uring); if (io::connect_pair(f.client,f.peer)) return 1;
        capy::run_async(f.context.get_executor())(exchange(f)); (void)f.context.run_for(2s);
        if (!f.done || !f.ok) return 2;
    }
    {
        Fixture f(uring); if (io::connect_pair(f.client,f.peer)) return 3;
        tls::ClientHello hello; hello.cipher_suites={0x1301}; hello.compression_methods={0};
        hello.extensions={{43,{2,3,4}},{10,{0,2,0,0x1d}},{51,{0,0}}};
        std::array<std::uint8_t,1> root{1}, name{'a'}; std::array<std::span<std::uint8_t const>,1> anchors{root};
        auto session=tls::ClientSessionHandshake::create(std::move(hello),0,anchors,tls::PeerNameKind::dns,name,0);
        if (!session) return 4;
        auto now=std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count();
        auto io=tls::ClientHandshakeIo::create(std::move(*session),now,now+150);
        if (!io) return 5;
        capy::run_async(f.context.get_executor())(handshake(f,std::move(*io))); (void)f.context.run_for(2s);
        if (!f.done || !f.ok || !f.transport.reads || !f.transport.writes) return 6;
    }
    {
        Fixture f(uring); if (io::connect_pair(f.client,f.peer)) return 7;
        capy::run_async(f.context.get_executor())(failures(f)); (void)f.context.run_for(2s);
        if (!f.done || !f.ok) return 8;
    }
    return 0;
}
int main() {
    if (auto result=run(false)) return result;
    if (io::has_uring) if (auto result=run(true)) return result;
    std::cout << "framed byte stream adapter, half-close and TLS timeout passed\n";
}
