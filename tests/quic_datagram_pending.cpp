import std;
import net.datagram_driver;
import quic.tls_client;
import capy;
import corosio;
import test.quic_tls_link;
import test.quic_datagram_link;

namespace io = ::corosio;
namespace q=quic;
namespace app=test::quic_datagram_link;
namespace support=test::quic_tls;
using namespace std::chrono_literals;
namespace {
    auto hash(std::span<std::uint8_t const> bytes) noexcept -> std::uint64_t {
        std::uint64_t result=1469598103934665603ULL; for (auto byte:bytes) result=(result^byte)*1099511628211ULL; return result;
    }
    // Inject only a prolonged first send await. All other operations go to the
    // same real backend socket; this adapter is test-only, outside production.
    struct HoldSocket {
        io::udp_socket socket;
        capy::async_event release;
        bool first=true,closed=false,sending=false,stable=true;
        std::span<std::uint8_t const> pending;
        std::uint64_t expected=0;
        explicit HoldSocket(io::io_context& context):socket(context) {}
        auto context() noexcept -> auto& { return socket.context(); }
        auto local_endpoint() const -> io::endpoint { return socket.local_endpoint(); }
        auto close() noexcept -> void { closed=true; socket.close(); release.set(); }
        auto recv_from(capy::mutable_buffer bytes,io::endpoint& source) { return socket.recv_from(bytes,source); }
        auto send_to(capy::const_buffer bytes,io::endpoint peer) -> capy::task<capy::results<std::size_t>> {
            sending=true; struct Guard { bool& active; ~Guard() { active=false; } } guard{sending};
            if (std::exchange(first,false)) {
                pending={static_cast<std::uint8_t const*>(bytes.data()),bytes.size()}; expected=hash(pending);
                auto [error]=co_await release.wait(); stable&=hash(pending)==expected;
                if (error || closed) co_return capy::results<std::size_t>{std::make_error_code(std::errc::operation_canceled),0};
            }
            co_return co_await socket.send_to(bytes,peer);
        }
    };
    auto scenario(bool uring) -> int {
        io::io_context context=io::make_io_context(uring); HoldSocket socket(context); io::udp_socket sink(context);
        io::endpoint local(io::ipv4_address::loopback(),0);
        if (socket.socket.open() || socket.socket.bind(local) || sink.open() || sink.bind(local)) return 1;
        q::TlsClient tls(support::hello(0x0804),29,support::Pki{{}},"h3");
        app::Endpoint endpoint(socket,tls,false,sink.local_endpoint()); endpoint.initial_rtt=1000000;
        if (endpoint.initialize()) return 2;
        auto began=app::Clock::now(); typename decltype(endpoint)::Driver driver(socket,endpoint,began+120ms); endpoint.driver=&driver;
        bool checked=false,done=false; unsigned before=0;
        auto control=[&]() -> capy::task<capy::results<>> {
            auto [error]=co_await io::delay(began+60ms); if (error) co_return capy::results<>{error};
            before=endpoint.expiries;
            checked=socket.sending && endpoint.connection.native() && !endpoint.transmissions && endpoint.expiries>=3 && hash(socket.pending)==socket.expected;
            socket.release.set(); co_return capy::results<>{};
        };
        auto execute=[&]() -> capy::task<> { auto [error,run,probe]=co_await capy::when_all(driver.run(),control()); (void)error; (void)run; (void)probe; done=true; };
        capy::run_async(context.get_executor())(execute()); context.run_for(300ms);
        if (!done || !checked || !socket.stable || socket.sending || !endpoint.clean() || !driver.drained() || endpoint.transmissions==0 || !driver.failure() ||
            !std::holds_alternative<net::DatagramFailure>(*driver.failure()) || std::get<net::DatagramFailure>(*driver.failure()).code!=net::DatagramError::deadline) {
            std::println("native pending details done={} checked={} stable={} sending={} clean={} expiry={} before={} sent={} failureindex={}",done,checked,socket.stable,socket.sending,endpoint.clean(),endpoint.expiries,before,endpoint.transmissions,driver.failure() ? static_cast<int>(driver.failure()->index()) : -1); return 3;
        }
        std::println("native QUIC pending send backend={} crossed{} expiries before first fullsend; total sent={} expiry={} bytes stable, deadline120ms exact, final native/keys/TLS=0",uring,before,endpoint.transmissions,endpoint.expiries);
        return 0;
    }
}
auto main() -> int {
    for (bool uring:{false,true}) if (auto error=scenario(uring)) { std::println("native QUIC pending send backend={} failed {}",uring,error); return 1; }
}
