import std;
import crypto;
import net.datagram_driver;
import quic.tls_client;
import quic.tls_server;
import tls.server_credential;
import capy;
import corosio;
import ngtcp2;
import test.quic_tls_link;
import test.quic_datagram_link;

namespace io = ::corosio;
namespace q=quic;
namespace t=tls;
namespace support=test::quic_tls;
namespace app=test::quic_datagram_link;
using namespace std::chrono_literals;
namespace {
    template<class Driver,class Condition> auto wait(Driver& driver,Condition condition) -> capy::task<bool> {
        while (!condition()) {
            driver.changed().clear();
            auto [error]=co_await driver.changed().wait();
            if (error) co_return false;
        }
        co_return true;
    }
    auto canceled(auto const& driver) -> bool {
        return driver.failure() && std::holds_alternative<net::DatagramFailure>(*driver.failure()) &&
            std::get<net::DatagramFailure>(*driver.failure()).code==net::DatagramError::canceled;
    }
    template<class Client,class Server,class ClientDriver,class ServerDriver>
    auto control(Client& client,Server& server,ClientDriver& client_driver,ServerDriver& server_driver,unsigned mode,bool& checked) -> capy::task<capy::results<>> {
        if (mode==0) co_return capy::results<>{};
        if (mode==1 || mode==2 || mode==5) {
            if (!co_await wait(server_driver,[&] { return server.app.authenticated || server_driver.drained(); })) co_return capy::results<>{std::make_error_code(std::errc::io_error)};
            if (!server.app.authenticated || !server.connection.native() || !server.app.http3.native() || !server.app.refs_valid()) co_return capy::results<>{std::make_error_code(std::errc::io_error)};
            if (mode==1) {
                server.app.http3.stop();
                checked=server.app.stop_requested && !server.app.http3.active() && server.app.http3.native() && server.connection.native() && server.app.refs_valid();
                server_driver.finish();
            } else if (mode==2) { server_driver.finish(); checked=true; }
            else { server_driver.cancel(); checked=true; }
        }
        if (!co_await wait(server_driver,[&] { return server_driver.drained(); })) co_return capy::results<>{std::make_error_code(std::errc::io_error)};
        if (mode==3 || mode==4) checked=server.app.acted==1 && !server.app.broken && server.clean();
        client_driver.finish();
        co_return capy::results<>{};
    }
    auto pair(t::ServerCredential const& credential,std::span<std::uint8_t const> anchor,bool uring,unsigned mode) -> int {
        io::io_context context=io::make_io_context(uring);
        io::udp_socket client_socket(context),server_socket(context);
        io::endpoint loopback(io::ipv4_address::loopback(),0);
        if (client_socket.open() || client_socket.bind(loopback) || server_socket.open() || server_socket.bind(loopback)) return 1;
        q::TlsClient client_tls(support::hello(*credential.scheme()),29,support::Pki{anchor},"h3"); q::TlsServer server_tls(credential,"h3");
        app::Endpoint client(client_socket,client_tls,false,server_socket.local_endpoint()); app::Endpoint server(server_socket,server_tls,true,client_socket.local_endpoint());
        client.wait_peer_close=true;
        if (client.initialize() || server.initialize()) return 2;
        auto deadline=app::Clock::now()+2s;
        typename decltype(client)::Driver client_driver(client_socket,client,deadline); typename decltype(server)::Driver server_driver(server_socket,server,deadline);
        client.driver=&client_driver; server.driver=&server_driver;
        server.app.action=mode==3 || mode==4 ? mode : 0; server.app.stop_stream=4;
        bool done=false,checked=mode==0,failed=false;
        auto execute=[&]() -> capy::task<> {
            auto [error,c,s,application]=co_await capy::when_all(client_driver.run(),server_driver.run(),control(client,server,client_driver,server_driver,mode,checked));
            (void)c; (void)s; (void)application; failed=bool(error); done=true;
        };
        capy::run_async(context.get_executor())(execute()); context.run_for(2500ms);
        if (!done || !checked || !client_driver.drained() || !server_driver.drained() || !client.clean() || !server.clean() || client.app.quic_closed!=1 || server.app.quic_closed!=1 || server.app.http3_closed!=1) return 3;
        if (mode==0 ? failed || !client.passed || !server.passed || client_driver.failure() || server_driver.failure() : mode==5 ? !canceled(server_driver) : server_driver.failure().has_value()) {
            std::println("driver native pair details mode={} failed={} clientpass={} serverpass={} clientfailure={} serverfailure={}",mode,failed,client.passed,server.passed,client_driver.failure().has_value(),server_driver.failure().has_value()); return 4;
        }
        std::println("driver native pair backend={} mode={} clean; serverQUIC={} H3={} closed={}/{} acted={}",uring,mode,server.memory.peak,server.app.memory.peak,server.app.quic_closed,server.app.http3_closed,server.app.acted);
        return 0;
    }
    auto blackhole(t::ServerCredential const& credential,std::span<std::uint8_t const> anchor,bool uring) -> int {
        io::io_context context=io::make_io_context(uring); io::udp_socket socket(context),sink(context);
        io::endpoint local(io::ipv4_address::loopback(),0);
        if (socket.open() || socket.bind(local) || sink.open() || sink.bind(local)) return 1;
        q::TlsClient tls(support::hello(*credential.scheme()),29,support::Pki{anchor},"h3");
        app::Endpoint endpoint(socket,tls,false,sink.local_endpoint()); if (endpoint.initialize()) return 2;
        auto began=app::Clock::now(); typename decltype(endpoint)::Driver driver(socket,endpoint,began+70ms); endpoint.driver=&driver;
        bool done=false; capy::run_async(context.get_executor(),[&](auto) { done=true; })(driver.run()); context.run_for(300ms);
        auto elapsed=app::Clock::now()-began;
        if (!done || !driver.drained() || !endpoint.clean() || endpoint.app.completed || !driver.failure() || !std::holds_alternative<net::DatagramFailure>(*driver.failure()) ||
            std::get<net::DatagramFailure>(*driver.failure()).code!=net::DatagramError::deadline || elapsed<65ms || elapsed>150ms) return 3;
        std::println("driver native blackhole backend={} elapsed={}ms clean; auth=0",uring,std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count());
        return 0;
    }
    auto late_initial(t::ServerCredential const& credential,std::span<std::uint8_t const> anchor,bool uring) -> int {
        io::io_context context=io::make_io_context(uring); io::udp_socket client_socket(context),server_socket(context);
        io::endpoint local(io::ipv4_address::loopback(),0);
        if (client_socket.open() || client_socket.bind(local) || server_socket.open() || server_socket.bind(local)) return 1;
        q::TlsClient client_tls(support::hello(*credential.scheme()),29,support::Pki{anchor},"h3"); q::TlsServer server_tls(credential,"h3");
        app::Endpoint client(client_socket,client_tls,false,server_socket.local_endpoint()); app::Endpoint server(server_socket,server_tls,true,client_socket.local_endpoint());
        if (client.initialize()) return 2;
        std::array<std::uint8_t,1500> initial{};
        auto written=client.connection.write_packet(initial,nullptr,nullptr,app::time(app::Clock::now())); if (!written || !*written) return 3;
        auto began=app::Clock::now(); typename decltype(server)::Driver driver(server_socket,server,began+70ms); server.driver=&driver;
        bool done=false; unsigned sent=0;
        auto send=[&]() -> capy::task<capy::results<>> {
            auto [error]=co_await io::delay(began+50ms); if (error) co_return capy::results<>{error};
            for (unsigned i=0;i<4;++i) {
                auto [error,size]=co_await client_socket.send_to(capy::const_buffer(initial.data(),*written),server_socket.local_endpoint());
                if (error || size!=*written) co_return capy::results<>{std::make_error_code(std::errc::io_error)};
                ++sent; auto [delay]=co_await io::delay(4ms); if (delay) break;
            }
            co_return capy::results<>{};
        };
        auto execute=[&]() -> capy::task<> { auto [error,run,output]=co_await capy::when_all(driver.run(),send()); (void)error; (void)run; (void)output; done=true; };
        capy::run_async(context.get_executor())(execute()); context.run_for(300ms); auto elapsed=app::Clock::now()-began;
        client.stop(); client.drain();
        if (!done || sent<3 || server.received<3 || !driver.drained() || !server.clean() || !client.clean() || server.app.completed || !driver.failure() ||
            !std::holds_alternative<net::DatagramFailure>(*driver.failure()) || std::get<net::DatagramFailure>(*driver.failure()).code!=net::DatagramError::deadline || elapsed<65ms || elapsed>150ms) return 4;
        std::println("driver native late valid Initial backend={} elapsed={}ms sent={} received={} clean; auth=0",uring,std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count(),sent,server.received);
        return 0;
    }
}
auto main(int argc,char** argv) -> int {
    if (argc!=3) return 1;
    try {
        auto cert=support::read(argv[1]),key=support::read(argv[2]); auto credential=t::ServerCredential::create(cert,key); ::crypto::cleanse(key); if (!credential) return 2;
        for (bool uring:{false,true}) {
            for (unsigned mode=0;mode<6;++mode) if (auto error=pair(*credential,cert,uring,mode)) { std::println("driver native pair backend={} mode={} failed {}",uring,mode,error); return 3; }
            if (auto error=blackhole(*credential,cert,uring)) { std::println("driver native blackhole backend={} failed {}",uring,error); return 4; }
            if (auto error=late_initial(*credential,cert,uring)) { std::println("driver native late Initial backend={} failed {}",uring,error); return 5; }
        }
        std::println("actual TLS/QUIC/H3 UDP driver16 lifecycle cases passed, including native callback stop and exact absolute deadline; unique native close after joined I/O");
    } catch (std::exception const& error) { std::println("driver native lifecycle exception {}",error.what()); return 99; }
}
