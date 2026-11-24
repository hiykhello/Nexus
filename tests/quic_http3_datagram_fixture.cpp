import std;
import crypto;
import net.datagram_driver;
import quic.tls_client;
import quic.tls_server;
import tls.server_credential;
import capy;
import corosio;
import test.quic_tls_link;
import test.quic_datagram_link;

namespace q=quic;
namespace t=tls;
namespace io = ::corosio;
namespace support=test::quic_tls;
namespace app=test::quic_datagram_link;
using namespace std::chrono_literals;
namespace {
    template<class Tls> auto run(Tls& tls,bool server,bool ipv6,unsigned port,bool uring) -> int {
        io::io_context context=io::make_io_context(uring); io::udp_socket socket(context);
        io::endpoint local=ipv6 ? io::endpoint(io::ipv6_address::loopback(),0) : io::endpoint(io::ipv4_address::loopback(),0);
        io::endpoint remote=ipv6 ? io::endpoint(io::ipv6_address::loopback(),port) : io::endpoint(io::ipv4_address::loopback(),port);
        if (socket.open(local.address().family()) || socket.bind(local)) return 1;
        app::Endpoint endpoint(socket,tls,server,remote);
        if (auto error=endpoint.initialize()) return error;
        typename decltype(endpoint)::Driver driver(socket,endpoint,app::Clock::now()+10s); endpoint.driver=&driver;
        bool done=false,failed=false;
        std::cout<<"READY "<<socket.local_endpoint().port()<<std::endl;
        capy::run_async(context.get_executor(),[&](auto result) { failed=bool(std::get<0>(result)); done=true; },
            [&](std::exception_ptr error) noexcept { try { std::rethrow_exception(error); } catch (std::exception const& error) { std::println("datagram native exception {}",error.what()); } failed=done=true; })(driver.run());
        context.run_for(12s);
        bool clean=endpoint.clean() && driver.drained();
        if (auto error=driver.failure()) std::visit([](auto const& failure) {
            if constexpr (std::same_as<std::remove_cvref_t<decltype(failure)>,int>) std::println("native datagram protocol failure {}",failure);
            else std::println("native datagram driver failure {} system={}",static_cast<int>(failure.code),failure.system.message());
        },*error);
        std::println("HTTP3 datagram driver Nexus {} done={} passed={} clean={} failed={} backend={} authenticated={} input={} DATA={} acknowledged={} sent={} received={} expiry={} QUICpeak={} H3peak={}",server ? "server" : "client",done,endpoint.passed,clean,failed,uring,endpoint.app.authenticated,endpoint.app.input,endpoint.app.payload,endpoint.app.slot(4).acked,endpoint.transmissions,endpoint.received,endpoint.expiries,endpoint.memory.peak,endpoint.app.memory.peak);
        return done && endpoint.passed && clean && !failed ? 0 : 2;
    }
}
auto main(int argc,char** argv) -> int {
    if (argc!=8) { std::println("usage: quic-http3-datagram client|server 4|6 PORT CERT.der KEY.der SCHEME BACKEND"); return 1; }
    try {
        bool server=std::string_view(argv[1])=="server",ipv6=std::string_view(argv[2])=="6",uring=std::string_view(argv[7])=="1";
        auto cert=support::read(argv[4]); auto scheme=static_cast<std::uint16_t>(std::stoul(argv[6],nullptr,0)); auto port=static_cast<unsigned>(std::stoul(argv[3]));
        if (server) {
            auto key=support::read(argv[5]); auto credential=t::ServerCredential::create(cert,key); ::crypto::cleanse(key); if (!credential) return 3;
            q::TlsServer tls(*credential,"h3"); return run(tls,true,ipv6,port,uring);
        }
        q::TlsClient tls(support::hello(scheme),29,support::Pki{cert},"h3"); return run(tls,false,ipv6,port,uring);
    } catch (std::exception const& error) { std::println("datagram fixture exception {}",error.what()); return 99; }
}
