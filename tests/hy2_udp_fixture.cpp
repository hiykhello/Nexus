import std;
import crypto;
import hysteria2.application;
import hysteria2.auth;
import hysteria2.stream_state;
import hysteria2.wire;
import hysteria2.udp_transmitter;
import hysteria2.udp_receiver;
import hysteria2.fragments;
import hysteria2.sessions;
import net.datagram_driver;
import quic.connection;
import quic.tls_client;
import quic.tls_server;
import tls.server_credential;
import nexus.thirdparty.ngtcp2;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;
import nexus.test.quic_tls_link;
import nexus.test.quic_datagram_link;

namespace n=nex::ngtcp2;
namespace q=quic;
namespace h=hysteria2;
namespace io=nex::corosio;
namespace capy=nex::capy;
namespace support=nexus::test::quic_tls;
namespace udp=nexus::test::quic_datagram_link;
using namespace std::chrono_literals;
using Clock=std::chrono::steady_clock;
std::string_view target_address="target.example:443";
bool paired=true;

struct Observer {
    unsigned created=0,closed=0;
    auto session_created(h::UdpSessionHandle,std::uint32_t) noexcept -> bool {++created;return true;}
    auto session_closed(h::UdpSessionHandle,std::uint32_t) noexcept -> void {++closed;}
};
struct Hooks {
    capy::async_event work;
    Observer observer;
    h::UdpReceiver<Observer,4,4> incoming;
    h::UdpTransmitter outgoing;
    unsigned packets=0;
    explicit Hooks(bool server):incoming(observer,server,5s,1024*1024,200ms){}
    auto changed() noexcept -> void { work.set(); }
    auto authenticate(h::ClientAuthView auth) noexcept -> bool { return ::crypto::constant_time_equal(support::bytes(auth.credential),support::bytes("test-password")); }
    auto datagram(std::span<std::uint8_t const> bytes) noexcept -> int {
        ++packets;auto status=incoming.receive(bytes,Clock::now());
        if(status==h::ReassemblyStatus::accepted)work.set();
        return status==h::ReassemblyStatus::allocation_failed ? n::err_nomem : 0;
    }
    auto datagram_output() noexcept {return outgoing.pending();}
    auto datagram_accepted() noexcept -> void {(void)outgoing.accepted();work.set();}
};
template<class Tls> struct Endpoint {
    using Failure=int;
    using App=h::Application<Tls,Hooks,4,16384>;
    using Driver=net::DatagramDriver<Endpoint>;
    io::udp_socket& socket;
    Tls& tls;
    Hooks hooks;
    support::Memory memory,h3memory;
    App app;
    q::Connection<Tls,App> connection;
    udp::Path path;
    io::endpoint local,remote;
    Driver* driver=nullptr;
    bool server,started=false,stopping=false,passed=false,close_pending=false;
    std::uint64_t token=0;
    unsigned sent=0,received=0;
    Endpoint(io::udp_socket& socket,Tls& tls,bool server,io::endpoint remote)
        :socket(socket),tls(tls),hooks(server),app(tls,hooks,server,h3memory.http3(),"test-password",{true,true,0}),connection(tls,app),local(socket.local_endpoint()),remote(remote),server(server) { app.attach(connection); }
    ~Endpoint() { stop(); drain(); }
    auto start(n::ngtcp2_cid const& destination,n::ngtcp2_cid const& source,n::ngtcp2_transport_params parameters,Clock::time_point now) -> int {
        path.assign(local,remote); auto settings=support::settings(); settings.initial_ts=udp::time(now);
        parameters.initial_max_stream_data_bidi_local=parameters.initial_max_stream_data_bidi_remote=16384;
        parameters.initial_max_streams_bidi=4;parameters.max_datagram_frame_size=65535;
        auto error=connection.start(server,destination,source,path.value,settings,parameters,memory.transport()); started=!error; return error;
    }
    auto initialize() -> int { return server ? 0 : start(udp::random_cid(),udp::random_cid(),support::parameters(false),Clock::now()); }
    auto request_stop() noexcept -> void { stopping=true;app.request_stop();hooks.outgoing.cancel();hooks.incoming.close();hooks.work.set(); }
    auto stop() noexcept -> void { app.joined(); connection.stop(); }
    auto drain() noexcept -> void { app.drain(); }
    auto next_expiry() const noexcept -> net::DatagramDeadline {
        auto next=connection.expiry();auto udp=hooks.incoming.expiry();
        if(!next || *next==std::numeric_limits<std::uint64_t>::max())return udp;
        auto quic=Clock::time_point(std::chrono::nanoseconds(*next));return udp?std::min(*udp,quic):quic;
    }
    auto expire(Clock::time_point now) -> std::expected<void,int> {
        if(!hooks.incoming.expire(now))return std::unexpected(n::err_callback_failure);
        auto next=connection.expiry();auto error=next && *next<=udp::time(now) ? connection.expire(udp::time(now)) : 0;return error ? std::expected<void,int>(std::unexpected(error)) : std::expected<void,int>{};
    }
    auto receive(io::endpoint const& source,std::span<std::uint8_t const> bytes,Clock::time_point now) -> std::expected<void,int> {
        if (!started) {
            n::ngtcp2_pkt_hd first{}; if (n::ngtcp2_accept(&first,bytes.data(),bytes.size()) || first.version!=1) return {};
            remote=source; auto parameters=support::parameters(true); parameters.original_dcid=first.dcid;
            if (auto error=start(first.scid,udp::random_cid(),parameters,now)) return std::unexpected(error);
        }
        if (source!=remote || close_pending) return {};
        ++received; app.time(udp::time(now)); auto error=connection.read(path.value,nullptr,bytes,udp::time(now));
        if (error==n::err_draining && passed) { driver->finish(); return {}; }
        return error ? std::expected<void,int>(std::unexpected(error)) : std::expected<void,int>{};
    }
    auto output(std::span<std::uint8_t> bytes,Clock::time_point now) -> std::expected<std::optional<net::DatagramOutput>,int> {
        if (!started || stopping) return std::optional<net::DatagramOutput>{};
        if(server && passed){
            n::ngtcp2_ccerr close{};n::ngtcp2_ccerr_default(&close);n::ngtcp2_ccerr_set_application_error(&close,0,nullptr,0);
            auto written=connection.write_close(bytes,nullptr,nullptr,close,udp::time(now));if(!written)return std::unexpected(written.error());
            if(!*written)return std::optional<net::DatagramOutput>{};close_pending=true;return net::DatagramOutput{remote,*written,++token};
        }
        auto written=app.output(bytes,udp::time(now)); if (!written) return std::unexpected(written.error());
        if (!*written) return std::optional<net::DatagramOutput>{};
        return net::DatagramOutput{remote,*written,++token};
    }
    auto transmitted(std::uint64_t current,Clock::time_point now) -> std::expected<void,int> {
        if (current!=token || !connection.native()) return std::unexpected(n::err_callback_failure);
        n::ngtcp2_conn_update_pkt_tx_time(connection.native(),udp::time(now)); ++sent;hooks.work.set();if(close_pending)driver->finish();return {};
    }
    auto wait() -> capy::task<bool> {
        if (stopping) co_return false;
        hooks.work.clear(); auto [error]=co_await io::timeout(hooks.work.wait(),Clock::now()+8s);
        co_return !error && !stopping;
    }
    auto business(std::size_t total) -> capy::task<capy::results<>> {
        while(!app.authenticated())if(!co_await wait())co_return capy::results<>{std::make_error_code(std::errc::io_error)};
        std::array<std::uint8_t,65000> bytes{};if(total>bytes.size())co_return capy::results<>{std::make_error_code(std::errc::message_size)};
        for(std::size_t i=0;i<total;++i)bytes[i]=static_cast<std::uint8_t>(i*71+37);
        auto transmit=[&](std::uint32_t session,std::uint16_t packet,std::string_view address,std::span<std::uint8_t const> input) -> capy::task<bool>{
            auto count=sent;auto submitted=hooks.outgoing.submit(session,packet,address,input,app.datagram_budget());if(!submitted)co_return false;
            driver->notify();
            while(!*hooks.outgoing.done(*submitted) || sent==count)if(!co_await wait())co_return false;
            co_return true;
        };
        if(!server){
            if(!hooks.incoming.open(0,Clock::now()) || !co_await transmit(0,0xffff,target_address,std::span(bytes).first(total)))co_return capy::results<>{std::make_error_code(std::errc::io_error)};
        }
        while(!hooks.incoming.packet(Clock::now()))if(!co_await wait())co_return capy::results<>{std::make_error_code(std::errc::io_error)};
        auto packet=*hooks.incoming.packet(Clock::now());
        if(packet.session!=0 || packet.address!=target_address || !std::ranges::equal(packet.payload,std::span(bytes).first(total)))co_return capy::results<>{std::make_error_code(std::errc::bad_message)};
        if(server && !co_await transmit(packet.session,1,packet.address,packet.payload))co_return capy::results<>{std::make_error_code(std::errc::io_error)};
        hooks.incoming.consume();
        if(server){
            // Application confirmation proves the response was delivered;
            // closing after DATAGRAM acceptance alone races Go's consumer.
            while(!hooks.incoming.packet(Clock::now()))if(!co_await wait())co_return capy::results<>{std::make_error_code(std::errc::io_error)};
            auto confirm=*hooks.incoming.packet(Clock::now());if(confirm.session!=0 || confirm.address!=target_address || confirm.payload.size()!=1 || confirm.payload[0]!=0xa5)co_return capy::results<>{std::make_error_code(std::errc::bad_message)};
            hooks.incoming.consume();
        }else{
            std::array<std::uint8_t,1> confirm{0xa5};if(!co_await transmit(0,2,target_address,confirm))co_return capy::results<>{std::make_error_code(std::errc::io_error)};
        }
        passed=true;
        std::println("Hy2 UDP application {} payload={} DATAGRAMs={} sessions={} receiver={} sender={} app={}",server?"server":"client",total,hooks.packets,hooks.incoming.size(),sizeof(hooks.incoming),sizeof(hooks.outgoing),sizeof(App));
        if(!paired && !server)driver->finish();else{driver->notify();while(driver->running())if(!co_await wait())break;}
        co_return capy::results<>{};
    }
    auto all(std::size_t total) -> capy::task<capy::results<>> {
        auto [error,a,b]=co_await capy::when_all(driver->run(),business(total)); (void)a;(void)b; co_return capy::results<>{error};
    }
};
template<class Tls> auto run(Tls& tls,bool server,bool ipv6,unsigned port,bool uring,std::size_t total) -> int {
    io::io_context context=io::make_io_context(uring); io::udp_socket socket(context);
    io::endpoint local=ipv6 ? io::endpoint(io::ipv6_address::loopback(),0) : io::endpoint(io::ipv4_address::loopback(),0);
    io::endpoint remote=ipv6 ? io::endpoint(io::ipv6_address::loopback(),port) : io::endpoint(io::ipv4_address::loopback(),port);
    if (socket.open(local.address().family()) || socket.bind(local)) return 1;
    Endpoint endpoint(socket,tls,server,remote); if (endpoint.initialize()) return 2;
    typename decltype(endpoint)::Driver driver(socket,endpoint,Clock::now()+10s); endpoint.driver=&driver;
    bool done=false,failed=false;
    std::cout<<"READY "<<socket.local_endpoint().port()<<std::endl;
    capy::run_async(context.get_executor(),[&](auto result) { failed=bool(std::get<0>(result)); done=true; },[&](std::exception_ptr error) noexcept { try { std::rethrow_exception(error); } catch (std::exception const& e) { std::println("exception {}",e.what()); } failed=done=true; })(endpoint.all(total));
    context.run_for(12s);
    if (driver.failure()) std::visit([](auto const& e) { if constexpr(std::same_as<std::remove_cvref_t<decltype(e)>,int>) std::println("protocol {}",e);else std::println("driver {} {}",static_cast<int>(e.code),e.system.message()); },*driver.failure());
    bool clean=driver.drained() && endpoint.app.clean() && !endpoint.memory.used && !endpoint.h3memory.used && !endpoint.connection.key_slots();
    std::println("done={} failed={} passed={} clean={} sent={} received={} QUICpeak={} H3peak={}",done,failed,endpoint.passed,clean,endpoint.sent,endpoint.received,endpoint.memory.peak,endpoint.h3memory.peak);
    return done && !failed && endpoint.passed && clean ? 0 : 3;
}
auto main(int argc,char** argv) -> int {
    if (argc<9 || argc>11) return 1;
    if (argc>=10) target_address=argv[9];
    if (argc==11) paired=std::string_view(argv[10])!="single";
    try {
        bool server=std::string_view(argv[1])=="server",ipv6=std::string_view(argv[2])=="6",uring=std::string_view(argv[7])=="1";
        auto cert=support::read(argv[4]); auto scheme=static_cast<std::uint16_t>(std::stoul(argv[6],nullptr,0)); auto port=static_cast<unsigned>(std::stoul(argv[3])); auto total=std::stoull(argv[8]);
        if (server) { auto key=support::read(argv[5]); auto credential=tls::ServerCredential::create(cert,key); ::crypto::cleanse(key); if (!credential) return 4; q::TlsServer tls(*credential,"h3"); return run(tls,true,ipv6,port,uring,total); }
        q::TlsClient tls(support::hello(scheme),29,support::Pki{cert},"h3"); return run(tls,false,ipv6,port,uring,total);
    } catch (std::exception const& e) { std::println("exception {}",e.what()); return 99; }
}
