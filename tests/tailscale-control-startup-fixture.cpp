import std;
import tailscale.control;
import tailscale.control_stream;
import tailscale.control_http;
import net.socket_stream;
import tls.profiles;
import tls.corosio_client;
import tls.corosio_application;
import tls.byte_stream;
import crypto;
import capy;
import corosio;
namespace noise=tailscale::control;
namespace startup=tailscale::control_stream;
namespace io = ::corosio;
using namespace std::chrono_literals;
struct Fixture {
    io::io_context context;
    io::tcp_socket socket{context};
    bool done=false,passed=false;
    std::string_view stage="connect";
    std::optional<startup::Failure> error;
    std::optional<tls::detail::AsyncHandshakeError> tls_error;
    explicit Fixture(bool uring) : context(io::make_io_context(uring)) {}
};
template<class Lower> struct Limited {
    Lower& lower;std::size_t limit;std::size_t reads=0;
    auto read(std::span<std::uint8_t> bytes,net::StreamDeadline deadline) {++reads;return lower.read(bytes.first(std::min(bytes.size(),limit)),deadline);}
    auto send(std::span<std::uint8_t const> bytes,net::StreamDeadline deadline) {return lower.send(bytes,deadline);}
    auto close_output(net::StreamDeadline deadline) {return lower.close_output(deadline);}
    auto cancel() noexcept -> void {lower.cancel();}
};
template<class Frame> auto exact(Frame& frame,std::span<std::uint8_t> bytes,startup::Clock::time_point deadline) -> capy::task<bool> {
    while (!bytes.empty()) {auto result=co_await frame.read(bytes,deadline);if (!result || !*result || *result>bytes.size()) co_return false;bytes=bytes.subspan(*result);}co_return true;
}
auto machine_key() -> noise::MachinePrivate {
    noise::KeyBytes bytes{};for (unsigned i=0;i<32;++i) bytes[i]=static_cast<std::uint8_t>(i+3);
    auto key=noise::MachinePrivate::from_bytes(bytes);::crypto::cleanse(bytes);if (!key) throw std::runtime_error("key");return std::move(*key);
}
template<class Lower>
auto application(Fixture& fixture,Lower& lower,noise::ControlPublic pin,bool early,std::size_t limit,std::string_view expected,
    startup::Clock::time_point started,startup::Clock::time_point deadline) -> capy::task<bool> {
    Limited bounded{lower,limit};auto local=machine_key();startup::Stream stream(bounded,local,pin);std::array<std::uint8_t,1024> storage{};
    fixture.stage="HTTP/Noise/early";
    auto result=co_await stream.start("localhost",storage,started,deadline);
    if (expected!="ok" && expected!="coalesced") {
        if (result || stream.ready() || stream.transport()) co_return false;
        fixture.error=result.error();
        co_return expected=="reject" || (expected=="timeout" && result.error().error==startup::Error::timeout) ||
            (expected=="http" && result.error().error==startup::Error::http && result.error().http==tailscale::control_http::Error::status);
    }
    if (!result || !stream.ready() || !stream.transport()) {if (!result) fixture.error=result.error();co_return false;}
    if (bool(result->early)!=early) co_return false;
    if (expected=="coalesced" && bounded.reads!=(early ? 1u : 2u)) {std::cerr<<"coalesced lower reads="<<bounded.reads<<'\n';co_return false;}
    constexpr std::string_view payload="{\"nodeKeyChallenge\":\"chalpub:0000000000000000000000000000000000000000000000000000000000000000\"}";
    if (early && !std::ranges::equal(*result->early,std::span(reinterpret_cast<std::uint8_t const*>(payload.data()),payload.size()))) co_return false;
    std::array<std::uint8_t,9> header{};auto prefix=result->http2_prefix();
    if (early) {if (!prefix.empty()) co_return false;auto first=co_await exact(*stream.transport(),header,deadline);if (!first) co_return false;}
    else {if (prefix.size()!=header.size()) co_return false;std::ranges::copy(prefix,header.begin());}
    fixture.stage="H2 first SETTINGS tail";
    if (header[3]!=4 || header[4]!=0 || std::ranges::any_of(std::span(header).subspan(5),[](auto b) {return b!=0;})) co_return false;
    auto length=(std::size_t(header[0])<<16)|(std::size_t(header[1])<<8)|header[2];if (length>16384 || length%6) co_return false;
    std::array<std::uint8_t,16384> body{};auto tail=co_await exact(*stream.transport(),std::span(body).first(length),deadline);if (!tail) co_return false;
    co_return true;
}
auto millis(startup::Clock::time_point value) -> std::uint64_t {return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(value.time_since_epoch()).count());}
auto root(Fixture& fixture,std::uint16_t port,noise::ControlPublic pin,bool early,std::size_t limit,std::string_view expected,
    unsigned budget,std::string_view ca,std::string_view name) -> capy::task<> {
    try {
        auto started=startup::Clock::now(),deadline=started+std::chrono::milliseconds(budget);
        if (ca=="-") {
            auto [error]=co_await io::timeout(fixture.socket.connect(io::endpoint(io::ipv4_address::loopback(),port)),deadline);
            if (!error) {net::SocketByteStream lower(fixture.socket);fixture.passed=co_await application(fixture,lower,pin,early,limit,expected,started,deadline);}
        } else {
            fixture.stage="TLS profile";constexpr std::array<std::string_view,1> protocols{"http/1.1"};
            auto profile=tls::ClientProfile::load(name,ca,0x001d,false,protocols);
            if (profile) {
                auto wall=std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
                auto handshake=profile->handshake(millis(started),millis(deadline),wall);
                if (handshake) {
                    fixture.stage="TLS connect/authenticate";tls::detail::OwnedClient owner(fixture.context,std::move(*handshake));
                    struct Cancel {tls::detail::OwnedClient& owner;~Cancel() {owner.cancel();}} cancel{owner};
                    auto connected=co_await owner.start(io::endpoint(io::ipv4_address::loopback(),port));
                    if (!connected) {fixture.tls_error=connected.error();fixture.passed=expected=="tls" && connected.error()==tls::detail::AsyncHandshakeError::authentication;}
                    else if (expected!="tls") {tls::detail::ByteStream lower(*owner.client()->application());fixture.passed=co_await application(fixture,lower,pin,early,limit,expected,started,deadline);}
                }
            }
        }
    } catch (...) {fixture.passed=false;}
    fixture.done=true;
}
auto number(std::string_view text,unsigned& value) -> bool {auto result=std::from_chars(text.data(),text.data()+text.size(),value);return result.ec==std::errc{} && result.ptr==text.data()+text.size();}
auto pin(std::string_view text) -> std::optional<noise::ControlPublic> {
    if (text.size()!=64) return {};noise::KeyBytes bytes{};
    auto hex=[](char c)->int {return c>='0' && c<='9' ? c-'0' : c>='a' && c<='f' ? c-'a'+10 : -1;};
    for (unsigned i=0;i<32;++i) {auto a=hex(text[i*2]),b=hex(text[i*2+1]);if (a<0 || b<0) return {};bytes[i]=static_cast<std::uint8_t>(a*16+b);}
    auto result=noise::ControlPublic::from_bytes(bytes);return result ? std::optional(*result) : std::nullopt;
}
auto main(int argc,char** argv) -> int {
    if (argc!=10) return 64;unsigned port=0,backend=0,early=0,limit=0,budget=0;auto control=pin(argv[2]);auto expected=std::string_view(argv[6]);
    if (!number(argv[1],port) || !port || port>65535 || !control || !number(argv[3],backend) || backend>1 || !number(argv[4],early) || early>1 ||
        !number(argv[5],limit) || !limit || limit>4096 || !number(argv[7],budget) || !budget || budget>10000 ||
        (expected!="ok" && expected!="coalesced" && expected!="reject" && expected!="http" && expected!="timeout" && expected!="tls")) return 64;
    if (backend && !io::has_uring) return 77;Fixture fixture(backend!=0);
    capy::run_async(fixture.context.get_executor())(root(fixture,static_cast<std::uint16_t>(port),*control,early!=0,limit,expected,budget,argv[8],argv[9]));
    fixture.context.run_for(std::chrono::milliseconds(budget)+2s);
    if (!fixture.done || !fixture.context.stopped()) std::_Exit(65);
    if (!fixture.passed) {
        std::cerr<<"startup failed at "<<fixture.stage;
        if (fixture.error) std::cerr<<" startup-error="<<static_cast<int>(fixture.error->error);
        if (fixture.tls_error) std::cerr<<" tls-error="<<static_cast<int>(*fixture.tls_error);
        std::cerr<<'\n';return 1;
    }
    std::println("control-startup-passed");
}
