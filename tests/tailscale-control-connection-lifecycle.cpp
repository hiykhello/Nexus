import std;
import tailscale.control;
import tailscale.control_connection;
import tailscale.control_messages;
import tls.profiles;
import tls.connector;
import platform.socket_options;
import http2.client_channel;
import memory.budget;
import crypto;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;
namespace noise=tailscale::control;
namespace cc=tailscale::control_connection;
namespace messages=tailscale::control_messages;
namespace h2=http2;
namespace capy=nex::capy;
namespace io=nex::corosio;
using namespace std::chrono_literals;
struct State {
    bool starting=false,started=false,parked=false,done=false,destroyed=false,drained=false,passed=false,borrowed=false,released=false;
    std::string_view stage="construct";
    std::array<std::uint8_t,16384> secret_storage{};
    std::size_t used=0;
    std::shared_ptr<::memory::Budget> budget=std::make_shared<::memory::Budget>(8*1024*1024);
};
struct Resolver {
    io::endpoint endpoint;
    auto cancel() noexcept -> void {}
    auto operator()(cc::Clock::time_point deadline) -> capy::task<std::expected<std::array<io::endpoint,1>,int>> {
        if (cc::Clock::now()>=deadline) co_return std::unexpected(1);co_return std::array{endpoint};
    }
};
using Connector=tls::detail::PhysicalConnector<Resolver,tls::ClientProfile>;
using Connection=cc::Connection<Connector,4>;
template<class Key> auto fixed(unsigned seed) -> Key {
    noise::KeyBytes bytes{};for (unsigned i=0;i<32;++i) bytes[i]=static_cast<std::uint8_t>(i+seed);auto key=Key::from_bytes(bytes);::crypto::cleanse(bytes);if (!key) throw std::runtime_error("key");return std::move(*key);
}
auto start(Connection& connection,State& state,cc::Clock::time_point deadline) -> capy::task<capy::results<>> {
    std::array<std::uint8_t,1024> early{};state.starting=state.parked=true;state.stage="startup";auto ready=co_await connection.start("localhost",early,deadline);
    state.passed=!ready && connection.drained() && !connection.channel();state.done=true;co_return capy::results<>{};
}
auto kill(Connection& connection,State& state) -> capy::task<capy::results<>> {
    auto [error]=co_await io::delay(30ms);if (error) co_return capy::results<>{error};state.drained=!connection.drained();connection.cancel();co_return capy::results<>{};
}
auto borrowed(Connection& connection,State& state,cc::Clock::time_point deadline,bool abandon) -> capy::task<capy::results<>> {
    auto& channel=*connection.channel();auto node=fixed<noise::NodePrivate>(17).public_key();if (!node) co_return capy::results<>{std::make_error_code(std::errc::io_error)};
    // Allow the peer's small INITIAL_WINDOW_SIZE to arrive before submission.
    auto [delay_error]=co_await io::delay(50ms);if (delay_error) co_return capy::results<>{delay_error};
    std::string auth(4096,'A');auto wire=messages::encode_register(state.secret_storage,{*node,auth,"fixture","linux","Nexus-fixture",false});
    if (!wire) co_return capy::results<>{std::make_error_code(std::errc::io_error)};state.used=wire->bytes().size();
    auto length=std::to_string(state.used);std::array<h2::FieldView,6> fields{{{":method","POST"},{":scheme","https"},{":authority","localhost"},{":path","/machine/register"},{"content-type","application/json"},{"content-length",length}}};
    auto ticket=channel.submit(fields,{wire->bytes(),true});if (!ticket) co_return capy::results<>{std::make_error_code(std::errc::io_error)};
    struct Borrow {
        Connection::Channel& channel;h2::StreamTicket ticket;State& state;messages::RegisterWire& wire;
        ~Borrow() {channel.cancel();auto released=channel.tx_consumed(ticket);state.released=released && *released;wire.clear();}
    } lease{channel,*ticket,state,*wire};
    state.stage="AuthKey body provider blocked";auto [wait_error]=co_await io::delay(100ms);if (wait_error) co_return capy::results<>{wait_error};
    auto consumed=channel.tx_consumed(*ticket);state.borrowed=consumed && !*consumed;
    if (!state.borrowed || !std::ranges::any_of(std::span(state.secret_storage).first(state.used),[](auto b) {return b!=0;})) co_return capy::results<>{std::make_error_code(std::errc::io_error)};
    state.parked=true;
    if (abandon) {while (co_await channel.wait_change(deadline)) {}}
    else {connection.cancel();state.passed=true;}
    co_return capy::results<>{};
}
auto root(io::io_context& context,State& state,std::uint16_t port,noise::ControlPublic pin,std::string_view ca,std::string_view mode) -> capy::task<> {
    try {
        constexpr std::array<std::string_view,1> protocols{"http/1.1"};auto profile=tls::ClientProfile::load("localhost",ca,0x001d,false,protocols);if (!profile) co_return;
        auto machine=fixed<noise::MachinePrivate>(3);::platform::TcpSocketOptions options;
        Connection connection(machine,pin,state.budget,131072,context,Resolver{io::endpoint(io::ipv4_address::loopback(),port)},*profile,options);
        struct Mark {State& state;Connection& connection;~Mark() {state.destroyed=true;state.drained=state.drained && connection.drained();}} mark{state,connection};
        auto deadline=cc::Clock::now()+5s;bool abandon=mode.ends_with("abandon");
        if (mode.starts_with("start")) {
            state.drained=true;
            if (abandon) co_await start(connection,state,deadline);
            else {auto [error,a,b]=co_await capy::when_all(start(connection,state,deadline),kill(connection,state));(void)error;(void)a;(void)b;}
        } else {
            std::array<std::uint8_t,1024> early{};state.stage="Connection start";auto ready=co_await connection.start("localhost",early,deadline);if (!ready || !connection.channel()) co_return;
            state.started=true;state.drained=true;
            auto [error,a,b]=co_await capy::when_all(connection.run(),borrowed(connection,state,deadline,abandon));(void)error;(void)a;(void)b;
            state.drained=connection.drained();state.done=true;
        }
    } catch (...) {state.passed=false;}
}
auto number(std::string_view text,unsigned& value) -> bool {auto r=std::from_chars(text.data(),text.data()+text.size(),value);return r.ec==std::errc{} && r.ptr==text.data()+text.size();}
auto pin(std::string_view text) -> std::optional<noise::ControlPublic> {
    if (text.size()!=64) return {};noise::KeyBytes bytes{};auto hex=[](char c)->int {return c>='0' && c<='9' ? c-'0' : c>='a' && c<='f' ? c-'a'+10 : -1;};
    for (unsigned i=0;i<32;++i) {auto a=hex(text[i*2]),b=hex(text[i*2+1]);if (a<0 || b<0) return {};bytes[i]=static_cast<std::uint8_t>(a*16+b);}auto r=noise::ControlPublic::from_bytes(bytes);return r ? std::optional(*r) : std::nullopt;
}
auto main(int argc,char** argv) -> int {
    if (argc!=6) return 64;unsigned port=0,backend=0;auto control=pin(argv[2]);auto mode=std::string_view(argv[5]);
    if (!number(argv[1],port) || !port || port>65535 || !control || !number(argv[3],backend) || backend>1 ||
        (mode!="start-cancel" && mode!="start-abandon" && mode!="upload-cancel" && mode!="upload-abandon")) return 64;
    if (backend && !io::has_uring) return 77;State state;bool abandon=mode.ends_with("abandon");
    {
        auto context=io::make_io_context(backend!=0);capy::run_async(context.get_executor())(root(context,state,static_cast<std::uint16_t>(port),*control,argv[4],mode));
        if (abandon) {
            auto end=cc::Clock::now()+2s;while (!state.parked && !state.done && cc::Clock::now()<end) {context.run_for(10ms);if (context.stopped()) break;}
            if (!state.parked || state.done || state.destroyed) {std::cerr<<"did not park "<<state.stage<<'\n';return 1;}
            context.run_for(10ms);
        } else {context.run_for(2s);if (!state.done || !context.stopped() || !state.passed) {std::cerr<<"cancel not drained "<<state.stage<<'\n';return 2;}}
    }
    if (!state.destroyed || !state.drained || (abandon && state.done) || state.budget->used() || (mode.starts_with("upload") &&
        (!state.borrowed || !state.released || !std::ranges::all_of(std::span(state.secret_storage).first(state.used),[](auto b) {return b==0;})))) {
        std::cerr<<"lifecycle cleanup failed stage="<<state.stage<<" destroyed="<<state.destroyed<<" drained="<<state.drained<<" body="<<state.borrowed<<':'<<state.released<<" used="<<state.budget->used()<<'\n';return 3;
    }
    std::println("control-connection-lifecycle-passed");
}
