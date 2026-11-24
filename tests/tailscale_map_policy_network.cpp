import std;
import tailscale.control;
import tailscale.control_stream;
import tailscale.control_connection;
import tailscale.control_application;
import tailscale.control_messages;
import tailscale.snapshot;
import tailscale.map_session;
import tls.connector;
import platform.socket_options;
import http2.client_channel;
import memory.budget;
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
    bool done=false,passed=false,application_done=false;
    std::string_view stage="connect";
    explicit Fixture(bool uring) : context(io::make_io_context(uring)) {}
};
namespace h2=http2;
namespace messages=tailscale::control_messages;
struct Resolver {
    io::endpoint endpoint;bool canceled=false;
    auto cancel() noexcept -> void {canceled=true;}
    auto operator()(startup::Clock::time_point deadline) -> capy::task<std::expected<std::array<io::endpoint,1>,int>> {
        if (canceled || startup::Clock::now()>=deadline) co_return std::unexpected(1);co_return std::array{endpoint};
    }
};
using Connector=tls::detail::PhysicalConnector<Resolver,tls::ClientProfile>;
using Connection=tailscale::control_connection::Connection<Connector,4>;
auto machine_key() -> noise::MachinePrivate {
    noise::KeyBytes bytes{};for (unsigned i=0;i<32;++i) bytes[i]=static_cast<std::uint8_t>(i+3);
    auto key=noise::MachinePrivate::from_bytes(bytes);::crypto::cleanse(bytes);if (!key) throw std::runtime_error("machine");return std::move(*key);
}
auto node_key() -> noise::NodePublic {
    noise::KeyBytes bytes{};for (unsigned i=0;i<32;++i) bytes[i]=static_cast<std::uint8_t>(i+17);
    auto key=noise::NodePrivate::from_bytes(bytes);::crypto::cleanse(bytes);if (!key) throw std::runtime_error("node");auto pub=key->public_key();if (!pub) throw std::runtime_error("node public");return *pub;
}
auto hex(std::span<std::uint8_t const> bytes) -> std::string {
    constexpr std::string_view digits="0123456789abcdef";std::string result;result.reserve(bytes.size()*2);for (auto b:bytes) {result+=digits[b>>4];result+=digits[b&15];}return result;
}
auto fields(std::string_view path,std::string_view length) -> std::array<h2::FieldView,6> {
    return {{{":method","POST"},{":scheme","https"},{":authority","localhost"},{":path",path},{"content-type","application/json"},{"content-length",length}}};
}
struct Collected {unsigned status=0;std::vector<std::uint8_t> bytes;};
struct BodyBorrow {
    Connection::Channel& channel;bool released=false;
    ~BodyBorrow() {if (!released) channel.cancel();}
};
auto release(Connection::Channel& channel,h2::StreamTicket ticket,startup::Clock::time_point deadline) -> capy::task<bool> {
    for (;;) {auto freed=channel.release(ticket);if (!freed) co_return false;if (*freed) co_return true;if (!co_await channel.wait_change(deadline)) co_return false;}
}
auto collect(Connection::Channel& channel,h2::StreamTicket ticket,startup::Clock::time_point deadline) -> capy::task<std::optional<Collected>> {
    Collected result;
    for (;;) {
        auto response=channel.response(ticket);auto body=channel.peek(ticket);if (!response || !body || response->failure) co_return std::nullopt;result.status=response->status;
        if (!body->empty()) {
            if (body->size()>16384-result.bytes.size()) co_return std::nullopt;
            result.bytes.insert(result.bytes.end(),body->begin(),body->end());if (!channel.consume(ticket,body->size())) co_return std::nullopt;continue;
        }
        if (response->remote_end && response->closed) co_return result;
        if (!co_await channel.wait_change(deadline)) co_return std::nullopt;
    }
}
auto application(Fixture& fixture,Connection& connection,std::shared_ptr<::memory::Budget> budget,startup::Clock::time_point deadline,std::string_view security_test) -> capy::task<capy::results<>> {
    BodyBorrow guard{*connection.channel()};auto& channel=*connection.channel();
    auto storage_charge=::memory::Budget::reserve(budget,messages::max_json_bytes+sizeof(messages::MapCandidate)+sizeof(tailscale::map_session::State)+sizeof(tailscale::snapshot::Scratch)+3*16384);
    if (!storage_charge) co_return capy::results<>{std::make_error_code(std::errc::not_enough_memory)};
    std::array<std::uint8_t,16384> register_storage{};auto node=node_key();
    auto wire=messages::encode_register(register_storage,{node,"fixture-auth","fixture","linux","Nexus-fixture",false});if (!wire) co_return capy::results<>{std::make_error_code(std::errc::invalid_argument)};
    auto length=std::to_string(wire->bytes().size());auto headers=fields("/machine/register",length);auto reg=channel.submit(headers,{wire->bytes(),true});
    if (!reg) co_return capy::results<>{std::make_error_code(std::errc::io_error)};
    BodyBorrow reg_borrow{channel};fixture.stage="H2 typed register";auto registered=co_await collect(channel,*reg,deadline);if (!registered) co_return capy::results<>{std::make_error_code(std::errc::io_error)};
    auto reply=messages::parse_register(registered->status,registered->bytes);
    if (!reply || reply->state!=messages::RegistrationState::authorized) co_return capy::results<>{std::make_error_code(std::errc::permission_denied)};
    auto used=wire->bytes().size();auto freed=co_await release(channel,*reg,deadline);if (!freed) co_return capy::results<>{std::make_error_code(std::errc::io_error)};
    reg_borrow.released=true;wire->clear();if (!std::ranges::all_of(std::span(register_storage).first(used),[](auto b) {return b==0;})) co_return capy::results<>{std::make_error_code(std::errc::io_error)};
    std::string map_body="{\"Version\":148,\"NodeKey\":\"nodekey:"+hex(node.view())+"\",\"Stream\":true}";
    auto map_length=std::to_string(map_body.size());auto map_headers=fields("/machine/map",map_length);
    auto map=channel.submit(map_headers,{{reinterpret_cast<std::uint8_t const*>(map_body.data()),map_body.size()},true});if (!map) co_return capy::results<>{std::make_error_code(std::errc::io_error)};
    BodyBorrow map_borrow{channel};fixture.stage="H2 typed Map streaming";
    std::vector<std::uint8_t> map_storage(messages::max_json_bytes);auto candidate=std::make_unique<messages::MapCandidate>();auto snap=std::make_unique<tailscale::map_session::State>();auto scratch=std::make_unique<tailscale::snapshot::Scratch>();
    messages::DecodeOrigin origin{node,1,map->generation};tailscale::map_session::Session map_session(origin,map_storage,*candidate,*snap,*scratch);
    if (!map_session.active()) co_return capy::results<>{std::make_error_code(std::errc::protocol_error)};
    bool rejected=false,ended=false,saw_ready=false,signaled_ready=false;std::size_t successful_bytes=0,consumed_bytes=0,failed_bytes=0,feed_calls=0;
    while (!ended && !rejected) {
        auto response=channel.response(*map);auto data=channel.peek(*map);
        if (!response || !data || response->failure || (response->status && response->status!=200)) co_return capy::results<>{std::make_error_code(std::errc::io_error)};
        if (!data->empty()) {
            auto n=std::min(std::size_t{1024},data->size());auto result=map_session.feed(data->first(n));++feed_calls;
            if (result.error) {if (security_test.empty() || !saw_ready || *result.error!=(security_test=="security-policy" ? tailscale::map_session::Error::policy : tailscale::map_session::Error::parse) || snap->ready() || !snap->peers().empty() || !snap->policy_chunks().empty()) co_return capy::results<>{std::make_error_code(std::errc::protocol_error)};failed_bytes=result.consumed;rejected=true;if (!channel.reset(*map)) co_return capy::results<>{std::make_error_code(std::errc::io_error)};break;}
            if (result.consumed!=n) co_return capy::results<>{std::make_error_code(std::errc::protocol_error)};
            if(snap->ready() && snap->peers().size()==1 && snap->peers()[0].id==3 && snap->policy_chunks().size()==1 && snap->policy_chunks()[0].name=="final")saw_ready=true;
            successful_bytes+=n;if (!channel.consume(*map,n)) co_return capy::results<>{std::make_error_code(std::errc::io_error)};consumed_bytes+=n;
            if (!security_test.empty() && saw_ready && !signaled_ready) {
                auto marker_headers=fields("/test-projection-ready","0");
                auto marker=channel.submit(marker_headers);if (!marker) co_return capy::results<>{std::make_error_code(std::errc::io_error)};
                BodyBorrow marker_borrow{channel};auto reply=co_await collect(channel,*marker,deadline);
                if (!reply || reply->status!=200 || !co_await release(channel,*marker,deadline)) co_return capy::results<>{std::make_error_code(std::errc::io_error)};
                marker_borrow.released=true;signaled_ready=true;
            }
            continue;
        }
        if (response->remote_end && response->closed) {if (response->status!=200) co_return capy::results<>{std::make_error_code(std::errc::protocol_error)};ended=true;break;}
        if (!co_await channel.wait_change(deadline)) co_return capy::results<>{std::make_error_code(std::errc::io_error)};
    }
    if (!feed_calls || successful_bytes!=consumed_bytes || (security_test.empty() ? (!snap->ready() || snap->peers().size()!=1 || snap->peers()[0].id!=3 || snap->policy_chunks().size()!=1 || snap->policy_chunks()[0].name!="final" || !map_session.eof() || snap->ready() || !snap->peers().empty() || !snap->policy_chunks().empty()) : (!rejected || !failed_bytes || !signaled_ready)) || !co_await release(channel,*map,deadline)) co_return capy::results<>{std::make_error_code(std::errc::protocol_error)};map_borrow.released=true;
    std::println("streamed-map successful={} app-consumed={} failed-bytes={} calls={} rejected={} ready-before-failure={}",successful_bytes,consumed_bytes,failed_bytes,feed_calls,rejected,saw_ready);
    std::string update_body="{\"Version\":148,\"NodeKey\":\"nodekey:"+hex(node.view())+"\",\"OmitPeers\":true}";
    auto update_length=std::to_string(update_body.size());auto update_headers=fields("/machine/map",update_length);
    auto update=channel.submit(update_headers,{{reinterpret_cast<std::uint8_t const*>(update_body.data()),update_body.size()},true});if (!update) co_return capy::results<>{std::make_error_code(std::errc::io_error)};
    BodyBorrow update_borrow{channel};fixture.stage="H2 update";auto updated=co_await collect(channel,*update,deadline);
    if (!updated || updated->status!=200 || !updated->bytes.empty() || !co_await release(channel,*update,deadline)) co_return capy::results<>{std::make_error_code(std::errc::io_error)};update_borrow.released=true;
    if (!channel.shutdown()) co_return capy::results<>{std::make_error_code(std::errc::io_error)};
    while (!channel.finished()) {if (!co_await channel.wait_change(deadline) && !channel.finished()) co_return capy::results<>{std::make_error_code(std::errc::io_error)};}
    fixture.application_done=true;guard.released=true;co_return capy::results<>{};
}
auto parallel(Fixture& fixture,Connection& connection,std::shared_ptr<::memory::Budget> budget,startup::Clock::time_point deadline,std::string_view mode) -> capy::task<capy::results<>> {
    auto& channel=*connection.channel();BodyBorrow guard{channel};auto node=node_key();
    auto storage_charge=::memory::Budget::reserve(budget,messages::max_json_bytes+sizeof(messages::MapCandidate)+sizeof(tailscale::map_session::State)+sizeof(tailscale::snapshot::Scratch)+3*16384);
    if (!storage_charge) co_return capy::results<>{std::make_error_code(std::errc::not_enough_memory)};
    std::string map_body="{\"Version\":148,\"NodeKey\":\"nodekey:"+hex(node.view())+"\",\"Stream\":true}";auto map_length=std::to_string(map_body.size());auto map_headers=fields("/machine/map",map_length);
    auto map=channel.submit(map_headers,{{reinterpret_cast<std::uint8_t const*>(map_body.data()),map_body.size()},true});if (!map) co_return capy::results<>{std::make_error_code(std::errc::io_error)};
    BodyBorrow map_borrow{channel};fixture.stage="Map stop credit";
    while (true) {auto data=channel.peek(*map);auto response=channel.response(*map);if (!data || !response || response->failure) co_return capy::results<>{std::make_error_code(std::errc::io_error)};if (!data->empty()) break;if (!co_await channel.wait_change(deadline)) co_return capy::results<>{std::make_error_code(std::errc::io_error)};}
    auto before=channel.peek(*map);auto first=before->front();auto pointer=before->data();auto [delay_error]=co_await io::delay(1100ms);
    auto paused=channel.peek(*map);auto map_response=channel.response(*map);
    if (delay_error || !paused || paused->empty() || paused->data()!=pointer || paused->front()!=first || !map_response || map_response->remote_end || map_response->failure)
        co_return capy::results<>{std::make_error_code(std::errc::io_error)};
    std::array<std::uint8_t,16384> register_storage{};auto wire=messages::encode_register(register_storage,{node,"fixture-auth","fixture","linux","Nexus-fixture",false});if (!wire) co_return capy::results<>{std::make_error_code(std::errc::invalid_argument)};
    auto reg_length=std::to_string(wire->bytes().size());auto reg_headers=fields("/machine/register",reg_length);auto reg=channel.submit(reg_headers,{wire->bytes(),true});if (!reg) co_return capy::results<>{std::make_error_code(std::errc::io_error)};
    BodyBorrow reg_borrow{channel};
    std::string update_body="{\"Version\":148,\"NodeKey\":\"nodekey:"+hex(node.view())+"\",\"OmitPeers\":true}";auto update_length=std::to_string(update_body.size());auto update_headers=fields("/machine/map",update_length);
    auto update=channel.submit(update_headers,{{reinterpret_cast<std::uint8_t const*>(update_body.data()),update_body.size()},true});if (!update) co_return capy::results<>{std::make_error_code(std::errc::io_error)};
    BodyBorrow update_borrow{channel};fixture.stage="register/update while Map remains stalled";
    auto registered=co_await collect(channel,*reg,deadline);if (!registered) co_return capy::results<>{std::make_error_code(std::errc::io_error)};
    auto reply=messages::parse_register(registered->status,registered->bytes);if (!reply || reply->state!=messages::RegistrationState::authorized) co_return capy::results<>{std::make_error_code(std::errc::permission_denied)};
    if (!co_await release(channel,*reg,deadline)) co_return capy::results<>{std::make_error_code(std::errc::io_error)};reg_borrow.released=true;auto used=wire->bytes().size();wire->clear();
    if (!std::ranges::all_of(std::span(register_storage).first(used),[](auto b) {return b==0;})) co_return capy::results<>{std::make_error_code(std::errc::io_error)};
    auto updated=co_await collect(channel,*update,deadline);if (!updated || updated->status!=200 || !updated->bytes.empty() || !co_await release(channel,*update,deadline)) co_return capy::results<>{std::make_error_code(std::errc::io_error)};update_borrow.released=true;
    map_response=channel.response(*map);if (!map_response || map_response->remote_end || map_response->failure) co_return capy::results<>{std::make_error_code(std::errc::io_error)};
    if (mode=="rst") {
        fixture.stage="independent Map RST";if (!channel.reset(*map) || !co_await release(channel,*map,deadline)) co_return capy::results<>{std::make_error_code(std::errc::io_error)};
    } else {
        fixture.stage="Map frame copy before credit";std::vector<std::uint8_t> storage(messages::max_json_bytes);tailscale::control_http::MapFrameDecoder decoder(storage);auto candidate=std::make_unique<messages::MapCandidate>();bool complete=false,rejected=false;
        for (;;) {
            auto data=channel.peek(*map);auto response=channel.response(*map);if (!data || !response || response->failure) co_return capy::results<>{std::make_error_code(std::errc::io_error)};
            if (!data->empty()) {
                auto fed=decoder.feed(*data);if (fed.consumed && !channel.consume(*map,fed.consumed)) co_return capy::results<>{std::make_error_code(std::errc::io_error)};
                if (fed.error) {rejected=true;break;}
                if (fed.ready) {
                    if (complete) co_return capy::results<>{std::make_error_code(std::errc::protocol_error)};
                    auto json=decoder.payload();if (!json || json->size()!=786432 || !messages::parse_map(*json,{node,17,map->generation},*candidate)) co_return capy::results<>{std::make_error_code(std::errc::protocol_error)};
                    auto view=candidate->view();if (!view || !view->keep_alive || view->origin.connection_generation!=17 || view->origin.stream_generation!=map->generation || !view->peers.empty()) co_return capy::results<>{std::make_error_code(std::errc::protocol_error)};
                    candidate->clear();if (!decoder.consume()) co_return capy::results<>{std::make_error_code(std::errc::protocol_error)};complete=true;
                }
                if (!fed.consumed) co_return capy::results<>{std::make_error_code(std::errc::io_error)};continue;
            }
            if (response->remote_end && response->closed) {if (!decoder.eof()) rejected=true;break;}
            if (!co_await channel.wait_change(deadline)) co_return capy::results<>{std::make_error_code(std::errc::io_error)};
        }
        if (mode=="parallel" ? !complete || rejected : complete || !rejected) co_return capy::results<>{std::make_error_code(std::errc::protocol_error)};
        if (rejected && !channel.reset(*map)) co_return capy::results<>{std::make_error_code(std::errc::io_error)};
        if (!co_await release(channel,*map,deadline)) co_return capy::results<>{std::make_error_code(std::errc::io_error)};
    }
    map_borrow.released=true;
    fixture.stage="sibling after Map release";auto again=channel.submit(update_headers,{{reinterpret_cast<std::uint8_t const*>(update_body.data()),update_body.size()},true});if (!again) co_return capy::results<>{std::make_error_code(std::errc::io_error)};
    BodyBorrow again_borrow{channel};auto again_reply=co_await collect(channel,*again,deadline);if (!again_reply || again_reply->status!=200 || !co_await release(channel,*again,deadline)) co_return capy::results<>{std::make_error_code(std::errc::io_error)};again_borrow.released=true;
    if (!channel.shutdown()) co_return capy::results<>{std::make_error_code(std::errc::io_error)};
    while (!channel.finished()) {if (!co_await channel.wait_change(deadline) && !channel.finished()) co_return capy::results<>{std::make_error_code(std::errc::io_error)};}
    fixture.application_done=true;guard.released=true;co_return capy::results<>{};
}
struct ApplicationSink {
    bool installed_final = false, revoked = false;
    auto install(tailscale::map_session::State const& state) -> bool {
        if (!state.ready() || !state.self()) return false;
        if (state.peers().size() == 1 && state.peers()[0].id == 3 && state.policy_chunks().size() == 1 &&
            state.policy_chunks()[0].name == "final") installed_final = true;
        return true;
    }
    auto revoke() noexcept -> void { revoked = true; }
};

auto control_application(Fixture& fixture, Connection& connection, std::shared_ptr<::memory::Budget> const& budget,
                         startup::Clock::time_point deadline) -> capy::task<capy::results<>> {
    namespace app = tailscale::control_application;
    ApplicationSink sink;
    app::Options options{"localhost", {node_key(), "fixture-auth", "fixture", "linux", "Nexus-fixture", false}, {}, 1};
    auto result = co_await app::run(*connection.channel(), options, sink, budget, deadline);
    fixture.application_done = !result && result.error() == app::Error::ended && sink.installed_final && sink.revoked;
    if (!fixture.application_done) co_return capy::results<>{std::make_error_code(std::errc::protocol_error)};
    std::println("control application registered, updated endpoints, published and revoked Map state");
    co_return capy::results<>{};
}

auto root(Fixture& fixture,std::uint16_t port,noise::ControlPublic pin,std::string_view ca,bool early_expected,std::string_view mode) -> capy::task<> {
    struct Done {Fixture& fixture;~Done() {fixture.done=true;}} done{fixture};
    try {
        auto deadline=startup::Clock::now()+5s;constexpr std::array<std::string_view,1> protocols{"http/1.1"};auto profile=tls::ClientProfile::load("localhost",ca,0x001d,false,protocols);if (!profile) co_return;
        auto machine=machine_key();auto budget=std::make_shared<::memory::Budget>(8*1024*1024);::platform::TcpSocketOptions options;
        Connection connection(machine,pin,budget,131072,fixture.context,Resolver{io::endpoint(io::ipv4_address::loopback(),port)},*profile,options);
        std::array<std::uint8_t,1024> early_storage{};fixture.stage="Connection start";auto ready=co_await connection.start("localhost",early_storage,deadline);
        if (!ready || bool(connection.early_info())!=early_expected || !connection.channel() || !connection.drained()) co_return;
        std::println("transport-reserved={} owner-size={} channel-size={}",connection.transport_reserved(),sizeof(Connection),sizeof(Connection::Channel));
        if (mode == "application") {
            fixture.stage = "control application";
            auto result = co_await capy::when_all(connection.run(), control_application(fixture, connection, budget, deadline));
            (void)result;
            fixture.passed = fixture.application_done && connection.drained();
            co_return;
        }
        auto [error,driver,app]=co_await capy::when_all(connection.run(),((mode=="basic" || mode=="security-tka" || mode=="security-policy") ? application(fixture,connection,budget,deadline,mode=="basic" ? std::string_view{} : mode) : parallel(fixture,connection,budget,deadline,mode)));(void)driver;(void)app;
        fixture.passed=!error && fixture.application_done && connection.drained() && connection.channel()->finished() && !connection.failure();
    } catch (...) {fixture.passed=false;}
}
auto number(std::string_view text,unsigned& value) -> bool {auto result=std::from_chars(text.data(),text.data()+text.size(),value);return result.ec==std::errc{} && result.ptr==text.data()+text.size();}
auto pin(std::string_view text) -> std::optional<noise::ControlPublic> {
    if (text.size()!=64) return {};noise::KeyBytes bytes{};auto digit=[](char c)->int {return c>='0' && c<='9' ? c-'0' : c>='a' && c<='f' ? c-'a'+10 : -1;};
    for (unsigned i=0;i<32;++i) {auto a=digit(text[i*2]),b=digit(text[i*2+1]);if (a<0 || b<0) return {};bytes[i]=static_cast<std::uint8_t>(a*16+b);}auto result=noise::ControlPublic::from_bytes(bytes);return result ? std::optional(*result) : std::nullopt;
}
auto main(int argc,char** argv) -> int {
    if (argc!=6 && argc!=7) return 64;unsigned port=0,backend=0,early=0;auto control=pin(argv[2]);auto mode=argc==7 ? std::string_view(argv[6]) : std::string_view("basic");if (!number(argv[1],port) || !port || port>65535 || !control || !number(argv[3],backend) || backend>1 || !number(argv[5],early) || early>1) return 64;
    if (backend && !io::has_uring) return 77;Fixture fixture(backend!=0);capy::run_async(fixture.context.get_executor())(root(fixture,static_cast<std::uint16_t>(port),*control,argv[4],early!=0,mode));fixture.context.run_for(7s);
    if (!fixture.done || !fixture.context.stopped()) {std::cerr<<"not drained stage="<<fixture.stage<<'\n';std::_Exit(65);}
    if (!fixture.passed) {std::cerr<<"control connection failed at "<<fixture.stage<<'\n';return 1;}std::println("control-connection-passed");
}
