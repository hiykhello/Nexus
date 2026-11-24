import std;
import crypto;
import hysteria2.auth;
import hysteria2.credential;
import hysteria2.listener;
import hysteria2.wire;
import net.stream_relay;
import relay.session_quota;
import quic.cid_registry;
import tls.server_credential;
import capy;
import corosio;
import test.quic_tls_link;
namespace h=hysteria2;namespace io = ::corosio;
using Clock=std::chrono::steady_clock;using namespace std::chrono_literals;
auto transfer(capy::task<bool> task)->capy::task<capy::results<>>{co_return capy::results<>{co_await std::move(task)?std::error_code{}:std::make_error_code(std::errc::io_error)};}
struct Hooks {
    using ConnectionState=relay::SessionQuota::Lease;
    io::io_context& context;h::Password const& password;unsigned origin;relay::SessionQuota& quota;
    auto admit(quic::SessionHandle,io::endpoint const&)noexcept->std::optional<ConnectionState>{return quota.try_acquire();}
    std::size_t completed=0,closed_count=0,authenticated=0;bool valid=true;
    auto authenticate(h::ClientAuthView request) noexcept->std::optional<std::size_t>{
        auto selected=h::authenticate({&password,1},request.credential);if(selected)++authenticated;return selected;
    }
    auto datagram(quic::SessionHandle,std::span<std::uint8_t const>) noexcept->int{return 0;}
    auto closed(quic::SessionHandle,std::optional<int>) noexcept->void{++closed_count;}
    template<class Request>auto serve(Request& request)->capy::task<> {
        if(request.address()=="denied.example:443"){(void)request.respond(h::TcpStatus::error,"denied");co_return;}
        auto logical=request.connection().try_acquire();if(!logical){(void)request.respond(h::TcpStatus::error,"capacity");co_return;}
        valid&=request.address()=="target.example:443" && request.user()==0 && request.peer().port();
        io::tcp_socket target(context);std::stop_callback stop(request.stop_token(),[&]()noexcept{target.cancel();request.channel.cancel();});
        auto [connected]=co_await io::timeout(target.connect(io::endpoint(io::ipv4_address::loopback(),origin)),Clock::now()+8s);
        if(connected || !valid){(void)request.respond(h::TcpStatus::error,"origin failed");valid=false;co_return;}
        if(!request.respond(h::TcpStatus::success)){valid=false;co_return;}
        auto adapter=net::ByteRelayAdapter{target,request.channel,[] {},false};
        auto [error,a,b]=co_await capy::when_all(transfer(net::stream_relay::upload(adapter)),transfer(net::stream_relay::download(adapter)));(void)a;(void)b;
        if(error)valid=false;else ++completed;
    }
};
auto main(int argc,char** argv)->int {
    if(argc!=8 && argc!=9)return 1;if(argc==9 && std::string_view(argv[8])!="standard")return 1;try{
        auto certificate=test::quic_tls::read(argv[1]),key=test::quic_tls::read(argv[2]);auto credential=tls::ServerCredential::create(certificate,key);::crypto::cleanse(key);if(!credential)return 2;
        auto password=h::Password::create(test::quic_tls::bytes("test-password"));if(!password)return 3;
        io::io_context context=io::make_io_context(std::string_view(argv[4])=="1");relay::SessionQuota quota(64);Hooks hooks{context,*password,static_cast<unsigned>(std::stoul(argv[7])),quota};
        h::Listener<Hooks,4,16,16384> listener(context,hooks,*credential);auto prepared=listener.prepare(std::string_view(argv[3])=="6"?io::endpoint(io::ipv6_address::loopback(),0):io::endpoint(io::ipv4_address::loopback(),0));if(!prepared)return 4;
        auto expected=std::stoul(argv[5]);listener.start();std::cout<<"READY "<<prepared->port()<<std::endl;
        auto deadline=Clock::now()+18s;while(Clock::now()<deadline && hooks.valid){context.run_for(10ms);listener.maintain();if(hooks.completed>=expected && (!listener.size() || (argc==9 && !listener.business())))break;}
        listener.stop();context.run_for(2s);listener.maintain();
        std::println("production Hy2 listener complete={} expected={} closed={} authenticated={} valid={} drained={} clean={} active_business={} native_sessions={} quota_used={} owner={}",hooks.completed,expected,hooks.closed_count,hooks.authenticated,hooks.valid,listener.drained(),listener.clean(),listener.business(),listener.size(),quota.used(),sizeof(listener));
        return hooks.completed==expected && hooks.valid && listener.drained() && listener.clean() && !quota.used()?0:5;
    }catch(std::exception const& error){std::println("fixture exception {}",error.what());return 99;}
}
