import std;
import net.tcp_fast_open;
import capy;
import corosio;
namespace io = ::corosio;
using namespace std::chrono_literals;

auto run(io::io_context& context,io::endpoint endpoint,std::string_view mode,bool& ok) -> capy::task<> {
    io::tcp_socket socket(context);auto deadline=std::chrono::steady_clock::now()+(mode=="timeout" ? 200ms : 3s);
    if(mode=="expired") {
        std::array<std::uint8_t,1> data{1};
        auto result=co_await net::tcp_fast_open_first_write(socket,endpoint,data,std::chrono::steady_clock::now()-1ms);
        ok=result.error==std::errc::timed_out && !socket.is_open();co_return;
    }
    if(mode=="unsupported") {
        std::array candidates{endpoint};std::array<std::uint8_t,1> byte{0x42};
        auto result=co_await net::tcp_fast_open_candidates(socket,candidates,[](auto const&,auto const&){return true;},byte,deadline);
        if(result.result.error || result.result.accepted || result.endpoint!=endpoint){socket.close();co_return;}
        auto [write_error,written]=co_await io::timeout(socket.write_some(capy::const_buffer(byte.data(),byte.size())),deadline);
        std::array<std::uint8_t,1> reply{};auto [read_error,count]=co_await io::timeout(socket.read_some(capy::mutable_buffer(reply.data(),reply.size())),deadline);
        ok=!write_error && written==1 && !read_error && count==1 && reply[0]==0x5a;socket.close();co_return;
    }
    if(mode=="candidates-empty" || mode=="candidates-commit") {
        auto dead=io::endpoint(endpoint.address(),static_cast<std::uint16_t>(endpoint.port()+1));
        std::array candidates{dead,endpoint};std::array<std::uint8_t,1> byte{0x42};
        auto payload=mode=="candidates-empty" ? std::span<std::uint8_t const>{} : std::span<std::uint8_t const>{byte};
        auto result=co_await net::tcp_fast_open_candidates(socket,candidates,[](auto const&,auto const&){return true;},payload,deadline);
        if(mode=="candidates-commit" && result.result.accepted) {
            ok=bool(result.result.error) && result.endpoint==dead && !socket.is_open();
            std::println("candidate committed={} error={}",result.result.accepted,result.result.error.message());co_return;
        }
        if(result.result.error || result.endpoint!=endpoint){socket.close();co_return;}
        if(!payload.empty()) {
            auto suffix=payload.subspan(result.result.accepted);
            if(!suffix.empty()) {auto [error,count]=co_await io::timeout(socket.write_some(capy::const_buffer(suffix.data(),suffix.size())),deadline);if(error || count!=suffix.size()){socket.close();co_return;}}
        }
        std::array<std::uint8_t,1> reply{};auto [error,count]=co_await io::timeout(socket.read_some(capy::mutable_buffer(reply.data(),reply.size())),deadline);
        ok=!error && count==1 && reply[0]==0x5a;socket.close();co_return;
    }
    bool cancel_done=mode!="cancel";capy::async_event cancel_finished;
    auto cancel=[&]() -> capy::task<> {
        io::steady_timer timer(context);timer.expires_at(std::chrono::steady_clock::now()+100ms);
        auto [error]=co_await timer.wait();if(!error)socket.cancel();cancel_done=true;cancel_finished.set();
    };
    if(mode=="cancel")capy::run_async(context.get_executor())(cancel());
    std::vector<std::uint8_t> bytes(mode=="empty" ? 0 : 200000);
    for(std::size_t i=0;i<bytes.size();++i)bytes[i]=static_cast<std::uint8_t>(i%251);
    auto result=co_await net::tcp_fast_open_first_write(socket,endpoint,bytes,deadline);
    if(mode=="cancel" && !cancel_done){auto [error]=co_await cancel_finished.wait();(void)error;}
    if(mode=="timeout" || mode=="cancel") {
        ok=bool(result.error) && result.accepted<=bytes.size() && (mode=="timeout" ? capy::is_timeout(result.error) || result.error==std::errc::timed_out : result.error==capy::cond::canceled);
        std::println("{} accepted={} error={}",mode,result.accepted,result.error.message());socket.close();co_return;
    }
    if(mode=="refused") {std::println("refused accepted={} error={} value={}",result.accepted,result.error.message(),result.error.value());ok=result.error==std::errc::connection_refused && result.accepted<=bytes.size();socket.close();co_return;}
    if(result.error || result.accepted>bytes.size()){socket.close();co_return;}
    auto remaining=std::span(bytes).subspan(result.accepted);
    while(!remaining.empty()) {
        auto [error,count]=co_await io::timeout(socket.write_some(capy::const_buffer(remaining.data(),remaining.size())),deadline);
        if(error || !count || count>remaining.size()){socket.close();co_return;}
        remaining=remaining.subspan(count);
    }
    std::array<std::uint8_t,1> reply{};
    auto [error,count]=co_await io::timeout(socket.read_some(capy::mutable_buffer(reply.data(),reply.size())),deadline);
    ok=!error && count==1 && reply[0]==0x5a;
    std::println("mode={} accepted={} error={}",mode,result.accepted,result.error.message());
    socket.close();
}
auto main(int argc,char** argv) -> int {
    if(argc!=5)return 2;bool uring=std::string_view(argv[1])=="uring";
    if(uring && !io::has_uring)return 77;
    auto context=io::make_io_context(uring);auto port=static_cast<std::uint16_t>(std::strtoul(argv[2],nullptr,10));
    auto address=std::string_view(argv[3]);
    auto endpoint=address=="v6" ? io::endpoint(io::ipv6_address::loopback(),port) : address=="blackhole" ?
        io::endpoint(io::ipv4_address({192,0,2,1}),port) : io::endpoint(io::ipv4_address::loopback(),port);
    if(std::string_view(argv[4])=="pre-canceled") {
        io::tcp_socket socket(context);std::stop_source stop;stop.request_stop();bool done=false,ok=false;
        auto test=[&]() -> capy::task<> {
            std::array<std::uint8_t,1> data{1};
            auto result=co_await net::tcp_fast_open_first_write(socket,endpoint,data,std::chrono::steady_clock::now()+2s);
            ok=result.error==capy::cond::canceled && !socket.is_open();
        };
        capy::run_async(context.get_executor(),stop.get_token(),[&]() noexcept {done=true;},[&](std::exception_ptr) noexcept {done=true;})(test());
        (void)context.run_for(3s);return done && ok ? 0 : 1;
    }
    bool done=false,ok=false;
    capy::run_async(context.get_executor(),[&]() noexcept {done=true;},[&](std::exception_ptr) noexcept {done=true;})(run(context,endpoint,argv[4],ok));
    (void)context.run_for(5s);return done && ok ? 0 : 1;
}
