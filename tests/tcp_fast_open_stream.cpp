import std;
import net.tcp_fast_open_stream;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;
namespace io=nex::corosio;namespace capy=nex::capy;
using namespace std::chrono_literals;
struct AbandonState {bool reader=false,writer=false,reader_destroyed=false,writer_destroyed=false,parent_destroyed=false,children_first=false,returned=false;};
auto abandon_reader(net::FastOpenStream& stream,AbandonState& state) -> capy::task<capy::results<>> {
    struct Guard {bool& destroyed;~Guard(){destroyed=true;}} guard{state.reader_destroyed};
    state.reader=true;std::array<std::uint8_t,1> data{};(void)co_await stream.read(data);co_return capy::results<>{};
}
auto abandon_writer(net::FastOpenStream& stream,AbandonState& state) -> capy::task<capy::results<>> {
    struct Guard {bool& destroyed;~Guard(){destroyed=true;}} guard{state.writer_destroyed};
    state.writer=true;std::vector<std::uint8_t> data(16*1024*1024,0x5a);(void)co_await stream.send(data);co_return capy::results<>{};
}
auto abandon_parent(io::io_context& context,io::endpoint endpoint,AbandonState& state) -> capy::task<> {
    net::FastOpenStream stream(context,{endpoint},std::chrono::steady_clock::now()+3s);
    struct Guard {AbandonState& state;~Guard(){state.children_first=state.reader_destroyed && state.writer_destroyed;state.parent_destroyed=true;}} guard{state};
    (void)co_await capy::when_all(abandon_reader(stream,state),abandon_writer(stream,state));state.returned=true;
}
auto abandon_test(bool uring,io::endpoint endpoint) -> int {
    AbandonState state;
    {
        auto context=io::make_io_context(uring);
        capy::run_async(context.get_executor())(abandon_parent(context,endpoint,state));
        (void)context.run_for(300ms);
        if(!state.reader || !state.writer || state.reader_destroyed || state.writer_destroyed || state.parent_destroyed)return 1;
    }
    if(!state.parent_destroyed || !state.children_first || state.returned)return 1;
    std::println("active reader and writer abandoned before stream owner");return 0;
}
auto main(int argc,char** argv) -> int {
    if(argc!=5)return 2;bool uring=std::string_view(argv[1])=="uring";
    if(uring && !io::has_uring)return 77;
    auto context=io::make_io_context(uring);auto port=static_cast<std::uint16_t>(std::strtoul(argv[2],nullptr,10));
    auto address=std::string_view(argv[3]);auto mode=std::string_view(argv[4]);
    auto endpoint=address=="v6" ? io::endpoint(io::ipv6_address::loopback(),port) : address=="blackhole" ?
        io::endpoint(io::ipv4_address({192,0,2,1}),port) : io::endpoint(io::ipv4_address::loopback(),port);
    if(mode=="abandon")return abandon_test(uring,endpoint);
    auto until=std::chrono::steady_clock::now()+3s;
    auto connect_until=mode=="later" ? std::chrono::steady_clock::now()+150ms : until;
    net::FastOpenStream stream(context,{endpoint},connect_until);
    std::vector<std::uint8_t> payload(200000);for(std::size_t i=0;i<payload.size();++i)payload[i]=i%251;
    bool cancel_mode=mode=="cancel" || mode=="duplicate";
    bool reader_done=false,writer_done=false,reader_ok=false,writer_ok=false,cancel_done=!cancel_mode,duplicate_ok=mode!="duplicate";
    auto reader=[&]() -> capy::task<> {
        std::array<std::uint8_t,1> data{};auto result=co_await stream.read(data,until);
        reader_ok=cancel_mode ? !result && result.error()==capy::cond::canceled : result && *result==1 && data[0]==0x5a;
    };
    auto writer=[&]() -> capy::task<> {
        if(mode=="half")writer_ok=co_await stream.close_output(until);
        else {
            if(mode=="later") {
                auto connected=co_await stream.send({},until);if(!connected)co_return;
                io::steady_timer timer(context);timer.expires_at(std::chrono::steady_clock::now()+250ms);
                auto [error]=co_await timer.wait();if(error)co_return;
            }
            auto sent=co_await stream.send(payload,until);
            writer_ok=cancel_mode ? !sent : sent && co_await stream.close_output(until);
        }
    };
    auto cancel=[&]() -> capy::task<> {
        io::steady_timer timer(context);timer.expires_at(std::chrono::steady_clock::now()+100ms);auto [error]=co_await timer.wait();
        if(!error && mode=="duplicate") {
            std::array<std::uint8_t,1> data{};
            auto second_read=co_await stream.read(data,until);auto second_write=co_await stream.send(data,until);
            duplicate_ok=!second_read && second_read.error()==std::errc::operation_in_progress && !second_write;
        }
        if(!error)stream.cancel();cancel_done=true;
    };
    auto launch_reader=[&] {capy::run_async(context.get_executor(),[&]() noexcept {reader_done=true;},[&](std::exception_ptr) noexcept {reader_done=true;})(reader());};
    auto launch_writer=[&] {capy::run_async(context.get_executor(),[&]() noexcept {writer_done=true;},[&](std::exception_ptr) noexcept {writer_done=true;})(writer());};
    if(mode=="read-first") {launch_reader();launch_writer();} else {launch_writer();launch_reader();}
    if(cancel_mode)capy::run_async(context.get_executor())(cancel());
    (void)context.run_for(5s);
    if(!reader_done || !writer_done || !cancel_done || !reader_ok || !writer_ok || !duplicate_ok) {
        stream.cancel();context.restart();(void)context.run();return 1;
    }
    std::println("{} concurrent reader/writer drained",mode);return 0;
}
