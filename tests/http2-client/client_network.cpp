import std;
import http2.client_channel;
import http2.headers;
import net.socket_stream;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;
namespace h=http2;
namespace io=nex::corosio;
namespace capy=nex::capy;
using namespace std::chrono_literals;
using Clock=std::chrono::steady_clock;
using Lower=net::SocketByteStream<io::tcp_socket>;
using Channel=h::ClientChannel<Lower,4>;
struct Fixture {
    io::io_context context;
    io::tcp_socket socket{context};
    capy::async_event map_paused;
    bool done=false,success=false,app_complete=false,waiter_complete=false;
    std::string_view stage="start";
    explicit Fixture(bool uring):context(io::make_io_context(uring)){}
};
static auto fields(std::string_view path,std::string_view length) -> std::array<h::FieldView,5> {
    return {{{":method","POST"},{":scheme","https"},{":authority","control.example"},{":path",path},{"content-length",length}}};
}
static auto header(std::span<h::Header const> fields,std::string_view name,std::string_view value) -> bool {
    return std::ranges::any_of(fields,[&](auto const& field){return field.name==name&&field.value==value;});
}
struct AppGuard {Channel& channel;bool released=false;~AppGuard(){if(!released)channel.cancel();}};
auto application(Fixture& fixture,Channel& channel,Clock::time_point deadline) -> capy::task<capy::results<>> {
    std::array<std::uint8_t,3> map_body{1,2,3};std::array<std::uint8_t,65536> auth;auth.fill(42);
    std::array<std::uint8_t,32768> update_body;update_body.fill(51);std::array<std::uint8_t,4096> update_last;update_last.fill(52);
    AppGuard guard{channel};
    try {
        auto map=channel.submit(fields("/map","3"),{map_body,true});auto registration=channel.submit(fields("/register","65536"),{auth,true});
        auto update=channel.submit(fields("/update","36864"),{update_body,false});if(!map||!registration||!update)throw 3;
        bool supplied=false,cleansed=false,resumed=false;std::size_t received=0;std::string registered;
        std::optional<Clock::time_point> paused;std::span<std::uint8_t const> stable_map;std::optional<h::StreamTicket> echo;
        fixture.stage="simultaneous Map/register/update";
        for(unsigned turn=0;turn<100000;++turn){
            if(Clock::now()>=deadline||channel.failure())throw 4;
            if(!echo){
                if(!supplied&&channel.tx_consumed(*update)==std::expected<bool,h::ClientFailure>{true}){if(channel.provide(*update,{update_last,true})!=std::expected<bool,h::ClientFailure>{true})throw 7;supplied=true;}
                if(!cleansed&&channel.tx_consumed(*registration)==std::expected<bool,h::ClientFailure>{true}){auth.fill(0);cleansed=true;}
                auto map_view=channel.peek(*map);if(!map_view)throw 8;
                if(!resumed&&!map_view->empty()){
                    if(!paused){paused=Clock::now();stable_map=*map_view;fixture.map_paused.set();}
                    if(map_view->data()!=stable_map.data()||map_view->size()<stable_map.size())throw 9;
                    for(std::size_t i=0;i<stable_map.size();++i)if(stable_map[i]!=static_cast<std::uint8_t>(i*17%251))throw 10;
                }
                auto short_view=channel.peek(*registration);if(!short_view)throw 11;
                registered.append(reinterpret_cast<char const*>(short_view->data()),short_view->size());if(!channel.consume(*registration,short_view->size()))throw 12;
                auto a=channel.response(*registration),b=channel.response(*update);if(!a||!b||a->failure||b->failure)throw 13;
                if(!resumed&&a->closed&&b->closed){
                    if(a->status!=200||b->status!=204||registered!="registered\n"||!header(a->trailers,"x-register-end","complete")||!paused||Clock::now()-*paused<1s||channel.response(*map)->remote_end)throw 14;
                    resumed=true;fixture.stage="resume Map after independent short streams";
                }
                if(resumed){
                    for(std::size_t i=0;i<map_view->size();++i)if((*map_view)[i]!=static_cast<std::uint8_t>((received+i)*17%251))throw 15;
                    received+=map_view->size();if(!channel.consume(*map,map_view->size()))throw 16;
                    auto response=channel.response(*map);if(!response||response->failure)throw 17;
                    if(response->closed&&channel.peek(*map)->empty()){
                        if(received!=786432||response->status!=200||!header(response->trailers,"x-map-end","complete")||!cleansed||!supplied)throw 18;
                        if(!*channel.release(*map)||!*channel.release(*registration)||!*channel.release(*update))throw 19;
                        if(channel.response(*registration))throw 20;
                        auto next=channel.submit(fields("/echo","0"));if(!next||next->generation<=map->generation)throw 21;echo=*next;fixture.stage="reuse released slot";
                    }else if(!channel.peek(*map)->empty())continue;
                }
            }else{
                auto response=channel.response(*echo);if(!response||response->failure)throw 22;
                if(response->closed){if(response->status!=204||!*channel.release(*echo)||!channel.shutdown())throw 23;fixture.app_complete=true;guard.released=true;co_return capy::results<>{};}
            }
            if(!co_await channel.wait_change(deadline))throw 24;
        }
    }catch(int code){std::cerr<<"H2 channel application stage="<<fixture.stage<<" code="<<code<<'\n';}
    co_return capy::results<>{std::make_error_code(std::errc::io_error)};
}
auto isolated_waiter(Fixture& fixture,Channel& channel) -> capy::task<capy::results<>> {
    auto [error]=co_await fixture.map_paused.wait();if(error)co_return capy::results<>{error};
    auto deadline=Clock::now()+60ms;
    while(co_await channel.wait_change(deadline)){}
    fixture.waiter_complete=!channel.failure()&&!channel.finished()&&Clock::now()>=deadline;
    co_return capy::results<>{fixture.waiter_complete?std::error_code{}:std::make_error_code(std::errc::io_error)};
}
auto exercise(Fixture& fixture,std::uint16_t port) -> capy::task<> {
    try {
        auto deadline=Clock::now()+15s;fixture.stage="connect";
        auto [error]=co_await fixture.socket.connect(io::endpoint(io::ipv4_address::loopback(),port));if(error)throw 1;
        Lower lower(fixture.socket);h::ClientLimits limits;limits.stream_window=4096;auto made=h::Client<4>::create(limits);if(!made)throw 2;
        Channel channel(lower,std::move(*made),deadline);
        auto [signal,run,app,waiter]=co_await capy::when_all(channel.run(),application(fixture,channel,deadline),isolated_waiter(fixture,channel));(void)run;(void)app;(void)waiter;
        fixture.success=!signal&&fixture.app_complete&&fixture.waiter_complete&&channel.finished()&&channel.drained()&&!channel.failure();
        if(!fixture.success&&channel.failure())std::cerr<<"H2 channel failed error="<<int(channel.failure()->error)<<":"<<channel.failure()->code<<'\n';
    }catch(...){std::cerr<<"H2 network fixture exception at "<<fixture.stage<<'\n';}
    fixture.socket.close();fixture.done=true;
}
auto main(int argc,char** argv) -> int {
    if(argc!=3)return 64;unsigned port=0,backend=0;auto [p,pe]=std::from_chars(argv[1],argv[1]+std::char_traits<char>::length(argv[1]),port);auto [b,be]=std::from_chars(argv[2],argv[2]+std::char_traits<char>::length(argv[2]),backend);
    if(pe!=std::errc{}||*p||!port||port>65535||be!=std::errc{}||*b||backend>1)return 64;if(backend&&!io::has_uring)return 77;
    Fixture fixture(backend);capy::run_async(fixture.context.get_executor())(exercise(fixture,static_cast<std::uint16_t>(port)));fixture.context.run_for(17s);
    if(!fixture.done){fixture.socket.close();fixture.context.restart();fixture.context.run_for(1s);}if(!fixture.done||!fixture.context.stopped())std::_Exit(90);
    if(fixture.success)std::println("H2 shared Driver Go TCP: backend={} three simultaneous streams, Map >=1s paused credit, caller body cleansing/deferred chunk, trailers, 768KiB resume, slot reuse, isolated waiter timeout and drained final GOAWAY passed",backend);
    return fixture.success?0:1;
}
