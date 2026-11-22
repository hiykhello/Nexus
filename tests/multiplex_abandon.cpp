import std;
import grpc.multiplex;
import grpc.multiplex_channel;
import grpc.headers;
import grpc.session;
import grpc.stream;
import net.socket_stream;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;
namespace g=grpc;namespace capy=nex::capy;namespace io=nex::corosio;
using namespace std::chrono_literals;
using Lower=net::SocketByteStream<io::local_stream_socket>;
extern "C" auto meter_begin(std::size_t,std::size_t)->void;
extern "C" auto meter_end()->std::size_t;
extern "C" auto meter_failed()->bool;
extern "C" auto meter_live()->std::size_t;
extern "C" auto meter_persistent(bool)->void;
struct State;
struct TrackedLower {
    Lower lower;State& state;
    ~TrackedLower();
    auto read(std::span<std::uint8_t>,g::Deadline)->capy::task<std::expected<std::size_t,std::error_code>>;
    auto send(std::span<std::uint8_t const>,g::Deadline)->capy::task<bool>;
    auto close_output(g::Deadline deadline){return lower.close_output(deadline);}
    auto cancel() noexcept->void;
};
using Channel=g::MultiplexChannel<TrackedLower,4>;
struct State {
    Channel* channel=nullptr;
    bool entered=false,destroyed=false,valid=true,returned=false,parameter_destroyed=false;
    unsigned apps=0,readers=0,writers=0,max_readers=0,max_writers=0,cancels=0;
};
struct Flight {
    State& state;unsigned& active;
    Flight(State& owner,unsigned& count,unsigned& maximum):state(owner),active(count){++active;maximum=std::max(maximum,active);if(active>1||state.destroyed)state.valid=false;}
    ~Flight(){if(state.destroyed)state.valid=false;--active;}
};
TrackedLower::~TrackedLower(){if(state.readers||state.writers)state.valid=false;state.destroyed=true;}
auto TrackedLower::cancel() noexcept->void{++state.cancels;lower.cancel();}
auto TrackedLower::read(std::span<std::uint8_t> bytes,g::Deadline deadline)->capy::task<std::expected<std::size_t,std::error_code>>{
    Flight flight(state,state.readers,state.max_readers);co_return co_await lower.read(bytes,deadline);
}
auto TrackedLower::send(std::span<std::uint8_t const> bytes,g::Deadline deadline)->capy::task<bool>{
    Flight flight(state,state.writers,state.max_writers);co_return co_await lower.send(bytes,deadline);
}
struct ParameterGuard{
    State* state;
    explicit ParameterGuard(State& value) noexcept:state(&value){}
    ParameterGuard(ParameterGuard const&)=delete;
    ParameterGuard(ParameterGuard&& other) noexcept:state(std::exchange(other.state,nullptr)){}
    ~ParameterGuard(){if(state)state->parameter_destroyed=true;}
};
auto waiting(Channel::Stream& stream,State& state,bool write)->capy::task<capy::results<>>{
    struct App{State& state;App(State& value):state(value){++state.apps;}~App(){--state.apps;}} app(state);
    if(write){std::vector<std::uint8_t> bytes(512*1024,13);(void)co_await stream.send(bytes,g::Clock::now()+5s);}
    else{std::array<std::uint8_t,32> bytes{};(void)co_await stream.read(bytes,g::Clock::now()+5s);}
    co_return capy::results<>{};
}
auto applications(Channel& channel,State& state,bool write)->capy::task<capy::results<>>{
    std::array<std::optional<Channel::Stream>,4> streams;
    for(auto& stream:streams){auto ticket=channel.open();if(!ticket)co_return capy::results<>{std::make_error_code(std::errc::io_error)};stream.emplace(channel,*ticket);}
    auto [error,a,b,c,d]=co_await capy::when_all(waiting(*streams[0],state,write),waiting(*streams[1],state,write),waiting(*streams[2],state,write),waiting(*streams[3],state,write));
    co_return capy::results<>{error};
}
auto owner(io::io_context& context,ParameterGuard parameter,bool write)->capy::task<>{
    auto& state=*parameter.state;io::local_stream_socket socket(context),peer(context);if(io::connect_pair(socket,peer))co_return;
    if(socket.set_option(io::socket_option::send_buffer_size{4096}))co_return;
    auto profile=*g::RequestProfile::create("multiplex","localhost",false);
    g::Limits limits{8192,4160,4096,65536,64,4*1024*1024};auto protocol=g::MultiplexSession<4>::create(g::Role::client,profile,g::ResponsePolicy::standard,limits);if(!protocol)co_return;
    TrackedLower lower{Lower(socket),state};Channel channel(lower,std::move(*protocol),g::Clock::now()+6s);
    struct Lifetime{State& state;~Lifetime(){state.channel=nullptr;}} lifetime{state};state.channel=&channel;state.entered=true;
    auto [error,run,app]=co_await capy::when_all(channel.run(),applications(channel,state,write));(void)error;(void)run;(void)app;
    state.returned=true;
}
static auto test(bool uring,std::string_view mode,bool write,bool oom)->bool{
    State state;bool pending=false;std::size_t allocations=0;bool fired=false;
    {
        auto context=io::make_io_context(uring);
        capy::run_async(context.get_executor(),[]{},[&](std::exception_ptr){state.valid=false;})(owner(context,ParameterGuard(state),write));
        if(mode!="queued"){
            context.run_for(10ms);pending=state.entered&&state.apps==4&&!state.returned&&state.readers==1&&(!write||state.writers==1);
            if(mode=="stop"&&state.channel){state.channel->cancel();context.restart();context.run_for(1s);}
        }
        if(oom){meter_persistent(true);meter_begin(1,1);}
    }
    if(oom){allocations=meter_end();fired=meter_failed();}
    bool clean=state.parameter_destroyed&&!state.apps&&!state.readers&&!state.writers&&state.valid&&!meter_live();
    bool expected=mode=="queued"?!state.entered:pending&&state.destroyed&&state.cancels&&(state.returned==(mode=="stop"));
    std::println("backend={} mode={} write={} oom={} pending={} clean={} expected={} max-readers={} max-writers={} cancels={} new-calls={} fired={} live={}",uring,mode,write,oom,pending,clean,expected,state.max_readers,state.max_writers,state.cancels,allocations,fired,meter_live());
    return clean&&expected;
}
int main(){for(bool uring:{false,true}){
    for(bool oom:{false,true})if(!test(uring,"queued",false,oom))return 1;
    for(bool write:{false,true}){
        if(!test(uring,"stop",write,false))return 2;
        for(bool oom:{false,true})if(!test(uring,"abandon",write,oom))return 3;
    }
}return 0;}
