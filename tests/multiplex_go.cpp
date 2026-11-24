import std;
import grpc.multiplex;
import grpc.multiplex_channel;
import grpc.headers;
import grpc.session;
import grpc.stream;
import vless;
import net.socket_stream;
import capy;
import corosio;
namespace g=grpc;namespace v=vless;namespace io = ::corosio;
using namespace std::chrono_literals;
using Lower=net::SocketByteStream<io::tcp_socket>;
using Channel=g::MultiplexChannel<Lower,4>;using Stream=Channel::Stream;
struct Result{bool done=false,success=false;unsigned calls=0;};
auto failure()->capy::results<>{return {std::make_error_code(std::errc::io_error)};}
auto request(Stream& stream,std::uint16_t target,unsigned index,Result& result)->capy::task<capy::results<>>{
    auto user=*v::parse_user_id("00010203-0405-0607-0809-0a0b0c0d0e0f");auto header=v::encode_tcp_request({user,v::AddressKind::ipv4,target,{127,0,0,1}});if(!header)co_return failure();
    std::vector<std::uint8_t> payload(512*1024+index*17);for(unsigned i=0;i<payload.size();++i)payload[i]=(i+index*17)%251;
    if(!co_await stream.send(*header)||!co_await stream.send(payload)||!co_await stream.close_output()){
        auto reason=stream.failure();std::println("request {} write failed error={} code={}",index,reason?int(reason->error):-1,reason?reason->code:0);co_return failure();
    }
    std::array<std::uint8_t,16384> input{};std::vector<std::uint8_t> received;
    for(;;){auto count=co_await stream.read(input);if(!count||received.size()+*count>payload.size()+2){std::println("request {} read failed error={} code={} received={}",index,count?-1:int(count.error().error),count?0:count.error().code,received.size());co_return failure();}if(!*count)break;received.insert(received.end(),input.begin(),input.begin()+*count);}
    auto parsed=v::parse_response(received);
    if(parsed.status!=v::HeaderStatus::accepted||parsed.consumed!=2||received.size()!=payload.size()+2||!std::ranges::equal(std::span(received).subspan(2),payload))co_return failure();
    ++result.calls;co_return capy::results<>{};
}
auto application(Channel& channel,std::uint16_t target,Result& result)->capy::task<capy::results<>>{
    auto deadline=g::Clock::now()+12s;
    for(unsigned batch=0;batch<3;++batch){
        std::array<std::optional<Stream>,4> streams;
        for(auto& stream:streams){auto ticket=channel.open();if(!ticket)co_return failure();std::println("rpc-id={} slot={} generation={}",ticket->id,ticket->slot,ticket->generation);stream.emplace(channel,*ticket,deadline);}
        auto [error,a,b,c,d]=co_await capy::when_all(request(*streams[0],target,batch*4,result),request(*streams[1],target,batch*4+1,result),request(*streams[2],target,batch*4+2,result),request(*streams[3],target,batch*4+3,result));
        if(error)co_return failure();
    }
    co_return channel.shutdown()?capy::results<>{}:failure();
}
auto execute(io::io_context& context,io::tcp_socket& raw,std::uint16_t remote,std::uint16_t target,bool lite,Result& result)->capy::task<>{
    try{
        auto [connected]=co_await io::timeout(raw.connect(io::endpoint(io::ipv4_address::loopback(),remote)),g::Clock::now()+3s);if(connected){result.done=true;co_return;}
        auto profile=*g::RequestProfile::create("nexus.Service","127.0.0.1:"+std::to_string(remote),false);
        g::Limits limits{};
        auto session=g::MultiplexSession<4>::create(g::Role::client,profile,lite?g::ResponsePolicy::sing_box_lite:g::ResponsePolicy::standard,limits);if(!session){result.done=true;co_return;}
        Lower lower(raw);Channel channel(lower,std::move(*session),g::Clock::now()+15s);
        auto [error,driver,app]=co_await capy::when_all(channel.run(),application(channel,target,result));
        result.success=!error&&result.calls==12&&channel.finished()&&channel.drained()&&!channel.failure();
        std::println("network calls={} success={} finished={} drained={} failure={}",result.calls,result.success,channel.finished(),channel.drained(),channel.failure()?int(channel.failure()->error):-1);
    }catch(std::exception const& error){std::println("exception {}",error.what());}
    raw.close();result.done=true;(void)context;
}
int main(int argc,char** argv){
    if(argc!=5)return 64;auto remote=std::stoul(argv[1]),target=std::stoul(argv[2]),backend=std::stoul(argv[3]),lite=std::stoul(argv[4]);
    auto context=io::make_io_context(backend);io::tcp_socket raw(context);Result result;
    capy::run_async(context.get_executor(),[]{},[&](std::exception_ptr){raw.close();})(execute(context,raw,remote,target,lite,result));context.run_for(18s);
    if(!result.done){raw.close();context.restart();context.run_for(2s);}if(!result.done)std::_Exit(90);return result.success?0:1;
}
