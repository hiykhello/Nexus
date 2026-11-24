import std;
import grpc.multiplex;
import grpc.multiplex_channel;
import grpc.headers;
import grpc.session;
import grpc.stream;
import net.socket_stream;
import capy;
import corosio;
namespace g=grpc;
namespace io = ::corosio;
using namespace std::chrono_literals;
using Lower=net::SocketByteStream<io::local_stream_socket>;
using Channel=g::MultiplexChannel<Lower,4>;
using Stream=Channel::Stream;
auto failed()->capy::results<>{return {std::make_error_code(std::errc::io_error)};}
struct Result {bool done=false,success=false;unsigned clients=0,servers=0;};
auto receive(Stream& stream,std::span<std::uint8_t const> expected)->capy::task<bool>{
    std::array<std::uint8_t,711> buffer{};std::size_t offset=0;
    for(;;){auto count=co_await stream.read(buffer);if(!count||*count>expected.size()-offset)co_return false;
        if(!*count)co_return offset==expected.size();
        if(!std::ranges::equal(std::span(buffer).first(*count),expected.subspan(offset,*count)))co_return false;
        offset+=*count;
    }
}
auto client_rpc(Stream& stream,std::span<std::uint8_t const> payload,unsigned index,Result& result)->capy::task<capy::results<>>{
    if(!co_await stream.accept())co_return failed();
    if(index==3&&!co_await receive(stream,payload))co_return failed();
    if(!co_await stream.send(payload)||!co_await stream.close_output())co_return failed();
    if(index!=3&&!co_await receive(stream,payload))co_return failed();
    ++result.clients;co_return capy::results<>{};
}
auto server_rpc(Stream& stream,std::span<std::uint8_t const> payload,unsigned index,Result& result)->capy::task<capy::results<>>{
    if(index==0){auto [error]=co_await io::delay(40ms);if(error)co_return failed();}
    if(index==3){if(!co_await stream.send(payload)||!co_await stream.close_output())co_return failed();}
    if(!co_await receive(stream,payload))co_return failed();
    if(index!=3&&(!co_await stream.send(payload)||!co_await stream.close_output()))co_return failed();
    ++result.servers;co_return capy::results<>{};
}
using Payload=std::array<std::vector<std::uint8_t>,4>;
auto client_batch(Channel& channel,Payload const& payload,Result& result)->capy::task<capy::results<>>{
    std::array<std::optional<Stream>,4> streams;
    for(auto& stream:streams){auto ticket=channel.open();if(!ticket)co_return failed();stream.emplace(channel,*ticket,g::Clock::now()+4s);}
    auto [error,a,b,c,d]=co_await capy::when_all(client_rpc(*streams[0],payload[0],0,result),client_rpc(*streams[1],payload[1],1,result),client_rpc(*streams[2],payload[2],2,result),client_rpc(*streams[3],payload[3],3,result));
    if(error)co_return failed();
    co_return channel.shutdown()?capy::results<>{}:failed();
}
auto server_batch(Channel& channel,Payload const& payload,Result& result)->capy::task<capy::results<>>{
    std::array<std::optional<Stream>,4> streams;unsigned count=0;
    while(count<4){if(auto ticket=channel.accept()){streams[count++].emplace(channel,*ticket,g::Clock::now()+4s);continue;}if(!co_await channel.wait_change(g::Clock::now()+4s))co_return failed();}
    auto [error,a,b,c,d]=co_await capy::when_all(server_rpc(*streams[0],payload[0],0,result),server_rpc(*streams[1],payload[1],1,result),server_rpc(*streams[2],payload[2],2,result),server_rpc(*streams[3],payload[3],3,result));
    if(error)co_return failed();
    co_return channel.shutdown()?capy::results<>{}:failed();
}
auto exercise(Channel& client,Channel& server,Payload const& payload,Result& result)->capy::task<>{
    try{
        auto [error,crun,srun,capp,sapp]=co_await capy::when_all(client.run(),server.run(),client_batch(client,payload,result),server_batch(server,payload,result));
        result.success=!error&&result.clients==4&&result.servers==4&&client.finished()&&server.finished()&&client.drained()&&server.drained()&&!client.failure()&&!server.failure();
    }catch(std::exception const& error){std::println("exception {}",error.what());client.cancel();server.cancel();}
    result.done=true;
}
auto expect_local(Stream& stream,bool manual)->capy::task<capy::results<>>{
    if(!co_await stream.accept())co_return failed();
    std::array<std::uint8_t,1> buffer{};auto read=co_await stream.read(buffer);
    if(read||read.error().error!=(manual?g::Error::canceled:g::Error::timeout))co_return failed();
    co_return capy::results<>{};
}
auto local_cancel(Stream& stream,bool manual)->capy::task<capy::results<>>{
    if(manual){auto [error]=co_await io::delay(20ms);if(error)co_return failed();stream.cancel();}
    co_return capy::results<>{};
}
auto expect_peer_reset(Stream& stream)->capy::task<capy::results<>>{
    std::array<std::uint8_t,1> buffer{};auto read=co_await stream.read(buffer);
    if(read||read.error().error!=g::Error::reset)co_return failed();co_return capy::results<>{};
}
auto selective_client(Channel& channel,std::span<std::uint8_t const> payload,Result& result,bool manual)->capy::task<capy::results<>>{
    auto first=channel.open(),second=channel.open();if(!first||!second)co_return failed();
    Stream idle(channel,*first,g::Clock::now()+(manual?2s:30ms)),healthy(channel,*second,g::Clock::now()+2s);
    auto [error,a,b,c]=co_await capy::when_all(expect_local(idle,manual),local_cancel(idle,manual),client_rpc(healthy,payload,1,result));
    if(error||channel.failure())co_return failed();co_return channel.shutdown()?capy::results<>{}:failed();
}
auto selective_server(Channel& channel,std::span<std::uint8_t const> payload,Result& result)->capy::task<capy::results<>>{
    std::array<std::optional<Stream>,2> streams;unsigned count=0;
    while(count<2){if(auto ticket=channel.accept()){streams[count++].emplace(channel,*ticket,g::Clock::now()+2s);continue;}if(!co_await channel.wait_change(g::Clock::now()+2s))co_return failed();}
    auto [error,a,b]=co_await capy::when_all(expect_peer_reset(*streams[0]),server_rpc(*streams[1],payload,1,result));
    if(error||channel.failure())co_return failed();co_return channel.shutdown()?capy::results<>{}:failed();
}
auto selective_exercise(Channel& client,Channel& server,std::span<std::uint8_t const> payload,Result& result,bool manual)->capy::task<>{
    try{
        auto [error,crun,srun,capp,sapp]=co_await capy::when_all(client.run(),server.run(),selective_client(client,payload,result,manual),selective_server(server,payload,result));
        result.success=!error&&result.clients==1&&result.servers==1&&client.finished()&&server.finished()&&client.drained()&&server.drained()&&!client.failure()&&!server.failure();
    }catch(...){client.cancel();server.cancel();}
    result.done=true;
}
auto selective(bool uring,bool manual)->bool{
    auto context=io::make_io_context(uring);io::local_stream_socket left(context),right(context);if(io::connect_pair(left,right))return false;
    auto profile=*g::RequestProfile::create("multiplex","localhost",false);g::Limits limits{8192,4160,4096,65536,64,4*1024*1024};
    auto c=g::MultiplexSession<4>::create(g::Role::client,profile,g::ResponsePolicy::standard,limits),s=g::MultiplexSession<4>::create(g::Role::server,profile,g::ResponsePolicy::standard,limits);if(!c||!s)return false;
    Lower clower(left),slower(right);Channel client(clower,std::move(*c),g::Clock::now()+3s),server(slower,std::move(*s),g::Clock::now()+3s);
    std::vector<std::uint8_t> payload(128*1024,17);Result result;
    capy::run_async(context.get_executor(),[]{},[&](std::exception_ptr){client.cancel();server.cancel();})(selective_exercise(client,server,payload,result,manual));context.run_for(4s);
    if(!result.done){client.cancel();server.cancel();context.restart();context.run_for(1s);}
    std::println("selective backend={} manual={} done={} success={} healthy={}/{} failures={}/{}",uring,manual,result.done,result.success,result.clients,result.servers,client.failure()?int(client.failure()->error):-1,server.failure()?int(server.failure()->error):-1);
    if(!result.done)std::_Exit(91);return result.success;
}
auto test(bool uring)->bool{
    auto context=io::make_io_context(uring);io::local_stream_socket left(context),right(context);
    if(io::connect_pair(left,right))return false;
    auto profile=*g::RequestProfile::create("multiplex","localhost",false);
    g::Limits limits{8192,4160,4096,65536,64,4*1024*1024};
    auto c=g::MultiplexSession<4>::create(g::Role::client,profile,g::ResponsePolicy::standard,limits);
    auto s=g::MultiplexSession<4>::create(g::Role::server,profile,g::ResponsePolicy::standard,limits);if(!c||!s)return false;
    Lower clower(left),slower(right);Channel client(clower,std::move(*c),g::Clock::now()+5s),server(slower,std::move(*s),g::Clock::now()+5s);
    Payload payload;for(unsigned i=0;i<4;++i){payload[i].resize(i==0?512*1024:32768+i*119);for(unsigned j=0;j<payload[i].size();++j)payload[i][j]=(j+i*79)%251;}
    Result result;capy::run_async(context.get_executor(),[]{},[&](std::exception_ptr){client.cancel();server.cancel();})(exercise(client,server,payload,result));context.run_for(6s);
    if(!result.done){client.cancel();server.cancel();context.restart();context.run_for(1s);}
    std::println("multiplex backend={} done={} success={} client-rpcs={} server-rpcs={} finished={}/{} drained={}/{} failures={}/{}",uring,result.done,result.success,result.clients,result.servers,client.finished(),server.finished(),client.drained(),server.drained(),client.failure()?int(client.failure()->error):-1,server.failure()?int(server.failure()->error):-1);
    if(!result.done)std::_Exit(90);return result.success;
}
int main(){for(bool uring:{false,true}){if(!test(uring))return 1;for(bool manual:{false,true})if(!selective(uring,manual))return 2;}return 0;}
