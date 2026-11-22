#include <sys/socket.h>
import std;
import shadowsocks.key;
import shadowsocks.chunk;
import shadowsocks.frame;
import shadowsocks.corosio_client;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;
namespace s=shadowsocks;namespace io=nex::corosio;namespace capy=nex::capy;
using namespace std::chrono_literals;
using Socket=io::local_stream_socket;
struct State {bool done=false,ok=false;};
auto read(s::detail::FrameReader<Socket>& reader,State& state,bool first) -> capy::task<> {
    std::array<std::uint8_t,32> bytes{};
    auto value=co_await reader.read(bytes,std::chrono::steady_clock::now()+(first ? 50ms : 1s),true);
    state.ok=first ? !value && value.error()==s::detail::ReadError::timeout :
        value && *value==3 && bytes[0]==1 && bytes[1]==2 && bytes[2]==3;
    state.done=true;
}
auto exercise(bool uring) -> bool {
    auto context=io::make_io_context(uring);Socket receiver(context),sender(context);
    if(io::connect_pair(receiver,sender))return false;
    std::array<std::uint8_t,16> psk{},salt{};
    auto tx=s::SessionKey::derive(psk,salt),rx=s::SessionKey::derive(psk,salt);
    if(!tx || !rx)return false;
    auto enc=s::ChunkCipher::create(std::move(*tx),true),dec=s::ChunkCipher::create(std::move(*rx),false);
    if(!enc || !dec)return false;
    s::FrameEncoder writer(std::move(*enc));auto frame=writer.encode(std::array<std::uint8_t,3>{1,2,3});
    if(!frame || frame->size()<7)return false;
    s::detail::FrameReader reader(receiver,s::detail::StartedResponse{std::move(*dec),{},{}});
    if(::send(sender.native_handle(),frame->data(),6,MSG_NOSIGNAL)!=6)return false;
    State first;capy::run_async(context.get_executor())(read(reader,first,true));context.run_for(1s);
    if(!first.done || !first.ok)return false;
    if(::send(sender.native_handle(),frame->data()+6,frame->size()-6,MSG_NOSIGNAL)!=static_cast<ssize_t>(frame->size()-6))return false;
    State second;capy::run_async(context.get_executor())(read(reader,second,false));context.restart();context.run_for(1s);
    return second.done && second.ok;
}
auto main()->int {if(!exercise(false) || !exercise(true))return 1;std::println("SS frame partial read timeout and resume passed");}
