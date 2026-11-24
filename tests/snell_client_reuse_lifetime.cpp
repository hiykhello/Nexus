import std;
import snell.record;
import snell.kdf;
import snell.cipher;
import snell.async_record;
import snell.owner;
import snell.client_owner;
import snell.client_stream;
import capy;
import corosio;
namespace s=snell;namespace io = ::corosio;
using namespace std::chrono_literals;
struct Socket {
    capy::async_event wait_cancel;s::Bytes input;std::size_t offset=0;bool canceled=false,block=false,waiting=false;
    explicit Socket(io::io_context&){}
    auto cancel() noexcept ->void {canceled=true;wait_cancel.set();}
    auto read_some(capy::mutable_buffer b)->capy::task<capy::results<std::size_t>> {
        auto n=std::min(b.size(),input.size()-offset);if(n)std::memcpy(b.data(),input.data()+offset,n);offset+=n;
        co_return capy::results<std::size_t>{std::error_code{},n};
    }
    auto write_some(capy::const_buffer b)->capy::task<capy::results<std::size_t>> {
        if(block){waiting=true;auto [ec]=co_await wait_cancel.wait();waiting=false;
            if(ec || canceled)co_return capy::results<std::size_t>{ec ? ec : std::make_error_code(std::errc::operation_canceled),0};}
        co_return capy::results<std::size_t>{std::error_code{},b.size()};
    }
};
using Token=s::ClientReuse<Socket>;using Stream=s::ClientStream<Socket>;
static auto reply(Socket& socket,s::View psk)->bool {
    std::array<std::uint8_t,16> salt{};auto key=s::Key::derive(psk,salt);if(!key)return false;
    s::Record<s::Cipher> writer{s::Cipher(std::move(*key))};std::array<std::uint8_t,2> first{0,'x'};
    auto data=writer.encode(first,{}),eof=writer.encode({},{});if(!data||!eof)return false;
    socket.input.assign(salt.begin(),salt.end());socket.input.insert(socket.input.end(),data->begin(),data->end());socket.input.insert(socket.input.end(),eof->begin(),eof->end());return true;
}
static auto complete(Socket& socket,s::ClientOwner const& owner)->capy::task<std::optional<Token>> {
    auto deadline=std::chrono::steady_clock::now()+2s;auto writer=co_await owner.start(socket,s::Request{5,{},"example.org",443},{},deadline);if(!writer)co_return std::nullopt;
    Stream stream(socket,owner,std::move(*writer));std::array<std::uint8_t,1> out{};
    if(!co_await stream.close_output(deadline))co_return std::nullopt;
    auto first=co_await stream.read(out,deadline);if(!first||*first!=1||out[0]!='x')co_return std::nullopt;
    auto eof=co_await stream.read(out,deadline);if(!eof||*eof)co_return std::nullopt;co_return stream.finish();
}
auto verify(io::io_context& context,bool& success)->capy::task<> {
    std::string psk="nexus-snell-test";auto bytes=s::Bytes(psk.begin(),psk.end());
    auto make_owner=[&](){return s::Credential::create(bytes,std::nullopt);};
    auto credential=make_owner(),other_credential=make_owner();if(!credential||!other_credential)co_return;
    s::ClientOwner owner(std::move(*credential)),other(std::move(*other_credential));auto deadline=std::chrono::steady_clock::now()+2s;
    {
        Socket first(context),second(context);if(!reply(first,bytes)||!reply(second,bytes))co_return;
        auto one=co_await complete(first,owner);auto two=co_await complete(second,owner);if(!one||!two)co_return;
        *one=std::move(*one);if(first.canceled||second.canceled||!one->can_resume(first,owner))co_return;
        *one=std::move(*two);if(!first.canceled||second.canceled||!one->can_resume(second,owner)||two->can_resume(second,owner))co_return;
        *two=std::move(*one);one.reset();if(second.canceled||!two->can_resume(second,owner))co_return;
        two.reset();if(!second.canceled)co_return;
    }
    {
        Socket socket(context);if(!reply(socket,bytes))co_return;auto token=co_await complete(socket,owner);if(!token)co_return;
        {auto abandoned=owner.resume_start(socket,std::move(*token),s::Request{5,{},"example.org",443},deadline);}
        token.reset();if(!socket.canceled)co_return;
    }
    for(bool wrong_owner:{false,true}){
        Socket socket(context),wrong_socket(context);if(!reply(socket,bytes))co_return;auto token=co_await complete(socket,owner);if(!token)co_return;
        auto& selected=wrong_owner?socket:wrong_socket;auto& chosen=wrong_owner?other:owner;
        auto result=co_await chosen.resume_start(selected,std::move(*token),s::Request{5,{},"example.org",443},deadline);token.reset();
        if(result||result.error()!=s::IoError::state||!socket.canceled||wrong_socket.canceled)co_return;
    }
    {
        Socket socket(context);if(!reply(socket,bytes))co_return;auto token=co_await complete(socket,owner);if(!token)co_return;
        auto result=co_await owner.resume_start(socket,std::move(*token),s::Request{5,{},"example.org",443},deadline);token.reset();if(!result||socket.canceled)co_return;
        {auto abandoned=std::move(*result);}if(!socket.canceled)co_return;
    }
    {
        Socket socket(context);if(!reply(socket,bytes))co_return;auto token=co_await complete(socket,owner);if(!token)co_return;
        std::unique_ptr<Stream> stream;
        {auto result=co_await owner.resume_start(socket,std::move(*token),s::Request{5,{},"example.org",443},deadline);token.reset();if(!result)co_return;
            stream=Stream::resume(socket,owner,std::move(*result));}
        if(!stream||socket.canceled)co_return;
        stream->cancel();if(!socket.canceled)co_return;
    }
    {
        Socket socket(context);if(!reply(socket,bytes))co_return;auto token=co_await complete(socket,owner);if(!token)co_return;socket.block=true;
        std::stop_source stop;bool done=false,failed=false;
        capy::run_async(context.get_executor(),stop.get_token(),[&](auto){done=true;},[&](std::exception_ptr){failed=true;done=true;})(
            owner.resume_start(socket,std::move(*token),s::Request{5,{},"example.org",443},deadline));token.reset();
        (void)co_await io::delay(20ms);bool suspended=socket.waiting&&!socket.canceled;stop.request_stop();
        for(int i=0;i<100&&!done;++i)(void)co_await io::delay(5ms);
        if(!done){socket.cancel();for(int i=0;i<100&&!done;++i)(void)co_await io::delay(5ms);}
        if(!done||failed||!suspended||!socket.canceled)co_return;
    }
    success=true;
}
int main(int argc,char** argv){bool uring=argc>1&&std::string_view(argv[1])=="uring";if(uring&&!io::has_uring)return 77;
    auto context=io::make_io_context(uring);bool success=false,done=false;
    capy::run_async(context.get_executor(),[&]{done=true;},[&](std::exception_ptr){done=true;})(verify(context,success));
    context.run_for(4s);if(!done||!success)return 1;std::println("Snell reuse token ownership and cancellation passed");return 0;}
