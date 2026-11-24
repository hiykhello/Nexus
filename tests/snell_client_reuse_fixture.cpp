import std;
import snell.record;
import snell.cipher;
import snell.owner;
import snell.client_owner;
import snell.client_stream;
import snell.async_record;
import capy;
import corosio;
namespace s=snell;namespace io = ::corosio;using namespace std::chrono_literals;
struct State{io::io_context context;io::tcp_socket socket{context};bool done=false,ok=false;explicit State(bool u):context(io::make_io_context(u)){} };
using Stream=s::ClientStream<io::tcp_socket>;
auto upload(Stream& stream,s::Deadline deadline,bool& ok)->capy::task<capy::results<>> {
    std::string data="early-data";ok=co_await stream.send(s::View(reinterpret_cast<std::uint8_t const*>(data.data()),data.size()),deadline) && co_await stream.close_output(deadline);
    co_return capy::results<>{ok?std::error_code{}:std::make_error_code(std::errc::io_error)};
}
auto download(Stream& stream,s::Deadline deadline,bool& ok)->capy::task<capy::results<>> {
    std::array<std::uint8_t,3> buffer{};std::string received;
    for(;;){auto count=co_await stream.read(buffer,deadline);if(!count)co_return capy::results<>{std::make_error_code(std::errc::io_error)};if(!*count)break;
        if(stream.finish())co_return capy::results<>{std::make_error_code(std::errc::state_not_recoverable)};
        received.append(reinterpret_cast<char*>(buffer.data()),*count);}
    auto again=co_await stream.read(buffer,deadline);ok=again && !*again && received=="server-response";co_return capy::results<>{ok?std::error_code{}:std::make_error_code(std::errc::io_error)};
}
auto operation(State& f,unsigned port)->capy::task<> {
    try {auto deadline=std::chrono::steady_clock::now()+5s;auto [ec]=co_await io::timeout(f.socket.connect(io::endpoint(io::ipv4_address::loopback(),port)),deadline);if(ec)co_return;
        std::string p="nexus-snell-test";auto credential=s::Credential::create(s::Bytes(p.begin(),p.end()),std::nullopt);if(!credential)co_return;s::ClientOwner owner(std::move(*credential));
        auto writer=co_await owner.start(f.socket,s::Request{5,{},"example.org",443},{},deadline);if(!writer)co_return;
        std::optional<s::ClientReuse<io::tcp_socket>> records;
        {Stream stream(f.socket,owner,std::move(*writer));if(stream.finish())co_return;
            bool up=false,down=false;auto [error,a,b]=co_await capy::when_all(upload(stream,deadline,up),download(stream,deadline,down));(void)a;(void)b;
            if(error||!up||!down)co_return;auto next=stream.finish();if(!next||stream.finish())co_return;records.emplace(std::move(*next));}
        std::string other="another-snell-user";auto other_credential=s::Credential::create(s::Bytes(other.begin(),other.end()),std::nullopt);if(!other_credential)co_return;
        s::ClientOwner other_owner(std::move(*other_credential));
        if(records->can_resume(f.socket,other_owner))co_return;
        io::tcp_socket wrong_socket(f.context);if(records->can_resume(wrong_socket,owner))co_return;
        for(int i=0;i<3;++i){
            auto sent=co_await owner.resume_start(f.socket,std::move(*records),s::Request{5,{},"example.org",443},deadline);records.reset();if(!sent)co_return;
            if(sent->can_resume(f.socket,owner))co_return;
            auto stream=Stream::resume(f.socket,owner,std::move(*sent));if(!stream||stream->finish())co_return;
            bool up=false,down=false;auto [error,a,b]=co_await capy::when_all(upload(*stream,deadline,up),download(*stream,deadline,down));(void)a;(void)b;
            if(error||!up||!down)co_return;auto next=stream->finish();if(!next||stream->finish())co_return;records.emplace(std::move(*next));
        }
        f.ok=true;
    }catch(...){}f.socket.close();f.done=true;
}
auto main(int argc,char** argv)->int {if(argc!=3)return 64;bool uring=std::string_view(argv[2])=="1";if(uring&&!io::has_uring)return 77;State f(uring);
    capy::run_async(f.context.get_executor())(operation(f,std::stoi(argv[1])));f.context.run_for(8s);if(!f.done){f.socket.cancel();f.context.restart();f.context.run_for(1s);}return f.done&&f.ok&&f.context.stopped()?0:1;}
