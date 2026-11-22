import std;
import snell.http_obfs;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;

namespace capy=nex::capy;
namespace io=nex::corosio;
using namespace std::chrono_literals;

// A bounded fake socket exposes partial writes and fragmented reads while the
// actual obfs adapter and the timeout/cancellation machinery remain in use.
struct Socket {
    capy::async_event wait_cancel;
    std::vector<std::uint8_t> input,output;
    std::size_t read_offset=0,read_chunk=3,writes=0,reads=0;
    int first_mode=0,fail_write=0,block_write=0,block_read=0;
    bool canceled=false;
    explicit Socket(io::io_context&){}
    auto cancel() noexcept -> void {canceled=true;wait_cancel.set();}
    auto read_some(capy::mutable_buffer buffer)->capy::task<capy::results<std::size_t>> {
        ++reads;
        if(block_read && reads==std::size_t(block_read)) {
            auto [ec]=co_await wait_cancel.wait();if(ec || canceled)co_return capy::results<std::size_t>{ec ? ec : std::make_error_code(std::errc::operation_canceled),0};
        }
        auto n=std::min({read_chunk,buffer.size(),input.size()-read_offset});
        if(n)std::memcpy(buffer.data(),input.data()+read_offset,n);
        read_offset+=n;co_return capy::results<std::size_t>{std::error_code{},n};
    }
    auto write_some(capy::const_buffer buffer)->capy::task<capy::results<std::size_t>> {
        ++writes;
        if(block_write && writes==std::size_t(block_write)) {
            auto [ec]=co_await wait_cancel.wait();if(ec || canceled)co_return capy::results<std::size_t>{ec ? ec : std::make_error_code(std::errc::operation_canceled),0};
        }
        if(fail_write && writes==std::size_t(fail_write))co_return capy::results<std::size_t>{std::make_error_code(std::errc::io_error),0};
        auto bytes=std::span(static_cast<std::uint8_t const*>(buffer.data()),buffer.size());
        std::size_t n=std::min<std::size_t>(bytes.size(),7);
        if(writes==1 && first_mode>=0){
            constexpr std::array<std::uint8_t,4> mark{'\r','\n','\r','\n'};
            auto found=std::ranges::search(bytes,mark);
            if(found.empty())co_return capy::results<std::size_t>{std::make_error_code(std::errc::protocol_error),0};
            auto head=std::size_t(found.end()-bytes.begin());
            n=first_mode==0 ? head-1 : first_mode==1 ? head : std::min(bytes.size(),head+5);
        }
        output.insert(output.end(),bytes.begin(),bytes.begin()+n);
        co_return capy::results<std::size_t>{std::error_code{},n};
    }
};

auto verify(io::io_context& context,bool& success) -> capy::task<> {
    success=false;
    {
        Socket socket(context);socket.first_mode=-1;socket.input={'a','b','c'};
        snell::HttpObfs adapter(socket,false,false);std::array<std::uint8_t,3> out{};
        auto [ec,n]=co_await adapter.read_some(capy::mutable_buffer(out.data(),out.size()));
        if(ec||n!=3||out!=std::array<std::uint8_t,3>{'a','b','c'})co_return;
        auto [error,written]=co_await adapter.write_some(capy::const_buffer(out.data(),out.size()));
        if(error||written!=3||socket.output!=std::vector<std::uint8_t>{'a','b','c'})co_return;
    }
    for(bool server:{false,true})for(int mode=0;mode<3;++mode){
        Socket socket(context);socket.first_mode=mode;
        snell::HttpObfs adapter(socket,true,server,"example.test","/fragment");
        std::string data="0123456789ABCDEFGHIJKLMNOP";std::size_t offset=0;
        while(offset<data.size()){
            auto [ec,n]=co_await adapter.write_some(capy::const_buffer(data.data()+offset,data.size()-offset));
            if(ec||!n||n>data.size()-offset)co_return;offset+=n;
        }
        std::string wire(socket.output.begin(),socket.output.end());auto end=wire.find("\r\n\r\n");
        if(end==wire.npos||wire.substr(end+4)!=data)co_return;
        if(!server && (wire.find("GET /fragment HTTP/1.1\r\n")!=0 ||
           wire.find("Host: example.test\r\n")==wire.npos || wire.find("Content-Length: 26\r\n")==wire.npos))co_return;
        if(server && wire.find("HTTP/1.1 101 ")!=0)co_return;
    }
    {
        Socket socket(context);std::string response="HTTP/1.1 101 OK\r\nX: y\r\n\r\nPAYLOAD";
        socket.input.assign(response.begin(),response.end());
        snell::HttpObfs adapter(socket,true,false);std::array<std::uint8_t,32> output{};std::string got;
        while(got.size()<7){auto [ec,n]=co_await adapter.read_some(capy::mutable_buffer(output.data(),output.size()));if(ec||!n)co_return;got.append(reinterpret_cast<char*>(output.data()),n);}
        if(got!="PAYLOAD")co_return;
    }
    {
        Socket socket(context);socket.input.assign(16385,'x');socket.read_chunk=512;
        snell::HttpObfs adapter(socket,true,true);std::array<std::uint8_t,1> out{};
        auto [ec,n]=co_await adapter.read_some(capy::mutable_buffer(out.data(),out.size()));if(!ec||n||!socket.canceled)co_return;
    }
    for(bool blocked:{false,true}){
        Socket socket(context);socket.first_mode=0;if(blocked)socket.block_write=2;else socket.fail_write=2;
        snell::HttpObfs adapter(socket,true,false);std::string data="payload";
        auto op=adapter.write_some(capy::const_buffer(data.data(),data.size()));
        auto [ec,n]=co_await io::timeout(std::move(op),std::chrono::steady_clock::now()+40ms);
        if(!ec||n||!socket.canceled||(blocked&&!capy::is_timeout(ec)))co_return;
    }
    {
        Socket socket(context);socket.input={'H','T','T','P'};socket.block_read=2;
        snell::HttpObfs adapter(socket,true,false);std::array<std::uint8_t,1> out{};
        auto op=adapter.read_some(capy::mutable_buffer(out.data(),out.size()));
        auto [ec,n]=co_await io::timeout(std::move(op),std::chrono::steady_clock::now()+40ms);
        if(!capy::is_timeout(ec)||n||!socket.canceled)co_return;
    }
    success=true;
}

int main(int argc,char** argv) {
    bool uring=argc>1 && std::string_view(argv[1])=="uring";
    if(uring&&!io::has_uring)return 77;
    auto context=io::make_io_context(uring);bool success=false,done=false;
    capy::run_async(context.get_executor(),[&]() noexcept {done=true;},[&](std::exception_ptr) noexcept {done=true;})(verify(context,success));
    (void)context.run_for(3s);
    if(!done||!success)return 1;
    std::println("Snell HTTP obfs partial writes, fragmented reads, bounds, error and timeout passed");return 0;
}
