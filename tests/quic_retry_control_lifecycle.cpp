import std;
import crypto;
import net.datagram_driver;
import tls.server_credential;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;
import nexus.test.quic_tls_link;
import nexus.test.hy2_retry_port_link;
namespace io=nex::corosio;namespace capy=nex::capy;namespace portlink=nexus::test::hy2_retry_port;namespace support=nexus::test::quic_tls;namespace net=net;
using Clock=std::chrono::steady_clock;using namespace std::chrono_literals;
auto hash(std::span<std::uint8_t const> bytes)noexcept->std::uint64_t{std::uint64_t value=1469598103934665603ull;for(auto byte:bytes)value=(value^byte)*1099511628211ull;return value;}
struct HoldSocket {
    io::udp_socket socket;capy::async_event entered,release;bool closed=false,sending=false,stable=true,fail_destination=false;std::span<std::uint8_t const> pending;std::uint64_t expected=0;unsigned send_attempts=0;
    explicit HoldSocket(io::io_context& context):socket(context){}
    auto context()noexcept->auto&{return socket.context();}
    auto close()noexcept->void{if(sending)stable&=hash(pending)==expected;closed=true;socket.close();release.set();}
    // Corosio borrows the buffer-sequence descriptor as well as its storage.
    // Forward the caller's descriptor reference; a by-value local would die
    // before the returned awaitable reads it.
    auto recv_from(capy::mutable_buffer const& bytes,io::endpoint& source){return socket.recv_from(bytes,source);}
    auto send_to(capy::const_buffer bytes,io::endpoint peer)->capy::task<capy::results<std::size_t>>{
        sending=true;struct Active{bool& flag;~Active(){flag=false;}}active{sending};pending={static_cast<std::uint8_t const*>(bytes.data()),bytes.size()};expected=hash(pending);entered.set();
        auto [error]=co_await release.wait();stable&=hash(pending)==expected;
        if(error || closed)co_return capy::results<std::size_t>{std::make_error_code(std::errc::operation_canceled),0};
        ++send_attempts;co_return co_await socket.send_to(bytes,fail_destination?io::endpoint(peer.address(),0):peer);
    }
};
auto initial()->std::array<std::uint8_t,1200>{
    std::array<std::uint8_t,1200> bytes{};bytes[0]=0xc0;bytes[4]=1;bytes[5]=8;bytes[14]=8;
    for(unsigned i=0;i<8;++i){bytes[6+i]=i+17;bytes[15+i]=i+71;}auto length=bytes.size()-26;bytes[24]=0x40|(length>>8);bytes[25]=length;return bytes;
}
auto trial(tls::ServerCredential const& credential,bool uring,unsigned mode)->bool{
    std::println("Retry control begin backend={} mode={}",uring,mode);std::fflush(nullptr);
    auto context=std::unique_ptr<io::io_context>(new io::io_context(io::make_io_context(uring)));HoldSocket socket(*context);io::udp_socket peer(*context);io::endpoint local(io::ipv4_address::loopback(),0);
    if(socket.socket.open() || socket.socket.bind(local) || peer.open() || peer.bind(local))return false;local=socket.socket.local_endpoint();
    portlink::Factory factory(credential,local);portlink::Port port(factory);using Driver=net::DatagramDriver<portlink::Port,HoldSocket>;Driver driver(socket,port,Clock::now()+2s);
    bool observed=false,done=false;std::error_code task_error;
    auto control=[&]()->capy::task<capy::results<>>{
        auto bytes=initial();auto [sent,size]=co_await peer.send_to(capy::const_buffer(bytes.data(),bytes.size()),local);if(sent || size!=bytes.size())co_return capy::results<>{std::make_error_code(std::errc::io_error)};
        auto [entered]=co_await io::timeout(socket.entered.wait(),Clock::now()+1s);if(entered)co_return capy::results<>{entered};
        observed=socket.sending && factory.retry.pending()==1 && factory.retry.key_slots()==2 && factory.retry.statistics().committed==0 && factory.created==0 && !port.size() && hash(socket.pending)==socket.expected;
        if(mode==0){
            auto [extra,extra_size]=co_await peer.send_to(capy::const_buffer(bytes.data(),bytes.size()),local);if(extra || extra_size!=bytes.size())co_return capy::results<>{std::make_error_code(std::errc::io_error)};
            auto [elapsed]=co_await io::delay(300ms);if(elapsed)co_return capy::results<>{elapsed};
            observed&=socket.sending && factory.retry.pending()==1 && factory.retry.statistics().expired==1 && !factory.retry.statistics().committed && driver.running() && !factory.created && hash(socket.pending)==socket.expected;
            socket.release.set();std::array<std::uint8_t,1200> reply{};io::endpoint source;
            auto [received,count]=co_await io::timeout(peer.recv_from(capy::mutable_buffer(reply.data(),reply.size()),source),Clock::now()+1s);
            observed&=!received && count<=146 && count>16 && source==local;
            while(!factory.retry.statistics().committed){driver.changed().clear();auto [changed]=co_await io::timeout(driver.changed().wait(),Clock::now()+1s);if(changed)co_return capy::results<>{changed};}
            driver.finish();
        }else if(mode==1)driver.cancel();
        else if(mode==2){socket.fail_destination=true;socket.release.set();}
        else{context->stop();auto [abandoned]=co_await io::delay(60s);co_return capy::results<>{abandoned};}
        co_return capy::results<>{};
    };
    auto all=[&]()->capy::task<>{auto [error,a,b]=co_await capy::when_all(driver.run(),control());(void)a;(void)b;task_error=error;done=true;};
    std::exception_ptr exception;capy::run_async(context->get_executor(),[&]()noexcept{},[&](std::exception_ptr error)noexcept{exception=error;})(all());context->run_for(3s);
    if(mode==3){
        observed&=!done && driver.running() && socket.sending && factory.retry.pending()==1 && !factory.created;
        {auto released_server=std::move(socket.socket);auto released_peer=std::move(peer);}
        context.reset();
    }
    port.drain();bool clean=observed && !exception && driver.drained() && port.drained() && factory.retry.drained() && !factory.retry.key_slots() && !factory.created && !factory.destroyed && !factory.failures && factory.valid && !socket.sending && socket.stable;
    if(mode==0)clean&=done && !driver.failure() && factory.retry.statistics().committed==1 && socket.send_attempts==1;
    else if(mode==1)clean&=done && driver.failure() && std::holds_alternative<net::DatagramFailure>(*driver.failure()) && std::get<net::DatagramFailure>(*driver.failure()).code==net::DatagramError::canceled && !factory.retry.statistics().committed && !socket.send_attempts;
    else if(mode==2)clean&=done && driver.failure() && std::holds_alternative<net::DatagramFailure>(*driver.failure()) && std::get<net::DatagramFailure>(*driver.failure()).code==net::DatagramError::send && bool(std::get<net::DatagramFailure>(*driver.failure()).system) && !factory.retry.statistics().committed && socket.send_attempts==1;
    else clean&=!done && !factory.retry.statistics().committed && !socket.send_attempts;
    std::println("Retry actual generic UDP driver backend={} mode={} observed={} completed={} clean={} transmitted={} send_attempts={} stable={} native_created={} key_slots={}",uring,mode,observed,done,clean,factory.retry.statistics().committed,socket.send_attempts,socket.stable,factory.created,factory.retry.key_slots());return clean;
}
auto main(int argc,char** argv)->int{
    if(argc!=3 && argc!=4)return 1;if(argc==4 && std::string_view(argv[3])!="0" && std::string_view(argv[3])!="1")return 1;auto cert=support::read(argv[1]),key=support::read(argv[2]);auto credential=tls::ServerCredential::create(cert,key);::crypto::cleanse(key);if(!credential)return 2;
    for(bool uring:{false,true})for(unsigned mode=0;mode<4;++mode){if(argc==4 && uring!=(std::string_view(argv[3])=="1"))continue;if(!trial(*credential,uring,mode))return 3;}
}
