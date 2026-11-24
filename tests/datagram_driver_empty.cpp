import std;
import net.datagram_driver;
import capy;
import corosio;
namespace io = ::corosio;
using namespace std::chrono_literals;
using Clock=std::chrono::steady_clock;
struct Protocol {
    using Failure=int;
    using Driver=net::DatagramDriver<Protocol,io::udp_socket,64,64>;
    Driver* driver=nullptr;
    io::endpoint peer;
    bool output_started=false,valid=true;
    unsigned sends=0,receives=0,requests=0,stops=0,drains=0;
    auto request_stop() noexcept -> void {++requests;}
    auto stop() noexcept -> void {++stops;}
    auto drain() noexcept -> void {++drains;}
    auto next_expiry() const noexcept -> net::DatagramDeadline {return {};}
    auto expire(Clock::time_point) -> std::expected<void,int> {return {};}
    auto output(std::span<std::uint8_t>,Clock::time_point) -> std::expected<std::optional<net::DatagramOutput>,int> {
        if(std::exchange(output_started,true))return std::optional<net::DatagramOutput>{};return net::DatagramOutput{peer,0,71};
    }
    auto transmitted(std::uint64_t token,Clock::time_point) -> std::expected<void,int> {valid&=token==71;++sends;if(receives)driver->finish();return {};}
    auto receive(io::endpoint const& source,std::span<std::uint8_t const> bytes,Clock::time_point) -> std::expected<void,int> {
        valid&=source==peer && bytes.empty();++receives;if(sends)driver->finish();return {};
    }
};
auto run(io::io_context& context,bool fail,bool ipv6) -> bool {
    io::udp_socket socket(context);io::endpoint loopback=ipv6?io::endpoint(io::ipv6_address::loopback(),0):io::endpoint(io::ipv4_address::loopback(),0);
    if(socket.open(loopback.address().family()) || socket.bind(loopback))return false;
    Protocol protocol;protocol.peer=fail?loopback:socket.local_endpoint();Protocol::Driver driver(socket,protocol,Clock::now()+100ms);protocol.driver=&driver;
    bool done=false,failed=false;capy::run_async(context.get_executor(),[&](capy::results<> result){done=true;failed=bool(std::get<0>(result));},[&](std::exception_ptr)noexcept{done=true;failed=true;})(driver.run());
    context.restart();context.run_for(200ms);
    std::println("empty actual socket family={} fail={} done={} taskfailed={} sends={} receives={} valid={} drains={} error={}",ipv6?6:4,fail,done,failed,protocol.sends,protocol.receives,protocol.valid,driver.drained(),driver.failure()?static_cast<int>(std::get<net::DatagramFailure>(*driver.failure()).code):-1);
    if(!done || !protocol.valid || protocol.requests!=1 || protocol.stops!=1 || protocol.drains!=1 || !driver.drained())return false;
    if(fail)return failed && protocol.sends==0 && protocol.receives==0 && driver.failure() && std::holds_alternative<net::DatagramFailure>(*driver.failure()) && std::get<net::DatagramFailure>(*driver.failure()).code==net::DatagramError::send;
    return !failed && !driver.failure() && protocol.sends==1 && protocol.receives==1;
}
auto main() -> int {
    bool valid=true;
    for(bool uring:{false,true}){
        io::io_context context=io::make_io_context(uring);
        for(bool ipv6:{false,true}){
            auto first=run(context,false,ipv6),failure=run(context,true,ipv6),recovery=run(context,false,ipv6);valid&=first&&failure&&recovery;
            std::println("generic UDP driver backend={} family={} actual zero-length socket send/receive={} transmitted1={} send-error0={} same-context new-owner recovery={}",uring,ipv6?6:4,first,first,failure,recovery);
        }
    }
    return valid?0:1;
}
