import std;
import quic.datagram_port;
import quic.cid_registry;
import ngtcp2;
import net.datagram_driver;
import capy;
import corosio;
namespace q=quic;namespace io = ::corosio;
using Clock=std::chrono::steady_clock;using namespace std::chrono_literals;
struct Socket {
 io::io_context& ctx;capy::async_event read,write;bool closed=false,held=false,fail=false;unsigned sends=0;
 auto context() noexcept -> io::io_context& {return ctx;}
 auto close() noexcept -> void {closed=true;read.set();write.set();}
 auto recv_from(capy::mutable_buffer,io::endpoint&) -> capy::task<capy::results<std::size_t>> {auto [e]=co_await read.wait();co_return capy::results<std::size_t>{e?e:std::make_error_code(std::errc::operation_canceled),0};}
 auto send_to(capy::const_buffer bytes,io::endpoint) -> capy::task<capy::results<std::size_t>> {++sends;held=true;auto [e]=co_await write.wait();held=false;if(e || closed)co_return capy::results<std::size_t>{std::make_error_code(std::errc::operation_canceled),0};co_return capy::results<std::size_t>{fail?std::make_error_code(std::errc::io_error):std::error_code{},bytes.size()};}
};
struct Session {
 using Failure=int;bool requested=false,alive=true;unsigned sent=0;
 auto request_stop() noexcept -> void {requested=true;} auto stopping()const noexcept ->bool{return requested;}
 auto stop() noexcept ->void{alive=false;}auto drain()noexcept->void{}
 auto next_expiry()const noexcept->net::DatagramDeadline{return {};}
 auto receive(io::endpoint const&,std::span<std::uint8_t const>,Clock::time_point)->std::expected<void,int>{return {};}
 auto expire(Clock::time_point)->std::expected<void,int>{return {};}
 auto output(std::span<std::uint8_t>,Clock::time_point)->std::expected<std::optional<net::DatagramOutput>,int>{return std::optional<net::DatagramOutput>{};}
 auto close_output(std::span<std::uint8_t> bytes,Clock::time_point)->std::expected<std::optional<net::DatagramOutput>,int>{bytes[0]=17;return net::DatagramOutput{io::endpoint(io::ipv4_address::loopback(),1),1,5};}
 auto transmitted(std::uint64_t token,Clock::time_point)->std::expected<void,int>{if(token!=5)return std::unexpected(1);++sent;return {};}
};
struct Factory {
 using Session=::Session;bool destroyed=false,had_failure=false;
 auto application_drained(q::SessionHandle,Session const&)const noexcept->bool{return true;}
 auto failed(q::SessionHandle,int)noexcept->void{had_failure=true;}
 auto destroy(q::SessionHandle,Session&)noexcept->void{destroyed=true;}
 auto admit(ngtcp2::ngtcp2_pkt_hd const&,io::endpoint const&,Clock::time_point)noexcept->bool{return false;}
 auto create(q::SessionHandle,q::CidRegistry<1,8>&,std::span<std::uint8_t const>,ngtcp2::ngtcp2_pkt_hd const&,io::endpoint const&,Clock::time_point)noexcept->std::expected<Session*,int>{return nullptr;}
};
using Port=q::DatagramPort<Factory,1,8,8,true>;
struct Trial {io::io_context ctx;Socket socket{ctx};Factory factory;Session session;Port port{factory};net::DatagramDriver<Port,Socket> driver{socket,port};q::SessionHandle owner;bool ok=true,done=false;unsigned mode;
 explicit Trial(bool uring,unsigned m):ctx(io::make_io_context(uring)),mode(m){owner=*port.registry().reserve();std::array<std::uint8_t,8> cid{1};port.registry().insert(owner,cid);port.attach(owner,session);}
};
auto control(Trial& t)->capy::task<capy::results<>> {
 auto [e]=co_await io::delay(10ms);if(e)co_return capy::results<>{e};t.port.begin_shutdown();t.driver.notify();
 for(unsigned i=0;i<100 && !t.socket.held;++i){auto [err]=co_await io::delay(1ms);if(err)co_return capy::results<>{err};}
 t.ok&=t.socket.held && t.port.pinned(t.owner) && t.session.alive && !t.factory.destroyed;
 if(t.mode==0 || t.mode==1){t.socket.fail=t.mode==1;t.socket.write.set();for(unsigned i=0;i<100 && !t.factory.destroyed && !t.driver.failure();++i){auto [err]=co_await io::delay(1ms);if(err)co_return capy::results<>{err};}}
 // mode 2 holds the write across the grace deadline and aborts it.
 if(t.mode==2){auto [err]=co_await io::delay(260ms);if(err)co_return capy::results<>{err};t.ok&=t.socket.held && t.port.pinned(t.owner) && t.session.alive;}
 t.driver.finish();co_return capy::results<>{};
}
auto run(Trial& t)->capy::task<> {auto [e,a,b]=co_await capy::when_all(t.driver.run(),control(t));(void)e;(void)a;(void)b;t.done=true;}
auto main()->int {
 for(bool uring:{false,true})for(unsigned mode=0;mode<3;++mode){Trial t(uring,mode);capy::run_async(t.ctx.get_executor())(run(t));t.ctx.run_for(2s);
  if(!t.done || !t.ok || !t.driver.drained() || !t.port.drained() || !t.factory.destroyed || t.socket.held)return 1;
  if(mode==0 && (t.session.sent!=1 || t.driver.failure()))return 2;
  if(mode==1 && (!t.driver.failure() || t.session.sent))return 3;
  if(mode==2 && (t.session.sent || t.driver.failure()))return 4;
 }
 std::println("graceful close pin, sent, send failure and pending cancel passed on both backends");
}
