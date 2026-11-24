import std;
import hysteria2.listener;
import hysteria2.auth;
import hysteria2.transport_options;
import quic.cid_registry;
import tls.server_credential;
import corosio;
import capy;
import test.quic_tls_link;
namespace h=hysteria2;namespace io = ::corosio;
struct Hooks {
 auto authenticate(h::ClientAuthView) noexcept -> std::optional<std::size_t> {return {};}
 auto datagram(quic::SessionHandle,std::span<std::uint8_t const>) noexcept -> int {return 0;}
 template<class Request> auto serve(Request&) -> capy::task<> {co_return;}
};
auto main(int argc,char** argv)->int {
 if(argc!=3)return 1;auto cert=test::quic_tls::read(argv[1]),key=test::quic_tls::read(argv[2]);auto cred=tls::ServerCredential::create(cert,key);if(!cred)return 2;
 for(bool uring:{false,true})for(unsigned mode=0;mode<3;++mode){
  auto context=std::unique_ptr<io::io_context>(new io::io_context(io::make_io_context(uring)));Hooks hooks;h::Listener<Hooks,1,4,16384> listener(*context,hooks,*cred);
  if(!listener.prepare(io::endpoint(io::ipv4_address::loopback(),0)))return 3;listener.start();listener.begin_shutdown();
  if(!listener.shutdown_drained() || listener.shutdown_failure() || listener.shutdown_unsent())return 4;
  if(mode==0){listener.stop();context->run_for(std::chrono::milliseconds(100));}
  else if(mode==1){context->run_for(std::chrono::milliseconds(10));listener.stop();context->restart();context->run_for(std::chrono::milliseconds(100));}
  else {{auto release=std::move(listener.transport_socket());}context.reset();listener.maintain();}
  if(!listener.drained() || !listener.clean())return 5;
 }

 std::println("graceful quiesce before first driver resume, immediate stop and abandonment passed");
}
