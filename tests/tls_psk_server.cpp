import std;
import tls.resuming_server;
import tls.record_stream;
namespace t=tls;namespace c = ::crypto;
extern "C" int socket(int,int,int);
extern "C" int bind(int,void const*,unsigned int);
extern "C" int listen(int,int);
extern "C" int accept4(int,void*,unsigned int*,int);
extern "C" int getsockname(int,void*,unsigned int*);
extern "C" long send(int,void const*,unsigned long,int);
extern "C" long recv(int,void*,unsigned long,int);
extern "C" int close(int);
extern "C" int setsockopt(int,int,int,void const*,unsigned int);
struct IPv4Address {unsigned short family,port;unsigned int address;unsigned char padding[8];};
struct Timeout {long seconds,microseconds;};
using Bytes=c::Bytes;using View=std::span<std::uint8_t const>;
auto read(char const* p)->Bytes {std::ifstream f(p,std::ios::binary);return {std::istreambuf_iterator<char>(f),{}};}
auto now_ms()->std::uint64_t {return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count());}
struct Socket {
 int fd=-1;Socket(Socket const&)=delete;Socket(int value=-1):fd(value){};~Socket(){if(fd>=0)::close(fd);}
 auto write(View data)->bool {while(!data.empty()){auto n=::send(fd,data.data(),data.size(),0x4000);if(n<=0)return false;data=data.subspan(static_cast<std::size_t>(n));}return true;}
 auto read()->std::expected<Bytes,std::string> {Bytes data(16389);auto n=::recv(fd,data.data(),data.size(),0);if(n<=0)return std::unexpected("socket read failed/EOF");data.resize(static_cast<std::size_t>(n));return data;}
};
auto serve(Socket& socket,t::ServerCredential const& credential,t::ServerTicketStore<>& store)->std::expected<bool,std::string> {
 auto copy=credential.clone();if(!copy)return std::unexpected("clone failed");auto now=now_ms();
 auto handshake=t::ResumingServerHandshake<>::create(std::move(*copy),now,now+8000,store,"http/1.1");if(!handshake)return std::unexpected("handshake create failed");
 Bytes unread;
 while(!handshake->complete()) {
  if(!handshake->pending_output().empty()){auto output=handshake->pending_output();if(!socket.write(output)||!handshake->written(output.size(),now_ms()))return std::unexpected("handshake write failed");continue;}
  if(unread.empty()){auto input=socket.read();if(!input)return std::unexpected(input.error());unread=std::move(*input);}
  std::size_t p=0;
  while(p<unread.size()&&handshake->pending_output().empty()&&!handshake->complete()) {
   auto fed=handshake->feed(View(unread).subspan(p),now_ms());if(!fed)return std::unexpected("handshake feed failed "+std::to_string(int(fed.error())));
   if(!fed->consumed)return std::unexpected("handshake no progress");p+=fed->consumed;
  }
  unread.erase(unread.begin(),unread.begin()+static_cast<std::ptrdiff_t>(p));
 }
 auto resumed=handshake->resumed();auto issuer=handshake->take_issuer();auto app=handshake->take_application_records();if(!issuer||!app)return std::unexpected("application/issuer failed");
 for(unsigned i=0;i<2;++i) {
  auto ticket=issuer->prepare();if(!ticket)return std::unexpected("ticket prepare failed "+std::to_string(int(ticket.error())));
  auto record=app->session_ticket(ticket->body());if(!record||!socket.write(*record)||!ticket->publish(store,now_ms()))return std::unexpected("ticket write/publish failed");
 }
 t::RecordStream stream;std::string request;bool sent=false,closed=false;
 while(!closed) {
  if(unread.empty()){auto input=socket.read();if(!input)return std::unexpected(input.error());unread=std::move(*input);}
  std::size_t p=0;
  while(p<unread.size()) {
   auto framed=stream.feed(View(unread).subspan(p),t::RecordFraming::ciphertext);if(!framed||!framed->consumed)return std::unexpected("record framing failed");p+=framed->consumed;if(!framed->record)continue;
   auto event=app->open_event(framed->record->bytes);if(!event)return std::unexpected("application open failed");
   if(event->kind==t::ApplicationEventKind::data){request.append(reinterpret_cast<char const*>(event->data.data()),event->data.size());}
   else if(event->kind==t::ApplicationEventKind::close_notify){closed=true;break;}
   else if(event->kind==t::ApplicationEventKind::fatal_alert)return std::unexpected("fatal alert "+std::to_string(event->alert_description));
   else if(event->kind==t::ApplicationEventKind::key_update_requested){auto update=app->key_update(false);if(!update||!socket.write(*update))return std::unexpected("update failed");}
   if(!sent&&request.find("\r\n\r\n")!=request.npos) {
    constexpr std::string_view response="HTTP/1.1 200 OK\r\nContent-Length: 13\r\nConnection: close\r\n\r\nNexus PSK OK\n";
    auto record=app->seal(View(reinterpret_cast<std::uint8_t const*>(response.data()),response.size()));auto close=app->close_notify();
    if(!record||!close||!socket.write(*record)||!socket.write(*close))return std::unexpected("response/close write failed");sent=true;
   }
  }
  unread.clear();
 }
 if(!sent||!app->finish_input())return std::unexpected("close state invalid");return resumed;
}
int main(int argc,char** argv) {
 if(argc<4)return 1;auto cert=read(argv[1]),key=read(argv[2]);auto credential=t::ServerCredential::create(cert,key);c::cleanse(key);if(!credential)return 2;
 unsigned count=std::stoul(argv[3]);bool clear=argc>4&&std::string_view(argv[4])=="clear";
 Socket listener(::socket(2,1|02000000,0));if(listener.fd<0)return 3;IPv4Address address{2,0,0x0100007f,{}};
 if(::bind(listener.fd,&address,sizeof(address))||::listen(listener.fd,16))return 4;unsigned int size=sizeof(address);
 if(::getsockname(listener.fd,&address,&size))return 5;auto port=static_cast<unsigned>((address.port<<8)|(address.port>>8))&65535;
 t::ServerTicketStore<> store;std::cout<<"READY "<<port<<"\n"<<std::flush;
 for(unsigned i=0;i<count;++i) {
  Socket client(::accept4(listener.fd,nullptr,nullptr,02000000));if(client.fd<0)return 6;Timeout timeout{8,0};
  if(::setsockopt(client.fd,1,20,&timeout,sizeof(timeout))||::setsockopt(client.fd,1,21,&timeout,sizeof(timeout)))return 7;
  if(clear&&i==1)store.clear();auto result=serve(client,*credential,store);
  if(!result){std::println("FAILED round={} {}",i,result.error());return 8;}
  std::cout<<std::format("round={} resumed={} cache={} authenticated HTTP and client close passed\n",i,*result,store.size())<<std::flush;
 }
}
