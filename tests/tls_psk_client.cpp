import std;
import tls.resuming_client;
import tls.hello_config;
import tls.record_stream;
namespace t=tls;namespace c = ::crypto;
extern "C" int socket(int,int,int);
extern "C" int connect(int,void const*,unsigned int);
extern "C" long send(int,void const*,unsigned long,int);
extern "C" long recv(int,void*,unsigned long,int);
extern "C" int close(int);
extern "C" int setsockopt(int,int,int,void const*,unsigned int);
struct IPv4Address {unsigned short family,port;unsigned int address;unsigned char padding[8];};
struct Timeout {long seconds,microseconds;};
using Bytes=c::Bytes;using View=std::span<std::uint8_t const>;
auto read(char const* p)->Bytes {std::ifstream f(p,std::ios::binary);return {std::istreambuf_iterator<char>(f),{}};}
struct Socket {
 int fd=-1;Socket(Socket const&)=delete;Socket(Socket&& o):fd(std::exchange(o.fd,-1)){};Socket()=default;~Socket(){if(fd>=0)::close(fd);}
 auto open(unsigned port)->bool {
  fd=::socket(2,1|02000000,0);if(fd<0)return false;Timeout timeout{8,0};
  if(::setsockopt(fd,1,20,&timeout,sizeof(timeout))||::setsockopt(fd,1,21,&timeout,sizeof(timeout)))return false;
  IPv4Address address{2,static_cast<unsigned short>((port<<8)|(port>>8)),0x0100007f,{}};return !::connect(fd,&address,sizeof(address));
 }
 auto write(View data)->bool {while(!data.empty()){auto n=::send(fd,data.data(),data.size(),0x4000);if(n<=0)return false;data=data.subspan(static_cast<std::size_t>(n));}return true;}
 auto read()->std::expected<Bytes,std::string> {
  Bytes data(16389);auto n=::recv(fd,data.data(),data.size(),0);if(n<=0)return std::unexpected("socket read failed/EOF");data.resize(static_cast<std::size_t>(n));return data;
 }
};
auto now_ms()->std::uint64_t {return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count());}
struct Round {bool resumed=false,selected=false;unsigned records=0,tickets=0,retries=0;std::size_t bytes=0;};
template<class Policy>
auto exchange(unsigned port, t::ClientHello hello, std::span<std::uint16_t const> groups,std::span<View const> anchors,Policy policy,t::ResumptionCache<>& cache,bool corrupt=false) -> std::expected<Round,std::string> {
 auto wall=std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
 constexpr std::string_view name="server.example";View name_bytes(reinterpret_cast<std::uint8_t const*>(name.data()),name.size());
 auto handshake=t::ResumingClientSession<Policy>::create(std::move(hello),groups,anchors,t::PeerNameKind::dns,name_bytes,wall,std::move(policy));
 if(!handshake)return std::unexpected("create failed "+std::to_string(int(handshake.error())));
 Socket socket;if(!socket.open(port))return std::unexpected("connect failed");
 auto initial=handshake->initial_record();if(corrupt&&initial)initial->back()^=1;if(!initial||!socket.write(*initial)||!handshake->sent())return std::unexpected("initial write failed");
 Bytes unread;unsigned retries=0;
 while(!handshake->negotiated()) {
  auto input=socket.read();if(!input)return std::unexpected(input.error());std::size_t position=0;
  while(position<input->size()) {
   auto fed=handshake->feed(View(*input).subspan(position));if(!fed)return std::unexpected("handshake feed failed "+std::to_string(int(fed.error())));
   if(!fed->consumed)return std::unexpected("handshake made no progress");position+=fed->consumed;
   if(fed->outbound){if(!socket.write(*fed->outbound)||!handshake->sent())return std::unexpected("retry/finished write failed");if(!handshake->negotiated())++retries;}
   if(handshake->negotiated()){unread.assign(input->begin()+static_cast<std::ptrdiff_t>(position),input->end());break;}
  }
 }
 Round out;out.retries=retries;out.resumed=handshake->resumed();out.selected=handshake->psk_selected();auto app=handshake->take_application();if(!app)return std::unexpected("take application failed");
 std::string request="GET / HTTP/1.0\r\nHost: server.example\r\nConnection: close\r\n\r\n";
 auto encrypted=app->seal(View(reinterpret_cast<std::uint8_t const*>(request.data()),request.size()));if(!encrypted||!socket.write(*encrypted))return std::unexpected("request write failed");
 t::RecordStream stream;bool closed=false;std::string response;
 while(!closed) {
  if(unread.empty()){auto input=socket.read();if(!input)return std::unexpected(input.error());unread=std::move(*input);}
  std::size_t offset=0;
  while(offset<unread.size()) {
   auto parsed=stream.feed(View(unread).subspan(offset),t::RecordFraming::ciphertext);if(!parsed||!parsed->consumed)return std::unexpected("application record framing failed");offset+=parsed->consumed;if(!parsed->record)continue;
   auto event=app->open_event(parsed->record->bytes,cache,now_ms());if(!event)return std::unexpected("application open failed "+std::to_string(int(event.error())));++out.records;
   if(event->kind==t::ApplicationEventKind::data){response.append(reinterpret_cast<char const*>(event->data.data()),event->data.size());out.bytes+=event->data.size();}
   else if(event->kind==t::ApplicationEventKind::ticket_received)++out.tickets;
   else if(event->kind==t::ApplicationEventKind::close_notify){closed=true;break;}
   else if(event->kind==t::ApplicationEventKind::fatal_alert)return std::unexpected("fatal TLS alert "+std::to_string(event->alert_description));
   else if(event->kind==t::ApplicationEventKind::key_update_requested){auto reply=app->key_update(false);if(!reply||!socket.write(*reply))return std::unexpected("key update failed");}
  }
  unread.clear();
 }
 if(!response.starts_with("HTTP/1.0 200")&&!response.starts_with("HTTP/1.1 200"))return std::unexpected("missing authenticated HTTP200");
 auto close=app->close_notify();if(!close||!socket.write(*close)||!app->finish_input())return std::unexpected("authenticated close failed");
 return out;
}
int main(int argc,char** argv) {
 if(argc<5)return 1;auto port=static_cast<unsigned>(std::stoul(argv[1]));auto ca=read(argv[2]);if(ca.empty())return 2;
 auto suite=static_cast<std::uint16_t>(std::stoul(argv[3],nullptr,0));auto mode=std::string_view(argv[4]);bool retry=mode.starts_with("hrr");unsigned count=argc>5 ? std::stoul(argv[5]) : 3;bool fallback=mode.ends_with("fallback"),corrupt=mode.ends_with("corrupt");unsigned next_port=argc>6 ? std::stoul(argv[6]) : port;
 std::array<View,1> anchors{ca};std::array<std::uint16_t,1> groups{29},initial{static_cast<std::uint16_t>(retry?0:29)};
 std::array<std::string_view,1> alpn{"http/1.1"};t::ResumptionCache<> cache;unsigned resumed=0,full=0;
 for(unsigned i=0;i<count;++i) {
  auto hello=t::make_client_hello("server.example",alpn,groups);if(!hello)return 3;hello->cipher_suites={suite};
  // TLS13 resumption tickets need the same selected protocol binding.
  View name(reinterpret_cast<std::uint8_t const*>("server.example"),14);View protocol(reinterpret_cast<std::uint8_t const*>("http/1.1"),8);
  auto binding=t::make_ticket_binding(*hello,anchors,t::PeerNameKind::dns,name,protocol);if(!binding)return 4;
  if(mode.ends_with("external")) {
   if(argc<9)return 10;std::string_view key=argv[7];if(key.empty()||key.size()%2)return 11;Bytes bytes;
   auto digit=[](char c)->int {if(c>='0'&&c<='9')return c-'0';if(c>='a'&&c<='f')return c-'a'+10;return -1;};
   for(std::size_t p=0;p<key.size();p+=2){auto hi=digit(key[p]),lo=digit(key[p+1]);if(hi<0||lo<0)return 12;bytes.push_back(static_cast<std::uint8_t>((hi<<4)|lo));}
   std::string_view identity=argv[8];auto material=t::ExternalPsk::create(t::Secret(std::move(bytes)),Bytes(identity.begin(),identity.end()),*binding,*t::psk_cipher_hash(suite));if(!material)return 13;
   std::inplace_vector<t::ExternalPsk,8> offered;offered.push_back(std::move(*material));auto policy=t::PskClientPolicy<t::ExternalPsk>::create(std::move(*binding),std::move(offered));if(!policy)return 14;
   auto result=exchange(port,std::move(*hello),retry ? std::span<std::uint16_t const>{} : std::span<std::uint16_t const>(initial),anchors,std::move(*policy),cache);
   if(!result||!result->selected||result->resumed||result->retries!=(retry ? 1u : 0u)){std::println("external failed round={} {}",i,result ? "unexpected negotiation" : result.error());return 15;}
   std::println("external round={} psk_selected={} resumed={} retries={} authenticated_bytes={}",i,result->selected,result->resumed,result->retries,result->bytes);continue;
  }
  std::inplace_vector<t::ResumptionTicket,8> offered;
  if(auto ticket=cache.take(*binding,hello->cipher_suites,now_ms()))offered.push_back(std::move(*ticket));
  if(i && offered.empty()){std::println("ticket missing round={} cache={}",i,cache.size());return 5;}
  auto policy=t::PskClientPolicy<>::create(std::move(*binding),std::move(offered));if(!policy)return 6;
  auto result=exchange(i ? next_port : port,std::move(*hello),retry ? std::span<std::uint16_t const>{} : std::span<std::uint16_t const>(initial),anchors,std::move(*policy),cache,corrupt&&i>0);
  if(!result){std::println("round={} {}",i,result.error());if(corrupt&&i>0){std::println("corrupt binder rejected without application release cached={}",cache.size());return 0;}return 7;}
  if(corrupt&&i>0)return 9;
  resumed+=result->resumed;full+=!result->resumed;
  std::println("round={} resumed={} tickets={} cached={} retries={} authenticated_bytes={}",i,result->resumed,result->tickets,cache.size(),result->retries,result->bytes);
  if((i==0&&result->resumed)||(i>0&&!result->resumed&&!(fallback&&i==1))||(fallback&&i==1&&result->resumed)||result->retries!=(retry ? 1u : 0u))return 8;
 }
 if(mode.ends_with("external"))std::println("external PSK authenticated {} connections passed",count);
 else std::println("authenticated full={} resumed={} ticket renewal and close passed",full,resumed);
}
