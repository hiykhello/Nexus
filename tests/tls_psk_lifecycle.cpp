import std;
import tls.resuming_client;
import tls.resuming_server;
import tls.hello_config;
namespace t=tls;namespace c = ::crypto;
using Bytes=c::Bytes;using View=std::span<std::uint8_t const>;
namespace fault {
 bool native=false,cpp=false,single=false,denied=false;
 std::ptrdiff_t allowance=-1;std::size_t calls=0;
 std::size_t native_live=0,native_bytes=0,cpp_live=0,cpp_bytes=0;
 struct alignas(std::max_align_t) NativeHeader {std::size_t size;};
 struct alignas(std::max_align_t) CppHeader {void* allocation;std::size_t size;};
 auto allow(bool enabled) noexcept->bool {
  if(!enabled)return true;++calls;
  if(!allowance){denied=true;if(single)allowance=-1;return false;}if(allowance>0)--allowance;return true;
 }
 auto allocate(std::size_t size,std::size_t alignment)->void* {
  if(!allow(cpp))throw std::bad_alloc{};alignment=std::max(alignment,alignof(CppHeader));
  if(size>std::numeric_limits<std::size_t>::max()-alignment-sizeof(CppHeader))throw std::bad_alloc{};
  auto allocation=std::malloc(size+alignment+sizeof(CppHeader));if(!allocation)throw std::bad_alloc{};
  auto address=(reinterpret_cast<std::uintptr_t>(allocation)+sizeof(CppHeader)+alignment-1)&~(alignment-1);
  auto header=reinterpret_cast<CppHeader*>(address)-1;header->allocation=allocation;header->size=size;++cpp_live;cpp_bytes+=size;return reinterpret_cast<void*>(address);
 }
 auto release(void* pointer)noexcept->void {
  if(!pointer)return;auto h=static_cast<CppHeader*>(pointer)-1;--cpp_live;cpp_bytes-=h->size;std::free(h->allocation);
 }
 auto disable()noexcept->void {native=false;cpp=false;}
}
void* operator new(std::size_t n){return fault::allocate(n,alignof(std::max_align_t));}
void* operator new[](std::size_t n){return fault::allocate(n,alignof(std::max_align_t));}
void* operator new(std::size_t n,std::align_val_t a){return fault::allocate(n,static_cast<std::size_t>(a));}
void* operator new[](std::size_t n,std::align_val_t a){return fault::allocate(n,static_cast<std::size_t>(a));}
void* operator new(std::size_t n,std::nothrow_t const&)noexcept{try{return ::operator new(n);}catch(...){return nullptr;}}
void* operator new[](std::size_t n,std::nothrow_t const&)noexcept{try{return ::operator new[](n);}catch(...){return nullptr;}}
void* operator new(std::size_t n,std::align_val_t a,std::nothrow_t const&)noexcept{try{return ::operator new(n,a);}catch(...){return nullptr;}}
void* operator new[](std::size_t n,std::align_val_t a,std::nothrow_t const&)noexcept{try{return ::operator new[](n,a);}catch(...){return nullptr;}}
void operator delete(void* p)noexcept{fault::release(p);}void operator delete[](void* p)noexcept{fault::release(p);}
void operator delete(void* p,std::size_t)noexcept{fault::release(p);}void operator delete[](void* p,std::size_t)noexcept{fault::release(p);}
void operator delete(void* p,std::align_val_t)noexcept{fault::release(p);}void operator delete[](void* p,std::align_val_t)noexcept{fault::release(p);}
void operator delete(void* p,std::size_t,std::align_val_t)noexcept{fault::release(p);}void operator delete[](void* p,std::size_t,std::align_val_t)noexcept{fault::release(p);}
extern "C" auto OPENSSL_memory_alloc(std::size_t n)noexcept->void* {
 if(!fault::allow(fault::native)||n>std::numeric_limits<std::size_t>::max()-sizeof(fault::NativeHeader))return nullptr;
 auto h=static_cast<fault::NativeHeader*>(std::malloc(sizeof(fault::NativeHeader)+n));if(!h)return nullptr;h->size=n;++fault::native_live;fault::native_bytes+=n;return h+1;
}
extern "C" auto OPENSSL_memory_free(void* p)noexcept->void {
 if(!p)return;auto h=static_cast<fault::NativeHeader*>(p)-1;--fault::native_live;fault::native_bytes-=h->size;
 auto size=sizeof(fault::NativeHeader)+h->size;auto bytes=reinterpret_cast<volatile unsigned char*>(h);for(std::size_t i=0;i<size;++i)bytes[i]=0;std::free(h);
}
extern "C" auto OPENSSL_memory_get_size(void* p)noexcept->std::size_t{return (static_cast<fault::NativeHeader*>(p)-1)->size;}
struct Clock {static auto now()noexcept->std::uint64_t{return 100000;}};
using Store=t::ServerTicketStore<8>;using ClientPolicy=t::PskClientPolicy<t::ResumptionTicket,Clock>;
using Client=t::ResumingClientSession<ClientPolicy>;using Server=t::ResumingServerHandshake<Store,Clock>;
auto read(char const* p)->Bytes {std::ifstream f(p,std::ios::binary);return {std::istreambuf_iterator<char>(f),{}};}
enum class Error {none,crypto,protocol,allocation};
struct Pair {bool complete=false,resumed=false;Error error=Error::protocol;};
auto exchange(t::ServerCredential const& credential,std::span<View const> anchors,Store& store,t::ResumptionCache<8>& cache,std::uint16_t group,std::uint16_t cipher,bool retry)->Pair {
 std::array<std::uint16_t,1> groups{group};std::array<std::string_view,1> protocols{"h2"};
 auto hello=t::make_client_hello("server.example",protocols,groups);if(!hello)return {false,false,Error::crypto};hello->cipher_suites={cipher};
 View name(reinterpret_cast<std::uint8_t const*>("server.example"),14),alpn(reinterpret_cast<std::uint8_t const*>("h2"),2);
 auto binding=t::make_ticket_binding(*hello,anchors,t::PeerNameKind::dns,name,alpn);if(!binding)return {false,false,binding.error()==t::PskError::crypto_error?Error::crypto:Error::protocol};
 std::inplace_vector<t::ResumptionTicket,8> offered;if(auto value=cache.take(*binding,hello->cipher_suites,Clock::now()))offered.push_back(std::move(*value));
 bool resume=!offered.empty();auto policy=ClientPolicy::create(std::move(*binding),std::move(offered));if(!policy)return {};
 auto wall=std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
 auto client=Client::create(std::move(*hello),retry?std::span<std::uint16_t const>{}:std::span<std::uint16_t const>(groups),anchors,t::PeerNameKind::dns,name,wall,std::move(*policy));
 if(!client)return {false,false,client.error()==t::ClientSessionHandshakeError::crypto_error?Error::crypto:Error::protocol};
 auto copy=credential.clone();if(!copy)return {false,false,Error::crypto};auto server=Server::create(std::move(*copy),Clock::now(),Clock::now()+1000,store,"h2");
 if(!server)return {false,false,server.error()==t::ServerHandshakeIoError::crypto_error?Error::crypto:Error::protocol};
 auto outbound=client->initial_record();if(!outbound)return {};Bytes c2s=std::move(*outbound);std::size_t pos=0;
 for(unsigned round=0;round<30000&&(!server->complete()||!client->negotiated());++round) {
  if(!server->pending_output().empty()) {
   auto bytes=server->pending_output();auto result=client->feed(bytes.first(std::min<std::size_t>(13,bytes.size())));
   if(!result)return {false,false,result.error()==t::ClientSessionHandshakeError::crypto_error?Error::crypto:Error::protocol};
   if(!result->consumed||!server->written(result->consumed,Clock::now()))return {};
   if(result->outbound){if(pos!=c2s.size())return {};c2s=std::move(*result->outbound);pos=0;}
  } else if(pos<c2s.size()) {
   auto bytes=View(c2s).subspan(pos);auto result=server->feed(bytes.first(std::min<std::size_t>(13,bytes.size())),Clock::now());
   if(!result)return {false,false,result.error()==t::ServerHandshakeIoError::crypto_error?Error::crypto:Error::protocol};
   if(!result->consumed)return {};pos+=result->consumed;if(pos==c2s.size()&&!client->sent())return {};
  } else return {};
 }
 if(!server->complete()||!client->negotiated()||client->resumed()!=resume||server->resumed()!=resume)return {};
 auto issuer=server->take_issuer();auto sa=server->take_application_records();auto ca=client->take_application();if(!issuer||!sa||!ca)return {false,false,Error::crypto};
 for(unsigned i=0;i<2;++i) {
  auto ticket=issuer->prepare();if(!ticket)return {false,false,ticket.error()==t::PskError::crypto_error?Error::crypto:Error::protocol};
  auto record=sa->session_ticket(ticket->body());if(!record)return {false,false,record.error()==t::RecordError::crypto_error?Error::crypto:Error::protocol};
  if(!ticket->publish(store,Clock::now()))return {};
  auto accepted=ca->open_event(*record,cache,Clock::now());if(!accepted)return {false,false,accepted.error()==t::RecordError::crypto_error?Error::crypto:Error::protocol};
  if(accepted->kind!=t::ApplicationEventKind::ticket_received)return {};
 }
 std::array<std::uint8_t,4> message{1,2,3,4};
 auto request=ca->seal(message);if(!request)return {false,false,request.error()==t::RecordError::crypto_error?Error::crypto:Error::protocol};
 auto received=sa->open_event(*request);if(!received)return {false,false,received.error()==t::RecordError::crypto_error?Error::crypto:Error::protocol};
 if(received->kind!=t::ApplicationEventKind::data||!std::ranges::equal(received->data,message))return {};
 auto sc=sa->close_notify();if(!sc)return {false,false,Error::crypto};auto closed=ca->open_event(*sc,cache,Clock::now());if(!closed)return {false,false,closed.error()==t::RecordError::crypto_error?Error::crypto:Error::protocol};
 if(closed->kind!=t::ApplicationEventKind::close_notify)return {};
 // A peer close only stops its sending direction. The client still sends a
 // complete authenticated application record and its own independent close.
 auto tail=ca->seal(message);if(!tail)return {false,false,Error::crypto};auto last=sa->open_event(*tail);if(!last)return {false,false,last.error()==t::RecordError::crypto_error?Error::crypto:Error::protocol};
 if(last->kind!=t::ApplicationEventKind::data||!std::ranges::equal(last->data,message))return {};
 auto cc=ca->close_notify();if(!cc)return {false,false,Error::crypto};auto end=sa->open_event(*cc);if(!end)return {false,false,end.error()==t::RecordError::crypto_error?Error::crypto:Error::protocol};
 if(end->kind!=t::ApplicationEventKind::close_notify||!sa->finish_input()||!ca->finish_input()||cache.size()<2)return {};
 return {true,resume,Error::none};
}
struct Trial {Pair result;bool clean=false,recovered=false,denied=false;std::size_t calls=0;};
auto trial(t::ServerCredential const& credential,std::span<View const> anchors,std::uint16_t group,std::uint16_t cipher,bool retry,bool resume,bool native,std::ptrdiff_t allowance,bool single)->Trial {
 Trial result;auto nl=fault::native_live,nb=fault::native_bytes,cl=fault::cpp_live,cb=fault::cpp_bytes;
 {
  Store store;t::ResumptionCache<8> cache;
  if(resume){auto seeded=exchange(credential,anchors,store,cache,group,cipher,retry);if(!seeded.complete)return {};}
  fault::calls=0;fault::denied=false;fault::allowance=allowance;fault::single=single;fault::native=native;fault::cpp=!native;
  try {result.result=exchange(credential,anchors,store,cache,group,cipher,retry);}catch(std::bad_alloc const&){result.result={false,false,Error::allocation};}catch(...){fault::disable();throw;}
  result.denied=fault::denied;result.calls=fault::calls;fault::disable();
  result.recovered=exchange(credential,anchors,store,cache,group,cipher,retry).complete;
 }
 nex::boringssl::ERR_clear_error();result.clean=nl==fault::native_live&&nb==fault::native_bytes&&cl==fault::cpp_live&&cb==fault::cpp_bytes;return result;
}
int main(int argc,char** argv) {
 if(argc<4)return 1;auto cert=read(argv[1]),key=read(argv[2]),root=read(argv[3]);auto credential=t::ServerCredential::create(cert,key);c::cleanse(key);if(!credential)return 2;
 std::array<View,1> anchors{root};bool failures=argc>4;unsigned total=0;
 // Warm all native one-time paths before checking exact allocation lifetimes.
 for(auto group:{23,24,25,29,4588})for(auto cipher:{0x1301,0x1302,0x1303})for(bool retry:{false,true}) {
  Store store;t::ResumptionCache<8> cache;
  auto first=exchange(*credential,anchors,store,cache,group,cipher,retry);auto second=exchange(*credential,anchors,store,cache,group,cipher,retry);
  if(!first.complete||first.resumed||!second.complete||!second.resumed){std::println("normal failed group={} cipher={:04x} retry={} first={} error={} second={} error={}",group,cipher,retry,first.complete,int(first.error),second.complete,int(second.error));return 3;}total+=2;
 }
 std::println("normal authenticated full/resumed {}, five groups three ciphers direct/HRR ticket renewal and independent close passed",total);
 if(!failures)return 0;
 unsigned injected=0,optional=0;
 for(auto cipher:{0x1301,0x1302,0x1303})for(bool retry:{false,true})for(bool resume:{false,true})for(bool native:{false,true})for(bool single:{false,true}) {
  auto baseline=trial(*credential,anchors,29,cipher,retry,resume,native,-1,single);
  if(!baseline.result.complete||!baseline.clean||!baseline.recovered){std::println("baseline failed cipher={} retry={} resume={} native={} clean={} recovered={} error={}",cipher,retry,resume,native,baseline.clean,baseline.recovered,int(baseline.result.error));return 4;}
  for(std::size_t point=0;point<=baseline.calls;++point) {
   auto value=trial(*credential,anchors,29,cipher,retry,resume,native,point,single);
   bool kind=value.result.complete||!value.denied||(native?value.result.error==Error::crypto:value.result.error==Error::allocation);
   if(!value.clean||!value.recovered||!kind||(!value.denied&&!value.result.complete)) {std::println("fault failed cipher={:04x} retry={} resume={} native={} single={} point={}/{} complete={} denied={} error={} clean={} recovered={}",cipher,retry,resume,native,single,point,baseline.calls,value.result.complete,value.denied,int(value.result.error),value.clean,value.recovered);return 5;}
   if(value.denied){++injected;optional+=value.result.complete;}
  }
  std::println("cipher={:04x} retry={} resume={} native={} single={} count={} allocation cleanup and authenticated same-store/cache next-owner recovery passed",cipher,retry,resume,native,single,baseline.calls);
 }
 std::println("PSK actual allocation failures={} optional-recovered={} all passed",injected,optional);
}
