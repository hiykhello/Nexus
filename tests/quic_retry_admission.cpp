import std;
import crypto;
import net.datagram_driver;
import quic.retry_admission;
import nexus.thirdparty.ngtcp2;
import nexus.thirdparty.corosio;
namespace q=quic;namespace n=nex::ngtcp2;namespace io=nex::corosio;
using Clock=std::chrono::steady_clock;using namespace std::chrono_literals;
namespace allocation {bool observe=false;unsigned calls=0;}
auto operator new(std::size_t size)->void*{if(allocation::observe)++allocation::calls;if(auto* p=std::malloc(size?size:1))return p;throw std::bad_alloc();}
auto operator new[](std::size_t size)->void*{return ::operator new(size);}
auto operator new(std::size_t size,std::align_val_t alignment)->void*{if(allocation::observe)++allocation::calls;auto a=static_cast<std::size_t>(alignment);size=std::max<std::size_t>(size,1);if(size>std::numeric_limits<std::size_t>::max()-a)throw std::bad_alloc();if(auto* p=std::aligned_alloc(a,((size+a-1)/a)*a))return p;throw std::bad_alloc();}
auto operator new[](std::size_t size,std::align_val_t alignment)->void*{return ::operator new(size,alignment);}
auto operator delete(void* p)noexcept->void{std::free(p);}
auto operator delete[](void* p)noexcept->void{std::free(p);}
auto operator delete(void* p,std::size_t)noexcept->void{std::free(p);}
auto operator delete[](void* p,std::size_t)noexcept->void{std::free(p);}
auto operator delete(void* p,std::align_val_t)noexcept->void{std::free(p);}
auto operator delete[](void* p,std::align_val_t)noexcept->void{std::free(p);}
auto operator delete(void* p,std::size_t,std::align_val_t)noexcept->void{std::free(p);}
auto operator delete[](void* p,std::size_t,std::align_val_t)noexcept->void{std::free(p);}
namespace entropy {
    bool fail=false,collide=false;unsigned calls=0;std::uint8_t value=17;
    auto fill(std::span<std::uint8_t> out)->std::expected<void,::crypto::Error>{++calls;if(fail)return std::unexpected(::crypto::Error::backend_failure);for(auto& byte:out)byte=collide?0x42:value++;return {};}
}
auto require(bool condition,char const* label)->void{if(!condition){std::println("Retry admission failure: {}",label);std::exit(1);}}
auto header(std::uint8_t seed=0x42)->n::ngtcp2_pkt_hd{
    n::ngtcp2_pkt_hd out{};out.version=1;out.type=n::NGTCP2_PKT_INITIAL;std::array<std::uint8_t,8> original{},client{};original.fill(seed);client.fill(seed+1);
    n::ngtcp2_cid_init(&out.dcid,original.data(),original.size());n::ngtcp2_cid_init(&out.scid,client.data(),client.size());return out;
}
struct Response {
    std::array<std::uint8_t,83> token;
    std::array<std::uint8_t,20> source{};std::size_t source_size=0;
};
auto response(std::span<std::uint8_t const> bytes)->Response{
    auto position=std::size_t{6}+bytes[5];Response out;out.source_size=bytes[position++];std::ranges::copy(bytes.subspan(position,out.source_size),out.source.begin());position+=out.source_size;
    require(bytes.size()-position==out.token.size()+16,"Retry token/native tag boundaries");std::ranges::copy(bytes.subspan(position,83),out.token.begin());return out;
}
auto main()->int{
    using Policy=q::RetryAdmission<2,8,entropy::fill,true>;Policy policy;io::endpoint peer(io::ipv4_address::loopback(),12345),wrong(io::ipv4_address::loopback(),12346);auto now=Clock::time_point(123456s);auto first=header();
    std::array<std::uint8_t,1200> wire{};
    require(!policy.inspect(first,peer,now,1200),"uninitialized local error");require(bool(policy.initialize()),"fresh key initialized");
    require(policy.inspect(first,peer,now,1199).value()==std::nullopt && !policy.pending(),"undersized Initial cannot reflect");
    auto invalid_version=first;invalid_version.version=2;require(!*policy.inspect(invalid_version,peer,now,1200) && !policy.pending(),"unsupported version drop");
    require(!*policy.inspect(first,peer,now,1200) && policy.pending()==1,"unvalidated Initial queues stateless reply only");
    require(!*policy.inspect(first,peer,now,1200) && policy.pending()==2,"bounded second reply");
    require(!*policy.inspect(first,peer,now,1200) && policy.pending()==2 && policy.statistics().throttled==1,"queue pressure no extra owner");
    auto output=policy.output(wire,now);require(output && *output && (**output).peer==peer && (**output).size<1200 && (**output).size<=146,"anti amplification actual response bound");
    auto token=(**output).token;auto saved=response(std::span(wire).first((**output).size));
    require(!policy.output(wire,now),"sealed output cannot be replaced before socket commit");
    require(!policy.transmitted(token+1,now) && policy.pending()==2,"wrong commit keeps sealed control");
    require(bool(policy.expire(now+250ms)) && policy.pending()==1 && policy.statistics().expired==1 && !policy.next_expiry(),"sealed packet retained, unsealed deadline expired without busy timer");
    require(bool(policy.transmitted(token,now+250ms)) && !policy.pending() && policy.statistics().committed==1,"only actual socket completion counted");
    require(!policy.transmitted(token,now) && policy.statistics().committed==1,"stale completion rejected");
    auto retried=first;n::ngtcp2_cid_init(&retried.dcid,saved.source.data(),saved.source_size);retried.token=saved.token.data();retried.tokenlen=saved.token.size();
    auto permit=policy.inspect(retried,peer,now+1s,1200);require(permit && *permit && (**permit).original.size==8 && std::ranges::equal((**permit).original.bytes(),std::span(first.dcid.data).first(8)),"authenticated address/CID permit before native allocation");
    require(!*policy.inspect(retried,wrong,now+1s,1200) && !policy.pending(),"wrong peer token dropped, no reflection");
    auto modified=saved.token;modified[40]^=1;retried.token=modified.data();require(!*policy.inspect(retried,peer,now+1s,1200) && !policy.pending(),"tampered token dropped");
    retried.token=saved.token.data();require(!*policy.inspect(retried,peer,now+10001ms,1200) && !policy.pending(),"expired token dropped");
    require(!policy.inspect(first,peer,Clock::time_point::max(),1200),"queue deadline cannot overflow");
    Policy rate;require(bool(rate.initialize()),"rate init");
    for(unsigned i=0;i<2;++i){require(!*rate.inspect(first,peer,now,1200),"initial burst");auto packet=rate.output(wire,now);require(packet && *packet && bool(rate.transmitted((**packet).token,now)),"burst actual send");}
    require(!*rate.inspect(first,peer,now+19ms,1200) && !rate.pending(),"no early quota refill");
    require(!*rate.inspect(first,peer,now+20ms,1200) && rate.pending()==1,"exact one token refill");
    require(!*rate.inspect(first,peer,now+20ms,1200) && rate.pending()==1,"rate quota bounds repeated same-tick input");
    rate.request_stop();require(!rate.inspect(first,peer,now,1200) && !rate.drained(),"request stop gates but preserves queued output");rate.stop();require(rate.drained() && rate.statistics().committed==2,"joined cancel does not fabricate send");
    Policy local_error;entropy::fail=true;require(!local_error.initialize(),"startup entropy failure");entropy::fail=false;require(bool(local_error.initialize()),"startup entropy recovery");
    require(!*local_error.inspect(first,peer,now,1200),"failure reply queued");entropy::fail=true;auto no_entropy=local_error.output(wire,now);require(!no_entropy && no_entropy.error().stage==q::RetryFailure::Stage::entropy && local_error.pending()==1,"runtime CSPRNG failure preserves cause/queue");entropy::fail=false;
    entropy::collide=true;auto before=entropy::calls;auto collision=local_error.output(wire,now);require(!collision && entropy::calls-before==8 && collision.error().stage==q::RetryFailure::Stage::entropy,"bounded original-CID collisions before native assert");entropy::collide=false;
    auto no_buffer=local_error.output(std::span(wire).first(1),now);require(!no_buffer && no_buffer.error().stage==q::RetryFailure::Stage::packet && no_buffer.error().native<0,"real native small-buffer error preserved");
    auto recovery=local_error.output(wire,now);require(recovery && *recovery && bool(local_error.transmitted((**recovery).token,now)),"fresh output after local failures");local_error.stop();require(local_error.drained(),"runtime failure recovery clean");
    q::RetryAdmission<> native;require(bool(native.initialize()) && !*native.inspect(first,peer,now,1200),"actual CSPRNG authority initialized");auto actual=native.output(wire,now);require(actual && *actual && bool(native.transmitted((**actual).token,now)),"actual CSPRNG Retry sent");native.stop();policy.stop();
    q::RetryAdmission<2,8,entropy::fill,false> steady;require(bool(steady.initialize()),"uninstrumented production policy initialized");allocation::observe=true;
    for(unsigned i=0;i<10000;++i){auto current=now+20ms*(i+1);require(!*steady.inspect(first,peer,current,1200),"steady unvalidated Initial");auto reply=steady.output(wire,current);require(reply && *reply && bool(steady.transmitted((**reply).token,current)),"steady native Retry actual output/commit");}
    steady.stop();allocation::observe=false;require(allocation::calls==0 && steady.drained(),"uninstrumented full policy lifecycle C++ ordinary/array/aligned new0");
    static_assert(sizeof(q::RetryAdmission<2,8,entropy::fill,false>)+sizeof(q::RetryStatistics)==sizeof(Policy));
    std::println("QUIC stateless Retry policy={} queue2 uninstrumented={} default_queue8_uninstrumented={} optional_counter_bytes={} steady10000_Cppnew={}, no-native-owner before token, response<=146/1200, token/peer/time/type/pressure/rate/sealed/expiry/cancel/entropy/collision/native-failure/recovery validated",sizeof(Policy),sizeof(q::RetryAdmission<2,8,entropy::fill,false>),sizeof(q::RetryAdmission<>),sizeof(q::RetryStatistics),allocation::calls);
}
