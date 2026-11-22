import std;
import crypto;
import net.datagram_driver;
import quic.datagram_port;
import quic.cid_registry;
import quic.retry_admission;
import quic.retry_token;
import nexus.thirdparty.ngtcp2;
import nexus.thirdparty.corosio;
namespace q=quic;namespace n=nex::ngtcp2;namespace io=nex::corosio;namespace net=net;
using Clock=std::chrono::steady_clock;using namespace std::chrono_literals;
namespace entropy {bool fail=false;auto fill(std::span<std::uint8_t> bytes)->std::expected<void,::crypto::Error>{if(fail)return std::unexpected(::crypto::Error::backend_failure);return ::crypto::random_bytes(bytes);}}
auto require(bool condition,char const* label)->void{if(!condition){std::println("Retry port failure: {}",label);std::exit(1);}}
struct Session {
    enum class Failure{native};q::SessionHandle owner;bool requested=false;unsigned receives=0,stops=0,drains=0;
    auto request_stop()noexcept->void{requested=true;}
    auto stopping()const noexcept->bool{return requested;}
    auto stop()noexcept->void{++stops;}
    auto drain()noexcept->void{++drains;}
    auto receive(io::endpoint const&,std::span<std::uint8_t const>,Clock::time_point)->std::expected<void,Failure>{++receives;return {};}
    auto output(std::span<std::uint8_t>,Clock::time_point)->std::expected<std::optional<net::DatagramOutput>,Failure>{return std::optional<net::DatagramOutput>{};}
    auto transmitted(std::uint64_t,Clock::time_point)->std::expected<void,Failure>{return {};}
    auto next_expiry()const noexcept->net::DatagramDeadline{return {};}
    auto expire(Clock::time_point)->std::expected<void,Failure>{return {};}
};
struct Factory {
    using Session=::Session;using ControlFailure=q::RetryFailure;
    q::RetryAdmission<2,8,entropy::fill,true> policy;std::optional<q::RetryClaims> permit;std::optional<ControlFailure> error;
    std::array<std::optional<Session>,2> sessions;unsigned created=0,destroyed=0,failures=0;bool valid=true;
    Factory(){auto initialized=policy.initialize();if(!initialized)error=initialized.error();}
    auto admit(n::ngtcp2_pkt_hd const& initial,io::endpoint const& peer,Clock::time_point now,std::size_t received)noexcept->bool{
        permit.reset();auto result=policy.inspect(initial,peer,now,received);
        if(!result){if(!error)error=result.error();return false;}permit=*result;return permit.has_value();
    }
    auto control_failure()const noexcept{return error;}
    auto control_output(std::span<std::uint8_t> bytes,Clock::time_point now)noexcept->std::expected<std::optional<net::DatagramOutput>,ControlFailure>{if(error)return std::unexpected(*error);return policy.output(bytes,now);}
    auto control_transmitted(std::uint64_t token,Clock::time_point now)noexcept{return policy.transmitted(token,now);}
    auto control_next_expiry()const noexcept{return policy.next_expiry();}
    auto control_expire(Clock::time_point now)noexcept{return policy.expire(now);}
    auto control_request_stop()noexcept->void{policy.request_stop();}
    auto control_stop()noexcept->void{permit.reset();policy.stop();}
    auto control_drained()const noexcept->bool{return policy.drained();}
    auto create(q::SessionHandle owner,q::CidRegistry<2,3>&,std::span<std::uint8_t const>,n::ngtcp2_pkt_hd const& initial,io::endpoint const&,Clock::time_point)noexcept->std::expected<Session*,Session::Failure>{
        if(!permit || !std::ranges::equal(permit->retry.bytes(),std::span(initial.dcid.data).first(initial.dcid.datalen))){valid=false;return std::unexpected(Session::Failure::native);}
        sessions[owner.slot].emplace(owner);permit.reset();++created;return &*sessions[owner.slot];
    }
    auto application_drained(q::SessionHandle,Session const&)const noexcept->bool{return true;}
    auto failed(q::SessionHandle,Session::Failure)noexcept->void{++failures;}
    auto destroy(q::SessionHandle owner,Session& session)noexcept->void{valid&=session.stops==1&&session.drains==1;++destroyed;sessions[owner.slot].reset();}
};
using Port=q::DatagramPort<Factory,2,3>;
static_assert(sizeof(Port)==472);
static_assert(std::same_as<Port::Failure,std::variant<q::DatagramPortError,q::RetryFailure>>);
auto initial(std::span<std::uint8_t const> destination,std::span<std::uint8_t const> source,std::span<std::uint8_t const> token={}) -> std::array<std::uint8_t,1200>{
    std::array<std::uint8_t,1200> packet{};packet[0]=0xc0;packet[4]=1;std::size_t at=5;
    packet[at++]=static_cast<std::uint8_t>(destination.size());std::ranges::copy(destination,packet.begin()+at);at+=destination.size();
    packet[at++]=static_cast<std::uint8_t>(source.size());std::ranges::copy(source,packet.begin()+at);at+=source.size();
    if(token.size()<64)packet[at++]=static_cast<std::uint8_t>(token.size());else{packet[at++]=0x40;packet[at++]=static_cast<std::uint8_t>(token.size());}
    std::ranges::copy(token,packet.begin()+at);at+=token.size();auto length=packet.size()-at-2;packet[at++]=static_cast<std::uint8_t>(0x40|(length>>8));packet[at++]=static_cast<std::uint8_t>(length);return packet;
}
auto main()->int{
    auto now=Clock::time_point(123456s);io::endpoint peer(io::ipv4_address::loopback(),12345);
    std::array<std::uint8_t,8> original{1,2,3,4,5,6,7,8},client{11,12,13,14,15,16,17,18};auto packet=initial(original,client);
    std::array<std::uint8_t,1200> output{};
    {
        Factory factory;Port port(factory);
        require(bool(port.receive(peer,packet,now)) && !port.size() && !factory.created && factory.policy.pending()==1,"Retry prepared before any native owner");
        auto reply=port.output(output,now);require(reply && *reply && (**reply).size<=146,"native Retry via sole port output");auto token=(**reply).token;
        auto saved=output;auto size=(**reply).size;
        require(!port.output(output,now) && output==saved,"second output cannot replace sealed packet");
        require(!port.transmitted(token+1,now) && !factory.policy.statistics().committed,"wrong completion preserves token");
        require(bool(port.receive(peer,packet,now)) && factory.policy.pending()==2 && !factory.created,"pending control still bounded admission");
        require(bool(port.expire(now+250ms)) && factory.policy.pending()==1 && !port.next_expiry(),"expiry does not free sealed pending send");
        require(bool(port.transmitted(token,now+250ms)) && factory.policy.statistics().committed==1 && !factory.created,"actual commit only, no native session");
        auto position=std::size_t{6}+saved[5];auto cid_bytes=saved[position++];std::array<std::uint8_t,20> retry{};std::ranges::copy(std::span(saved).subspan(position,cid_bytes),retry.begin());position+=cid_bytes;
        require(size-position==83+16,"native Retry token retained");auto validated=initial(std::span(retry).first(cid_bytes),client,std::span(saved).subspan(position,83));
        require(bool(port.receive(peer,validated,now+1s)) && port.size()==1 && factory.created==1 && factory.sessions[0]->receives==1 && factory.valid,"only actual verified token allocates session");
        require(bool(port.receive(peer,validated,now+1s)) && factory.created==1 && factory.sessions[0]->receives==2,"existing CID routes to same session");
        auto wrong=validated;wrong[6]^=0x80;
        require(bool(port.receive(peer,wrong,now+1s)) && factory.created==1 && factory.policy.statistics().invalid==1,"token cannot authorize a different destination CID");
        io::endpoint elsewhere(io::ipv4_address::loopback(),12346);require(bool(port.receive(elsewhere,packet,now+1s)),"new unauthenticated source receives only Retry");
        require(factory.created==1,"no source-address owner guessing");
        port.request_stop();require(!port.drained() && factory.destroyed==0,"stop gates and waits generic driver join");port.stop();port.drain();require(port.drained() && factory.created==factory.destroyed && factory.valid,"joined native/control cleanup");
    }
    {
        Factory factory;Port port(factory);require(bool(port.receive(peer,packet,now)),"cancel queued");auto reply=port.output(output,now);require(reply && *reply,"cancel sealed");
        port.request_stop();port.maintain();require(factory.policy.pending()==1 && !factory.policy.statistics().committed,"canceled pending is not committed or prematurely released");port.stop();require(port.drained() && !factory.policy.statistics().committed && !factory.created,"join cancels pending without native owner");
    }
    {
        Factory factory;Port port(factory);require(bool(port.receive(peer,packet,now)),"entropy fault queued");entropy::fail=true;auto failed=port.output(output,now);entropy::fail=false;
        require(!failed && std::holds_alternative<q::RetryFailure>(failed.error()) && std::get<q::RetryFailure>(failed.error()).stage==q::RetryFailure::Stage::entropy,"actual entropy cause reaches port error");port.request_stop();port.stop();require(port.drained() && !factory.created,"entropy failure drains");
    }
    {
        entropy::fail=true;Factory factory;entropy::fail=false;Port port(factory);auto failed=port.output(output,now);
        require(!failed && std::holds_alternative<q::RetryFailure>(failed.error()) && std::get<q::RetryFailure>(failed.error()).token==q::RetryTokenError::entropy,"startup entropy error preserved when writer starts before receive");port.request_stop();port.stop();require(port.drained() && !factory.created,"startup failure has no native owner");
    }
    {
        Factory factory;Port port(factory);require(bool(port.receive(peer,packet,now)),"native error queued");auto failed=port.output(std::span(output).first(1),now);
        require(!failed && std::holds_alternative<q::RetryFailure>(failed.error()) && std::get<q::RetryFailure>(failed.error()).native<0,"actual native output error reaches port");port.request_stop();port.stop();require(port.drained(),"native error drains");
    }
    std::println("QUIC Retry shared port={} preserves old layout; control sealed output/expiry/actual commit/joined cancel, no native before valid token, CID routing and typed local faults pass",sizeof(Port));
}
