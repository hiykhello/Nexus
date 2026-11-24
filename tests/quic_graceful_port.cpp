import std;
import quic.datagram_port;
import quic.cid_registry;
import net.datagram_driver;
import ngtcp2;
import corosio;
namespace q=quic;
namespace n = ::ngtcp2;
namespace io = ::corosio;
using Clock=std::chrono::steady_clock;
using namespace std::chrono_literals;
struct Factory;
auto retire(q::SessionHandle) noexcept -> void;
auto pinned(q::SessionHandle) noexcept -> bool;
auto live(q::SessionHandle) noexcept -> bool;
struct Session {
    enum class Failure { receive=71,output=72,transmit=73,expiry=74 };
    Factory& factory;
    q::SessionHandle owner;
    io::endpoint peer;
    std::array<std::uint8_t,8> cid{};
    bool alive=true,in_callback=false,requested=false,ready=true;
    unsigned action=0,received=0,transmissions=0,stops=0,drains=0;
    Clock::time_point expiry=Clock::now()+10ms;
    auto request_stop() noexcept -> void {requested=true;}
    auto stopping() const noexcept -> bool {return requested;}
    auto stop() noexcept -> void;
    auto drain() noexcept -> void;
    auto receive(io::endpoint const&,std::span<std::uint8_t const>,Clock::time_point) -> std::expected<void,Failure>;
    auto output(std::span<std::uint8_t>,Clock::time_point) -> std::expected<std::optional<net::DatagramOutput>,Failure>;
    auto close_output(std::span<std::uint8_t>,Clock::time_point) -> std::expected<std::optional<net::DatagramOutput>,Failure>;
    auto transmitted(std::uint64_t,Clock::time_point) -> std::expected<void,Failure>;
    auto next_expiry() const noexcept -> net::DatagramDeadline {return requested?net::DatagramDeadline{}:expiry;}
    auto expire(Clock::time_point) -> std::expected<void,Failure>;
};
struct Factory {
    using Session=::Session;
    std::array<std::optional<Session>,2> sessions;
    std::array<bool,2> drained{true,true};
    unsigned created=0,destroyed=0,failures=0;
    bool valid=true,deny=false,admission=true;
    auto admit(n::ngtcp2_pkt_hd const&,io::endpoint const&,Clock::time_point) const noexcept -> bool {return admission;}
    auto create(q::SessionHandle owner,q::CidRegistry<2,3>&,std::span<std::uint8_t const> source,n::ngtcp2_pkt_hd const&,io::endpoint const& peer,Clock::time_point) noexcept -> std::expected<Session*,Session::Failure> {
        if(deny)return std::unexpected(Session::Failure::receive);
        auto& state=sessions[owner.slot];if(state){valid=false;return std::unexpected(Session::Failure::receive);}
        state.emplace(*this,owner,peer);std::ranges::copy(source,state->cid.begin());++created;return &*state;
    }
    auto application_drained(q::SessionHandle owner,Session const&) const noexcept -> bool {return drained[owner.slot];}
    auto failed(q::SessionHandle,Session::Failure) noexcept -> void {++failures;}
    auto destroy(q::SessionHandle owner,Session& state) noexcept -> void {
        valid&=!state.alive && !state.in_callback && state.stops==1 && state.drains==1 && !pinned(owner) && !live(owner);++destroyed;sessions[owner.slot].reset();
    }
};
using Port=q::DatagramPort<Factory,2,3,8,true>;
Port* current=nullptr;
auto retire(q::SessionHandle owner) noexcept -> void {(void)current->request_retire(owner);}
auto pinned(q::SessionHandle owner) noexcept -> bool {return current->pinned(owner);}
auto live(q::SessionHandle owner) noexcept -> bool {return current->live(owner);}
struct Flight {Session& state;explicit Flight(Session& state):state(state){state.in_callback=true;}~Flight(){state.in_callback=false;}};
auto Session::stop() noexcept -> void {factory.valid&=alive && !in_callback && !pinned(owner) && factory.drained[owner.slot];++stops;alive=false;}
auto Session::drain() noexcept -> void {factory.valid&=!alive && !in_callback;++drains;}
auto Session::receive(io::endpoint const&,std::span<std::uint8_t const>,Clock::time_point) -> std::expected<void,Failure> {
    Flight flight{*this};++received;if(action==1)retire(owner);if(action==2)return std::unexpected(Failure::receive);return {};
}
auto Session::output(std::span<std::uint8_t> bytes,Clock::time_point) -> std::expected<std::optional<net::DatagramOutput>,Failure> {
    Flight flight{*this};if(action==3)retire(owner);if(action==4)return std::unexpected(Failure::output);
    if(!ready)return std::optional<net::DatagramOutput>{};ready=false;
    for(std::size_t i=0;i<bytes.size();++i)bytes[i]=static_cast<std::uint8_t>(owner.generation*71+i);
    return net::DatagramOutput{peer,bytes.size(),17};
}
auto Session::close_output(std::span<std::uint8_t> bytes,Clock::time_point) -> std::expected<std::optional<net::DatagramOutput>,Failure> {
    Flight flight{*this};if(action==9)return std::unexpected(Failure::output);
    bytes[0]=42;return net::DatagramOutput{peer,1,17};
}
auto Session::transmitted(std::uint64_t token,Clock::time_point) -> std::expected<void,Failure> {
    Flight flight{*this};factory.valid&=alive&&token==17;++transmissions;if(action==5)retire(owner);if(action==6)return std::unexpected(Failure::transmit);return {};
}
auto Session::expire(Clock::time_point now) -> std::expected<void,Failure> {
    Flight flight{*this};expiry=now+10ms;if(action==7)retire(owner);if(action==8)return std::unexpected(Failure::expiry);return {};
}
auto initial(std::uint8_t seed) -> std::array<std::uint8_t,1200> {
    std::array<std::uint8_t,1200> out{};out[0]=0xc0;out[4]=1;out[5]=8;out[14]=8;
    for(unsigned i=0;i<8;++i){out[6+i]=seed+i;out[15+i]=seed+32+i;}
    auto length=out.size()-26;out[24]=static_cast<std::uint8_t>(0x40|(length>>8));out[25]=static_cast<std::uint8_t>(length);return out;
}
auto short_packet(std::array<std::uint8_t,8> const& cid) -> std::array<std::uint8_t,40> {
    std::array<std::uint8_t,40> out{};out[0]=0x40;std::ranges::copy(cid,out.begin()+1);return out;
}
auto admission() -> bool {
    Factory factory;Port port(factory);current=&port;auto now=Clock::now();io::endpoint peer(io::ipv4_address::loopback(),54321);
    auto a=initial(1),b=initial(2),c=initial(3);std::array<std::uint8_t,64> output{};
    if(!port.receive(peer,a,now)||!port.receive(peer,b,now)||!port.receive(peer,c,now)||port.size()!=2||factory.created!=2)return false;
    auto owner=factory.sessions[0]->owner;auto old_cid=factory.sessions[0]->cid;
    factory.drained[owner.slot]=false;
    auto packet=port.output(output,now);if(!packet||!*packet||!port.pinned(owner))return false;
    auto sealed=output;port.request_retire(owner);port.maintain();
    if(!factory.sessions[owner.slot]||!factory.sessions[owner.slot]->alive||port.active(owner)||!port.pinned(owner))return false;
    if(port.transmitted((**packet).token+1,now).error()!=q::DatagramPortError::invalid_token||!port.pinned(owner)||output!=sealed)return false;
    if(!port.transmitted((**packet).token,now)||port.pinned(owner)||factory.sessions[owner.slot]->transmissions!=1)return false;
    port.maintain();if(!factory.sessions[owner.slot]||!factory.sessions[owner.slot]->alive)return false;
    auto before=factory.sessions[1]->received;auto wrong=short_packet(old_cid);if(!port.receive(peer,wrong,now)||factory.sessions[1]->received!=before)return false;
    factory.drained[owner.slot]=true;port.maintain();if(port.live(owner)||factory.sessions[owner.slot]||factory.destroyed!=1)return false;
    if(!port.receive(peer,c,now)||factory.created!=3||!factory.sessions[owner.slot]||factory.sessions[owner.slot]->owner.generation==owner.generation)return false;
    auto fresh=factory.sessions[owner.slot]->owner;before=factory.sessions[owner.slot]->received;
    if(!port.receive(peer,wrong,now)||factory.sessions[owner.slot]->received!=before)return false;
    auto good=short_packet(factory.sessions[owner.slot]->cid);if(!port.receive(peer,good,now)||factory.sessions[owner.slot]->received!=before+1)return false;
    port.request_stop();port.maintain();if(factory.destroyed!=1)return false;
    port.stop();port.drain();return port.drained()&&factory.valid&&factory.created==factory.destroyed&&!port.live(fresh);
}
auto callback(unsigned action) -> bool {
    Factory factory;Port port(factory);current=&port;auto now=Clock::now();io::endpoint peer(io::ipv4_address::loopback(),54321);auto first=initial(21);
    if(!port.receive(peer,first,now)||!factory.sessions[0])return false;
    auto owner=factory.sessions[0]->owner;factory.sessions[0]->action=action;std::array<std::uint8_t,64> bytes{};
    if(action==1||action==2){auto wire=short_packet(factory.sessions[0]->cid);if(!port.receive(peer,wire,now))return false;}
    else if(action==3||action==4){if(!port.output(bytes,now))return false;}
    else if(action==5||action==6){auto packet=port.output(bytes,now);if(!packet||!*packet||!port.transmitted((**packet).token,now))return false;}
    else {
        auto packet=port.output(bytes,now);if(!packet||!*packet)return false;
        if(!port.expire(now+20ms)||!factory.sessions[0]||!factory.sessions[0]->alive||!port.pinned(owner))return false;
        if(!port.transmitted((**packet).token,now+20ms))return false;
    }
    if(factory.sessions[0]||factory.destroyed!=1||port.live(owner))return false;
    if(factory.failures!=(action%2==0?1u:0u))return false;
    port.request_stop();port.stop();return port.drained()&&factory.valid;
}
auto cancelled_pending() -> bool {
    Factory factory;Port port(factory);current=&port;auto now=Clock::now();io::endpoint peer(io::ipv4_address::loopback(),54321);auto first=initial(31);
    if(!port.receive(peer,first,now))return false;auto owner=factory.sessions[0]->owner;std::array<std::uint8_t,64> bytes{};auto packet=port.output(bytes,now);
    if(!packet||!*packet||!port.pinned(owner))return false;
    port.request_stop();port.maintain();if(!factory.sessions[0]||factory.destroyed||!port.pinned(owner))return false;
    factory.drained[0]=false;port.stop();if(!factory.sessions[0]||factory.destroyed||port.pinned(owner)||port.drained())return false;
    if(factory.sessions[0]->transmissions)return false;
    factory.drained[0]=true;port.drain();return port.drained()&&factory.valid&&factory.destroyed==1;
}
auto rejection() -> bool {
    Factory factory;Port port(factory);current=&port;factory.admission=false;factory.deny=true;auto wire=initial(41);auto now=Clock::now();io::endpoint peer(io::ipv4_address::loopback(),1);
    std::array<std::uint8_t,8> malformed{};if(!port.receive(peer,malformed,now)||port.size())return false;
    for(unsigned i=0;i<10;++i)if(!port.receive(peer,wire,now)||port.size()||factory.created)return false;
    factory.admission=true;
    for(unsigned i=0;i<10;++i)if(!port.receive(peer,wire,now)||port.size()||factory.created)return false;
    factory.deny=false;if(!port.receive(peer,wire,now)||port.size()!=1||factory.created!=1)return false;
    port.request_stop();port.stop();return port.drained()&&factory.valid;
}
auto graceful(unsigned mode) -> bool {
    Factory factory;Port port(factory);current=&port;auto now=Clock::now();io::endpoint peer(io::ipv4_address::loopback(),54321);auto first=initial(81);
    if(!port.receive(peer,first,now)||!factory.sessions[0])return false;auto owner=factory.sessions[0]->owner;std::array<std::uint8_t,64> bytes{};
    // Preserve any normal packet pin across the shutdown request.
    auto normal=port.output(bytes,now);if(!normal||!*normal)return false;port.begin_shutdown();
    if(port.active(owner) || !port.pinned(owner) || port.quiescent())return false;
    auto new_owner=port.registry().reserve();if(!new_owner)return false;Session other{factory,*new_owner,peer};
    if(port.attach(*new_owner,other) || !port.registry().release(*new_owner))return false;
    if(!port.transmitted((**normal).token,now) || !factory.sessions[0] || !factory.sessions[0]->requested)return false;
    factory.drained[0]=false;if(mode==2)factory.sessions[0]->action=9;
    auto close=port.output(bytes,now);if(!close)return false;
    if(mode==2){if(*close || factory.failures!=1 || !port.shutdown_failure() || *port.shutdown_failure()!=Session::Failure::output)return false;}
    else {
        if(!*close || (**close).size!=1 || bytes[0]!=42 || !port.pinned(owner))return false;
        if(mode==1) {port.request_stop();port.stop();if(port.pinned(owner) || !factory.sessions[0])return false;}
        else if(!port.transmitted((**close).token,now) || !factory.sessions[0])return false;
    }
    factory.drained[0]=true;port.maintain();if(!port.quiescent() || factory.destroyed!=1)return false;
    port.request_stop();port.stop();return port.drained()&&factory.valid;
}
auto main() -> int {
    for(unsigned i=0;i<3;++i)if(!graceful(i)){std::println("graceful {} failed",i);return 9;}
    if(!admission())return 1;
    for(unsigned action=1;action<=8;++action)if(!callback(action)){std::println("port callback action={} failed",action);return 2;}
    if(!cancelled_pending()||!rejection())return 3;
    std::println("QUIC shared port11 deterministic lifecycle cases passed: bounded CID admission, pre-submit sealed pin, pending expiry/stop, eight callback faults, deferred native retirement, business drain gate, failed-send discard and nonreviving generations; port={} bytes",sizeof(Port));
}
