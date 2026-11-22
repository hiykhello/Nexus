import std;
import crypto;
import net.udp_socket;
import wireguard;
import wireguard.crypto;
import wireguard.noise;
import wireguard.endpoint;
import wireguard.port_types;
import wireguard.port;
import wireguard.routing;
import wireguard.registry;
namespace {
    namespace w=wireguard;
    using namespace std::chrono_literals;
    struct State {bool allowed=false;unsigned calls=0;};
    struct Policy {
        State* state;
        auto allows(w::EndpointAddress const&) const noexcept -> bool {++state->calls;return state->allowed;}
    };
    struct Block {
        static inline unsigned calls=0;
        static auto before_send(std::optional<w::PeerHandle>,w::OutboundKind,std::span<std::uint8_t const>) noexcept -> std::optional<std::error_code> {
            ++calls;return std::make_error_code(std::errc::resource_unavailable_try_again);
        }
    };
    using Port=w::UdpPort<2,2,256,4,Block,Policy>;
    auto key(unsigned start) -> ::crypto::X25519Private {
        w::Key bytes;for(std::size_t i=0;i<bytes.size();++i)bytes[i]=static_cast<std::uint8_t>(start+i);
        auto value=::crypto::X25519Private::from_bytes(bytes);if(!value)std::terminate();return std::move(*value);
    }
    auto require(bool value,unsigned line=0) -> void {if(!value){std::println("outer policy assertion {}",line);throw 1;}}
    auto trial(bool cookie,bool ipv6) -> void {
        auto first=key(0),second=key(32);auto first_public=first.public_key(),second_public=second.public_key();
        require(first_public && second_public,1);
        w::Key bytes;for(std::size_t i=0;i<bytes.size();++i)bytes[i]=static_cast<std::uint8_t>(i);
        State state;auto port=Port::create(bytes,{.require_cookie=cookie},Policy{&state});require(port.has_value(),2);
        w::EndpointAddress local{ipv6 ? std::uint8_t{6}:std::uint8_t{4},{},0};if(ipv6)local.address[15]=1;else{local.address[0]=127;local.address[3]=1;}
        net::UdpSocket remote;require(remote.bind(local).has_value(),3);auto source=remote.local_endpoint();require(source.has_value(),4);
        auto now=w::Clock::time_point(10s);auto wall=std::chrono::system_clock::now();
        require(port->open(local,now).has_value(),5);auto target=port->local_endpoint();require(target.has_value(),6);
        w::EndpointConfig settings{.peer_public=*second_public,.allowed_ips={{4,{10,42,0,2},32}},.peer=*source,.mtu=128};
        auto peer=port->add_peer(std::move(settings));require(peer.has_value(),7);
        auto handshake=w::Handshake::create(second,*first_public);require(handshake.has_value(),8);
        auto timestamp=w::make_timestamp(1000,1);require(timestamp.has_value(),9);
        auto initiation=handshake->initiate(100,*timestamp,key(96));require(initiation.has_value(),10);
        // A fully authentic initiation from an excluded outer source is dropped
        // before cookie/DH/replay state. Accept the identical bytes afterwards.
        require(remote.send(*target,*initiation).has_value(),11);
        auto rejected=port->poll(now,wall);require(rejected && rejected->received==1 && !rejected->sent,12);
        auto status=port->status();require(status.metrics.source_rejects==1 && status.metrics.dropped==1 && status.metrics.sent==0 && !status.pending_sends && !status.registry.reservations && state.calls==1,13);
        state.allowed=true;Block::calls=0;
        require(remote.send(*target,*initiation).has_value(),14);
        auto staged=port->poll(now+1ms,wall+1ms);require(staged && staged->received==1 && staged->write_blocked && Block::calls==1,15);
        // Pending handshake/cookie output must recheck immutable outer policy
        // at the physical send, before the lower send hook/system call.
        state.allowed=false;auto calls=Block::calls;
        auto denied=port->poll(now+2ms,wall+2ms);
        require(denied && denied->send_error==std::errc::permission_denied && !denied->sent && Block::calls==calls,16);
        require(port->status().metrics.sent==0 && port->status().metrics.send_errors==1 && state.calls>=4,17);
        std::array<std::uint8_t,256> buffer{};auto physical=remote.receive(buffer);require(physical && !*physical,18);
        port->stop();require(port->drained(),19);
    }
}
auto main() -> int {
    try{for(bool cookie:{false,true})for(bool ipv6:{false,true})trial(cookie,ipv6);}catch(int code){return code;}
    std::println("outer IPv4/IPv6 exclusion before authentic initiation processing; identical initiation recovery; pending cookie/response rechecked before every physical send; default Port={} static-policy Port={}",sizeof(w::UdpPort<>),sizeof(Port));
}
