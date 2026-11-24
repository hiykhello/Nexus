import std;
import endpoint.config;
import net.udp_socket;
import endpoint.credentials;
import endpoint.owner;
import packet.tun_default_policy;
import wireguard.port_types;
import platform.netlink_abi;
import platform.netlink_socket;
import wireguard;
import wireguard.routing;
import crypto;
import test.lease_support;
namespace {
    namespace e=endpoint;
    namespace n = ::platform::netlink;
    namespace t=test::lease;
    using Clock=std::chrono::steady_clock;
    struct Cancel : n::NoHooks {
        static inline unsigned calls=0,target=0;
        static inline bool requested=false;
        static auto cancelled() noexcept -> bool {return requested;}
        static auto before_send(std::span<std::uint8_t const>,bool) noexcept -> std::error_code {
            if(++calls==target)requested=true;return {};
        }
    };
    template<bool Default=false> auto trial(unsigned target) -> unsigned {
        e::Wireguard config;config.name="test";config.device="nx-cancel";config.listen={4,{127,0,0,1},0};
        config.network=t::options();
        if constexpr(Default){config.default_route=true;config.network.route_count=0;config.binding.routing_mark=0x6e780001;}
        e::Peer peer;peer.name="peer";
        peer.allowed_ips={{4,{10,42,0,2},32},{6,{0xfd,0x42},128}};peer.allowed_ips[1].address[15]=2;
        peer.server=e::Server{"127.0.0.2",51820,net::UdpEndpoint{4,{127,0,0,2},51820}};
        if constexpr(Default)peer.allowed_ips={{4,{},0},{6,{},0}};
        config.peers.push_back(std::move(peer));
        e::Prepared material;material.private_key.writable()[0]=42;
        std::array<std::uint8_t,32> bytes{};bytes[0]=77;
        auto identity=::crypto::X25519Private::from_bytes(bytes);t::require(identity.has_value());auto public_key=identity->public_key();t::require(public_key.has_value());
        material.peers[0].public_key=*public_key;material.peers[0].selected=config.peers[0].server->numeric;material.count=1;
        Cancel::calls=0;Cancel::target=target;Cancel::requested=false;
        using Policy=std::conditional_t<Default,::packet::TunDefaultPolicy<Cancel>,e::SplitRoutePolicy>;
        e::Owner<Cancel,wireguard::PortNoHooks,Policy> owner(config,material);auto end=Clock::now()+std::chrono::seconds(2);
        auto started=owner.start(material,end,end+std::chrono::seconds(1));auto calls=Cancel::calls;
        t::require(target ? !started : started.has_value());
        if(target)t::require(Cancel::requested);
        // Cleanup deliberately retains the cancellation request; its explicit
        // independent budget must still remove all owned kernel state.
        auto report=owner.stop(Clock::now()+std::chrono::seconds(1));t::require(!report.total && owner.drained());
        return calls;
    }
}
auto main(int argc,char**argv) -> int {
    try {
        t::isolation(argc,argv);
        auto baseline=trial(0);t::require(baseline>10);
        for(unsigned target=1;target<=baseline;++target) {
            trial(target);trial(0);
        }
        auto defaults=trial<true>(0);t::require(defaults>baseline);
        for(unsigned target=1;target<=defaults;++target){trial<true>(target);trial<true>(0);}
        std::println("endpoint startup: split={} default={} including physical bypass/rules/RPF cancellation points; original {} native route/identity/MTU/address/route/readback cancellation points, canceled rollback honors independent budget, same-name/new-owner recovery passed",baseline,defaults,baseline);
    }catch(int code){return code;}
}
