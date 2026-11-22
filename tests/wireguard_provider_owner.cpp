import std;
import wireguard;
import wireguard.port_types;
import platform.netlink_socket;
import endpoint.config;
import endpoint.credentials;
import endpoint.owner;

namespace e=endpoint;
namespace w=wireguard;
namespace {
    template<class Profile>
    auto rejects(e::Wireguard const& config,Profile profile={}) -> bool {
        e::Prepared material;
        std::ranges::fill(material.private_key.writable(),0x42);
        e::Owner<::platform::netlink::NoHooks,w::PortNoHooks,e::SplitRoutePolicy,Profile> owner(config,material,profile);
        auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(1);
        auto result=owner.start(material,deadline,deadline);
        return !result && result.error().contains("provider-profile mismatch") && owner.drained() && !owner.local_endpoint() && std::ranges::all_of(material.private_key.view(),[](auto byte){return byte==0;});
    }
}
auto main() -> int {
    e::Wireguard config;config.provider_profile=w::Provider::warp;config.reserved={17,34,51};
    auto profile=w::ReservedProfile::create(config.provider_profile,config.reserved);
    if (!profile || !rejects(config,w::PortStandardWire{}) || !rejects(config,w::ReservedProfile{})) return 1;
    auto changed=config;changed.reserved[2]^=1;
    if (!rejects(changed,*profile)) return 2;
    changed=config;changed.provider_profile=w::Provider::standard;
    if (!rejects(changed,*profile) || !rejects(changed,w::PortStandardWire{})) return 3;
    std::println("typed endpoint rejects five config/profile mismatches before UDP/TUN startup, clears private material and drains without creating kernel resources");
}
