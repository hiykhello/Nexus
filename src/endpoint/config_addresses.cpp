module endpoint.config;
import std;
import endpoint.host_dns_types;
import dns.local_config;
import net.udp_socket;
import wireguard.routing;
import packet.tun_network_types;
import platform.socket_options;

namespace endpoint {
    namespace config_detail {
        auto address(std::string_view input,bool route,bool allow_default) -> std::optional<packet::TunAddress> {
            auto slash=input.find('/');
            if (slash==input.npos || slash+1==input.size()) return {};
            auto literal=dns::parse_local_address(input.substr(0,slash));
            unsigned prefix=0; auto text=input.substr(slash+1);
            auto parsed=std::from_chars(text.data(),text.data()+text.size(),prefix);
            if (!literal || parsed.ec!=std::errc{} || parsed.ptr!=text.data()+text.size() || prefix>(literal->ipv6 ? 128u : 32u) ||
                (text.size()>1 && text.front()=='0')) return {};
            packet::TunAddress result{literal->ipv6 ? std::uint8_t{6} : std::uint8_t{4},literal->address,static_cast<std::uint8_t>(prefix)};
            if (route ? (!wireguard::routing::valid_prefix({result.family,result.bytes,result.prefix}) || (!allow_default && !result.prefix)) :
                        !packet::tun_network_detail::valid(result,false)) return {};
            return result;
        }
        auto hostname(std::string_view name) -> bool {
            if (name.empty() || name.size()>253 || std::ranges::all_of(name,[](char c) { return (c>='0' && c<='9') || c=='.'; })) return false;
            if (!std::ranges::all_of(name,[](unsigned char c) { return (c>='a' && c<='z') || (c>='A' && c<='Z') || (c>='0' && c<='9') || c=='-' || c=='.'; })) return false;
            auto normalized=dns::normalize_local_name(name); if (!normalized) return false;
            std::string_view labels=*normalized;
            while (!labels.empty()) {
                auto dot=labels.find('.'); auto label=labels.substr(0,dot);
                if (label.front()=='-' || label.back()=='-') return false;
                if (dot==labels.npos) break;
                labels.remove_prefix(dot+1);
            }
            return true;
        }
        struct Range { std::uint8_t family; std::array<std::uint8_t,16> first,last; };
        auto range(wireguard::routing::Prefix const& prefix) -> Range {
            Range result{prefix.family,prefix.address,prefix.address};
            for (unsigned bit=prefix.bits;bit<(prefix.family==4 ? 32u : 128u);++bit) result.last[bit/8]|=std::uint8_t(1u<<(7-bit%8));
            return result;
        }
        auto successor(Range const& value) -> std::optional<std::array<std::uint8_t,16>> {
            auto result=value.last;
            for (std::size_t count=value.family==4 ? 4 : 16;count;--count) if (++result[count-1]) return result;
            return {};
        }
        auto validate(Document const& document) -> std::expected<void,std::string> {
            auto const& config=document.wireguard;
            if (!packet::tun_network_detail::validate(config.network) || config.network.mtu>2016)
                return std::unexpected("invalid device MTU, local-address or route-include");
            if (config.queue_packets<1 || config.queue_packets>1024 || config.queue_bytes<config.network.mtu || config.queue_bytes>16*1024*1024)
                return std::unexpected("queue requires packets 1..1024 and bytes from MTU to 16 MiB");
            if (config.device.empty() || config.device.size()>15 || config.device.find_first_of(std::string_view("%\0",2))!=config.device.npos)
                return std::unexpected("invalid literal device name");
            platform::SocketBinding device; std::ranges::copy(config.device,device.bind_interface.begin());
            if (!device.valid() || !config.binding.valid() ||
                config.binding.inet4_bind_address || config.binding.inet6_bind_address || config.binding.reuse_addr==true)
                return std::unexpected("invalid device name or endpoint socket binding");
            if(config.default_route && (config.network.route_count || !config.binding.routing_mark || !*config.binding.routing_mark))
                return std::unexpected("default route-mode requires no route-include and a nonzero routing-mark");
            std::vector<Range> ranges;
            std::vector<wireguard::routing::Prefix> prefixes;
            for (auto const& peer:config.peers) {
                if (peer.allowed_ips.empty()) return std::unexpected("each peer requires allowed-ip");
                if (prefixes.size()+peer.allowed_ips.size()>1024) return std::unexpected("allowed-ip exceeds global capacity 1024");
                for (auto const& prefix:peer.allowed_ips) {
                    if (std::ranges::find(prefixes,prefix)!=prefixes.end()) return std::unexpected("duplicate exact allowed-ip across peers");
                    if (prefix.family==6 && config.network.mtu<1280) return std::unexpected("IPv6 allowed-ip requires MTU at least 1280");
                    prefixes.push_back(prefix); ranges.push_back(range(prefix));
                }
                if (!peer.server && (peer.local_bootstrap || peer.strategy)) return std::unexpected("passive peer cannot configure bootstrap or address-strategy");
                if (peer.server) {
                    if (peer.server->numeric) {
                        if (peer.local_bootstrap || peer.strategy) return std::unexpected("numeric endpoint cannot configure bootstrap or address-strategy");
                        if (!outer_allowed(config,*peer.server->numeric)) return std::unexpected("peer endpoint conflicts with listen family or captured/local TUN address");
                    } else if (!peer.local_bootstrap) return std::unexpected("hostname endpoint requires bootstrap-resolver local");
                }
            }
            if (!outer_allowed(config,config.listen) && std::ranges::any_of(config.listen.address,[](auto byte) { return byte!=0; }))
                return std::unexpected("listen address overlaps a captured/local TUN address");
            std::ranges::sort(ranges,[](Range const& lhs,Range const& rhs) { return std::tie(lhs.family,lhs.first,lhs.last)<std::tie(rhs.family,rhs.first,rhs.last); });
            std::vector<Range> merged;
            for (auto const& value:ranges) {
                if (!merged.empty() && merged.back().family==value.family) {
                    auto next=successor(merged.back());
                    if (value.first<=merged.back().last || (next && value.first<=*next)) { merged.back().last=std::max(merged.back().last,value.last); continue; }
                }
                merged.push_back(value);
            }
            for (std::size_t i=0;i<config.network.route_count;++i) {
                auto const& route=config.network.routes[i]; auto desired=range({route.family,route.bytes,route.prefix});
                if (!std::ranges::any_of(merged,[&](Range const& value) { return value.family==desired.family && value.first<=desired.first && value.last>=desired.last; }))
                    return std::unexpected("route-include must be covered by the allowed-ip union");
            }
            if(config.default_route)for(std::size_t i=0;i<config.network.address_count;++i) {
                auto family=config.network.addresses[i].family;auto desired=range({family,{},0});
                if(!std::ranges::any_of(merged,[&](Range const& value){return value.family==family && value.first==desired.first && value.last==desired.last;}))
                    return std::unexpected("default route-mode requires full allowed-ip coverage for each local-address family");
            }
            if(!config.host_dns.valid())return std::unexpected("invalid host-dns options");
            for(std::size_t i=0;i<config.host_dns.server_count;++i) {
                auto const& server=config.host_dns.servers[i];auto family=server.ipv6 ? std::uint8_t{6} : std::uint8_t{4};
                packet::TunAddress target{family,server.address,server.ipv6 ? std::uint8_t{128} : std::uint8_t{32}};
                bool local=false,configured=false,os_route=config.default_route,allowed=false;
                for(std::size_t j=0;j<config.network.address_count;++j){auto const& address=config.network.addresses[j];configured|=address.family==family;local|=address.family==family && address.bytes==server.address;}
                for(std::size_t j=0;j<config.network.route_count;++j)os_route|=packet::tun_network_detail::contains(config.network.routes[j],target);
                for(auto const& peer:config.peers)for(auto const& prefix:peer.allowed_ips)allowed|=wireguard::routing::prefix_contains(prefix,family,std::span(server.address).first(server.ipv6 ? 16 : 4));
                if(local || !configured || !os_route || !allowed)return std::unexpected("host-dns servers require matching TUN family, OS route and allowed-ip coverage and cannot be local TUN addresses");
            }
            return {};
        }
    }
    auto outer_allowed(Wireguard const& config,net::UdpEndpoint const& peer) noexcept -> bool {
        using wireguard::routing::prefix_contains;
        if (peer.family!=4 && peer.family!=6) return false;
        if (std::ranges::all_of(peer.address,[](auto byte) { return !byte; }) ||
            (peer.family==4 && peer.address[0]>=224) ||
            (peer.family==6 && (peer.address[0]==255 || (peer.address[0]==254 && (peer.address[1]&192)==128)))) return false;
        if (peer.family==6 && std::ranges::all_of(std::span(peer.address).first(10),[](auto byte) { return !byte; }) && peer.address[10]==255 && peer.address[11]==255) return false;
        bool any_listen=std::ranges::all_of(config.listen.address,[](auto byte) { return byte==0; });
        if (peer.family!=config.listen.family && (config.listen.family!=6 || !any_listen)) return false;
        for (std::size_t i=0;i<config.network.address_count;++i) {
            auto const& local=config.network.addresses[i]; if (local.family==peer.family && local.bytes==peer.address) return false;
        }
        for (std::size_t i=0;i<config.network.route_count;++i) {
            auto const& route=config.network.routes[i];
            if (prefix_contains({route.family,route.bytes,route.prefix},peer.family,std::span(peer.address).first(peer.family==4 ? 4 : 16))) return false;
        }
        return true;
    }
}
