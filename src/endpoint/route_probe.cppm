export module endpoint.route_probe;
import std;
import endpoint.config;
import platform.netlink_abi;
import platform.netlink_codec;
import platform.netlink_socket;
import packet.tun_network_types;
import packet.tun_network_records;
import packet.tun_network_view;
import net.udp_socket;

export namespace endpoint {
    // Read-only lookup of the same UDP source/port/mark/interface policy that
    // the bound outer socket will use. No packet or route mutation is issued.
    template<class Hooks=platform::netlink::NoHooks> class RouteProbe {
        using Clock=platform::netlink::Clock;
        using Socket=platform::netlink::Socket<Hooks>;
        Socket socket_;
      public:
        struct Selected { std::uint32_t interface=0,table=0; };
        [[nodiscard]] auto inspect(Wireguard const& config,net::UdpEndpoint const& peer,net::UdpEndpoint const& local,Clock::time_point deadline)
            -> std::expected<Selected,std::string> {
            namespace a=platform::netlink_abi; namespace n=platform::netlink; namespace d=packet::tun_network_detail;
            if (socket_.native_handle()<0) { auto opened=socket_.open(); if (!opened) return std::unexpected("cannot open outer route lookup"); }
            std::uint32_t interface=0;
            if (!config.binding.interface_name().empty()) {
                auto link=d::View<Socket>(socket_,0,deadline).link(config.binding.interface_name());
                if (!link || !*link || !((**link).flags&a::IFF_UP)) return std::unexpected("bound outer interface is missing or down");
                interface=(**link).index;
            }
            a::rtmsg header{.rtm_family=d::native_family(peer.family),.rtm_dst_len=static_cast<std::uint8_t>(peer.family==4 ? 32 : 128),.rtm_flags=a::RTM_F_LOOKUP_TABLE};
            bool has_source=local.family==peer.family && std::ranges::any_of(local.address,[](auto byte) { return byte!=0; });
            if (has_source) header.rtm_src_len=header.rtm_dst_len;
            n::Request request(a::RTM_GETROUTE,a::NLM_F_REQUEST,header);
            request.append(a::RTA_DST,std::span(peer.address).first(peer.family==4 ? 4 : 16));
            if (has_source) request.append(a::RTA_SRC,std::span(local.address).first(peer.family==4 ? 4 : 16));
            if (interface) request.scalar(a::RTA_OIF,interface);
            if (config.binding.routing_mark) request.scalar(a::RTA_MARK,*config.binding.routing_mark);
            request.scalar(a::RTA_IP_PROTO,std::uint8_t(a::IPPROTO_UDP));
            std::array<std::uint8_t,2> sport{static_cast<std::uint8_t>(local.port>>8),static_cast<std::uint8_t>(local.port)},
                                       dport{static_cast<std::uint8_t>(peer.port>>8),static_cast<std::uint8_t>(peer.port)};
            request.append(a::RTA_SPORT,sport); request.append(a::RTA_DPORT,dport);
            std::optional<d::RouteRecord> route;
            auto reply=socket_.query(std::move(request),deadline,[&](n::Message message) -> std::expected<void,n::Failure> {
                if (route) return n::fail(n::Error::protocol);
                auto parsed=d::parse_route(message); if (!parsed) return std::unexpected(parsed.error());
                route=*parsed; return {};
            });
            if (!reply) return std::unexpected(reply.error().code==n::Error::canceled ? "endpoint startup canceled" :
                                                reply.error().code==n::Error::timeout ? "endpoint startup deadline expired" : "outer UDP route lookup failed");
            if (!route || !route->index || (route->type!=a::RTN_UNICAST && route->type!=a::RTN_LOCAL) || (interface && route->index!=interface))
                return std::unexpected("outer UDP route is not usable");
            auto link=d::View<Socket>(socket_,route->index,deadline).link();
            if (!link || !*link || !((**link).flags&a::IFF_UP) || std::string_view((**link).name.data())==config.device)
                return std::unexpected("outer UDP route selects a down or captured device");
            return Selected{route->index,route->table};
        }
    };
}
