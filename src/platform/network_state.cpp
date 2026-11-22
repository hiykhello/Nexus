module platform.network_state;
import std;
import platform.netlink_abi;
import platform.netlink_codec;
import platform.netlink_socket;
import platform.netlink_watch;

namespace platform::network {
    namespace {
        namespace abi=netlink_abi;
        namespace nl=netlink;

        constexpr std::array groups{abi::RTNLGRP_LINK,abi::RTNLGRP_IPV4_IFADDR,abi::RTNLGRP_IPV6_IFADDR,
            abi::RTNLGRP_IPV4_ROUTE,abi::RTNLGRP_IPV6_ROUTE,abi::RTNLGRP_NEIGH};
        constexpr std::size_t neighbor_limit=4096;

        auto family_width(std::uint8_t family) noexcept -> std::size_t {
            return family==abi::AF_INET ? 4 : family==abi::AF_INET6 ? 16 : 0;
        }

        auto copy_address(nl::Attribute value,std::size_t width,std::array<std::uint8_t,16>& out)
            -> std::expected<void,nl::Failure> {
            if (value.flags || value.bytes.size()!=width) return nl::fail(nl::Error::protocol);
            std::ranges::copy(value.bytes,out.begin());
            return {};
        }

        auto read_link(nl::Message message,std::vector<Link>& links) -> std::expected<void,nl::Failure> {
            auto header=nl::native<abi::ifinfomsg>(message.payload);
            if (message.header.nlmsg_type!=abi::RTM_NEWLINK || !header || header->ifi_index<=0)
                return nl::fail(nl::Error::protocol);
            if (links.size()>=4096) return nl::fail(nl::Error::limit);
            Link link{.index=static_cast<std::uint32_t>(header->ifi_index),.flags=header->ifi_flags,
                .hardware=header->ifi_type};
            auto attributes=nl::attributes(message.payload.subspan(sizeof(*header)),[&](nl::Attribute value)
                -> std::expected<void,nl::Failure> {
                if (value.type==abi::IFLA_IFNAME) {
                    auto name=nl::text(value,15);
                    if (!name || name->empty() || !link.name.empty()) return nl::fail(nl::Error::protocol);
                    link.name=*name;
                } else if (value.type==abi::IFLA_LINKINFO) {
                    return nl::attributes(value.bytes,[&](nl::Attribute info) -> std::expected<void,nl::Failure> {
                        if (info.type==abi::IFLA_INFO_KIND) {
                            auto kind=nl::text(info,63);
                            if (!kind || kind->empty() || !link.kind.empty()) return nl::fail(nl::Error::protocol);
                            link.kind=*kind;
                        }
                        return {};
                    });
                }
                return {};
            });
            if (!attributes) return attributes;
            if (link.name.empty()) return nl::fail(nl::Error::protocol);
            links.push_back(std::move(link));
            return {};
        }

        auto read_address(nl::Message message,std::vector<Address>& addresses) -> std::expected<void,nl::Failure> {
            auto header=nl::native<abi::ifaddrmsg>(message.payload);
            if (message.header.nlmsg_type!=abi::RTM_NEWADDR || !header || !header->ifa_index)
                return nl::fail(nl::Error::protocol);
            auto width=family_width(header->ifa_family);
            if (!width) return {};
            if (header->ifa_prefixlen>width*8) return nl::fail(nl::Error::protocol);
            if (addresses.size()>=16384) return nl::fail(nl::Error::limit);
            Address address{.index=header->ifa_index,.flags=header->ifa_flags,.family=header->ifa_family,
                .prefix=header->ifa_prefixlen,.scope=header->ifa_scope};
            std::optional<std::array<std::uint8_t,16>> local,peer;
            auto attributes=nl::attributes(message.payload.subspan(sizeof(*header)),[&](nl::Attribute value)
                -> std::expected<void,nl::Failure> {
                if (value.type==abi::IFA_LOCAL || value.type==abi::IFA_ADDRESS) {
                    auto& bytes=value.type==abi::IFA_LOCAL ? local : peer;
                    if (bytes) return nl::fail(nl::Error::protocol);
                    return copy_address(value,width,bytes.emplace());
                }
                if (value.type==abi::IFA_FLAGS) {
                    auto flag=nl::scalar<std::uint32_t>(value);
                    if (!flag) return std::unexpected(flag.error());
                    address.flags=*flag;
                }
                return {};
            });
            if (!attributes) return attributes;
            if (!local && !peer) return nl::fail(nl::Error::protocol);
            address.local=local ? *local : *peer;
            addresses.push_back(address);
            return {};
        }

        auto read_neighbor(nl::Message message,Snapshot& snapshot,bool& overflow)
            -> std::expected<void,nl::Failure> {
            auto header=nl::native<abi::ndmsg>(message.payload);
            if (message.header.nlmsg_type!=abi::RTM_NEWNEIGH || !header) return nl::fail(nl::Error::protocol);
            auto width=family_width(header->family);
            if (overflow || !width || header->index<=0 || !(header->state&abi::NUD_VALID_ETHERNET)) return {};
            Neighbor neighbor{.index=static_cast<std::uint32_t>(header->index),.family=header->family};
            bool address=false,mac=false;
            auto attributes=nl::attributes(message.payload.subspan(sizeof(*header)),[&](nl::Attribute value)
                -> std::expected<void,nl::Failure> {
                if (value.type==abi::NDA_DST) {
                    address=true;
                    return copy_address(value,width,neighbor.address);
                }
                if (value.type==abi::NDA_LLADDR && !value.flags && value.bytes.size()==neighbor.mac.size()) {
                    std::ranges::copy(value.bytes,neighbor.mac.begin());
                    mac=!(neighbor.mac.front()&1) && std::ranges::any_of(neighbor.mac,[](auto byte){return byte!=0;});
                }
                return {};
            });
            if (!attributes) return attributes;
            if (address && mac) {
                if (snapshot.neighbors.size()==neighbor_limit) {
                    overflow=true;
                    snapshot.neighbors.clear();
                } else snapshot.neighbors.push_back(neighbor);
            }
            return {};
        }

        auto neighbor_key(Neighbor const& value) noexcept {
            return std::tie(value.family,value.address);
        }

        auto set_gateway_macs(Snapshot& snapshot) -> void {
            for (auto family : {abi::AF_INET,abi::AF_INET6}) {
                Route const* best=nullptr;
                bool ambiguous=false;
                for (auto const& route : snapshot.routes) {
                    if (route.family!=family || route.table!=abi::RT_TABLE_MAIN ||
                        route.type!=abi::RTN_UNICAST || (route.flags&abi::RTNH_F_LINKDOWN) ||
                        !route.default_route()) continue;
                    if (!best || route.priority<best->priority) {
                        best=&route;
                        ambiguous=false;
                    } else if (route.priority==best->priority &&
                               (route.gateway!=best->gateway || route.index!=best->index || route.multiple_hops))
                        ambiguous=true;
                }
                if (best && !ambiguous && !best->multiple_hops && best->gateway && best->index)
                    snapshot.gateway_macs[family==abi::AF_INET6]=snapshot.neighbor_mac(
                        std::span(*best->gateway).first(family_width(family)),best->index);
            }
        }

        auto read_route(nl::Message message,std::vector<Route>& routes) -> std::expected<void,nl::Failure> {
            auto header=nl::native<abi::rtmsg>(message.payload);
            if (message.header.nlmsg_type!=abi::RTM_NEWROUTE || !header) return nl::fail(nl::Error::protocol);
            auto width=family_width(header->rtm_family);
            if (!width) return {};
            if (header->rtm_dst_len>width*8 || header->rtm_src_len>width*8) return nl::fail(nl::Error::protocol);
            if (routes.size()>=65536) return nl::fail(nl::Error::limit);
            Route route{.table=header->rtm_table,.flags=header->rtm_flags,.family=header->rtm_family,
                .prefix=header->rtm_dst_len,.source_prefix=header->rtm_src_len,.type=header->rtm_type,
                .protocol=header->rtm_protocol,.scope=header->rtm_scope};
            bool destination=false;
            auto attributes=nl::attributes(message.payload.subspan(sizeof(*header)),[&](nl::Attribute value)
                -> std::expected<void,nl::Failure> {
                switch (value.type) {
                case abi::RTA_DST:
                    if (std::exchange(destination,true)) return nl::fail(nl::Error::protocol);
                    return copy_address(value,width,route.destination);
                case abi::RTA_GATEWAY: return copy_address(value,width,route.gateway.emplace());
                case abi::RTA_PREFSRC: return copy_address(value,width,route.preferred_source.emplace());
                case abi::RTA_MULTIPATH: route.multiple_hops=true;return {};
                case abi::RTA_TABLE:
                case abi::RTA_PRIORITY:
                case abi::RTA_OIF: {
                    auto number=nl::scalar<std::uint32_t>(value);
                    if (!number) return std::unexpected(number.error());
                    if (value.type==abi::RTA_TABLE) route.table=*number;
                    else if (value.type==abi::RTA_PRIORITY) route.priority=*number;
                    else route.index=*number;
                    return {};
                }
                default: return {};
                }
            });
            if (!attributes) return attributes;
            if (route.prefix && !destination) return nl::fail(nl::Error::protocol);
            routes.push_back(route);
            return {};
        }
    }

    auto Link::up(this Link const& self) noexcept -> bool {return self.flags&abi::IFF_UP;}
    auto Link::carrier(this Link const& self) noexcept -> bool {return self.flags&abi::IFF_LOWER_UP;}
    auto Address::usable(this Address const& self) noexcept -> bool {
        return !(self.flags&(abi::IFA_F_TENTATIVE|abi::IFA_F_DADFAILED));
    }

    auto Snapshot::find_link(this Snapshot const& self,std::uint32_t index) noexcept -> Link const* {
        auto found=std::ranges::lower_bound(self.links,index,{},&Link::index);
        return found!=self.links.end() && found->index==index ? &*found : nullptr;
    }

    auto Snapshot::neighbor_mac(this Snapshot const& self,std::span<std::uint8_t const> address,
        std::uint32_t index) noexcept -> std::optional<MacAddress> {
        Neighbor key;
        if (address.size()==4) key.family=abi::AF_INET;
        else if (address.size()==16) key.family=abi::AF_INET6;
        else return {};
        std::ranges::copy(address,key.address.begin());
        auto found=std::ranges::lower_bound(self.neighbors,neighbor_key(key),{},neighbor_key);
        std::optional<MacAddress> result;
        for (;found!=self.neighbors.end() && neighbor_key(*found)==neighbor_key(key);++found) {
            if (index && found->index!=index) continue;
            if (result && *result!=found->mac) return {};
            result=found->mac;
        }
        return result;
    }

    auto Monitor::drain(this Monitor& self) -> std::expected<std::size_t,nl::Failure> {
        return self.watch_.drain(self.query_.receive_buffer(),[](nl::Message) -> std::expected<void,nl::Failure> {
            return {};
        });
    }

    auto Monitor::start(this Monitor& self,Clock::time_point deadline) -> std::expected<void,nl::Failure> {
        if (self.watch_.native_handle()>=0 || self.query_.native_handle()>=0) return nl::fail(nl::Error::configuration);
        auto watched=self.watch_.open(std::span(groups).first(groups.size()-(self.include_neighbors_ ? 0 : 1)));
        if (!watched) return watched;
        auto queried=self.query_.open();
        if (!queried) {
            self.stop();
            return queried;
        }
        auto loaded=self.refresh(deadline);
        if (!loaded) self.stop();
        return loaded;
    }

    auto Monitor::poll(this Monitor& self,Clock::time_point deadline) -> std::expected<bool,nl::Failure> {
        if (self.watch_.native_handle()<0) return nl::fail(nl::Error::closed);
        auto notices=self.drain();
        if (!notices || *notices) self.invalidate();
        if (!notices && notices.error().code!=nl::Error::uncertain && notices.error().code!=nl::Error::limit)
            return std::unexpected(notices.error());
        if (self.get()) return false;
        auto loaded=self.refresh(deadline);
        if (!loaded) return std::unexpected(loaded.error());
        return true;
    }

    auto Monitor::refresh(this Monitor& self,Clock::time_point deadline) -> std::expected<void,nl::Failure> {
        if (self.watch_.native_handle()<0) return nl::fail(nl::Error::closed);
        self.invalidate();
        if (self.generation_==std::numeric_limits<std::uint64_t>::max()) return nl::fail(nl::Error::sequence_exhausted);
        // A dump can overlap mutations. Discard the candidate if any relevant
        // multicast group reports work since the pre-dump queue was drained.
        while (Clock::now()<deadline) {
            auto previous=self.drain();
            if (!previous) {
                if (previous.error().code==nl::Error::uncertain || previous.error().code==nl::Error::limit) continue;
                return std::unexpected(previous.error());
            }
            auto candidate=std::make_shared<Snapshot>();
            auto links=self.query_.dump(abi::RTM_GETLINK,abi::AF_UNSPEC,deadline,[&](nl::Message message) {
                return read_link(message,candidate->links);
            });
            if (!links) return links;
            auto addresses=self.query_.dump(abi::RTM_GETADDR,abi::AF_UNSPEC,deadline,[&](nl::Message message) {
                return read_address(message,candidate->addresses);
            });
            if (!addresses) return addresses;
            for (auto family : {abi::AF_INET,abi::AF_INET6}) {
                auto routes=self.query_.dump(abi::RTM_GETROUTE,family,deadline,[&](nl::Message message) {
                    return read_route(message,candidate->routes);
                });
                if (!routes) return routes;
            }
            if (self.include_neighbors_) {
                bool overflow=false;
                auto neighbors=self.query_.dump(abi::RTM_GETNEIGH,abi::AF_UNSPEC,deadline,[&](nl::Message message) {
                    return read_neighbor(message,*candidate,overflow);
                });
                if (!neighbors) return neighbors;
                std::ranges::sort(candidate->neighbors,{},neighbor_key);
                set_gateway_macs(*candidate);
            }
            auto changed=self.drain();
            if (!changed) {
                if (changed.error().code==nl::Error::uncertain || changed.error().code==nl::Error::limit) continue;
                return std::unexpected(changed.error());
            }
            if (*changed) continue;
            std::ranges::sort(candidate->links,{},&Link::index);
            if (std::ranges::adjacent_find(candidate->links,{},&Link::index)!=candidate->links.end())
                return nl::fail(nl::Error::protocol);
            candidate->generation=++self.generation_;
            candidate->observed=Clock::now();
            self.live_.store(std::move(candidate),std::memory_order_release);
            return {};
        }
        return nl::fail(nl::Error::timeout);
    }

    auto Monitor::stop(this Monitor& self) noexcept -> void {
        self.invalidate();
        self.watch_.close();
        self.query_.close();
    }
}
