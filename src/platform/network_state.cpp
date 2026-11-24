module platform.network_state;
import std;
import platform.netlink_abi;
import platform.netlink_codec;
import platform.netlink_socket;
import platform.netlink_watch;

namespace platform::network {
    namespace {
        namespace abi = netlink_abi;
        namespace nl = netlink;

        static_assert(constants::af_inet == abi::AF_INET);
        static_assert(constants::af_inet6 == abi::AF_INET6);
        static_assert(constants::rt_scope_universe == abi::RT_SCOPE_UNIVERSE);
        static_assert(constants::rt_table_main == abi::RT_TABLE_MAIN);
        static_assert(constants::rtn_unicast == abi::RTN_UNICAST);
        static_assert(constants::rtnh_f_linkdown == abi::RTNH_F_LINKDOWN);
        static_assert(constants::iff_up == static_cast<std::uint32_t>(abi::IFF_UP));
        static_assert(constants::iff_lower_up == static_cast<std::uint32_t>(abi::IFF_LOWER_UP));
        static_assert(constants::ifa_f_tentative == static_cast<std::uint32_t>(abi::IFA_F_TENTATIVE));
        static_assert(constants::ifa_f_dadfailed == static_cast<std::uint32_t>(abi::IFA_F_DADFAILED));

        constexpr std::array groups{abi::RTNLGRP_LINK, abi::RTNLGRP_IPV4_IFADDR, abi::RTNLGRP_IPV6_IFADDR,
            abi::RTNLGRP_IPV4_ROUTE, abi::RTNLGRP_IPV6_ROUTE, abi::RTNLGRP_NEIGH};
        constexpr std::size_t neighbor_limit = 4096;

        auto to_monitor_failure(nl::Failure const& failure) noexcept -> MonitorFailure {
            MonitorError code = MonitorError::system;
            switch (failure.code) {
            case nl::Error::closed: code = MonitorError::closed; break;
            case nl::Error::configuration: code = MonitorError::configuration; break;
            case nl::Error::system: code = MonitorError::system; break;
            case nl::Error::timeout: code = MonitorError::timeout; break;
            case nl::Error::protocol: code = MonitorError::protocol; break;
            case nl::Error::limit: code = MonitorError::limit; break;
            case nl::Error::sequence_exhausted: code = MonitorError::sequence_exhausted; break;
            case nl::Error::uncertain: code = MonitorError::uncertain; break;
            case nl::Error::canceled: code = MonitorError::system; break;
            }
            return {code, failure.system};
        }

        auto family_width(std::uint8_t family) noexcept -> std::size_t {
            return family == abi::AF_INET ? 4 : family == abi::AF_INET6 ? 16 : 0;
        }

        auto copy_address(nl::Attribute value, std::size_t width, std::array<std::uint8_t, 16>& out)
            -> std::expected<void, nl::Failure> {
            if (value.flags || value.bytes.size() != width) return nl::fail(nl::Error::protocol);
            std::ranges::copy(value.bytes, out.begin());
            return {};
        }

        auto read_link(nl::Message message, std::vector<Link>& links) -> std::expected<void, nl::Failure> {
            auto header = nl::native<abi::ifinfomsg>(message.payload);
            if (message.header.nlmsg_type != abi::RTM_NEWLINK || !header || header->ifi_index <= 0)
                return nl::fail(nl::Error::protocol);
            if (links.size() >= 4096) return nl::fail(nl::Error::limit);
            Link link{.index = static_cast<std::uint32_t>(header->ifi_index), .flags = header->ifi_flags,
                .hardware = header->ifi_type};
            auto attributes = nl::attributes(message.payload.subspan(sizeof(*header)), [&](nl::Attribute value)
                -> std::expected<void, nl::Failure> {
                if (value.type == abi::IFLA_IFNAME) {
                    auto name = nl::text(value, 15);
                    if (!name || name->empty() || !link.name.empty()) return nl::fail(nl::Error::protocol);
                    link.name = *name;
                } else if (value.type == abi::IFLA_LINKINFO) {
                    return nl::attributes(value.bytes, [&](nl::Attribute info) -> std::expected<void, nl::Failure> {
                        if (info.type == abi::IFLA_INFO_KIND) {
                            auto kind = nl::text(info, 63);
                            if (!kind || kind->empty() || !link.kind.empty()) return nl::fail(nl::Error::protocol);
                            link.kind = *kind;
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

        auto read_address(nl::Message message, std::vector<Address>& addresses) -> std::expected<void, nl::Failure> {
            auto header = nl::native<abi::ifaddrmsg>(message.payload);
            if (message.header.nlmsg_type != abi::RTM_NEWADDR || !header || !header->ifa_index)
                return nl::fail(nl::Error::protocol);
            auto width = family_width(header->ifa_family);
            if (!width) return {};
            if (header->ifa_prefixlen > width * 8) return nl::fail(nl::Error::protocol);
            if (addresses.size() >= 16384) return nl::fail(nl::Error::limit);
            Address address{.index = header->ifa_index, .flags = header->ifa_flags, .family = header->ifa_family,
                .prefix = header->ifa_prefixlen, .scope = header->ifa_scope};
            std::optional<std::array<std::uint8_t, 16>> local, peer;
            auto attributes = nl::attributes(message.payload.subspan(sizeof(*header)), [&](nl::Attribute value)
                -> std::expected<void, nl::Failure> {
                if (value.type == abi::IFA_LOCAL || value.type == abi::IFA_ADDRESS) {
                    auto& bytes = value.type == abi::IFA_LOCAL ? local : peer;
                    if (bytes) return nl::fail(nl::Error::protocol);
                    return copy_address(value, width, bytes.emplace());
                }
                if (value.type == abi::IFA_FLAGS) {
                    auto flag = nl::scalar<std::uint32_t>(value);
                    if (!flag) return std::unexpected(flag.error());
                    address.flags = *flag;
                }
                return {};
            });
            if (!attributes) return attributes;
            if (!local && !peer) return nl::fail(nl::Error::protocol);
            address.local = local ? *local : *peer;
            addresses.push_back(address);
            return {};
        }

        auto read_neighbor(nl::Message message, Snapshot& snapshot, bool& overflow)
            -> std::expected<void, nl::Failure> {
            auto header = nl::native<abi::ndmsg>(message.payload);
            if (message.header.nlmsg_type != abi::RTM_NEWNEIGH || !header) return nl::fail(nl::Error::protocol);
            auto width = family_width(header->family);
            if (overflow || !width || header->index <= 0 || !(header->state & abi::NUD_VALID_ETHERNET)) return {};
            Neighbor neighbor{.index = static_cast<std::uint32_t>(header->index), .family = header->family};
            bool address = false, mac = false;
            auto attributes = nl::attributes(message.payload.subspan(sizeof(*header)), [&](nl::Attribute value)
                -> std::expected<void, nl::Failure> {
                if (value.type == abi::NDA_DST) {
                    address = true;
                    return copy_address(value, width, neighbor.address);
                }
                if (value.type == abi::NDA_LLADDR && !value.flags && value.bytes.size() == neighbor.mac.size()) {
                    std::ranges::copy(value.bytes, neighbor.mac.begin());
                    mac = !(neighbor.mac.front() & 1) && std::ranges::any_of(neighbor.mac, [](auto byte) { return byte != 0; });
                }
                return {};
            });
            if (!attributes) return attributes;
            if (address && mac) {
                if (snapshot.neighbors.size() == neighbor_limit) {
                    overflow = true;
                    snapshot.neighbors.clear();
                } else snapshot.neighbors.push_back(neighbor);
            }
            return {};
        }

        auto neighbor_key(Neighbor const& value) noexcept { return std::tie(value.family, value.address); }

        auto set_gateway_macs(Snapshot& snapshot) -> void {
            for (auto family : {abi::AF_INET, abi::AF_INET6}) {
                Route const* best = nullptr;
                bool ambiguous = false;
                for (auto const& route : snapshot.routes) {
                    if (route.family != family || route.table != abi::RT_TABLE_MAIN ||
                        route.type != abi::RTN_UNICAST || (route.flags & abi::RTNH_F_LINKDOWN) ||
                        !route.default_route()) continue;
                    if (!best || route.priority < best->priority) {
                        best = &route; ambiguous = false;
                    } else if (route.priority == best->priority &&
                               (route.gateway != best->gateway || route.index != best->index || route.multiple_hops))
                        ambiguous = true;
                }
                if (best && !ambiguous && !best->multiple_hops && best->gateway && best->index)
                    snapshot.gateway_macs[family == abi::AF_INET6] = snapshot.neighbor_mac(
                        std::span(*best->gateway).first(family_width(family)), best->index);
            }
        }

        auto read_route(nl::Message message, std::vector<Route>& routes) -> std::expected<void, nl::Failure> {
            auto header = nl::native<abi::rtmsg>(message.payload);
            if (message.header.nlmsg_type != abi::RTM_NEWROUTE || !header) return nl::fail(nl::Error::protocol);
            auto width = family_width(header->rtm_family);
            if (!width) return {};
            if (header->rtm_dst_len > width * 8 || header->rtm_src_len > width * 8) return nl::fail(nl::Error::protocol);
            if (routes.size() >= 65536) return nl::fail(nl::Error::limit);
            Route route{.table = header->rtm_table, .flags = header->rtm_flags, .family = header->rtm_family,
                .prefix = header->rtm_dst_len, .source_prefix = header->rtm_src_len, .type = header->rtm_type,
                .protocol = header->rtm_protocol, .scope = header->rtm_scope};
            bool destination = false;
            auto attributes = nl::attributes(message.payload.subspan(sizeof(*header)), [&](nl::Attribute value)
                -> std::expected<void, nl::Failure> {
                switch (value.type) {
                case abi::RTA_DST:
                    if (std::exchange(destination, true)) return nl::fail(nl::Error::protocol);
                    return copy_address(value, width, route.destination);
                case abi::RTA_GATEWAY: return copy_address(value, width, route.gateway.emplace());
                case abi::RTA_PREFSRC: return copy_address(value, width, route.preferred_source.emplace());
                case abi::RTA_MULTIPATH: route.multiple_hops = true; return {};
                case abi::RTA_TABLE:
                case abi::RTA_PRIORITY:
                case abi::RTA_OIF: {
                    auto number = nl::scalar<std::uint32_t>(value);
                    if (!number) return std::unexpected(number.error());
                    if (value.type == abi::RTA_TABLE) route.table = *number;
                    else if (value.type == abi::RTA_PRIORITY) route.priority = *number;
                    else route.index = *number;
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

    struct Monitor::Impl {
        nl::Socket<> query_;
        nl::Watch watch_;
        auto drain() -> std::expected<std::size_t, nl::Failure> {
            return watch_.drain(query_.receive_buffer(), [](nl::Message) -> std::expected<void, nl::Failure> { return {}; });
        }
    };

    Monitor::Monitor(bool include_neighbors)
        : impl_(std::make_unique<Impl>()), include_neighbors_(include_neighbors) {}
    Monitor::~Monitor() = default;

    auto Monitor::started() const noexcept -> bool { return impl_ && impl_->watch_.native_handle() >= 0; }

    auto Monitor::start(Clock::time_point deadline) -> std::expected<void, MonitorFailure> {
        if (!impl_) return fail_monitor(MonitorError::closed);
        if (impl_->watch_.native_handle() >= 0 || impl_->query_.native_handle() >= 0)
            return fail_monitor(MonitorError::configuration);
        if (auto watched = impl_->watch_.open(std::span(groups).first(groups.size() - (include_neighbors_ ? 0 : 1))); !watched)
            return std::unexpected(to_monitor_failure(watched.error()));
        if (auto queried = impl_->query_.open(); !queried) {
            stop();
            return std::unexpected(to_monitor_failure(queried.error()));
        }
        auto loaded = refresh(deadline);
        if (!loaded) stop();
        return loaded;
    }

    auto Monitor::poll(Clock::time_point deadline) -> std::expected<bool, MonitorFailure> {
        if (!impl_ || impl_->watch_.native_handle() < 0) return fail_monitor(MonitorError::closed);
        auto notices = impl_->drain();
        if (!notices || *notices) invalidate();
        if (!notices && notices.error().code != nl::Error::uncertain && notices.error().code != nl::Error::limit)
            return std::unexpected(to_monitor_failure(notices.error()));
        if (get()) return false;
        auto loaded = refresh(deadline);
        if (!loaded) return std::unexpected(loaded.error());
        return true;
    }

    auto Monitor::refresh(Clock::time_point deadline) -> std::expected<void, MonitorFailure> {
        if (!impl_ || impl_->watch_.native_handle() < 0) return fail_monitor(MonitorError::closed);
        invalidate();
        if (generation_ == std::numeric_limits<std::uint64_t>::max()) return fail_monitor(MonitorError::sequence_exhausted);
        while (Clock::now() < deadline) {
            auto previous = impl_->drain();
            if (!previous) {
                if (previous.error().code == nl::Error::uncertain || previous.error().code == nl::Error::limit) continue;
                return std::unexpected(to_monitor_failure(previous.error()));
            }
            auto candidate = std::make_shared<Snapshot>();
            auto links = impl_->query_.dump(abi::RTM_GETLINK, abi::AF_UNSPEC, deadline,
                [&](nl::Message message) { return read_link(message, candidate->links); });
            if (!links) return std::unexpected(to_monitor_failure(links.error()));
            auto addresses = impl_->query_.dump(abi::RTM_GETADDR, abi::AF_UNSPEC, deadline,
                [&](nl::Message message) { return read_address(message, candidate->addresses); });
            if (!addresses) return std::unexpected(to_monitor_failure(addresses.error()));
            for (auto family : {abi::AF_INET, abi::AF_INET6}) {
                auto routes = impl_->query_.dump(abi::RTM_GETROUTE, family, deadline,
                    [&](nl::Message message) { return read_route(message, candidate->routes); });
                if (!routes) return std::unexpected(to_monitor_failure(routes.error()));
            }
            if (include_neighbors_) {
                bool overflow = false;
                auto neighbors = impl_->query_.dump(abi::RTM_GETNEIGH, abi::AF_UNSPEC, deadline,
                    [&](nl::Message message) { return read_neighbor(message, *candidate, overflow); });
                if (!neighbors) return std::unexpected(to_monitor_failure(neighbors.error()));
                std::ranges::sort(candidate->neighbors, {}, neighbor_key);
                set_gateway_macs(*candidate);
            }
            auto changed = impl_->drain();
            if (!changed) {
                if (changed.error().code == nl::Error::uncertain || changed.error().code == nl::Error::limit) continue;
                return std::unexpected(to_monitor_failure(changed.error()));
            }
            if (*changed) continue;
            std::ranges::sort(candidate->links, {}, &Link::index);
            if (std::ranges::adjacent_find(candidate->links, {}, &Link::index) != candidate->links.end())
                return fail_monitor(MonitorError::protocol);
            Route const* best_route = nullptr;
            for (auto const& route : candidate->routes) {
                if (route.table != constants::rt_table_main || route.type != constants::rtn_unicast ||
                    !route.default_route() || !route.index || (route.flags & constants::rtnh_f_linkdown))
                    continue;
                if (!best_route || route.priority < best_route->priority) best_route = &route;
            }
            if (best_route) {
                candidate->default_interface_index = best_route->index;
                if (auto const* link = candidate->find_link(best_route->index)) {
                    auto kind = infer_network_type(*link);
                    candidate->default_network_type = kind;
                    candidate->network_is_expensive = kind == NetworkType::cellular;
                    candidate->network_is_constrained = false;
                }
            }
            candidate->generation = ++generation_;
            candidate->observed = Clock::now();
            live_.store(std::move(candidate), std::memory_order_release);
            return {};
        }
        return fail_monitor(MonitorError::timeout);
    }

    auto Monitor::stop() noexcept -> void {
        invalidate();
        if (impl_) { impl_->watch_.close(); impl_->query_.close(); }
    }
}
